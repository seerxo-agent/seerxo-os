"""Company OS internal API (§108).

Internal only (§109): this app binds inside the Docker network and is never published
to a host port. Public access, when it is ever wanted, goes through Cloudflare Access
plus a tunnel — not through an opened port.
"""
import hashlib
import json
import os
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import (api_auth, approval_identity, audit, keys, context_builder, control, desk as desk_read, desk_stream, dispatch, enums, goals,
                 event_router, metric_sources, metrics_store, models, notebook, packaging, polar_metrics, registry,
                 runreport, schemas, stage_c_ci, stage_c_worker, worker)
from app.config import settings
from app.db import get_db
from app.notify import NotificationService, fingerprint, notifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("company.api")

# Status writes through the public task APIs are manual reports, not worker claims.
# Workers record FAILED directly after bounded execution; a human must own terminal
# closure/reopening and REVIEW decisions.
_FOUNDER_ONLY_TASK_STATES = (
    enums.TaskStatus.DONE,
    enums.TaskStatus.CANCELLED,
    enums.TaskStatus.FAILED,
    enums.TaskStatus.REVIEW,
)

app = FastAPI(
    title="Company OS",
    description="Internal company state, tasks, events, incidents and approvals.",
    version="0.1.0",
)
app.middleware("http")(api_auth.middleware)


# --------------------------------------------------------------------------- helpers

def _by_key(db: Session, model, key: str | None):
    if not key:
        return None
    obj = db.execute(select(model).where(model.key == key)).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, f"{model.__name__} '{key}' not found")
    return obj


def _parse_ts(value: str | None) -> datetime | None:
    """Parse an ISO timestamp from an external tool, tolerating a trailing Z."""
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _record_event(db: Session, payload: schemas.EventIn) -> models.Event:
    event = models.Event(
        event_type=payload.event_type,
        source=payload.source,
        severity=payload.severity,
        payload=payload.payload,
        dedupe_key=payload.dedupe_key
        or fingerprint(payload.event_type, payload.source, str(payload.payload or "")),
    )
    for field, model in (
        ("business_unit", models.BusinessUnit), ("project", models.Project),
        ("service", models.Service), ("task", models.Task), ("incident", models.Incident),
    ):
        obj = _by_key(db, model, getattr(payload, field))
        if obj is not None:
            setattr(event, f"{field}_id", obj.id)
    db.add(event)
    db.commit()
    db.refresh(event)
    event_router.safe_route(db, event)  # event -> incident -> task, deterministic
    return event


# --------------------------------------------------------------------------- desk UI

_DESK = Path(__file__).resolve().parent / "static" / "desk.html"
_PWA_ASSETS = {
    "manifest.webmanifest": "application/manifest+json",
    "sw.js": "text/javascript",
    "icons/sez-192.png": "image/png",
    "icons/sez-512.png": "image/png",
    "icons/apple-touch-icon.png": "image/png",
}


@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
def desk() -> HTMLResponse:
    """The founder desk (§87).

    Served from the same internal API (§109), via SSH or an Access-protected Tunnel.
    Access assertions authorize only the Desk routes; the browser has no API token.

    Still one self-contained file with no CDN, so serving needs no pipeline (§104). Its
    source is `desk/` (React + shadcn/ui, founder request 2026-10-05); `npm run build` there
    rewrites this file and CI fails if the committed file does not match the source.
    """
    return HTMLResponse(_DESK.read_text(), headers={"cache-control": "no-store"})


@app.get("/manifest.webmanifest", include_in_schema=False)
@app.get("/sw.js", include_in_schema=False)
@app.get("/icons/{icon}", include_in_schema=False)
def pwa_asset(request: Request) -> FileResponse:
    """A fixed allowlist keeps service-worker scope at / without exposing other files."""
    asset_path = request.url.path.lstrip("/")
    media_type = _PWA_ASSETS.get(asset_path)
    if not media_type:
        raise HTTPException(404)
    headers = {"cache-control": "no-store", "x-content-type-options": "nosniff"}
    if asset_path == "sw.js":
        headers["service-worker-allowed"] = "/"
    return FileResponse(_DESK.parent / asset_path, media_type=media_type, headers=headers)


# --------------------------------------------------------------------------- health

@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    """Liveness plus a real database round-trip — §130, a 200 must mean something."""
    db.execute(select(1))
    return {"status": "ok", "environment": settings.environment,
            "utc": datetime.now(timezone.utc).isoformat()}


# --------------------------------------------------------------------------- boot / state

def _state(db: Session) -> dict:
    """§118 company snapshot. This is what an agent loads instead of asking the founder."""
    open_tasks = db.execute(
        select(models.Task).where(models.Task.status.in_(enums.OPEN_TASK_STATES))
    ).scalars().all()
    incidents = db.execute(
        select(models.Incident).where(models.Incident.status != enums.IncidentStatus.RESOLVED)
    ).scalars().all()
    delivered_incidents = NotificationService.delivered_incident_ids(db, incidents)
    approvals = db.execute(
        select(models.Approval).where(models.Approval.status == enums.ApprovalStatus.REQUESTED)
    ).scalars().all()
    bus = db.execute(select(models.BusinessUnit)).scalars().all()
    phases = db.execute(select(models.Phase).order_by(models.Phase.number)).scalars().all()
    last_ckpt = db.execute(
        select(models.Checkpoint).order_by(models.Checkpoint.created_at.desc()).limit(1)
    ).scalar_one_or_none()
    last_backup = db.execute(
        select(models.BackupRun).order_by(models.BackupRun.started_at.desc()).limit(1)
    ).scalar_one_or_none()
    last_restore = db.execute(
        select(models.BackupRun)
        .where(models.BackupRun.ok.is_(True),
               models.BackupRun.integrity_verified.is_(True),
               models.BackupRun.uploaded.is_(True),  # off-site evidence only; a local-dump restore proves the file
               models.BackupRun.restore_tested_at.is_not(None))
        .order_by(models.BackupRun.restore_tested_at.desc(), models.BackupRun.id.desc())
        .limit(1)
    ).scalar_one_or_none()

    prio = [t for t in open_tasks if t.priority in (enums.Priority.P0, enums.Priority.P1)]
    prio.sort(key=lambda t: (t.priority.value, t.created_at))

    return {
        "status": "degraded" if any(
            i.severity in (enums.IncidentSeverity.SEV0, enums.IncidentSeverity.SEV1)
            for i in incidents
        ) else "ok",
        "utc": datetime.now(timezone.utc).isoformat(),
        "business_units": [
            {"key": b.key, "name": b.name, "status": b.status.value, "priority": b.priority.value}
            for b in bus
        ],
        "active_projects": db.execute(
            select(func.count()).select_from(models.Project)
            .where(models.Project.status == enums.ProjectStatus.ACTIVE)
        ).scalar_one(),
        "open_tasks": len(open_tasks),
        "blocked_tasks": sum(1 for t in open_tasks if t.status == enums.TaskStatus.BLOCKED),
        "priorities": [
            {"key": t.key, "priority": t.priority.value, "title": t.title, "status": t.status.value}
            for t in prio[:5]
        ],
        "incidents": [
            {"key": i.key, "severity": i.severity.value, "status": i.status.value,
             "title": i.title, "founder_notified": i.id in delivered_incidents}
            for i in incidents
        ],
        "pending_approvals": [
            {"key": a.key, "action": a.action, "risk": a.risk_level.value,
             "requested_by": a.requested_by, "waiting_hours": round(
                 (datetime.now(timezone.utc) - a.created_at).total_seconds() / 3600, 1)}
            for a in approvals
        ],
        "phases": [{"n": p.number, "name": p.name, "status": p.status.value} for p in phases],
        "last_checkpoint": {
            "at": last_ckpt.created_at.isoformat(), "actor": last_ckpt.actor,
            "next_action": last_ckpt.next_action,
        } if last_ckpt else None,
        "last_backup": {
            "target": last_backup.target, "at": last_backup.started_at.isoformat(),
            "ok": last_backup.ok, "integrity_verified": last_backup.integrity_verified,
            "restore_tested_at": last_backup.restore_tested_at.isoformat()
            if last_backup.restore_tested_at else None,
        } if last_backup else None,
        "last_restore": {
            "target": last_restore.target,
            "at": last_restore.restore_tested_at.isoformat(),
        } if last_restore else None,
    }


@app.get("/company/state")
@app.post("/company/boot")
def company_boot(db: Session = Depends(get_db)) -> dict:
    return _state(db)


@app.get("/company")
def company(db: Session = Depends(get_db)) -> dict:
    return _state(db)


@app.get("/desk/state")
def founder_desk_state(db: Session = Depends(get_db)) -> dict:
    """One consistent operational read model for the internal Founder Desk."""
    return desk_read.build_state(db, registry.load(), control.agents_paused(db))


@app.get("/desk/stream")
async def founder_desk_stream(request: Request):
    """Server-Sent Events: a notice each time committed state changes; the Desk re-reads /desk/state (read only)."""
    return desk_stream.response(request)


@app.get("/desk/metrics/series")
def desk_metric_series(source: str, subject: str, metric: str, window: str = "",
                       days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db)) -> dict:
    """The history of one business series, for the Desk trend charts (read only)."""
    return metrics_store.series(db, source=source, subject=subject, metric=metric, window=window, days=days)


# The company's real facts live on the host, mounted read-only (docker-compose.yml). Where that mount exists (every
# production container), only the host file counts: missing or unreadable is reported, never replaced by the
# repository's docs/PERMANENT_FACTS.md, which may be a public example. Only without the mount and outside a deployed
# container (local development, tests) is the repository file shown.
_HOST_FACTS = Path("/run/company-facts/PERMANENT_FACTS.md")
_PERMANENT_FACTS = Path(__file__).resolve().parent.parent / "docs" / "PERMANENT_FACTS.md"
FACTS_UNAVAILABLE = ("## Permanent facts unavailable\n\nThe host's facts file ({path}) is missing or unreadable. "
                     "Nothing is shown rather than example facts; restore it on the host.\n")


def _permanent_facts() -> str | None:
    # A deployed container (the deploy sets COMPANY_OS_GIT_SHA) needs the host file even if the mount is missing.
    if _HOST_FACTS.parent.is_dir() or os.environ.get("COMPANY_OS_GIT_SHA"):
        try:
            return _HOST_FACTS.read_text()
        except OSError:
            return FACTS_UNAVAILABLE.format(path=_HOST_FACTS)
    try:
        return _PERMANENT_FACTS.read_text()
    except OSError:
        return None


@app.get("/desk/memory")
def founder_desk_memory(db: Session = Depends(get_db)) -> dict:
    """Decisions, learnings, notebooks and permanent facts for the desk's Memory view."""
    return {
        "decisions": list_decisions(db),
        "learnings": list_learnings(db),
        "notes": list_notes(db=db, limit=200),
        "permanent": _permanent_facts(),
    }


DESK_UNATTENDED_AGENTS = ("research", "ceo")


@app.post("/desk/command", status_code=201)
def founder_desk_command(body: schemas.DeskCommand, db: Session = Depends(get_db), request: Request = None) -> dict:
    """Founder command -> READY task for an agent (CEO by default).

    Deterministic on purpose: no model reads the text here. A LOW-risk task for research or
    the CEO is opted in to the unattended worker (next tick); other agents' tasks wait for
    the attended dispatcher (herdr) or Stage C.
    """
    text = " ".join(body.text.split())
    project = _by_key(db, models.Project, body.project)
    unit = _by_key(db, models.BusinessUnit, body.business_unit)
    if project and unit and project.business_unit_id != unit.id:
        raise HTTPException(422, f"project '{project.key}' is not in business unit '{unit.key}'")
    task = create_task(schemas.TaskCreate(
        title=" ".join((body.title or text[:200]).split()), description=text,
        status=enums.TaskStatus.READY, priority=body.priority, assigned_agent=body.agent,
        # The request text is the objective unless one was given: an empty objective would
        # hold the task at the worker's quality gate (underspecified).
        created_by="founder", objective=body.objective or text, risk_level=body.risk_level,
        business_unit=body.business_unit, project=body.project, goal=body.goal,
        success_criteria=body.success_criteria or "Request answered, routed to an owning agent "
                         "task, or declined with a recorded reason",
        # The founder's own request to a Stage B agent runs unattended: research and CEO runs
        # are tool-less in company-reasoner, so they can only produce text that lands in
        # REVIEW. Developer work stays on the attended path (herdr) or Stage C.
        context={"source": "founder-desk-command", "scope": body.business_unit or "company-os",
                 "autonomous": body.agent in DESK_UNATTENDED_AGENTS
                 and body.risk_level == enums.RiskLevel.LOW,
                 # An answer with no deliverable item is not an answer (2026-10-10, TASK-0048 promised a ranking
                 # "below" and returned none; it was approved). The supervisor now needs at least one item.
                 "verify": {"min_actions": 1}},
        dedupe_key="desk:" + hashlib.sha256(text.lower().encode()).hexdigest()[:32],
        reason="founder desk command",
    ), db, request)
    _record_event(db, schemas.EventIn(
        event_type="TASK_CREATED", source="founder-desk", severity=enums.Severity.INFO,
        task=task.key, payload={"title": f"Founder created {task.key}: {task.title}"},
    ))
    return {"key": task.key, "status": task.status.value, "agent": body.agent}


@app.get("/company/brief", response_class=PlainTextResponse)
def company_brief(db: Session = Depends(get_db)) -> str:
    """§92 founder brief as plain text, so the CLI and Telegram share one renderer.

    Deliberately terse: the founder should not need to read infrastructure logs.
    """
    st = _state(db)
    m = metrics(db)
    L: list[str] = ["COMPANY DAILY BRIEF", f"generated {st['utc']}  status={st['status'].upper()}", ""]

    active = [b for b in st["business_units"] if b["status"] == "ACTIVE"]
    L += [f"Business units   {len(active)} active / {len(st['business_units'])} total"
          f"   ({', '.join(b['key'] for b in active) or 'none'})",
          f"Tasks            {st['open_tasks']} open, {st['blocked_tasks']} blocked",
          f"Agent runs 24h   {m['agent_runs_24h']}"
          + (f", success {m['agent_success_rate_24h']}" if m["agent_success_rate_24h"] is not None else "")
          + f", AI cost ${m['ai_cost_24h_usd']:.2f}",
          f"Notifications 24h {m['alerts_delivered_24h']} delivered; {m['events_24h']} events recorded", ""]

    lb = st["last_backup"]
    if lb:
        L += ["Backups", f"  last: {lb['target']} at {lb['at']} ok={lb['ok']} "
                         f"integrity={lb['integrity_verified']}"]
        restore = st["last_restore"]
        L += [f"  last successful restore test: {restore['at'] if restore else 'NEVER'}", ""]
    else:
        L += ["Backups", "  NONE RECORDED", ""]

    if st["incidents"]:
        L.append("Incidents")
        for i in st["incidents"]:
            L.append(f"  [{i['severity']}] {i['key']} {i['status']}: {i['title']}")
        L.append("")

    if st["priorities"]:
        L.append("Priorities")
        for t in st["priorities"]:
            L.append(f"  {t['priority']} {t['key']} [{t['status']}] {t['title']}")
        L.append("")
    else:
        L += ["Priorities", "  no open P0/P1 tasks", ""]

    if st["pending_approvals"]:
        L.append("Approvals required")
        for a in st["pending_approvals"]:
            L.append(f"  {a['key']} ({a['risk']}, waiting {a['waiting_hours']}h): {a['action']}")
        L.append("")

    phase = next((p for p in st["phases"] if p["status"] == "IN_PROGRESS"), None)
    L.append(f"Current phase    {phase['n']}. {phase['name']}" if phase else "Current phase    none in progress")
    if st["last_checkpoint"]:
        cp = st["last_checkpoint"]
        L.append(f"Recorded checkpoint ({cp['at']}, {cp['actor']}): {cp['next_action'] or '(none recorded)'}")
    return "\n".join(L)


# --------------------------------------------------------------------------- registries

@app.get("/business-units")
def list_business_units(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(models.BusinessUnit).order_by(models.BusinessUnit.priority)).scalars()
    return [{"key": b.key, "name": b.name, "status": b.status.value,
             "priority": b.priority.value, "revenue_model": b.revenue_model} for b in rows]


@app.get("/projects")
def list_projects(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(models.Project).order_by(models.Project.priority)).scalars()
    return [{"key": p.key, "name": p.name, "status": p.status.value,
             "priority": p.priority.value, "repository": p.repository,
             "production_url": p.production_url} for p in rows]


@app.get("/services")
def list_services(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(models.Service).order_by(models.Service.key)).scalars()
    return [{"key": s.key, "name": s.name, "status": s.status.value, "risk": s.risk.value,
             "container": s.container, "domain": s.domain, "backup": s.backup,
             "last_verified": s.last_verified.isoformat() if s.last_verified else None}
            for s in rows]


@app.get("/agents")
def list_agents(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(models.Agent).order_by(models.Agent.key)).scalars()
    return [{"key": a.key, "role": a.role, "enabled": a.enabled,
             "autonomy_level": a.autonomy_level, "prompt_version": a.prompt_version,
             "last_heartbeat_at": a.last_heartbeat_at.isoformat() if a.last_heartbeat_at else None,
             "last_success_at": a.last_success_at.isoformat() if a.last_success_at else None,
             "last_error": a.last_error} for a in rows]


@app.get("/agents/{key}")
def get_agent(key: str, db: Session = Depends(get_db)) -> dict:
    agent = _by_key(db, models.Agent, key)
    spec = registry.load().get(key)
    if spec is None:
        raise HTTPException(404, f"Agent '{key}' is not in the registry")
    return desk_read.agent_detail(db, agent, spec, control.agents_paused(db))


@app.get("/phases")
def list_phases(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(models.Phase).order_by(models.Phase.number)).scalars()
    return [{"number": p.number, "name": p.name, "status": p.status.value,
             "deliverables": p.deliverables, "notes": p.notes,
             "completed_at": p.completed_at.isoformat() if p.completed_at else None}
            for p in rows]


@app.post("/phases/{number}")
def update_phase(number: int, body: schemas.PhaseUpdate, db: Session = Depends(get_db),
                 request: Request = None) -> dict:
    """Move a build phase with evidence, audited. COMPLETE is founder-only (§45): a verified founder
    principal, never `body.actor`, which is untrusted metadata (app/approval_identity.py)."""
    phase = db.execute(select(models.Phase).where(models.Phase.number == number)).scalar_one_or_none()
    if phase is None:
        raise HTTPException(404, f"phase {number} not found")
    who = (approval_identity.require_founder(request) if body.status == enums.PhaseStatus.COMPLETE
           else approval_identity.principal_of(request))
    before = audit.snapshot(phase)
    phase.status = body.status
    phase.notes = body.evidence
    phase.completed_at = (datetime.now(timezone.utc)
                          if body.status == enums.PhaseStatus.COMPLETE else None)
    after = audit.snapshot(phase)
    if body.actor != who.id:
        after["client_claimed_actor"] = body.actor
    audit.record(db, actor=who.id, action="phase.status", entity_type="phase",
                 entity_key=str(number), reason=body.evidence[:500], before=before, after=after)
    db.commit()
    return {"number": phase.number, "name": phase.name, "status": phase.status.value}


@app.get("/registry")
def agent_registry(db: Session = Depends(get_db)) -> dict:
    """The roster as git defines it, with validation problems surfaced.

    Foundation defines four agents. An enabled definition is eligibility, not a model
    call: every trigger still passes a deterministic work-check (§36A).
    """
    specs = registry.load()
    known = {b.key for b in db.execute(select(models.BusinessUnit)).scalars()}
    return {
        "defined": len(specs),
        "enabled": sorted(k for k, s in specs.items() if s.enabled),
        "daily_budget_usd": registry.enabled_budget(specs),
        "problems": registry.validate(specs, known),
        "agents": [
            {"key": k, "name": s.name, "role": s.role, "team": s.team,
             "enabled": s.enabled, "model_class": s.model_class,
             "autonomy_level": s.autonomy_level, "execution": s.execution,
             "reports_to": s.reports_to,
             "owns": s.owns, "business_units": s.business_units,
             "capabilities": s.capabilities, "allowed_tools": s.allowed_tools,
             "forbidden_tools": s.forbidden_tools, "required_secrets": s.required_secrets,
             "projects": s.projects, "skills": s.skills, "schedule": s.schedule,
             "work_check": s.work_check, "prompt_version": s.prompt_version,
             "triggers": [t.get("type") for t in s.triggers],
             "daily_usd": s.daily_budget,
             "enable_when": s.enable_when, "blocked_by": s.blocked_by}
            for k, s in specs.items()
        ],
    }


@app.post("/registry/sync")
def sync_registry(db: Session = Depends(get_db)) -> dict:
    """Reconcile registry.yaml into the agents table.

    Refuses on validation problems: a roster that cannot pass its own checks should not
    become runtime state. Rows absent from the file are retained for audit, disabled,
    and reported; they are never deleted (§23).
    """
    specs = registry.load()
    known = {b.key for b in db.execute(select(models.BusinessUnit)).scalars()}
    problems = registry.validate(specs, known)
    if problems:
        raise HTTPException(422, {"problems": problems})
    result = registry.sync(db, specs)
    audit.record(db, actor="registry-sync", action="registry.sync", entity_type="agent",
                 reason=f"{result['defined']} defined, {result['enabled']} enabled",
                 after=result)
    db.commit()
    return result


@app.get("/goals")
def list_goals(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(models.Goal).order_by(models.Goal.priority, models.Goal.id)).scalars()
    return [goals.view(db, g) for g in rows]


def _goal(db: Session, goal_id: int) -> models.Goal:
    goal = db.get(models.Goal, goal_id)
    if goal is None:
        raise HTTPException(404, f"goal {goal_id} not found")
    return goal


@app.get("/goals/{goal_id}")
def get_goal(goal_id: int, db: Session = Depends(get_db)) -> dict:
    goal = _goal(db, goal_id)
    tasks = db.execute(select(models.Task).where(models.Task.goal_id == goal.id)
                       .order_by(models.Task.priority, models.Task.created_at)).scalars()
    return {**goals.view(db, goal), "tasks": [
        {"key": t.key, "title": t.title, "status": t.status.value, "priority": t.priority.value} for t in tasks]}


@app.post("/goals", status_code=201)
def create_goal(body: schemas.GoalCreate, db: Session = Depends(get_db)) -> dict:
    project = _by_key(db, models.Project, body.project)
    if body.project and project is None:
        raise HTTPException(404, f"project {body.project} not found")
    goal = models.Goal(title=body.title, description=body.description, metric=body.metric,
                       baseline=body.baseline, target=body.target, deadline=body.deadline,
                       priority=body.priority, status=body.status, created_by=body.created_by,
                       project_id=project.id if project else None,
                       metric_selector=body.selector.model_dump(exclude_none=True) if body.selector else None)
    try:
        goals.check_activation(goal)
    except goals.GoalNotMeasurable as e:
        raise HTTPException(422, str(e))
    db.add(goal)
    db.flush()
    audit.record(db, actor=body.created_by, action="goal.create", entity_type="goal",
                 entity_key=str(goal.id), reason=body.reason, after=audit.snapshot(goal))
    db.commit()
    return goals.view(db, goal)


@app.patch("/goals/{goal_id}")
def update_goal(goal_id: int, body: schemas.GoalUpdate, db: Session = Depends(get_db), request: Request = None) -> dict:
    who = approval_identity.principal_of(request)  # audit identity; `body.actor` is untrusted metadata
    goal = _goal(db, goal_id)
    before = audit.snapshot(goal)
    changes = body.model_dump(exclude_unset=True, exclude={"actor", "reason", "selector"})
    for field, value in changes.items():
        setattr(goal, field, value)
    if "selector" in body.model_fields_set:
        goal.metric_selector = body.selector.model_dump(exclude_none=True) if body.selector else None
    try:
        goals.check_activation(goal)
    except goals.GoalNotMeasurable as e:
        db.rollback()
        raise HTTPException(422, str(e))
    after = audit.snapshot(goal)
    if body.actor != who.id:
        after["client_claimed_actor"] = body.actor
    audit.record(db, actor=who.id, action="goal.update", entity_type="goal",
                 entity_key=str(goal.id), reason=body.reason, before=before, after=after)
    db.commit()
    return goals.view(db, goal)


# --------------------------------------------------------------------------- tasks

@app.get("/tasks", response_model=list[schemas.TaskOut])
def list_tasks(status: enums.TaskStatus | None = None, db: Session = Depends(get_db)):
    stmt = select(models.Task)
    if status:
        stmt = stmt.where(models.Task.status == status)
    return db.execute(stmt.order_by(models.Task.priority, models.Task.created_at)).scalars().all()


@app.post("/tasks", response_model=schemas.TaskOut, status_code=201)
def create_task(body: schemas.TaskCreate, db: Session = Depends(get_db), request: Request = None):
    # §150 duplicate protection — an equivalent OPEN task blocks a new one.
    if body.dedupe_key:
        dup = db.execute(
            select(models.Task).where(
                models.Task.dedupe_key == body.dedupe_key,
                models.Task.status.in_(enums.OPEN_TASK_STATES),
            )
        ).scalar_one_or_none()
        if dup:
            raise HTTPException(409, f"equivalent open task exists: {dup.key}")

    task = models.Task(
        title=body.title, description=body.description, objective=body.objective,
        success_criteria=body.success_criteria, priority=body.priority,
        risk_level=body.risk_level, status=body.status,
        approval_required=body.approval_required, context=body.context,
        max_attempts=body.max_attempts, dedupe_key=body.dedupe_key, created_by=body.created_by,
    )
    for field, model, attr in (
        ("business_unit", models.BusinessUnit, "business_unit_id"),
        ("project", models.Project, "project_id"),
        ("assigned_agent", models.Agent, "assigned_agent_id"),
    ):
        obj = _by_key(db, model, getattr(body, field))
        if obj is not None:
            setattr(task, attr, obj.id)
    if body.goal is not None:
        goal = db.get(models.Goal, body.goal)
        if goal is None:
            raise HTTPException(404, f"goal {body.goal} not found")
        if goal.status in goals.CLOSED:
            raise HTTPException(409, f"goal {goal.id} is {goal.status.value}; new work cannot serve it")
        task.goal_id = goal.id

    try:
        keys.add_with_key(db, task, "TASK")
    except keys.DuplicateOpenWork:
        # A concurrent writer committed the same open work after the check above.
        db.rollback()
        raise HTTPException(409, "equivalent open task exists")
    # The audit actor is the verified principal; `created_by` is the task's label, kept as the client's claim.
    who = approval_identity.principal_of(request)
    after = audit.snapshot(task)
    if body.created_by != who.id:
        after["client_claimed_actor"] = body.created_by
    audit.record(db, actor=who.id, action="task.create", entity_type="task",
                 entity_key=task.key, reason=body.reason, after=after,
                 task_id=task.id)
    db.commit()
    db.refresh(task)
    return task


@app.get("/tasks/{key}/context")
def task_context(key: str, db: Session = Depends(get_db)) -> dict:
    """Materialise only the context allowed by the assigned agent's policy."""
    task = _by_key(db, models.Task, key)
    agent = db.get(models.Agent, task.assigned_agent_id) if task.assigned_agent_id else None
    if agent is None:
        raise HTTPException(409, f"{key} has no assigned agent")
    spec = registry.load().get(agent.key)
    if spec is None:
        raise HTTPException(409, f"assigned agent '{agent.key}' is not in the registry")
    return context_builder.build(db, task, spec)


@app.get("/tasks/{key}")
def get_task(key: str, db: Session = Depends(get_db)) -> dict:
    return desk_read.task_detail(db, _by_key(db, models.Task, key))


@app.post("/tasks/{key}/status", response_model=schemas.TaskOut)
def update_task_status(key: str, body: schemas.TaskStatusUpdate, db: Session = Depends(get_db),
                       request: Request = None):
    """Move a task through §32's states.

    Terminal states and REVIEW require the verified founder; DONE also needs evidence.
    Worker supervision records execution failures through its own path.
    """
    task = _by_key(db, models.Task, key)
    # Manual terminal/REVIEW changes are the founder's, proven by the verified principal; `body.actor` is untrusted metadata and only
    # ever lands in the audit row as evidence of what the client claimed (app/approval_identity.py).
    who = (approval_identity.require_founder(request) if body.status in _FOUNDER_ONLY_TASK_STATES
           else approval_identity.principal_of(request))
    if body.status == enums.TaskStatus.READY and not _may_requeue(who):
        raise HTTPException(403, "only the founder or a host operator may make a task READY")
    # Same row lock as worker.recover_stale's claim recovery: a person's takeover (even a same-status
    # one, which changes no column) and the worker's requeue serialize, and each sees the other's result.
    db.refresh(task, with_for_update=True)
    if task.status in _FOUNDER_ONLY_TASK_STATES:
        who = approval_identity.require_founder(request)  # a closed or reviewed task is changed by the founder only
    # Worker-recorded error markers are facts: a status caller may neither write one nor overwrite one (erasing a
    # "PR closed" marker would turn a closed PR's task back into a retryable repair).
    reserved = (stage_c_worker.REPAIR_INTERRUPTED, stage_c_worker.JOB_UNFINISHED, stage_c_ci.MERGE_NOT_RECORDED,
                stage_c_worker.PR_CLOSED, "PR_FAILED", "superseded:")
    if body.error and (body.error.startswith(reserved) or (task.error or "").startswith(reserved)):
        db.rollback()
        raise HTTPException(422, "that error marker is recorded by the worker, not set through the status route")
    # READY hands the task to the worker: never while a run may still be going, and for code writes only with every
    # Stage C condition met now (worker.ready_refusal). The refusal names the reason; nothing is written.
    # Re-coding a stopped CI repair of a published PR is the founder's decision (recover_interrupted: "nothing is
    # re-coded until the founder decides"): a host operator may re-queue other work, not this.
    if body.status == enums.TaskStatus.READY and stage_c_worker.blocked_repair(db, task):
        who = approval_identity.require_founder(request)
    if body.status == enums.TaskStatus.READY and (refusal := worker.ready_refusal(db, task)):
        db.rollback()
        raise HTTPException(409, f"{task.key} cannot be made READY: {refusal}")
    if body.status == enums.TaskStatus.DONE:
        if not (body.evidence or body.result):
            raise HTTPException(422, "DONE requires evidence or a result (§35, §130)")

    before = audit.snapshot(task)
    previous = task.status
    task.status = body.status
    if body.result:
        task.result = body.result
    if body.error:
        task.error = body.error
    if body.status == enums.TaskStatus.IN_PROGRESS and task.started_at is None:
        task.started_at = datetime.now(timezone.utc)
    if body.status in (enums.TaskStatus.DONE, enums.TaskStatus.CANCELLED):
        task.completed_at = datetime.now(timezone.utc)
    if body.status == enums.TaskStatus.FAILED:
        task.retry_count += 1

    after = audit.snapshot(task)
    if body.actor != who.id:
        after["client_claimed_actor"] = body.actor
    audit.record(db, actor=who.id, action="task.status", entity_type="task",
                 entity_key=task.key, reason=body.reason or body.evidence,
                 before=before, after=after, task_id=task.id)
    db.commit()
    db.refresh(task)

    if body.status == enums.TaskStatus.FAILED and task.retry_count >= task.max_attempts:
        # §149 dead letter: stop retrying and let a human or the supervisor look.
        event = _record_event(db, schemas.EventIn(
            event_type="TASK_FAILED_REPEATEDLY", source="company-api",
            severity=enums.Severity.HIGH, task=task.key,
            payload={"title": f"{task.key} exhausted {task.max_attempts} attempts",
                     "message": (body.error or task.error or "no error recorded")[:300]},
        ))
        notifier.dispatch(db, event)

    log.info("task %s %s -> %s by %s", task.key, previous.value, task.status.value, who.id)
    return task


@app.post("/tasks/{key}/assign", response_model=schemas.TaskOut)
def assign_task(key: str, body: schemas.TaskAssign, db: Session = Depends(get_db), request: Request = None):
    """Give a task an owner. Without one the dispatcher's work-check skips it."""
    who = approval_identity.principal_of(request)
    task = _by_key(db, models.Task, key)
    agent = _by_key(db, models.Agent, body.agent)
    if not agent.enabled:
        raise HTTPException(409, f"agent '{agent.key}' is disabled")
    # Same row lock as update_task_status and the worker's owner check. Reassigning a running attempt would only
    # block it (owner changed during run), so it is refused; the worker's atomic check still covers a race.
    db.refresh(task, with_for_update=True)
    if task.status == enums.TaskStatus.IN_PROGRESS:
        raise HTTPException(409, f"{task.key} is IN_PROGRESS: an attempt owns it; block or cancel it first")
    before = audit.snapshot(task)
    task.assigned_agent_id = agent.id
    after = audit.snapshot(task)
    if body.actor != who.id:
        after["client_claimed_actor"] = body.actor
    audit.record(db, actor=who.id, action="task.assign", entity_type="task",
                 entity_key=task.key, reason=body.reason or f"assigned to {agent.key}",
                 before=before, after=after, task_id=task.id)
    db.commit()
    db.refresh(task)
    return task


HERDR_PROVIDER = "herdr/project-control-center"


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _may_requeue(who) -> bool:
    """Re-queueing (READY) hands work to the worker: the verified founder, a host operator (local/host) or the admin
    credential may; a service token (desk, youtube) or an anonymous caller may not, in any auth mode."""
    return who.is_founder or who.kind == "operator" or who.id == "service:admin"


@app.post("/tasks/{key}/run-report", status_code=201)
def report_run(key: str, body: schemas.RunReport, db: Session = Depends(get_db), request: Request = None) -> dict:
    """Record a herdr run against a Company OS task (§4.2).

    The control center's review is the supervisor (§45), so its verdict is translated,
    not second-guessed. The task can reach REVIEW here but never DONE.
    """
    task = _by_key(db, models.Task, key)
    # A report may create or overwrite REVIEW from caller-supplied state. Require the verified founder for that
    # outcome, and for any change to REVIEW or a founder-closed task. Check under the row lock before writing;
    # `body.reported_by` is untrusted metadata, never the audit actor.
    db.refresh(task, with_for_update=True)
    st = body.herdr_state
    outcome = runreport.interpret(st)
    who = (approval_identity.require_founder(request)
           if task.status in _FOUNDER_ONLY_TASK_STATES
           or outcome.task_status == enums.TaskStatus.REVIEW
           else approval_identity.principal_of(request))

    agent = db.execute(
        select(models.Agent).where(models.Agent.key == "developer")
    ).scalar_one_or_none()
    started = _parse_ts(st.get("created_at"))
    if started is None:
        # created_at is the herdr run's identity (state.json sets it once). Without it a snapshot cannot be matched to
        # its run, and recording it as a new STARTED row would leave the task stuck IN_PROGRESS (review of #396, P3-d).
        raise HTTPException(422, "herdr_state.created_at (the run identity) is required")
    ended = _parse_ts(st.get("finished_at") or st.get("cancelled_at")
                      or (st.get("updated_at") if runreport.is_terminal(st) else None))

    # One herdr run reports several snapshots (state.json per task, same created_at). A later snapshot updates its own
    # open row instead of adding one, so an earlier "running" snapshot never stays STARTED and blocks the task.
    # Under the task row lock taken above, so concurrent reports for this task serialize. One herdr run (one
    # state.json, same created_at) reports many snapshots; they are matched to that run's rows and applied in order:
    # the exact same snapshot again is a no-op; a snapshot older than one already recorded (updated_at) is stale; after
    # "cancelled" (final for that run) nothing more applies; a newer snapshot updates the run's open row(s).
    snapshot = hashlib.sha256(json.dumps(st, sort_keys=True, default=str).encode()).hexdigest()
    seen_at = _parse_ts(st.get("updated_at") or st.get("finished_at") or st.get("cancelled_at"))
    run, also_open = None, []
    if started:
        same = [r for r in db.scalars(select(models.AgentRun).where(
            models.AgentRun.task_id == task.id, models.AgentRun.provider == HERDR_PROVIDER)
            .order_by(models.AgentRun.id).with_for_update())
            if r.started_at and _aware(r.started_at) == _aware(started)]
        recorded = [_parse_ts((r.tool_calls or {}).get("updated_at")) for r in same]
        newest = max((t for t in recorded if t), default=None)
        ignore = ("duplicate" if any((r.tool_calls or {}).get("snapshot") == snapshot for r in same)
                  else "cancelled" if any((r.tool_calls or {}).get("herdr_state") == "cancelled" for r in same)
                  else "stale" if seen_at and newest and _aware(seen_at) < _aware(newest) else None)
        if ignore:
            log.info("run-report for %s ignored (%s): herdr run %s, state %s", task.key, ignore, started, st.get("state"))
            db.rollback()
            last = same[-1]
            return {"task": task.key, "task_status": task.status.value, "run_id": last.id,
                    "outcome": outcome.as_dict(), "notes_recorded": 0, "notified": False, "ignored": ignore}
        open_rows = [r for r in same if r.status == enums.AgentRunStatus.STARTED]
        run, also_open = (open_rows[0], open_rows[1:]) if open_rows else (None, [])
    if run is None:
        run = models.AgentRun(agent_id=agent.id if agent else None, task_id=task.id, provider=HERDR_PROVIDER)
    for k, v in dict(
        status=outcome.run_status,
        # model_class, not a model id: router.toml owns which model runs (§84).
        model=(st.get("workflow") or {}).get("name"),
        supervisor_verdict=outcome.supervisor_verdict,
        supervisor_notes=outcome.summary,
        result=st.get("goal"),
        error=((st.get("checks") or {}).get("summary") if outcome.run_status ==
               enums.AgentRunStatus.FAILED else None),
        tool_calls={
            "herdr_state": st.get("state"),
            "branch": st.get("branch"),
            "checkout": st.get("checkout"),
            "source_commit": st.get("source_commit"),
            "risk": st.get("risk"),
            "changed_files": body.changed_files[:200],
            "snapshot": snapshot, "updated_at": seen_at.isoformat() if seen_at else None,
        },
    ).items():
        setattr(run, k, v)
    for extra in also_open:  # older duplicate open rows of the same herdr run: closed once, no retry spent for them
        extra.status, extra.ended_at = enums.AgentRunStatus.FAILED, ended or datetime.now(timezone.utc)
        extra.error = f"superseded by a later snapshot of the same herdr run (row {run.id or 'new'})"
    if started:
        run.started_at = started
    if ended:
        run.ended_at = ended
    db.add(run)
    db.flush()
    # A cancelled herdr run re-queues the task (READY), past the same guard as the status route, evaluated after this
    # report closed its own row: only an unrelated open run, or a code-writing task missing a Stage C condition, or a
    # caller who may not re-queue (founder, host operator or admin), keeps the task where it is; the report and run are
    # still recorded and the reason is in the audit row.
    requeue_refusal = None
    if outcome.task_status == enums.TaskStatus.READY:
        requeue_refusal = (None if _may_requeue(who) else "only the founder or a host operator may re-queue a task") \
            or (None if who.is_founder or not stage_c_worker.blocked_repair(db, task)
                else "re-coding a stopped CI repair is the founder's decision") \
            or worker.ready_refusal(db, task)

    before = audit.snapshot(task)
    if not requeue_refusal:
        task.status = outcome.task_status
    task.result = outcome.summary
    if outcome.run_status == enums.AgentRunStatus.FAILED:
        task.retry_count += 1
    if task.started_at is None and started:
        task.started_at = started

    # §53A: what a run learned is a NOTE, not yet a learning. It becomes a learning only
    # after compaction sees the same lesson recur, and then only as a candidate for
    # review. Writing straight to `learnings` would skip the review the rule exists for.
    for lesson in body.learnings:
        notebook.record(db, note=lesson,
                        agent_key=agent.key if agent else None, task_key=task.key)

    after = audit.snapshot(task)
    if body.reported_by != who.id:
        after["client_claimed_reported_by"] = body.reported_by
    if requeue_refusal:
        after["requeue_refused"] = requeue_refusal
    audit.record(db, actor=who.id, action="task.run-report", entity_type="task",
                 entity_key=task.key, reason=outcome.summary,
                 before=before, after=after, task_id=task.id)
    db.commit()
    db.refresh(run)

    event = _record_event(db, schemas.EventIn(
        event_type=outcome.event_type, source="herdr/project-control-center",
        severity=outcome.severity, task=task.key,
        payload={"title": f"{task.key}: {outcome.summary}",
                 "detail": f"workflow={run.model} branch={st.get('branch')}",
                 "message": task.title},
    ))
    delivered, _ = notifier.dispatch(db, event)

    return {"task": task.key, "task_status": task.status.value, "run_id": run.id,
            "outcome": outcome.as_dict(), "notes_recorded": len(body.learnings),
            "notified": delivered}


@app.get("/tasks/{key}/dispatch")
def dispatch_plan(key: str, db: Session = Depends(get_db)) -> dict:
    """Translate a Company OS task into a herdr control-center plan (§4.1).

    Read-only: it returns the plan, it never starts anything. `hctl` runs on the laptop,
    so the server's job ends at producing an unambiguous instruction.
    """
    task = _by_key(db, models.Task, key)
    project = db.get(models.Project, task.project_id) if task.project_id else None
    agent = db.get(models.Agent, task.assigned_agent_id) if task.assigned_agent_id else None
    if agent is None:
        raise HTTPException(409, f"{key} has no assigned agent")
    if not agent.enabled:
        raise HTTPException(409, f"{key} is assigned to disabled agent '{agent.key}'")
    try:
        plan = dispatch.plan_for(task, project, agent_key=agent.key)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return plan.as_dict()


@app.post("/dispatch/run")
def run_outer_loop(db: Session = Depends(get_db)) -> dict:
    """Run the deterministic half of `companyctl run`.

    The inner loop remains attended in herdr on the laptop (AGENT_EXECUTION §2). This
    endpoint therefore checks eligibility and returns exact next commands; it never
    calls a model or moves a task merely because a schedule fired.
    """
    tasks = db.execute(
        select(models.Task).where(
            models.Task.status.in_((enums.TaskStatus.READY, enums.TaskStatus.QUEUED))
        ).order_by(models.Task.priority, models.Task.created_at)
    ).scalars().all()

    if control.agents_paused(db):
        skipped = [{"task": task.key, "reason": "agents_paused"} for task in tasks]
        audit.record(db, actor="companyctl", action="dispatch.work-check",
                     entity_type="agent", reason="agent execution is paused",
                     after={"work": [], "skipped": skipped})
        db.commit()
        return {
            "paused": True, "model_calls": 0, "work_count": 0, "work": [],
            "skipped": skipped, "execution": "paused",
            "note": "Agent execution is paused; production services are unchanged.",
        }

    work: list[dict] = []
    skipped: list[dict] = []
    enabled_agents = list(db.execute(
        select(models.Agent).where(models.Agent.enabled.is_(True))
    ).scalars())
    for task in tasks:
        agent = db.get(models.Agent, task.assigned_agent_id) if task.assigned_agent_id else None
        unit = db.get(models.BusinessUnit, task.business_unit_id) if task.business_unit_id else None
        dependency_statuses = list(db.execute(
            select(models.Task.status)
            .join(models.TaskDependency, models.Task.id == models.TaskDependency.depends_on_id)
            .where(models.TaskDependency.task_id == task.id)
        ).scalars())
        reason = dispatch.skip_reason(task, agent, unit, dependency_statuses)
        if reason:
            skipped.append({"task": task.key, "reason": reason})
            continue

        project = db.get(models.Project, task.project_id) if task.project_id else None
        plan = dispatch.plan_for(task, project, agent_key=agent.key).as_dict()
        plan["next_command"] = f"company-dispatch {task.key} --run"
        work.append(plan)

    # This is the heartbeat of the outer-loop check, not proof that a model ran.
    now = datetime.now(timezone.utc)
    for agent in enabled_agents:
        agent.last_heartbeat_at = now
    audit.record(db, actor="companyctl", action="dispatch.work-check",
                 entity_type="agent", reason=f"{len(work)} runnable, {len(skipped)} skipped",
                 after={"work": [item["task"] for item in work], "skipped": skipped})
    db.commit()

    return {
        "paused": False,
        "model_calls": 0,
        "work_count": len(work),
        "work": work,
        "skipped": skipped,
        "execution": "attended-herdr",
        "note": "Run next_command on the laptop; Company OS does not store model credentials.",
    }


@app.post("/stage-c/authorization", status_code=201)
def stage_c_authorize(body: schemas.StageCAuthorize, request: Request, db: Session = Depends(get_db)) -> dict:
    """Issue the one-task, one-SHA, short-lived Stage C pilot authorization. Founder only, derived from the
    verified principal. It enables nothing by itself (flag, acceptance and readiness still apply). The SHA is
    the deployed source, and the API and worker must agree on it."""
    who = approval_identity.require_founder(request)
    api_sha = os.environ.get("COMPANY_OS_GIT_SHA") or ""
    worker_sha = ((worker.worker_state(db).get("runtime") or {}).get("git_sha")) or ""
    if not api_sha or api_sha != worker_sha:
        raise HTTPException(409, "the API and the worker do not report the same deployed source SHA")
    try:
        value = control.authorize_pilot(db, body.task_key, api_sha, founder=who.id,
                                        ttl=timedelta(minutes=body.minutes))
    except ValueError as e:
        db.rollback()
        raise HTTPException(422, str(e))
    return {k: value[k] for k in ("task_key", "source_sha", "expires_at", "issued_by", "action")}


@app.post("/stage-c/standing", status_code=201)
def stage_c_standing(body: schemas.StageCStanding, request: Request, db: Session = Depends(get_db)) -> dict:
    """Issue the standing Stage C authorization: named files, a few days, a few runs a day, bound to the
    deployed SHA. Founder only, from the verified principal; it enables nothing by itself."""
    who = approval_identity.require_founder(request)
    api_sha = os.environ.get("COMPANY_OS_GIT_SHA") or ""
    worker_sha = ((worker.worker_state(db).get("runtime") or {}).get("git_sha")) or ""
    if not api_sha or api_sha != worker_sha:
        raise HTTPException(409, "the API and the worker do not report the same deployed source SHA")
    try:
        value = control.issue_standing(db, body.paths, api_sha, founder=who.id, days=body.days,
                                       max_per_day=body.max_per_day)
    except ValueError as e:
        db.rollback()
        raise HTTPException(422, str(e))
    return {k: value[k] for k in ("source_sha", "paths", "max_per_day", "expires_at", "issued_by", "action")}


@app.post("/stage-c/standing/revoke")
def stage_c_standing_revoke(body: schemas.StageCRevoke, request: Request, db: Session = Depends(get_db)) -> dict:
    who = approval_identity.require_decider(request)  # withdrawing authority: founder or host operator
    return {"revoked": control.revoke_standing(db, actor=who.id, reason=body.reason)}


@app.post("/stage-c/authorization/revoke")
def stage_c_revoke(body: schemas.StageCRevoke, request: Request, db: Session = Depends(get_db)) -> dict:
    who = approval_identity.require_decider(request)  # withdrawing authority: founder or host operator
    return {"revoked": control.revoke_pilot_authorization(db, actor=who.id, reason=body.reason)}


@app.post("/control/agents")
def control_agents(body: schemas.AgentExecutionControl,
                   db: Session = Depends(get_db), request: Request = None) -> dict:
    """Pause/resume agent execution only; never touch serving infrastructure. Pausing is the emergency stop
    and stays open to every authorized caller; RESUMING lifts the kill switch and needs the verified founder.
    The audit actor is the verified principal, never `body.actor`."""
    who = approval_identity.principal_of(request) if body.paused else approval_identity.require_founder(request)
    try:
        return control.set_agents_paused(db, body.paused, actor=who.id,
                                         reason=body.reason + ("" if body.actor == who.id else f" [claimed actor: {body.actor[:60]}]"))
    except control.PauseUnavailable as exc:
        db.rollback()
        raise HTTPException(503, str(exc)) from exc


# --------------------------------------------------------------------------- incidents

@app.get("/incidents")
def list_incidents(open_only: bool = True, db: Session = Depends(get_db)) -> list[dict]:
    stmt = select(models.Incident)
    if open_only:
        stmt = stmt.where(models.Incident.status != enums.IncidentStatus.RESOLVED)
    rows = db.execute(stmt.order_by(models.Incident.severity, models.Incident.started_at)).scalars()
    incidents = list(rows)
    delivered_incidents = NotificationService.delivered_incident_ids(db, incidents)
    return [{"key": i.key, "severity": i.severity.value, "status": i.status.value,
             "title": i.title, "started_at": i.started_at.isoformat(),
             "detected_by": i.detected_by, "founder_notified": i.id in delivered_incidents,
             "root_cause": i.root_cause} for i in incidents]


@app.post("/incidents", status_code=201)
def create_incident(body: schemas.IncidentCreate, db: Session = Depends(get_db)) -> dict:
    inc = models.Incident(
        severity=body.severity, title=body.title,
        description=body.description, detected_by=body.detected_by,
        started_at=body.started_at or datetime.now(timezone.utc), root_cause=body.root_cause,
    )
    svc = _by_key(db, models.Service, body.service)
    if svc:
        inc.service_id = svc.id
    prj = _by_key(db, models.Project, body.project)
    if prj:
        inc.project_id = prj.id
    keys.add_with_key(db, inc, "INC")
    audit.record(db, actor=body.detected_by, action="incident.create", entity_type="incident",
                 entity_key=inc.key, after=audit.snapshot(inc))
    db.commit()
    db.refresh(inc)

    sev_map = {enums.IncidentSeverity.SEV0: enums.Severity.CRITICAL,
               enums.IncidentSeverity.SEV1: enums.Severity.HIGH,
               enums.IncidentSeverity.SEV2: enums.Severity.MEDIUM,
               enums.IncidentSeverity.SEV3: enums.Severity.LOW}
    event = _record_event(db, schemas.EventIn(
        event_type="INCIDENT_CREATED", source="company-api",
        severity=sev_map[body.severity], incident=inc.key,
        payload={"title": inc.title, "message": inc.description[:400]},
    ))
    delivered, reason = notifier.dispatch(db, event)
    return {"key": inc.key, "notified": delivered, "notify_reason": reason}


@app.post("/incidents/{key}/resolve")
def resolve_incident(key: str, body: schemas.IncidentResolve,
                     db: Session = Depends(get_db), request: Request = None) -> dict:
    """An incident tracker that cannot close an incident is not a tracker.

    §94 requires a root cause and a lesson, so both are mandatory and the learning is
    written into learning memory rather than dying inside the incident row.
    """
    inc = _by_key(db, models.Incident, key)
    if inc.status == enums.IncidentStatus.RESOLVED:
        raise HTTPException(409, f"{key} is already resolved")
    who = approval_identity.principal_of(request)  # `body.resolved_by` is untrusted metadata
    before = audit.snapshot(inc)
    inc.root_cause = body.root_cause
    inc.resolution = body.resolution
    inc.status = body.status
    if body.status == enums.IncidentStatus.RESOLVED:
        inc.resolved_at = datetime.now(timezone.utc)
    if body.learning:
        inc.learning = body.learning
        # Always a CANDIDATE: trusted memory is promoted only by the verified founder (POST /learnings/{id}/approve).
        db.add(models.Learning(title=f"From {inc.key}: {inc.title[:120]}",
                               lesson=body.learning, evidence=body.resolution,
                               incident_id=inc.id, created_by=who.id, status=enums.LearningStatus.CANDIDATE))
    after = audit.snapshot(inc)
    if body.resolved_by != who.id:
        after["client_claimed_resolved_by"] = body.resolved_by
    audit.record(db, actor=who.id, action="incident.resolve",
                 entity_type="incident", entity_key=inc.key, reason=body.resolution,
                 before=before, after=after)
    db.commit()
    event = _record_event(db, schemas.EventIn(
        event_type="INCIDENT_RESOLVED" if body.status == enums.IncidentStatus.RESOLVED else "INCIDENT_UPDATED",
        source="company-api", severity=enums.Severity.INFO,
        incident=inc.key, payload={"title": inc.title, "message": body.resolution[:300]},
    ))
    if body.status == enums.IncidentStatus.RESOLVED:
        notifier.dispatch(db, event)
    return {"key": inc.key, "status": inc.status.value,
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
            "event_id": event.id}


# --------------------------------------------------------------------------- decisions / learnings

@app.get("/decisions")
def list_decisions(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(models.Decision).order_by(models.Decision.created_at.desc())).scalars()
    return [{"key": d.key, "title": d.title, "decision": d.decision, "reason": d.reason,
             "status": d.status.value, "approved_by": d.approved_by,
             "created_at": d.created_at.isoformat()} for d in rows]


@app.post("/decisions", status_code=201)
def create_decision(body: schemas.DecisionCreate, db: Session = Depends(get_db)) -> dict:
    dec = models.Decision(
        title=body.title, decision=body.decision,
        reason=body.reason, approved_by=body.approved_by,
    )
    bu = _by_key(db, models.BusinessUnit, body.business_unit)
    if bu:
        dec.business_unit_id = bu.id
    prj = _by_key(db, models.Project, body.project)
    if prj:
        dec.project_id = prj.id
    prev = _by_key(db, models.Decision, body.supersedes)
    if prev:
        dec.supersedes_id = prev.id
        prev.status = enums.DecisionStatus.SUPERSEDED
    keys.add_with_key(db, dec, "DEC")
    audit.record(db, actor=body.approved_by, action="decision.create", entity_type="decision",
                 entity_key=dec.key, reason=body.reason, after=audit.snapshot(dec))
    db.commit()
    return {"key": dec.key}


# --------------------------------------------------------------------------- notebook

@app.post("/notes", status_code=201)
def create_note(body: schemas.NoteCreate, db: Session = Depends(get_db)) -> dict:
    """Record a notebook note (§53A). Equivalent notes merge rather than duplicate."""
    row = notebook.record(db, note=body.note, agent_key=body.agent,
                          task_key=body.task, tags=body.tags)
    return {"id": row.id, "reference_count": row.reference_count,
            "merged": row.reference_count > 1}


@app.get("/notes")
def list_notes(agent: str | None = None, include_archived: bool = False,
               limit: int = 50, db: Session = Depends(get_db)) -> list[dict]:
    stmt = select(models.AgentNote)
    if not include_archived:
        stmt = stmt.where(models.AgentNote.archived_at.is_(None))
    if agent:
        a = _by_key(db, models.Agent, agent)
        stmt = stmt.where(models.AgentNote.agent_id == a.id)
    rows = db.execute(
        stmt.order_by(models.AgentNote.reference_count.desc(),
                      models.AgentNote.last_seen_at.desc()).limit(limit)
    ).scalars().all()
    return [{"id": n.id, "note": n.note, "refs": n.reference_count, "tags": n.tags,
             "last_seen_at": n.last_seen_at.isoformat(),
             "promoted": n.promoted_learning_id is not None,
             "archived": n.archived_at.isoformat() if n.archived_at else None}
            for n in rows]


@app.post("/notes/compact")
def compact_notes(body: schemas.CompactionRequest, db: Session = Depends(get_db)) -> dict:
    """Weekly review (§53A): deduplicate, promote what recurred, archive what did not.

    Defaults to a dry run. Promotion creates a *candidate* learning; §53A still routes it
    through the supervisor, and the founder for high impact, before it becomes a rule.
    Nothing is deleted and the constitution is never touched.
    """
    plan = notebook.plan_compaction(db, promote_after=body.promote_after,
                                    retention_days=body.retention_days)
    if not body.apply:
        return {"applied": False, **plan.summary()}
    result = notebook.apply_compaction(db, plan, actor=body.actor)
    audit.record(db, actor=body.actor, action="notebook.compact", entity_type="agent_note",
                 reason=f"promoted {result['promoted']}, archived {result['archived']}",
                 after=result)
    db.commit()
    return {"applied": True, **result}


@app.get("/learnings")
def list_learnings(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(models.Learning).order_by(models.Learning.created_at.desc())).scalars()
    return [{"id": x.id, "title": x.title, "lesson": x.lesson, "tags": x.tags,
             "status": x.status.value, "created_at": x.created_at.isoformat()} for x in rows]


@app.post("/learnings/{learning_id}/approve")
def approve_learning(learning_id: int, body: schemas.LearningApprove,
                     db: Session = Depends(get_db), request: Request = None) -> dict:
    """§53A review step: a candidate becomes trusted memory only through this, and only for the verified
    founder (agents load APPROVED learnings as instructions). `body.actor` is untrusted metadata."""
    who = approval_identity.require_founder(request)  # 401/403 before anything is read or written
    row = db.scalar(select(models.Learning).where(models.Learning.id == learning_id)
                    .with_for_update().execution_options(populate_existing=True))
    if row is None:
        raise HTTPException(404, f"learning {learning_id} not found")
    if row.status != enums.LearningStatus.CANDIDATE:
        raise HTTPException(409, f"learning {learning_id} is {row.status.value}, not CANDIDATE")
    row.status = enums.LearningStatus.APPROVED
    after = {"status": "APPROVED"}
    if body.actor != who.id:
        after["client_claimed_actor"] = body.actor
    audit.record(db, actor=who.id, action="learning.approve", entity_type="learning",
                 entity_key=str(row.id), reason=body.reason, before={"status": "CANDIDATE"}, after=after)
    db.commit()
    return {"id": row.id, "status": row.status.value, "approved_by": who.id}


@app.post("/learnings", status_code=201)
def create_learning(body: schemas.LearningCreate, db: Session = Depends(get_db), request: Request = None) -> dict:
    """Always a CANDIDATE: the model default is APPROVED, which would let any writer mint trusted memory."""
    who = approval_identity.principal_of(request)
    row = models.Learning(title=body.title, lesson=body.lesson, evidence=body.evidence,
                          tags=body.tags, created_by=who.id, status=enums.LearningStatus.CANDIDATE)
    inc = _by_key(db, models.Incident, body.incident)
    if inc:
        row.incident_id = inc.id
    bu = _by_key(db, models.BusinessUnit, body.business_unit)
    if bu:
        row.business_unit_id = bu.id
    db.add(row)
    db.flush()
    audit.record(db, actor=who.id, action="learning.create", entity_type="learning", entity_key=str(row.id),
                 after={"status": "CANDIDATE", **({"client_claimed_created_by": body.created_by}
                                                   if body.created_by != who.id else {})})
    db.commit()
    return {"id": row.id, "status": "CANDIDATE"}


# --------------------------------------------------------------------------- approvals

@app.get("/approvals")
def list_approvals(pending_only: bool = True, db: Session = Depends(get_db)) -> list[dict]:
    stmt = select(models.Approval)
    if pending_only:
        stmt = stmt.where(models.Approval.status == enums.ApprovalStatus.REQUESTED)
    rows = db.execute(stmt.order_by(models.Approval.created_at)).scalars()
    return [{"key": a.key, "action": a.action, "reason": a.reason,
             "expected_effect": a.expected_effect, "risk": a.risk_level.value,
             "rollback": a.rollback, "requested_by": a.requested_by,
             "status": a.status.value, "created_at": a.created_at.isoformat()} for a in rows]


@app.post("/approvals", status_code=201)
def request_approval(body: schemas.ApprovalCreate, db: Session = Depends(get_db)) -> dict:
    apr = models.Approval(
        action=body.action, reason=body.reason,
        expected_effect=body.expected_effect, risk_level=body.risk_level,
        rollback=body.rollback, requested_by=body.requested_by,
    )
    task = _by_key(db, models.Task, body.task)
    if task:
        apr.task_id = task.id
    keys.add_with_key(db, apr, "APR")
    audit.record(db, actor=body.requested_by, action="approval.request", entity_type="approval",
                 entity_key=apr.key, reason=body.reason, after=audit.snapshot(apr))
    db.commit()
    db.refresh(apr)

    delivered = False
    # §111 — only high-risk approvals are worth interrupting the founder for.
    if apr.risk_level in (enums.RiskLevel.HIGH, enums.RiskLevel.CRITICAL):
        event = _record_event(db, schemas.EventIn(
            event_type="APPROVAL_REQUIRED", source="company-api", severity=enums.Severity.HIGH,
            payload={"title": apr.action, "message": apr.reason[:300],
                     "detail": f"risk={apr.risk_level.value} rollback={apr.rollback[:120]}"},
        ))
        delivered, _ = notifier.dispatch(db, event)
    return {"key": apr.key, "notified": delivered}


@app.post("/approvals/{key}")
def decide_approval(key: str, body: schemas.ApprovalDecision, request: Request,
                    db: Session = Depends(get_db)) -> dict:
    """Decisions are recorded for the verified principal only. `body.decided_by` is an untrusted hint: it
    never becomes `decided_by` or the audit actor, so it cannot claim the founder (app/approval_identity.py)."""
    who = approval_identity.require_decider(request)  # 401/403 before anything is read or written
    apr = _by_key(db, models.Approval, key)
    db.refresh(apr, with_for_update=True)  # two deciders serialize: the second sees the first's result
    if apr.status != enums.ApprovalStatus.REQUESTED:
        raise HTTPException(409, f"approval already {apr.status.value}")
    if body.granted and apr.risk_level in approval_identity.FOUNDER_ONLY_RISKS and not who.is_founder:
        raise HTTPException(403, f"{apr.risk_level.value} risk approvals can only be granted by the verified founder")
    before = audit.snapshot(apr)
    apr.status = enums.ApprovalStatus.GRANTED if body.granted else enums.ApprovalStatus.REJECTED
    apr.decided_by = who.id
    apr.decided_at = datetime.now(timezone.utc)
    apr.decision_notes = body.notes
    after = audit.snapshot(apr)
    if body.decided_by != who.id:
        after["client_claimed_decided_by"] = body.decided_by  # evidence of a claim, not an identity
    audit.record(db, actor=who.id, action="approval.decide", entity_type="approval",
                 entity_key=apr.key, reason=body.notes, before=before, after=after)
    db.commit()
    return {"key": apr.key, "status": apr.status.value, "decided_by": who.id}


# --------------------------------------------------------------------------- events

@app.post("/notifications/{event_id}/retry")
def retry_notification(event_id: int, request: Request,
                       db: Session = Depends(get_db)) -> dict:
    """A verified founder can retry an ambiguous page or resume an exhausted recovery."""
    who = approval_identity.require_founder(request)
    event = db.get(models.Event, event_id)
    if event is None:
        raise HTTPException(404, "notification event not found")
    try:
        delivered, reason = notifier.retry_uncertain(db, event)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    audit.record(db, actor=who.id, action="notification.retry", entity_type="event",
                 entity_key=str(event_id),
                 reason=("founder resumed exhausted recovery delivery"
                         if event.event_type in ("INCIDENT_RESOLVED", "WATCHDOG_CONDITION_RECOVERED")
                         else "founder retried an uncertain critical delivery"),
                 after={"delivered": delivered, "notify_reason": event.notify_reason})
    db.commit()
    return {"event_id": event_id, "delivered": delivered, "reason": reason}

@app.get("/events")
def list_events(limit: int = 50, event_type: str | None = None,
                db: Session = Depends(get_db)) -> list[dict]:
    stmt = select(models.Event)
    if event_type:
        stmt = stmt.where(models.Event.event_type == event_type)
    rows = db.execute(stmt.order_by(models.Event.occurred_at.desc()).limit(limit)).scalars()
    return [{"id": e.id, "event_type": e.event_type, "source": e.source,
             "severity": e.severity.value, "occurred_at": e.occurred_at.isoformat(),
             "notified": e.notified, "notify_error": e.notify_error,
             "notify_reason": e.notify_reason,
             "payload": e.payload} for e in rows]


@app.post("/events", status_code=201)
def ingest_event(body: schemas.EventIn, db: Session = Depends(get_db)) -> dict:
    """Generic ingestion for host scripts (backup, watchdog) and future agents."""
    event = _record_event(db, body)
    delivered, reason = notifier.dispatch(db, event)
    return {"id": event.id, "notified": delivered, "notify_reason": reason}


# --------------------------------------------------------------------------- youtube-auto webhook

# saglik-kontrol.js emits exactly these five codes. Mapped explicitly rather than
# guessed, so an unknown future code is visible instead of silently downgraded.
_YT_CODE_MAP = {
    "STALE_LOCK": ("WORKER_UNHEALTHY", enums.Severity.HIGH),
    "JOB_RETRYING": ("TASK_FAILED_REPEATEDLY", enums.Severity.HIGH),
    "UPLOAD_BLOCKED": ("YOUTUBE_PIPELINE_STOPPED", enums.Severity.HIGH),
    "DAILY_NOT_STARTED": ("SCHEDULED_PRODUCTION_MISSING", enums.Severity.HIGH),
    "DAILY_NOT_PUBLISHED": ("SCHEDULED_PRODUCTION_MISSING", enums.Severity.MEDIUM),
}
_SEVERITY_ORDER = [enums.Severity.INFO, enums.Severity.LOW, enums.Severity.MEDIUM,
                   enums.Severity.HIGH, enums.Severity.CRITICAL]


@app.post("/webhooks/youtube-packaging")
def youtube_packaging_submit(body: schemas.PackagingIn, db: Session = Depends(get_db)) -> dict:
    """TASK-0023: a new package triggers its own review; obvious repeats are rejected by rule."""
    out = packaging.submit(db, body.job, body.title, body.thumbnailText, body.history)
    # The review is the point; its activity event must never turn a submit into an error.
    has_service = db.execute(select(models.Service.id).where(
        models.Service.key == "youtube-auto")).first() is not None
    _record_event(db, schemas.EventIn(
        event_type="YOUTUBE_PACKAGING_CREATED", source="youtube-auto",
        service="youtube-auto" if has_service else None,
        task=out["task"], severity=enums.Severity.INFO,
        payload={"title": f"Packaging {out['status']}: {body.title[:100]} / {body.thumbnailText}",
                 "detail": "; ".join(out["reasons"])[:400]},
        dedupe_key=f"packaging:{body.job}:{out['hash']}"))
    return out


@app.get("/youtube/packaging/{job}")
def youtube_packaging_status(job: str, hash: str, db: Session = Depends(get_db)) -> dict:
    """What youtube-auto's publish gate asks before uploading."""
    return packaging.status(db, job, hash)


@app.post("/webhooks/youtube-auto")
async def youtube_auto_webhook(request: Request, db: Session = Depends(get_db)) -> dict:
    """Adapter for youtube-auto's AUTOMATION_ALERT_WEBHOOK_URL.

    That script POSTs {event, status, at, gun, saat, yayinda, bugunUretim, uyarilar[]}.
    Telegram needs {chat_id, text}, so the shapes do not match and a raw Bot API URL
    would not work — hence this translation layer rather than a hand-built URL.
    """
    body = await request.json()
    warnings = body.get("uyarilar") or []
    if not warnings:
        return {"recorded": False, "reason": "no warnings in payload"}

    codes = [w.get("kod", "UNKNOWN") for w in warnings]
    mapped = [_YT_CODE_MAP.get(c) for c in codes]
    unknown = [c for c, m in zip(codes, mapped) if m is None]
    known = [m for m in mapped if m is not None]

    if known:
        event_type = max(known, key=lambda m: _SEVERITY_ORDER.index(m[1]))[0]
        severity = max((m[1] for m in known), key=_SEVERITY_ORDER.index)
    else:
        event_type, severity = "YOUTUBE_PIPELINE_STOPPED", enums.Severity.HIGH

    event = _record_event(db, schemas.EventIn(
        event_type=event_type,
        source="youtube-auto/saglik-kontrol",
        severity=severity,
        service="youtube-auto",
        payload={
            "title": f"AxiomTalesHQ pipeline: {len(warnings)} warning(s)",
            "detail": f"day={body.get('gun')} hour={body.get('saat')} "
                      f"published_today={body.get('yayinda')} produced_today={body.get('bugunUretim')}",
            "warnings": [f"{w.get('kod')}: {w.get('mesaj')}" for w in warnings],
            "codes": codes,
            "unknown_codes": unknown,
        },
        dedupe_key=fingerprint(event_type, "youtube-auto", "|".join(sorted(codes))),
    ))
    delivered, reason = notifier.dispatch(db, event)
    if unknown:
        log.warning("unmapped youtube-auto warning codes: %s", unknown)
    return {"recorded": True, "event_id": event.id, "event_type": event_type,
            "notified": delivered, "notify_reason": reason}


# --------------------------------------------------------------------------- backups

@app.post("/metrics/observations", status_code=201)
def record_metrics(body: schemas.MetricsIn, request: Request, db: Session = Depends(get_db)) -> dict:
    """Executors (youtube-auto, future sources) report measured business values here.
    Internal network only: not in the Founder Desk proxy allowlist. Each caller writes only
    its own business unit and sources (api_auth.METRIC_WRITERS)."""
    who = getattr(request.state, "caller", "anonymous")
    denial = api_auth.metric_denial(who, body.business_unit, {o.source for o in body.observations})
    if denial:
        raise HTTPException(403, denial)
    # Revenue is read from Polar in-process (app/polar_metrics.py); no caller may report it as Polar.
    internal = sorted({o.source for o in body.observations if metric_sources.internal_only(o.source)})
    if internal:  # e.g. polar-api: written only in-process by its sync, never over HTTP
        raise HTTPException(403, f"source '{internal[0]}' is written only by the Polar sync"
                            if internal == [polar_metrics.SOURCE] else f"sources {internal} are internal only")
    try:
        return metrics_store.record(db, body)
    except metrics_store.UnknownBusinessUnit as e:
        raise HTTPException(404, f"business unit '{e}' not found")


@app.post("/backups", status_code=201)
def report_backup(body: schemas.BackupReport, db: Session = Depends(get_db)) -> dict:
    run = models.BackupRun(
        target=body.target, destination=body.destination, size_bytes=body.size_bytes,
        checksum=body.checksum, uploaded=body.uploaded,
        integrity_verified=body.integrity_verified, ok=body.ok, error=body.error,
        ended_at=datetime.now(timezone.utc),
    )
    if body.restore_tested:
        run.restore_tested_at = datetime.now(timezone.utc)
    db.add(run)
    # Success evidence and its source row must commit together. Do not copy paths,
    # destinations or error text into the worker's external-input proof.
    checksum = body.checksum or ""
    verified = (body.ok and body.uploaded and body.integrity_verified and not body.expected
            and not body.error and body.destination and body.destination.strip()
            and body.size_bytes is not None and body.size_bytes > 0
            and 0 < len(body.target) <= 300 and body.target.strip()
            and len(checksum) == 64 and all(c in "0123456789abcdefABCDEF" for c in checksum))
    if verified:
        db.flush()
        db.add(models.Event(event_type="BACKUP_VERIFIED", source="company-backup",
            severity=enums.Severity.INFO, dedupe_key=f"backup-verified:{run.id}",
            payload={"target": body.target, "status": "VERIFIED", "backup_run_id": run.id,
                     "evidence": [f"backup_run:{run.id}", f"sha256:{checksum.lower()}"]}))
    db.commit()
    db.refresh(run)
    if verified:
        condition = "restore" if body.restore_tested else "backup"
        notifier.recover_condition(db, source="company-backup",
                                   condition_key=f"{condition}:{body.target}")

    delivered = False
    if not body.ok and not body.expected:
        event_type = "RESTORE_VERIFICATION_FAILED" if body.restore_tested else "BACKUP_FAILED"
        event = _record_event(db, schemas.EventIn(
            event_type=event_type, source="company-backup", severity=enums.Severity.CRITICAL,
            payload={"title": f"{event_type}: {body.target}",
                     "message": (body.error or "no error detail")[:400],
                     "detail": f"uploaded={body.uploaded} integrity={body.integrity_verified}",
                     "condition_key": f"{'restore' if body.restore_tested else 'backup'}:{body.target}"},
        ))
        delivered, _ = notifier.dispatch(db, event)
    return {"id": run.id, "ok": run.ok, "notified": delivered, "expected_gap": body.expected}


@app.get("/backups")
def list_backups(limit: int = 20, db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(
        select(models.BackupRun).order_by(models.BackupRun.started_at.desc()).limit(limit)
    ).scalars()
    return [{"id": b.id, "target": b.target, "started_at": b.started_at.isoformat(),
             "ok": b.ok, "uploaded": b.uploaded, "integrity_verified": b.integrity_verified,
             "size_bytes": b.size_bytes, "error": b.error} for b in rows]


# --------------------------------------------------------------------------- checkpoint

@app.post("/checkpoints", status_code=201)
def create_checkpoint(body: schemas.CheckpointIn, db: Session = Depends(get_db)) -> dict:
    """§58 — persist before forgetting. This is what makes a session restart survivable."""
    ckpt = models.Checkpoint(actor=body.actor, summary=body.summary, completed=body.completed,
                             unfinished=body.unfinished, next_action=body.next_action)
    db.add(ckpt)
    db.commit()
    db.refresh(ckpt)
    return {"id": ckpt.id, "created_at": ckpt.created_at.isoformat()}


@app.get("/checkpoints")
def list_checkpoints(limit: int = 10, db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(
        select(models.Checkpoint).order_by(models.Checkpoint.created_at.desc()).limit(limit)
    ).scalars()
    return [{"id": c.id, "actor": c.actor, "summary": c.summary,
             "next_action": c.next_action, "created_at": c.created_at.isoformat()} for c in rows]


# --------------------------------------------------------------------------- metrics / audit

@app.get("/metrics")
def metrics(db: Session = Depends(get_db)) -> dict:
    day_ago = datetime.now(timezone.utc) - timedelta(days=1)
    runs = db.execute(select(models.AgentRun).where(models.AgentRun.started_at >= day_ago)).scalars().all()
    done = sum(1 for r in runs if r.status == enums.AgentRunStatus.SUCCEEDED)
    return {
        "tasks_by_status": {
            s.value: db.execute(
                select(func.count()).select_from(models.Task).where(models.Task.status == s)
            ).scalar_one() for s in enums.TaskStatus
        },
        "open_incidents": db.execute(
            select(func.count()).select_from(models.Incident)
            .where(models.Incident.status != enums.IncidentStatus.RESOLVED)
        ).scalar_one(),
        "pending_approvals": db.execute(
            select(func.count()).select_from(models.Approval)
            .where(models.Approval.status == enums.ApprovalStatus.REQUESTED)
        ).scalar_one(),
        "agent_runs_24h": len(runs),
        "agent_success_rate_24h": round(done / len(runs), 3) if runs else None,
        "ai_cost_24h_usd": float(sum(r.estimated_cost_usd or 0 for r in runs)),
        "events_24h": db.execute(
            select(func.count()).select_from(models.Event)
            .where(models.Event.occurred_at >= day_ago)
        ).scalar_one(),
        "alerts_delivered_24h": db.execute(
            select(func.count()).select_from(models.Event)
            .where(models.Event.occurred_at >= day_ago, models.Event.notified.is_(True))
        ).scalar_one(),
    }


@app.get("/audit")
def list_audit(limit: int = 50, entity_type: str | None = None,
               db: Session = Depends(get_db)) -> list[dict]:
    stmt = select(models.AuditLog)
    if entity_type:
        stmt = stmt.where(models.AuditLog.entity_type == entity_type)
    rows = db.execute(stmt.order_by(models.AuditLog.occurred_at.desc()).limit(limit)).scalars()
    return [{"id": a.id, "actor": a.actor, "action": a.action, "entity_type": a.entity_type,
             "entity_key": a.entity_key, "reason": a.reason,
             "occurred_at": a.occurred_at.isoformat()} for a in rows]
