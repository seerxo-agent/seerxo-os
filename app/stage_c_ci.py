"""Stage C: feed the existing GitHub CI result of an improvement PR back into its lifecycle.

Called by the worker control loop for published tasks. Deterministic, no model call. Input is a facts dict
read from GitHub (`gh_facts`); `ingest` decides one step:

  PR_OPEN  -> CI                 once CI for the published commit is observed
  CI       -> READY_TO_MERGE     exact-head CI and independent fingerprint approval both pass
  CI       -> IMPLEMENTING       a workflow failed: a bounded repair (MAX_REPAIRS)
  CI       -> (task BLOCKED)     repairs exhausted: Needs You, no further automatic attempt
  PR_OPEN/CI -> ABANDONED        PR closed without merge
  READY_TO_MERGE -> MERGED       the founder merged exactly the published commit (GitHub facts)

Only CI for the exact commit the control plane published counts (evidence `commit` from
`publish()`): a PR head that moved means someone else pushed, and nothing is concluded.
Pending, cancelled or incomplete results leave the stage unchanged; unknown is never success.
Merging stays the founder's. A merge is recorded only as the founder's act, from evidence:
GitHub's merged_by is `founder_login`, the PR is not a draft, it merged into the tracked
branch, and its head is the published commit. Anything else (another login, a bot, a merge
before CI passed) leaves the task unmerged and BLOCKED for the founder to look at.
"""
import json
import re
import subprocess
from datetime import datetime, timezone
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, enums, merge_authorization, models, stage_c
from app.commit_statuses import (STATUS_FAILED, STATUS_PAGE, STATUS_QUERY, latest_statuses,
                                 status_checks)

ACTOR = "stage-c-ci"
MERGE_NOT_RECORDED = "Merge not recorded: "
MAX_REPAIRS = 2
FAILED = {"failure", "timed_out", "startup_failure"}
# A fork PR's workflow run that waits for the founder's "Approve and run workflows" has not run: it is pending, never a
# failure (B-15, 2026-10-23: PR #432 was sent back to repair and its merge then refused as MERGE_UNVERIFIED).
AWAITING_APPROVAL = "action_required"


def _evidence(task: models.Task, stage: str) -> dict:
    hist = ((task.context or {}).get("improvement") or {}).get("history", [])
    # Malformed rows are skipped, never raised on: callers outside reconcile()'s per-task try use this.
    ev = next((h.get("evidence") for h in reversed(hist if isinstance(hist, list) else [])
               if isinstance(h, dict) and h.get("stage") == stage), None)
    return ev if isinstance(ev, dict) else {}


def merge_recovery_block(db: Session, task: models.Task):
    """Return the latest exact system audit that permits retrying merge observation.

    A generic BLOCKED task is always founder-owned. Recovery is limited to this worker's
    merge-specific block for the same published PR and recorded GitHub merge identity.
    """
    if (task.status != enums.TaskStatus.BLOCKED
            or not (task.error or "").startswith(MERGE_NOT_RECORDED)):
        return None
    imp = (task.context or {}).get("improvement") or {}
    stage = imp.get("stage")
    if stage not in ("PR_OPEN", "CI", "READY_TO_MERGE"):
        return None
    number = pr_number(_evidence(task, "PR_OPEN").get("pr"))
    if number is None:
        return None
    latest = db.scalar(select(models.AuditLog).where(
        models.AuditLog.entity_type == "task", models.AuditLog.entity_key == task.key,
        models.AuditLog.task_id == task.id).order_by(models.AuditLog.id.desc()).limit(1))
    if (not latest or latest.actor != ACTOR or latest.action != "improvement.blocked"
            or not isinstance(latest.after, dict)):
        return None
    prior_status = db.scalar(select(models.AuditLog).where(
        models.AuditLog.entity_type == "task", models.AuditLog.entity_key == task.key,
        models.AuditLog.task_id == task.id, models.AuditLog.action == "task.status",
        models.AuditLog.id < latest.id).order_by(models.AuditLog.id.desc()).limit(1))
    if (prior_status and isinstance(prior_status.after, dict)
            and prior_status.after.get("status") == enums.TaskStatus.BLOCKED.value):
        return None
    evidence = latest.after
    audit_number = evidence.get("pr_number")
    if (not isinstance(audit_number, int) or isinstance(audit_number, bool) or audit_number != number
            or (evidence.get("stage") is not None and evidence.get("stage") != stage)
            or not (evidence.get("merge_problems")
                    or evidence.get("merge_eligibility") == "refused")
            or not re.fullmatch(r"[0-9a-f]{40}", evidence.get("merge_commit") or "")
            or not isinstance(evidence.get("merged_by"), str) or not evidence["merged_by"]):
        return None
    return latest


def _eligibility(db: Session, task: models.Task, context: dict, facts: dict,
                 repository: str | None, tracked_branch: str | None, required_statuses: tuple[str, ...],
                 *, allow_blocked_recovery: bool = False, head_repository: str | None = None):
    decision = merge_authorization.evaluate(
        context=context, repository=repository or "", task_key=task.key,
        target_branch=tracked_branch or "", facts=facts,
        blocked=task.status == enums.TaskStatus.BLOCKED and not allow_blocked_recovery,
        required_statuses=required_statuses, head_repository=head_repository)
    approval = ((context or {}).get("improvement") or {}).get("approval") or {}
    audit_id = approval.get("audit_id")
    event = db.get(models.AuditLog, audit_id) if isinstance(audit_id, int) and not isinstance(audit_id, bool) else None
    recorded = (event and event.action == "improvement.review_approved" and event.entity_type == "task"
                and event.entity_key == task.key and event.task_id == task.id
                and event.actor == approval.get("reviewer")
                and (event.after or {}).get("fingerprint") == approval.get("fingerprint")
                and (event.after or {}).get("reviewer") == approval.get("reviewer")
                and (event.after or {}).get("coder") == approval.get("coder")
                and (event.after or {}).get("review_stage_at") == approval.get("review_stage_at"))
    if not recorded:
        decision.eligible = False
        decision.reasons.append("review approval does not match its task audit record")
    return decision


def repairs_used(task: models.Task) -> int:
    hist = ((task.context or {}).get("improvement") or {}).get("history", [])
    return sum(1 for a, b in zip(hist, hist[1:]) if a["stage"] == "CI" and b["stage"] == "IMPLEMENTING")


def pr_number(url_or_number) -> int | None:
    m = re.search(r"(\d+)$", str(url_or_number or ""))
    # Bounded before int(): a very long digit run raises ValueError and would abort reconcile() for every task.
    return int(m.group(1)) if m and len(m.group(1)) <= 10 else None


def _block(db: Session, task: models.Task, why: str, after: dict) -> None:
    task.status = enums.TaskStatus.BLOCKED
    task.error = why[:500]
    audit.record(db, actor=ACTOR, action="improvement.blocked", entity_type="task",
                 entity_key=task.key, after=after, task_id=task.id)


def _timestamp(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except (AttributeError, TypeError, ValueError):
        return None


def _record_ready(db: Session, task: models.Task, base: dict, evidence: dict | None = None) -> None:
    approval = task.context["improvement"]["approval"]
    stage_c.advance(db, task, "READY_TO_MERGE", ACTOR, {
        **base, "ci_state": "passed", "merge_eligibility": "eligible",
        "fingerprint": approval["fingerprint"], "reviewer": approval["reviewer"],
        "coder": approval["coder"], "review_audit_id": approval["audit_id"], **(evidence or {}),
    })


def _merge_problems(stage: str, facts: dict, base: dict, founder_login: str | None,
                    tracked_branch: str | None) -> list[str]:
    login = facts.get("merged_by")
    problems = []
    if stage != "READY_TO_MERGE":
        problems.append(f"merged at {stage}, before CI passed")
    if not founder_login or login != founder_login:
        problems.append(f"merged by {login or 'unknown'}, not the founder's login")
    if facts.get("draft"):
        problems.append("PR was a draft")
    if not tracked_branch or facts.get("base_ref") != tracked_branch:
        problems.append(f"merged into {facts.get('base_ref')}, not {tracked_branch}")
    if facts.get("head_sha") != base["commit"]:
        problems.append("merged head is not the published commit")
    if not re.fullmatch(r"[0-9a-f]{40}", facts.get("merge_commit") or ""):
        problems.append("no merge commit")
    return problems


def _record_merge(db: Session, task: models.Task, stage: str, facts: dict, base: dict,
                  founder_login: str | None, tracked_branch: str | None,
                  recovered_block=None) -> dict:
    login = facts.get("merged_by")
    problems = _merge_problems(stage, facts, base, founder_login, tracked_branch)
    if problems:
        # Never recorded as MERGED: a human decides what this merge was.
        _block(db, task, MERGE_NOT_RECORDED + "; ".join(problems),
               {"merge_problems": problems, "stage": stage, "merged_by": login,
                "merge_commit": facts.get("merge_commit"), "pr_number": base.get("pr_number")})
        return {"outcome": "MERGE_UNVERIFIED", "problems": problems}
    approval = ((task.context or {}).get("improvement") or {}).get("approval") or {}
    published_pr = _evidence(task, "PR_OPEN").get("pr", "")
    repository = published_pr.removeprefix("https://github.com/").split("/pull/", 1)[0]
    authorizations = list(db.scalars(select(models.AuditLog).where(
        models.AuditLog.action == "improvement.merge_authorized",
        models.AuditLog.entity_key == task.key,
        models.AuditLog.task_id == task.id).order_by(models.AuditLog.id.desc())))
    authorization = next((event for event in authorizations if (
        event.actor == "scripts/merge-pr" and event.entity_type == "task"
        and (event.after or {}).get("repository") == repository
        and (event.after or {}).get("pr_number") == base.get("pr_number")
        and (event.after or {}).get("head_sha") == facts.get("head_sha")
        and (event.after or {}).get("fingerprint") == approval.get("fingerprint")
        and (event.after or {}).get("review_audit_id") == approval.get("audit_id"))), None)
    # GitHub proves the founder merged this PR, but a prior receipt cannot prove
    # whether the merge came from this script or the founder's GitHub UI.
    merge_path = "founder_github"
    stage_c.advance(db, task, "MERGED",
                    f"founder (github:{login}, via {merge_path})",
                    {**base, "merged_by": login, "merge_commit": facts["merge_commit"],
                     "branch": tracked_branch,
                     "review_audit_id": _evidence(task, "READY_TO_MERGE").get("review_audit_id"),
                     "merge_path": merge_path,
                     "merge_authorization_id": authorization.id if authorization else None})
    if recovered_block is not None:
        before = {"status": task.status.value, "error": task.error}
        task.status = enums.TaskStatus.REVIEW
        task.error = None
        audit.record(db, actor=ACTOR, action="improvement.merge_block_recovered", entity_type="task",
                     entity_key=task.key, task_id=task.id,
                     reason="same published PR now has complete pre-merge CI and independent-review proof",
                     before=before,
                     after={"status": task.status.value, "stage": "MERGED",
                            "blocked_audit_id": recovered_block.id,
                            "pr_number": base.get("pr_number"), "head_sha": base.get("commit"),
                            "merge_commit": facts["merge_commit"]})
    return {"outcome": "MERGED"}


def ingest(db: Session, task: models.Task, facts: dict, max_repairs: int = MAX_REPAIRS, *,
           repository: str | None = None, tracked_branch: str | None = None,
           founder_login: str | None = None, required_statuses: tuple[str, ...],
           head_repository: str | None = None) -> dict:
    """One deterministic step from CI facts. Caller commits. Returns {"outcome", ...}.
    `head_repository`: the one repository the PR head may come from (default: `repository`)."""
    stage = ((task.context or {}).get("improvement") or {}).get("stage")
    original_stage = stage
    recovery_block = merge_recovery_block(db, task)
    recovering = recovery_block is not None
    published = _evidence(task, "PR_OPEN")
    commit, number = published.get("commit"), pr_number(published.get("pr"))
    base = {"pr_number": number, "commit": commit}

    # B3: a PR number is only an identity together with its repository and published head. Facts about
    # another repository's PR, or a closed PR whose head is not the one this task published, change nothing.
    if repository is not None and (number is None
                                   or published.get("pr") != f"https://github.com/{repository}/pull/{number}"):
        return {"outcome": "WAITING", "reason": "pr_identity_mismatch"}
    if (facts.get("state") == "closed" and not facts.get("merged")
            and facts.get("head_sha") is not None and facts.get("head_sha") != commit):
        return {"outcome": "WAITING", "reason": "closed_pr_head_mismatch"}

    if task.status == enums.TaskStatus.BLOCKED and not recovering:
        return {"outcome": "SKIPPED", "reason": "blocked; waiting for the founder"}
    if recovering and not facts.get("merged"):
        return {"outcome": "WAITING", "reason": "recorded system merge is not confirmed by GitHub"}
    if facts.get("state") == "closed" and not facts.get("merged"):
        stage_c.advance(db, task, "ABANDONED", ACTOR, {**base, "reason": "PR closed without merge"})
        return {"outcome": "ABANDONED"}
    if facts.get("merged") and commit and stage != "MERGED":
        if (task.error or "").startswith(MERGE_NOT_RECORDED) and not recovering:
            return {"outcome": "SKIPPED", "reason": "merge block is not recoverable by automation"}
        if recovering and (recovery_block.after.get("merged_by") != facts.get("merged_by")
                           or recovery_block.after.get("merge_commit") != facts.get("merge_commit")):
            return {"outcome": "SKIPPED", "reason": "merge identity differs from the recorded system block"}
        if recovering and _merge_problems("READY_TO_MERGE", facts, base, founder_login, tracked_branch):
            return {"outcome": "WAITING", "reason": "founder merge identity is not verified"}
        # Polling or an outage may hide the green interval before the founder merges. Reconstruct
        # it only from complete exact-head CI timestamps and the persisted independent review.
        completed, merged_at = _timestamp(facts.get("ci_completed_at")), _timestamp(facts.get("merged_at"))
        if (stage in ("PR_OPEN", "CI") and completed and merged_at and completed <= merged_at):
            context = {**(task.context or {}), "improvement": {
                **((task.context or {}).get("improvement") or {}), "stage": "READY_TO_MERGE"}}
            premerge_facts = {**facts, "state": "open", "merged": False}
            decision = _eligibility(db, task, context, premerge_facts, repository, tracked_branch,
                                    required_statuses, allow_blocked_recovery=recovering,
                                    head_repository=head_repository)
            approval = context["improvement"].get("approval") or {}
            review = db.get(models.AuditLog, approval["audit_id"]) if decision.eligible else None
            reviewed_at = review.occurred_at if review else None
            if reviewed_at and reviewed_at.tzinfo is None:
                reviewed_at = reviewed_at.replace(tzinfo=timezone.utc)
            if decision.eligible and reviewed_at and reviewed_at <= merged_at:
                if stage == "PR_OPEN":
                    stage_c.advance(db, task, "CI", ACTOR, {**base, "ci_state": "observed after merge"})
                _record_ready(db, task, base, {"ci_observed_after_merge": True,
                    "ci_completed_at": facts["ci_completed_at"], "merged_at": facts["merged_at"]})
                stage = "READY_TO_MERGE"
        if recovering and original_stage == "READY_TO_MERGE":
            # READY_TO_MERGE may already have been recorded before the first poll. Re-check its
            # audit time as well as the independently timestamped CI and review before recovery.
            ready_at = _timestamp(next((h.get("at") for h in reversed(
                ((task.context or {}).get("improvement") or {}).get("history", []))
                if h.get("stage") == "READY_TO_MERGE"), None))
            approval = ((task.context or {}).get("improvement") or {}).get("approval") or {}
            audit_id = approval.get("audit_id")
            review = db.get(models.AuditLog, audit_id) if isinstance(audit_id, int) else None
            reviewed_at = review.occurred_at if review else None
            if reviewed_at and reviewed_at.tzinfo is None:
                reviewed_at = reviewed_at.replace(tzinfo=timezone.utc)
            if (not completed or not merged_at or completed > merged_at or not ready_at or ready_at > merged_at
                    or not reviewed_at or reviewed_at > merged_at):
                return {"outcome": "WAITING", "reason": "pre-merge CI or review timing is not proven"}
            premerge_facts = {**facts, "state": "open", "merged": False}
            decision = _eligibility(db, task, task.context or {}, premerge_facts,
                                    repository, tracked_branch, required_statuses,
                                    allow_blocked_recovery=True, head_repository=head_repository)
            if not decision.eligible:
                return {"outcome": "WAITING", "reason": "pre-merge eligibility is not proven"}
        elif recovering and stage != "READY_TO_MERGE":
            return {"outcome": "WAITING", "reason": "pre-merge CI or review timing is not proven"}
        # A merge is judged from its GitHub facts at any stage after publication, not only at
        # READY_TO_MERGE. A PR merged after its CI failed (stage moved to IMPLEMENTING for a
        # repair) is BLOCKED here, never restarted: _record_merge refuses it and keeps the history.
        if stage == "READY_TO_MERGE":
            premerge_facts = {**facts, "state": "open", "merged": False}
            decision = _eligibility(db, task, task.context or {}, premerge_facts,
                                    repository, tracked_branch, required_statuses,
                                    allow_blocked_recovery=recovering, head_repository=head_repository)
            if not decision.eligible:
                why = MERGE_NOT_RECORDED + "eligibility was not proven: " + "; ".join(decision.reasons)
                _block(db, task, why, {"merge_eligibility": "refused", "reasons": decision.reasons,
                                      "merged_by": facts.get("merged_by"),
                                      "merge_commit": facts.get("merge_commit"), "pr_number": number})
                return {"outcome": "MERGE_UNVERIFIED", "problems": decision.reasons}
        return _record_merge(db, task, stage, facts, base, founder_login, tracked_branch,
                             recovered_block=recovery_block if recovering else None)
    if stage not in ("PR_OPEN", "CI", "READY_TO_MERGE"):
        return {"outcome": "SKIPPED", "reason": f"stage {stage}"}
    if task.status == enums.TaskStatus.BLOCKED:
        return {"outcome": "SKIPPED", "reason": "blocked; waiting for the founder"}
    if stage == "READY_TO_MERGE":
        return {"outcome": "WAITING", "reason": "ready; the founder merges"}
    if not commit or facts.get("head_sha") != commit:
        # Someone else moved the PR head: the CI result is not about the reviewed bytes.
        return {"outcome": "HEAD_MOVED", "expected": commit, "head": facts.get("head_sha")}

    checks = facts.get("checks") or []
    if stage == "PR_OPEN":
        if not checks:
            return {"outcome": "WAITING", "reason": "no CI observed yet"}
        stage_c.advance(db, task, "CI", ACTOR, {**base, "ci_state": "running"})
        stage = "CI"

    statuses = facts.get("statuses") or {}
    failed = [c["name"] for c in checks if c.get("status") == "completed" and c.get("conclusion") in FAILED]
    failed += [context for context in required_statuses
               if statuses.get(context) in STATUS_FAILED and context not in failed]
    awaiting = [c["name"] for c in checks if c.get("status") == "completed" and c.get("conclusion") == AWAITING_APPROVAL]
    if awaiting and not failed:
        return {"outcome": "WAITING", "reason": "workflow approval required: " + ", ".join(awaiting)}
    if failed:
        used = repairs_used(task)
        if used >= max_repairs:
            _block(db, task, f"CI failed after {used} repair attempt(s): {', '.join(failed)}",
                   {"failed": failed, "repairs": used})
            return {"outcome": "BLOCKED", "failed": failed, "repairs": used}
        stage_c.advance(db, task, "IMPLEMENTING", ACTOR,
                        {**base, "ci_state": "failed", "failed_check": failed[0], "repairs": f"{used + 1}/{max_repairs}"})
        return {"outcome": "REPAIR", "failed": failed, "repair": used + 1}

    done = facts.get("checks_complete") and checks and all(
        c.get("status") == "completed" and c.get("conclusion") == "success" for c in checks)
    if done:
        # CircleCI reports later than Actions: a pending or not-yet-posted status is waiting, not a
        # refusal. Untrusted, malformed or incomplete status evidence falls through to eligibility.
        waiting_on = [context for context in required_statuses if statuses.get(context) in (None, "pending")]
        if waiting_on and not facts.get("status_problems") and facts.get("statuses_complete"):
            return {"outcome": "WAITING", "reason": "commit statuses pending: " + ", ".join(waiting_on)}
        context = dict(task.context or {})
        improvement = dict(context.get("improvement") or {})
        improvement["stage"] = "READY_TO_MERGE"
        context["improvement"] = improvement
        decision = _eligibility(db, task, context, facts, repository, tracked_branch, required_statuses,
                                head_repository=head_repository)
        if not decision.eligible:
            _block(db, task, "Merge eligibility refused: " + "; ".join(decision.reasons),
                   {**base, "merge_eligibility": "refused", "reasons": decision.reasons})
            return {"outcome": "BLOCKED", "reasons": decision.reasons}
        _record_ready(db, task, base)
        return {"outcome": "READY_TO_MERGE"}
    return {"outcome": "WAITING", "reason": "CI pending or incomplete"}


def gh_facts(repository: str, number: int, workflows: set[str], *, publisher: dict,
             status_contexts: tuple[str, ...], run=subprocess.run) -> dict:
    """Read-only GitHub facts for one PR: state, head SHA, the configured workflows' latest
    pull_request runs on that head (check runs), and the latest commit status per required context
    from the trusted publisher (commit statuses, a separate GitHub API). Error bodies are never
    surfaced (they may carry secrets)."""
    if not isinstance(status_contexts, tuple) or (not workflows and not status_contexts):
        raise ValueError("explicit required CI workflows or status contexts are required")

    def api(path: str, jq: str) -> dict:
        out = run(["gh", "api", "--method", "GET", path, "--jq", jq], capture_output=True, text=True, timeout=20)
        if out.returncode:
            raise RuntimeError("GitHub read failed")
        return json.loads(out.stdout)
    pr = api(f"repos/{repository}/pulls/{int(number)}",
             "{state, merged, draft, head_sha: .head.sha, head_ref: .head.ref, head_repo: .head.repo.full_name, base_ref: .base.ref, "
             "merged_by: .merged_by.login, merged_at, merge_commit: .merge_commit_sha}")
    sha = pr["head_sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha or ""):
        raise ValueError("invalid head sha")
    runs = api(f"repos/{repository}/actions/runs?head_sha={quote(sha)}&event=pull_request&per_page=100",
               "{total_count, workflow_runs: [.workflow_runs[] | {path, name, head_sha, head_branch, event, status, conclusion, run_number, run_attempt, updated_at, run_repo: .repository.full_name, head_repo: .head_repository.full_name}]}") if workflows else {
                   "total_count": 0, "workflow_runs": []}
    latest = {}
    for r in runs["workflow_runs"]:
        # The list query is not identity evidence: the same SHA can run on another branch or fork.
        # Fork runs can have an empty pull_requests list, so pin the upstream, trigger and exact head branch.
        if (r["path"] in workflows and r["head_sha"] == sha and r.get("event") == "pull_request"
                and isinstance(r.get("run_repo"), str) and r["run_repo"].lower() == repository.lower()
                and isinstance(pr["head_ref"], str) and bool(pr["head_ref"])
                and r.get("head_branch") == pr["head_ref"] and isinstance(pr["head_repo"], str)
                and isinstance(r.get("head_repo"), str) and r["head_repo"].lower() == pr["head_repo"].lower()):
            if r["path"] not in latest or (r["run_number"], r["run_attempt"]) > (latest[r["path"]]["run_number"], latest[r["path"]]["run_attempt"]):
                latest[r["path"]] = r
    # Statuses are read for the same head SHA; a moved head is caught by the callers (HEAD_MOVED).
    raw = api(f"repos/{repository}/commits/{sha}/statuses?per_page={STATUS_PAGE}", STATUS_QUERY) if status_contexts else []
    statuses = latest_statuses(raw, status_contexts, publisher)
    checks = [{"name": r["name"], "status": r["status"], "conclusion": r["conclusion"]} for r in latest.values()]
    checks += status_checks(statuses["statuses"], status_contexts)
    actions_complete = (type(runs["total_count"]) is int
                        and 0 <= runs["total_count"] == len(runs["workflow_runs"]) < 100
                        and set(latest) == set(workflows))
    statuses_complete = statuses["statuses_complete"] and set(statuses["statuses"]) == set(status_contexts)
    completed = [_timestamp(r.get("updated_at")) for r in latest.values()]
    status_rows = raw if isinstance(raw, list) else []
    completed += [_timestamp(next((s.get("created_at") for s in status_rows
                                  if isinstance(s, dict) and s.get("id") == status_id), None))
                  for status_id in statuses.get("status_ids", {}).values()]
    timed_green = (actions_complete and statuses_complete and not statuses["status_problems"]
                   and checks and all(c["status"] == "completed" and c["conclusion"] == "success" for c in checks)
                   and completed and all(at is not None for at in completed))
    return {"state": pr["state"], "merged": bool(pr["merged"]), "head_sha": sha,
            # GitHub returns the canonical casing ("Seerxo/seerxo-os"); repository identities here are lowercase.
            "head_ref": pr["head_ref"], "head_repo": (pr["head_repo"] or "").lower() or None, "checks": checks,
            "draft": bool(pr["draft"]), "base_ref": pr["base_ref"], "merged_by": pr["merged_by"],
            "merge_commit": pr["merge_commit"] if pr["merged"] else None,
            "merged_at": pr.get("merged_at") if pr["merged"] else None,
            "ci_completed_at": max(completed).isoformat() if timed_green else None,
            "checks_complete": actions_complete and statuses_complete,
            **{k: v for k, v in statuses.items() if k != "status_ids"}}
