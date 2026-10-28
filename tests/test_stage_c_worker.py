"""Worker admission and the existing Stage C pipeline; external boundaries use local doubles."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import subprocess
import sys

import pytest

from app import (audit, control, enums, models, providers, stage_c, stage_c_ci,
                 stage_c_runner, stage_c_verify, stage_c_worker, worker)
from tests.test_worker import _db, _task, _good, SPECS


@pytest.fixture(autouse=True)
def _same_repository_publishing(monkeypatch):
    """These tests cover publishing from Seerxo/seerxo-os itself; the repository's policy now names the B5 fork, whose
    path the B5 tests cover by setting it explicitly."""
    from app import repo_guardian_github
    load = repo_guardian_github.load_policy
    monkeypatch.setattr(repo_guardian_github, "load_policy",
                        lambda path: {k: v for k, v in load(path).items() if k != "publish_forks"})

REQUIRED_CONTEXTS = ("ci/circleci: python-tests", "ci/circleci: frontend-tests")
GREEN_STATUSES = {context: "success" for context in REQUIRED_CONTEXTS}


def ingest_ci(*args, **kwargs):
    """ingest with the policy's required commit statuses (the production contract)."""
    return stage_c_ci.ingest(*args, required_statuses=REQUIRED_CONTEXTS, **kwargs)


FOUNDER_ID = "founder:access:founder@example.invalid"


def write_task(db, **over):
    project = models.Project(key="company-os", name="Company OS",
                             repository="seerxo/seerxo-os", status=enums.ProjectStatus.ACTIVE)
    db.add(project)
    db.flush()
    agent = db.query(models.Agent).filter_by(key="developer").one()
    return _task(db, project_id=project.id, assigned_agent_id=agent.id,
                 context={"autonomous": True, "write": True,
                          "stage_c": {"paths": ["tests/test_metrics.py"]}}, **over)


def _published_task_for_merge_reconciliation(db):
    task = write_task(db, key="TASK-0123")
    fingerprint = "f" * 64
    for stage, actor, evidence in (
        ("DETECTED", "stage-c-runner", {}),
        ("PLANNED", "stage-c-runner", {}),
        ("IMPLEMENTING", "stage-c-runner", {}),
        ("TESTING", "stage-c-runner", {"coder": "claude"}),
        ("INDEPENDENT_REVIEW", "stage-c-runner", {"fingerprint": fingerprint}),
    ):
        stage_c.advance(db, task, stage, actor, evidence)
    review_stage_at = task.context["improvement"]["history"][-1]["at"]
    approval = {"fingerprint": fingerprint, "review_stage_at": review_stage_at,
                "reviewer": "codex", "coder": "claude", "findings": []}
    review = audit.record(db, actor="codex", action="improvement.review_approved", entity_type="task",
                          entity_key=task.key, after=approval, task_id=task.id)
    db.flush()
    approval["audit_id"] = review.id
    task.context = {**task.context, "improvement": {**task.context["improvement"],
                                                      "approval": approval}}
    stage_c.advance(db, task, "PR_OPEN", "stage-c-runner", {
        "branch": f"task/{task.key}", "commit": "a" * 40, "fingerprint": fingerprint,
        "pr": f"https://github.com/{stage_c_worker.REPOSITORY}/pull/81"})
    task.status = enums.TaskStatus.REVIEW
    db.commit()
    return task


def _merged_pr_facts(task, *, timestamps=False):
    now = datetime.now(timezone.utc)
    facts = {"state": "closed", "merged": True, "head_sha": "a" * 40,
             "head_ref": f"task/{task.key}", "head_repo": stage_c_worker.REPOSITORY,
             "base_ref": "main", "draft": False, "merged_by": "semihbugrasezer",
             "merge_commit": "c" * 40, "checks_complete": True,
             "checks": [{"name": "python", "status": "completed", "conclusion": "success"}],
             "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": []}
    if timestamps:
        facts.update(ci_completed_at=(now + timedelta(seconds=1)).isoformat(),
                     merged_at=(now + timedelta(seconds=5)).isoformat())
    return facts


def test_explicit_low_risk_active_project_write_is_admitted(monkeypatch):
    monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", True)
    db = _db()
    task = write_task(db)
    runtime_report(db, "a" * 40)
    monkeypatch.setenv("COMPANY_OS_GIT_SHA", "a" * 40)
    reason, spec = worker._admission_gate(db, task, SPECS)
    assert reason is None and spec.key == "developer"


@pytest.mark.parametrize("path", [
    "migrations/versions/change.py", "app/api_auth.py", "app/main.py", "app/config.py",
    "app/worker.py", "agents/repository_guardian.yaml", "AGENTS.md", "CLAUDE.md",
    "docs/CONSTITUTION_REFERENCE.md", ".github/workflows/ci.yml", "docker-compose.yml",
    "scripts/deploy-company-os.sh", "app/billing.py", "tests/test_api_auth.py",
    "../escape.py", "unknown/file.py",
])
def test_protected_or_unknown_scope_never_admitted(monkeypatch, path):
    monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", True)
    db = _db()
    task = write_task(db)
    task.context = {**task.context, "stage_c": {"paths": [path]}}
    db.commit()
    assert worker._admission_gate(db, task, SPECS)[0] == "stage_c_scope_refused"


@pytest.mark.parametrize("change", ["missing_paths", "inactive", "other_repo", "write_not_boolean"])
def test_write_scope_must_be_explicit_and_project_allowed(monkeypatch, change):
    monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", True)
    db = _db()
    task = write_task(db)
    project = db.get(models.Project, task.project_id)
    if change == "missing_paths":
        task.context = {"autonomous": True, "write": True}
    elif change == "inactive":
        project.status = enums.ProjectStatus.PAUSED
    elif change == "other_repo":
        project.repository = "semihbugrasezer/youtube-auto"
    else:
        task.context = {**task.context, "write": "true"}
    db.commit()
    assert worker._admission_gate(db, task, SPECS)[0] is not None


def test_reconcile_recovers_its_merge_block_from_complete_github_proof(monkeypatch):
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    policy = {"repositories": [stage_c_worker.REPOSITORY],
              "branches": {stage_c_worker.REPOSITORY: "main"},
              "workflows": [".github/workflows/ci.yml"]}
    monkeypatch.setattr(stage_c_worker.repo_guardian_github, "load_policy", lambda _: policy)
    monkeypatch.setattr(stage_c_worker.repo_guardian_github, "merge_statuses",
                        lambda _: ({"login": "circleci-app[bot]", "id": 127350680}, REQUIRED_CONTEXTS))
    initial = stage_c_ci.ingest(db, task, _merged_pr_facts(task), repository=stage_c_worker.REPOSITORY,
                                tracked_branch="main", founder_login="semihbugrasezer",
                                required_statuses=REQUIRED_CONTEXTS)
    db.commit()
    assert initial["outcome"] == "MERGE_UNVERIFIED" and task.status == enums.TaskStatus.BLOCKED

    reads = []
    monkeypatch.setattr(stage_c_ci, "gh_facts",
                        lambda *a, **k: reads.append((a, k)) or _merged_pr_facts(task, timestamps=True))
    outcomes = stage_c_worker.reconcile(db)

    assert len(reads) == 1
    assert outcomes == [{"task": task.key, "outcome": "MERGED"}]
    assert task.status == enums.TaskStatus.REVIEW and task.error is None
    assert task.context["improvement"]["stage"] == "MERGED"
    assert db.query(models.AuditLog).filter_by(
        task_id=task.id, action="improvement.merge_block_recovered").count() == 1
    assert db.query(models.AgentRun).filter_by(task_id=task.id).count() == 0


def test_reconcile_does_not_poll_or_reopen_a_founder_reasserted_merge_block(monkeypatch):
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    policy = {"repositories": [stage_c_worker.REPOSITORY],
              "branches": {stage_c_worker.REPOSITORY: "main"},
              "workflows": [".github/workflows/ci.yml"]}
    monkeypatch.setattr(stage_c_worker.repo_guardian_github, "load_policy", lambda _: policy)
    monkeypatch.setattr(stage_c_worker.repo_guardian_github, "merge_statuses",
                        lambda _: ({"login": "circleci-app[bot]", "id": 127350680}, REQUIRED_CONTEXTS))
    stage_c_ci.ingest(db, task, _merged_pr_facts(task), repository=stage_c_worker.REPOSITORY,
                      tracked_branch="main", founder_login="semihbugrasezer",
                      required_statuses=REQUIRED_CONTEXTS)
    db.flush()
    blocked_error = task.error
    audit.record(db, actor="founder", action="task.status", entity_type="task",
                 entity_key=task.key, before={"status": "BLOCKED"},
                 after={"status": "BLOCKED", "error": blocked_error}, task_id=task.id)
    db.commit()
    reads = []
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: reads.append(1))

    outcomes = stage_c_worker.reconcile(db)

    assert outcomes == [] and reads == []
    assert task.status == enums.TaskStatus.BLOCKED and task.error == blocked_error
    assert task.context["improvement"]["stage"] == "PR_OPEN"


class Reviewer(providers.Provider):
    def __init__(self, name):
        super().__init__(name=name, binary=name, environ={"PATH": ""})
        self.packets = []

    def health_check(self):
        return providers.Health.AVAILABLE, None

    def _run(self, prompt, schema, **kw):
        if schema != stage_c_runner.REVIEW_SCHEMA:
            return providers.ProviderResult(self.name, providers.Health.AVAILABLE, output=_good("TASK-0100"))
        packet = json.loads(prompt[len(stage_c_runner.REVIEW_PROMPT):])
        self.packets.append(packet)
        return providers.ProviderResult(self.name, providers.Health.AVAILABLE, output={
            "verdict": "APPROVE", "fingerprint": packet["fingerprint"], "findings": []})


def pipeline(monkeypatch, tmp_path, hooks=None, *, mock_authorization=True, publish_repository="seerxo/seerxo-os"):
    hooks = hooks if hooks is not None else {}
    monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", True)
    monkeypatch.setenv("STAGE_C_JOBS_ROOT", str(tmp_path / "jobs"))
    monkeypatch.setattr(stage_c_worker, "ready", lambda db: None, raising=False)
    monkeypatch.setattr(stage_c_worker, "runtime_ready", lambda db, now=None: True)
    # GitHub's answer for the worker token's upstream role at publication; tests that grant Write override it.
    monkeypatch.setattr(stage_c_worker, "publication_role", lambda: ("PASS", "read-only (test)"))
    if mock_authorization:
        monkeypatch.setattr(control, "pilot_authorization_denial", lambda *a, **k: None)
        monkeypatch.setattr(control, "consume_pilot_authorization", lambda *a, **k: None)
    mirror = tmp_path / "jobs/.control/sez-company.git"
    mirror.mkdir(parents=True)
    git = lambda *a, **k: subprocess.run(["git", "-C", str(mirror), *a], check=True, capture_output=True)
    git("init", "-q", "-b", "main")
    (mirror / "tests").mkdir()
    (mirror / "tests/test_metrics.py").write_text("def test_metric():\n    assert 1 == 0\n")
    git("add", ".")
    git("-c", "user.name=test", "-c", "user.email=test@localhost", "commit", "-qm", "base")
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
    original_git = stage_c_runner._git
    def local_git(repo, *args, **kw):
        if args[0] == "fetch":
            return ""  # external fetch boundary; the fixture mirror already has main
        return original_git(repo, *args, **kw)
    monkeypatch.setattr(stage_c_runner, "_git", local_git)
    def coder(directory, job):
        assert job.paths == ["tests/test_metrics.py"]
        assert not (directory / ".git").exists()
        (directory / job.paths[0]).write_text("def test_metric():\n    assert 1 == 1\n")
    def launcher_coder(**kw):
        def call(directory, job):
            before = kw.get("before_enqueue")
            after = kw.get("after_start")
            if before is not None:
                before()
            try:
                if hooks.get("during_coder_start"):
                    hooks["during_coder_start"]()
                if after is not None:
                    after(True)  # the container is about to exec the coder under the task lock
                    after = None
                if hooks.get("after_coder_start"):
                    hooks["after_coder_start"]()
                return coder(directory, job)
            finally:
                if after is not None:
                    after(False)
        return call
    monkeypatch.setattr(stage_c_runner, "launcher_coder", launcher_coder)
    def checks(directory):
        done = directory.parent / "done"
        done.mkdir(exist_ok=True)
        (done / "result.json").write_text('{"exit": 0}')
        result = subprocess.run([sys.executable, "-m", "pytest", "-q"],
                                cwd=directory, capture_output=True)
        return {"passed": result.returncode == 0, "summary": "local fixture checks"}
    monkeypatch.setattr(stage_c_runner, "launcher_checks", lambda repo, **kw: checks)
    original_publish = stage_c_runner.publish
    def publish(db, task, job, diff, worktree, destination, open_pr, *args, **kwargs):
        assert destination == f"https://github.com/{publish_repository}.git"
        if hooks.get("before_publish"):
            hooks["before_publish"](db, task)
        def fake_open_pr(*a, **k):
            if hooks.get("during_open_pr"):
                hooks["during_open_pr"](db, task)
            return "https://github.com/seerxo/seerxo-os/pull/999"
        return original_publish(db, task, job, diff, worktree, str(remote),
                                fake_open_pr, *args, **kwargs)
    monkeypatch.setattr(stage_c_runner, "publish", publish)
    return remote


def test_a_new_attempt_codes_on_current_main_while_history_keeps_the_old_base(monkeypatch, tmp_path):
    """TASK-0054: a retry was pinned to its first IMPLEMENTING base, so a fix merged since (PR #242) never
    reached it. A fresh attempt re-bases on main and records it; the earlier base stays in the history."""
    from app import stage_c
    remote = pipeline(monkeypatch, tmp_path)
    mirror = tmp_path / "jobs/.control/sez-company.git"
    git = lambda *a, **k: subprocess.run(["git", "-C", str(mirror), *a], check=True, capture_output=True, text=True).stdout.strip()
    old = git("rev-parse", "main")
    (mirror / "tests/conftest.py").write_text("# the fix that landed after the first attempt\n")
    git("add", ".")
    git("-c", "user.name=test", "-c", "user.email=test@localhost", "commit", "-qm", "fix")
    current = git("rev-parse", "main")
    db = _db()
    task = write_task(db)
    for stage, evidence in (("DETECTED", {}), ("PLANNED", {"paths": ["tests/test_metrics.py"]}),
                            ("IMPLEMENTING", {"base": old}), ("TESTING", {"fingerprint": FINGERPRINT, "coder": "claude"})):
        stage_c.advance(db, task, stage, "stage-c-runner", evidence)
    db.commit()
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    out = worker.run_once(db, ps, SPECS)
    history = task.context["improvement"]["history"]
    bases = [h["evidence"]["base"] for h in history if h["stage"] == "IMPLEMENTING" and "base" in h["evidence"]]
    assert bases == [old, current], out
    assert [h["evidence"].get("base") for h in history if h["stage"] == "TESTING"][-1] == current
    assert task.context["improvement"]["stage"] == "PR_OPEN", out


def test_worker_routes_write_through_export_checks_independent_review_and_publish(monkeypatch, tmp_path):
    remote = pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    task.context = {**task.context, "improvement": {"measure": {
        "selector": {"subject": "repository:seerxo/seerxo-os", "metric": "metrics_test_cases",
                     "source": "pytest-collection", "window": ""}, "direction": "up", "window_hours": 0}}}
    db.commit()
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    out = worker.run_once(db, ps, SPECS)
    assert task.context.get("improvement", {}).get("stage") == "PR_OPEN", out
    assert task.context["improvement"]["measure"]["direction"] == "up"
    approval = task.context["improvement"]["approval"]
    assert approval["coder"] != approval["reviewer"]
    reviewed = next(h for h in reversed(task.context["improvement"]["history"])
                    if h["stage"] == "INDEPENDENT_REVIEW")
    assert approval["review_stage_at"] == reviewed["at"]
    review_event = db.get(models.AuditLog, approval["audit_id"])
    assert review_event.action == "improvement.review_approved" and review_event.actor == approval["reviewer"]
    assert ps[approval["reviewer"]].packets[0]["fingerprint"] == approval["fingerprint"]
    assert task.status == enums.TaskStatus.REVIEW and out["model_calls"] == 2
    head = subprocess.run(["git", "--git-dir", str(remote), "show", "task/TASK-0100:tests/test_metrics.py"],
                          capture_output=True, check=True).stdout
    assert b"assert 1 == 1" in head
    assert db.query(models.Learning).count() == 0


def test_publish_refuses_replayed_approval_from_an_earlier_review_attempt(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    original = stage_c_runner.publish

    def stale_publish(db, task, *args, **kwargs):
        imp = task.context["improvement"]
        task.context = {**task.context, "improvement": {**imp, "approval": {
            **imp["approval"], "review_stage_at": "earlier-attempt"}}}
        return original(db, task, *args, **kwargs)

    monkeypatch.setattr(stage_c_runner, "publish", stale_publish)
    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)

    assert out["verdict"] == "NOT_APPROVED"
    assert task.context["improvement"]["stage"] == "INDEPENDENT_REVIEW"
    assert "pr" not in (task.artifacts or {})


def test_unknown_host_acceptance_waits_without_claim_or_stage_b_call(monkeypatch):
    monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", True)
    monkeypatch.setenv("COMPANY_OS_GIT_SHA", "a" * 40)
    db = _db()
    task = write_task(db)
    runtime_report(db, "a" * 40)
    control.authorize_pilot(db, task.key, "a" * 40, founder=FOUNDER_ID)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    out = worker.run_once(db, ps, SPECS)
    assert out.get("blocked") == "stage_c_host_not_accepted"
    assert task.status == enums.TaskStatus.READY and out["model_calls"] == 0
    assert not task.context.get("improvement")


def test_only_control_plane_https_git_gets_the_scoped_credential(monkeypatch, tmp_path):
    from types import SimpleNamespace
    monkeypatch.setenv("GH_TOKEN", "fixture-credential")
    monkeypatch.setenv("DATABASE_URL", "must-not-reach-git")
    calls = []
    def git(argv, **kw):
        calls.append((argv, kw["env"]))
        return SimpleNamespace(stdout=b"diff with trailing space \n\n")
    monkeypatch.setattr(stage_c_runner.subprocess, "run", git)
    assert stage_c_runner._git(tmp_path, "diff", strip=False) == "diff with trailing space \n\n"
    stage_c_runner._git(tmp_path, "ls-remote", "https://github.com/seerxo/seerxo-os.git", protocol="https")
    assert "GH_TOKEN" not in calls[0][1]
    assert calls[1][1]["GH_TOKEN"] == "fixture-credential"
    assert "credential.helper=!gh auth git-credential" in calls[1][0]
    assert all("DATABASE_URL" not in env for _, env in calls)


def test_disarmed_control_loop_recognizes_a_green_interval_missed_during_an_outage(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    commit = task.artifacts["commit"]
    monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", False)
    now = datetime.now(timezone.utc)
    facts = {"state": "closed", "merged": True, "merged_by": "semihbugrasezer", "draft": False,
             "head_sha": commit, "head_ref": "task/TASK-0100", "head_repo": "seerxo/seerxo-os",
             "base_ref": "main", "merge_commit": "c" * 40,
             "checks_complete": True, "checks": [{"name": "ci", "status": "completed", "conclusion": "success"}],
             "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
             "ci_completed_at": (now + timedelta(seconds=1)).isoformat(),
             "merged_at": (now + timedelta(seconds=5)).isoformat()}
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: facts)

    result = worker.run_once(db, {}, SPECS)

    assert task.context["improvement"]["stage"] == "MERGED"
    assert task.status == enums.TaskStatus.REVIEW and result["model_calls"] == 0


def test_control_loop_tracks_ci_founder_merge_and_unknown_live_evidence(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    commit = task.artifacts["commit"]
    facts = {"state": "open", "head_sha": commit, "head_ref": "task/TASK-0100",
             "head_repo": "seerxo/seerxo-os", "base_ref": "main",
             "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
             "checks": [{"name": "ci", "status": "completed", "conclusion": "success"}]}
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: facts)
    worker.run_once(db, {}, SPECS)
    assert task.context["improvement"]["stage"] == "READY_TO_MERGE"
    advance_events = db.query(models.AuditLog).filter_by(entity_key=task.key, action="improvement.advance").all()
    ready_event = next(e for e in reversed(advance_events) if (e.after or {}).get("stage") == "READY_TO_MERGE")
    review_audit_id = task.context["improvement"]["approval"]["audit_id"]
    assert ready_event.after["evidence"]["review_audit_id"] == review_audit_id
    facts.update(merged=True, merged_by="semihbugrasezer", merge_commit="c" * 40, base_ref="main", draft=False)
    worker.run_once(db, {}, SPECS)
    assert task.context["improvement"]["stage"] == "MERGED"
    advance_events = db.query(models.AuditLog).filter_by(entity_key=task.key, action="improvement.advance").all()
    merged_event = next(e for e in reversed(advance_events) if (e.after or {}).get("stage") == "MERGED")
    assert merged_event.after["evidence"]["review_audit_id"] == review_audit_id
    assert merged_event.after["evidence"]["merge_path"] == "founder_github"
    assert merged_event.after["evidence"]["merge_authorization_id"] is None
    monkeypatch.setattr(stage_c_verify, "gh_facts", lambda *a, **k: {"main_ci": "success", "live_contains_merge": None})
    worker.run_once(db, {}, SPECS)
    assert task.context["improvement"]["stage"] == "MERGED"
    # A live attestation is independently required, even if GitHub's adapter is replaced.
    monkeypatch.setattr(stage_c_verify, "gh_facts", lambda *a, **k: {"main_ci": "success", "live_contains_merge": True})
    worker.run_once(db, {}, SPECS)
    assert task.context["improvement"]["stage"] == "MERGED"
    from app import watchdog
    monkeypatch.setenv("COMPANY_OS_GIT_SHA", "d" * 40)
    watchdog.record_host_metrics(db, {"cpu_used_pct": 1,
                                      "runtime": {"api_sha": "d" * 40, "worker_sha": "d" * 40}})
    worker.run_once(db, {}, SPECS)
    assert task.context["improvement"]["stage"] == "VERIFYING"
    worker.run_once(db, {}, SPECS)
    assert task.context["improvement"]["stage"] == "MEASURED"
    assert task.context["improvement"]["history"][-1]["evidence"]["outcome"] == "NOT_MEASURABLE"
    assert db.query(models.Learning).count() == 0 and task.status == enums.TaskStatus.REVIEW


def test_ci_repair_reuses_same_pr_and_stops_at_existing_limit(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    worker.run_once(db, ps, SPECS)
    def failed(*a, **k):
        return {"state": "open", "head_sha": task.artifacts["commit"], "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
                "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}
    monkeypatch.setattr(stage_c_ci, "gh_facts", failed)
    for _ in range(2):
        worker.run_once(db, ps, SPECS)
        assert task.context["improvement"]["stage"] == "PR_OPEN"
        assert task.artifacts["pr"].endswith("/999")
    worker.run_once(db, ps, SPECS)
    assert task.status == enums.TaskStatus.BLOCKED and stage_c_ci.repairs_used(task) == 2


def test_claude_always_codes_and_codex_only_reviews(monkeypatch, tmp_path):
    """Codex's own sandbox cannot start inside the hardened coder container on the host
    (bubblewrap needs user namespaces; acceptance run 2026-10-07), so it never writes code."""
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("codex", "claude")}  # codex listed first on purpose
    worker.run_once(db, ps, SPECS)
    approval = task.context["improvement"]["approval"]
    assert (approval["coder"], approval["reviewer"]) == ("claude", "codex")


def test_without_a_usable_claude_nothing_is_coded(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    def no_coder(**kw):
        raise AssertionError("Codex must never be launched as the coder")
    monkeypatch.setattr(stage_c_runner, "launcher_coder", no_coder)

    class Down(Reviewer):
        def health_check(self):
            return providers.Health.AUTH_REQUIRED, None

    db = _db()
    task = write_task(db)
    out = worker.run_once(db, {"claude": Down("claude"), "codex": Reviewer("codex")}, SPECS)
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0
    assert out.get("model_calls", 0) == 0


def record_coders(monkeypatch):
    original, seen = stage_c_runner.launcher_coder, []
    def wrapped(**kw):
        call = original(**kw)
        def coder(directory, job):
            seen.append(job.provider)
            return call(directory, job)
        return coder
    monkeypatch.setattr(stage_c_runner, "launcher_coder", wrapped)
    return seen


class Down(Reviewer):
    def health_check(self):
        return providers.Health.AUTH_REQUIRED, None


@pytest.fixture
def saved_review(monkeypatch, tmp_path):
    def crash(*args):
        raise SystemExit("worker stopped after review committed")

    hooks = {"before_publish": crash}
    pipeline(monkeypatch, tmp_path, hooks, mock_authorization=False)
    monkeypatch.setenv("COMPANY_OS_GIT_SHA", SHA_A)
    coded = record_coders(monkeypatch)
    db = _db()
    task = write_task(db)
    control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    with pytest.raises(SystemExit):
        worker.run_once(db, ps, SPECS)
    db.rollback()
    assert len(ps["codex"].packets) == 1 and task.context["improvement"]["approval"]
    run = db.query(models.AgentRun).one()
    run.started_at = worker._now() - timedelta(hours=2)
    db.commit()
    hooks.clear()
    # A pilot is one attempt; recovery needs separately issued authority too.
    control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    return db, task, ps, coded


@pytest.mark.parametrize("availability", ["available", "unavailable", "no_providers"])
def test_restart_after_saved_approval_publishes_without_repeating_review(saved_review, availability):
    db, task, ps, coded = saved_review
    resumed = ({} if availability == "no_providers" else {n: Down(n) for n in ps}
               if availability == "unavailable" else ps)
    outcome = worker.run_once(db, resumed, SPECS)

    assert outcome.get("verdict") == "PR_OPEN", outcome
    assert outcome["model_calls"] == 0 and len(ps["codex"].packets) == 1
    assert coded == ["claude"] and task.status == enums.TaskStatus.REVIEW
    assert task.retry_count == 0


@pytest.mark.parametrize("field,value", [("base", "f" * 40), ("checks", "different checks"), ("checks_passed", False)])
def test_saved_approval_is_bound_to_the_original_base_and_checks(saved_review, field, value):
    db, task, _, _ = saved_review
    imp = task.context["improvement"]
    stage = "TESTING" if field == "base" else "INDEPENDENT_REVIEW"
    history = [dict(h) for h in imp["history"]]
    entry = next(h for h in reversed(history) if h["stage"] == stage)
    entry["evidence"] = {**entry["evidence"], field: value}
    task.context = {**task.context, "improvement": {**imp, "history": history}}
    db.commit()

    assert stage_c_runner.approved_review(db, task) is False


@pytest.mark.parametrize("change", ["objective", "criteria", "owner", "scope", "audit", "independence",
                                    "legacy_approval", "diff", "malformed_history", "pause", "cancel", "metered",
                                    "authorization_missing", "authorization_consumed", "authorization_expired",
                                    "authorization_sha", "write_disabled"])
def test_saved_review_never_bypasses_current_contract_proof_or_authority(saved_review, monkeypatch, change):
    db, task, ps, coded = saved_review
    imp = task.context["improvement"]
    approval = dict(imp["approval"])
    if change == "objective":
        task.objective = "A different founder objective"
    elif change == "criteria":
        task.success_criteria = "Different required acceptance evidence"
    elif change == "owner":
        task.assigned_agent_id = db.query(models.Agent).filter_by(key="research").one().id
    elif change == "scope":
        task.context = {**task.context, "stage_c": {"paths": ["tests/test_packaging.py"]}}
    elif change == "audit":
        approval["audit_id"] = db.query(models.AuditLog).filter(models.AuditLog.action != "improvement.review_approved").first().id
    elif change == "independence":
        approval["reviewer"] = approval["coder"]
    elif change == "legacy_approval":
        approval.pop("contract_hash")
    elif change == "diff":
        worktree = stage_c_worker.jobs_root() / task.key / "worktrees" / task.key
        (worktree / "tests/test_metrics.py").write_text("def test_metric():\n    assert False\n")
    elif change == "malformed_history":
        imp = {**imp, "history": [*imp["history"][:-1], {**imp["history"][-1], "evidence": ["malformed"]}]}
    elif change == "pause":
        control.set_agents_paused(db, True, actor="founder", reason="pause after independent review")
    elif change == "cancel":
        task.status = enums.TaskStatus.CANCELLED
    elif change == "authorization_missing":
        control.revoke_pilot_authorization(db, actor="operator:test")
    elif change == "authorization_consumed":
        assert control.consume_pilot_authorization(db, task.key, SHA_A, db.query(models.AgentRun).one().id) is None
    elif change == "authorization_expired":
        control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID,
                                now=datetime.now(timezone.utc) - timedelta(hours=1))
    elif change == "authorization_sha":
        control.authorize_pilot(db, task.key, SHA_B, founder=FOUNDER_ID)
    elif change == "write_disabled":
        monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", False)
    task.context = {**task.context, "improvement": {**imp, "approval": approval}}
    db.commit()
    resumed = {n: Down(n) for n in ps}
    if change == "metered":
        monkeypatch.setattr(resumed["claude"], "health_check", lambda: (providers.Health.METERED_BLOCKED, "metered"))

    outcome = worker.run_once(db, resumed, SPECS)

    assert outcome["model_calls"] == 0 and coded == ["claude"]
    assert len(ps["codex"].packets) == 1 and not (task.artifacts or {}).get("pr")
    assert task.context["improvement"]["stage"] != "PR_OPEN"


def test_a_finished_diff_waits_for_the_reviewer_without_being_recoded(monkeypatch, tmp_path):
    """The writer never reviews itself. If Codex is out after Claude has coded, the exact diff
    waits at INDEPENDENT_REVIEW (no retry spent, no second coder run) until a reviewer is back."""
    pipeline(monkeypatch, tmp_path)
    seen = record_coders(monkeypatch)
    db = _db()
    task = write_task(db)
    out = worker.run_once(db, {"claude": Reviewer("claude"), "codex": Down("codex")}, SPECS)
    assert seen == ["claude"] and out["model_calls"] == 1
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0
    assert task.context["improvement"]["stage"] == "INDEPENDENT_REVIEW"
    assert "approval" not in task.context["improvement"] and "pr" not in (task.artifacts or {})
    # Still no reviewer: nothing is claimed, nothing runs.
    runs = db.query(models.AgentRun).count()
    out = worker.run_once(db, {"claude": Reviewer("claude"), "codex": Down("codex")}, SPECS)
    assert out["blocked"] == "stage_c_reviewer_unavailable" and db.query(models.AgentRun).count() == runs
    assert task.status == enums.TaskStatus.READY
    def no_coder(**kw):
        raise AssertionError("a completed coder must not run again")
    monkeypatch.setattr(stage_c_runner, "launcher_coder", no_coder)
    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    approval = task.context["improvement"]["approval"]
    assert out["verdict"] == "PR_OPEN", out
    assert (approval["coder"], approval["reviewer"]) == ("claude", "codex")


def test_codex_alone_never_codes(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    def no_coder(**kw):
        raise AssertionError("Codex cannot code in the hardened container")
    monkeypatch.setattr(stage_c_runner, "launcher_coder", no_coder)
    db = _db()
    task = write_task(db)
    out = worker.run_once(db, {"claude": Down("claude"), "codex": Reviewer("codex")}, SPECS)
    assert out["blocked"] == "stage_c_coder_unavailable" and out["model_calls"] == 0
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0


def test_coder_quota_cools_down_without_spending_task_retry(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    def launcher_coder(**callbacks):
        def quota(*a, **k):
            callbacks["before_enqueue"]()
            callbacks["after_start"](True)
            raise RuntimeError("subscription usage limit reached")
        return quota
    monkeypatch.setattr(stage_c_runner, "launcher_coder", launcher_coder)
    db = _db()
    task = write_task(db)
    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    run = db.get(models.AgentRun, out["run_id"])
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0
    assert worker._capacity_only(run) and worker._cooldowns(db)[run.provider]["health"] == "QUOTA_EXHAUSTED"
    assert out["model_calls"] == 1


def test_start_ack_persistence_failure_blocks_without_spending_retry(monkeypatch, tmp_path):
    real_launcher_coder = stage_c_runner.launcher_coder
    pipeline(monkeypatch, tmp_path)
    def launcher_coder(**callbacks):
        after_start = callbacks["after_start"]
        def fail_after_start(started):
            after_start(started)
            raise RuntimeError("start acknowledgement commit failed")
        callbacks["after_start"] = fail_after_start
        def host_start(_):
            done = tmp_path / "jobs" / task.key / "done"
            done.mkdir(parents=True, exist_ok=True)
            (done / "started.json").touch()
            (done / "result.json").write_text('{"exit": 0, "timed_out": false}')
        callbacks["sleep"] = host_start
        return real_launcher_coder(**callbacks)
    monkeypatch.setattr(stage_c_runner, "launcher_coder", launcher_coder)
    db = _db()
    task = write_task(db)

    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)

    assert out["verdict"] == "LEASE_LOST" and out["model_calls"] == 1
    assert task.status == enums.TaskStatus.BLOCKED and task.retry_count == 0
    assert (tmp_path / "jobs" / task.key / "done" / "result.json").is_file()


def test_review_quota_resumes_the_exact_diff_without_recoding(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    original = stage_c_runner.provider_reviewer
    limited = [True]
    def reviewer(provider):
        call = original(provider)
        def review(packet):
            if limited[0]:
                limited[0] = False
                raise RuntimeError("subscription usage limit reached")
            return call(packet)
        return review
    monkeypatch.setattr(stage_c_runner, "provider_reviewer", reviewer)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    out = worker.run_once(db, ps, SPECS)
    assert out["verdict"] == "REVIEW_FAILED" and task.retry_count == 0
    tested = task.context["improvement"]["history"][-1]["evidence"]["fingerprint"]
    row = db.get(models.ControlState, "worker")
    row.value = {**row.value, "cooldown": {}}
    db.commit()
    def no_coder(**kw):
        raise AssertionError("a completed coder must not run again")
    monkeypatch.setattr(stage_c_runner, "launcher_coder", no_coder)
    out = worker.run_once(db, ps, SPECS)
    assert out["verdict"] == "PR_OPEN", out
    assert task.context["improvement"]["approval"]["fingerprint"] == tested
    assert out["model_calls"] == 1


def test_lease_contention_does_not_call_a_model(monkeypatch, tmp_path):
    from app import stage_c
    from datetime import timedelta
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    stage_c.acquire(db, "seerxo/seerxo-os", stage_c_runner.HOLDER, timedelta(minutes=30))
    db.commit()
    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    assert out["verdict"] == "LEASE_BUSY" and out["model_calls"] == 0
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0


def test_runtime_capability_is_reported_separately_from_enablement():
    db = _db()
    worker.run_once(db, {}, SPECS)
    autonomy = worker.worker_state(db)["autonomy"]
    assert autonomy["code_write_implemented"] is True
    assert autonomy["stage"] == "B" and autonomy["auto_pr"] is False


def test_pausing_during_review_prevents_publishing(monkeypatch, tmp_path):
    from app import control
    remote = pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    original = stage_c_runner.review
    def pause(*args, **kwargs):
        out = original(*args, **kwargs)
        control.set_agents_paused(db, True, actor="founder", reason="stop")
        return out
    monkeypatch.setattr(stage_c_runner, "review", pause)
    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    assert out["verdict"] == "WAITING_BEFORE_PUBLISH"
    assert subprocess.run(["git", "--git-dir", str(remote), "show-ref"], capture_output=True).returncode != 0


def test_host_provenance_is_sha_only_and_stale_or_mismatched_evidence_waits(monkeypatch):
    from app import watchdog
    from datetime import timedelta
    db = _db()
    monkeypatch.setenv("COMPANY_OS_GIT_SHA", "a" * 40)
    watchdog.record_host_metrics(db, {"cpu_used_pct": 1, "runtime": {"api_sha": "bad-value", "worker_sha": "a" * 40}})
    row = db.get(models.ControlState, "host_metrics")
    assert row.value["runtime"]["api_sha"] is None
    assert stage_c_worker.live_shas(db) is None
    watchdog.record_host_metrics(db, {"cpu_used_pct": 1, "runtime": {"api_sha": "b" * 40, "worker_sha": "a" * 40}})
    assert stage_c_worker.live_shas(db) == ("b" * 40, "a" * 40)
    row.value = {**row.value, "at": (worker._now() - timedelta(minutes=6)).isoformat()}
    db.commit()
    assert stage_c_worker.live_shas(db) is None


def runtime_report(db, sha, *, ready=True, age=timedelta(minutes=1), writer="watchdog"):
    """What the host watchdog stores each tick from the live preflight (app/watchdog.py)."""
    at = (datetime.now(timezone.utc) - age).isoformat()
    row = db.get(models.ControlState, "stage-c-runtime-readiness")
    value = {"ready": ready, "checked_at": at, "source_sha": sha, "failed": [] if ready else ["launcher"]}
    if row is None:
        db.add(models.ControlState(key="stage-c-runtime-readiness", value=value, updated_by=writer))
    else:
        row.value, row.updated_by = value, writer
    db.commit()


def fully_accepted(monkeypatch, tmp_path, sha="a" * 40):
    monkeypatch.setenv("STAGE_C_JOBS_ROOT", str(tmp_path))
    monkeypatch.setenv("COMPANY_OS_GIT_SHA", sha)
    monkeypatch.setenv("GH_TOKEN", "fixture-credential")
    monkeypatch.setattr(stage_c_worker.shutil, "which", lambda name: "/usr/bin/" + name)
    (tmp_path / ".control/sez-company.git").mkdir(parents=True)
    db = _db()
    db.add(models.ControlState(key="stage-c-host-acceptance", updated_by="founder", value={
        "source_sha": sha, "checks": dict.fromkeys(stage_c_worker.ACCEPTANCE_CHECKS, True)}))
    db.commit()
    return db


def test_code_writes_fail_closed_unless_the_live_runtime_report_is_fresh_ready_and_ours(monkeypatch, tmp_path):
    """Acceptance is a past attestation. A launcher, proxy or image that broke after it must stop
    the next claim, not just raise an alert (the watchdog stores what it sees; ready() enforces it)."""
    db = fully_accepted(monkeypatch, tmp_path)
    assert stage_c_worker.ready(db) == "stage_c_runtime_not_ready"          # no report at all
    runtime_report(db, "a" * 40)
    assert stage_c_worker.ready(db) is None
    for kwargs in ({"ready": False}, {"age": timedelta(minutes=16)}, {"age": timedelta(minutes=-5)},
                   {"writer": "company-worker"}):
        runtime_report(db, "a" * 40, **kwargs)
        assert stage_c_worker.ready(db) == "stage_c_runtime_not_ready", kwargs
    runtime_report(db, "b" * 40)                                             # another deployment's report
    assert stage_c_worker.ready(db) == "stage_c_runtime_not_ready"
    runtime_report(db, "a" * 40)
    row = db.get(models.ControlState, "stage-c-runtime-readiness")
    row.value = {**row.value, "ready": "true"}                               # not literally true
    db.commit()
    assert stage_c_worker.ready(db) == "stage_c_runtime_not_ready"


def test_lost_runtime_readiness_skips_the_write_task_without_spend_and_stage_b_still_runs(monkeypatch, tmp_path):
    db = fully_accepted(monkeypatch, tmp_path)
    monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", True)
    write = write_task(db, priority=enums.Priority.P1)
    stage_b = _task(db, key="TASK-0200", priority=enums.Priority.P3, assigned_agent_id=write.assigned_agent_id,
                    context={"autonomous": True}, project_id=write.project_id)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    out = worker.run_once(db, ps, SPECS)                        # no runtime report: write task is skipped
    assert out["model_calls"] == 1 and "blocked" not in out and out["provider"] == "codex", out
    assert write.status == enums.TaskStatus.READY and write.retry_count == 0
    assert not write.context.get("improvement")
    stage_b.status = enums.TaskStatus.DONE; db.commit()
    out = worker.run_once(db, ps, SPECS)                        # only the write task left: nothing runs
    assert out["work"] is None and out["model_calls"] == 0
    assert out["skipped"] == [{"task": write.key, "reason": "stage_c_runtime_not_ready"}]
    assert write.status == enums.TaskStatus.READY and write.retry_count == 0


def test_acceptance_requires_founder_all_checks_and_this_deployed_source(monkeypatch, tmp_path):
    monkeypatch.setenv("STAGE_C_JOBS_ROOT", str(tmp_path))
    monkeypatch.setenv("COMPANY_OS_GIT_SHA", "a" * 40)
    monkeypatch.setenv("GH_TOKEN", "fixture-credential")
    monkeypatch.setattr(stage_c_worker.shutil, "which", lambda name: "/usr/bin/" + name)
    (tmp_path / ".control/sez-company.git").mkdir(parents=True)
    db = _db()
    checks = {"image_build": True, "egress": True, "launcher": True, "permissions": True,
              "direct_egress_blocked": True, "github_blocked": True, "random_hosts_blocked": True,
              "provider_hosts": True, "claude_edit": True, "offline_checks": True, "credential_isolation": True}
    # Codex is the reviewer only: its edit sandbox is not an acceptance requirement.
    row = models.ControlState(key="stage-c-host-acceptance", updated_by="founder",
                              value={"source_sha": "a" * 40, "checks": checks})
    db.add(row); db.commit()
    assert stage_c_worker.ready(db) == "stage_c_host_not_accepted"
    row.value = {"source_sha": "a" * 40, "checks": {**checks, "codex_review_probe": True}}
    db.commit()
    assert stage_c_worker.ready(db) == "stage_c_runtime_not_ready"  # accepted, but nothing watched it live
    runtime_report(db, "a" * 40)
    assert stage_c_worker.ready(db) is None
    row.updated_by = "company-worker"; db.commit()
    assert stage_c_worker.ready(db) == "stage_c_host_not_accepted"
    row.updated_by = "founder"; db.commit()
    monkeypatch.setenv("COMPANY_OS_GIT_SHA", "b" * 40)
    assert stage_c_worker.ready(db) == "stage_c_host_not_accepted"


# --------------------------------------------------------------------------- interrupted attempts

BASE = "b" * 40
FINGERPRINT = "f" * 64
STAGE_EVIDENCE = {"DETECTED": {"repository": "seerxo/seerxo-os"}, "PLANNED": {"paths": ["tests/test_metrics.py"]},
                  "IMPLEMENTING": {"base": BASE}, "TESTING": {"fingerprint": FINGERPRINT, "coder": "claude"},
                  "INDEPENDENT_REVIEW": {"fingerprint": FINGERPRINT, "checks": "ok"}}


def interrupted(db, stage, *, jobs=None):
    """A Stage C write task whose worker died mid-attempt: IN_PROGRESS, a STARTED run older than the
    stale window, the improvement lifecycle at `stage`, and the repository lease still held. Claimed by the
    worker as in production, so the run holds the attempt (worker.holds_attempt)."""
    task = write_task(db)
    assert worker.claim(db, task)
    from app import stage_c
    path = [s for s in stage_c.STAGES[:stage_c.STAGES.index(stage) + 1]] if stage else []
    for s in path:
        stage_c.advance(db, task, s, "stage-c-runner", STAGE_EVIDENCE[s])
    run = models.AgentRun(task_id=task.id, agent_id=task.assigned_agent_id,
                          provider="claude", status=enums.AgentRunStatus.STARTED,
                          tool_calls={"stage_c": True},
                          started_at=worker._now() - timedelta(hours=1, minutes=1))
    db.add(run)
    db.add(models.ControlState(key=stage_c.lease_key(stage_stage_c_repo()), updated_by=f"stage-c-runner:{task.key}",
                               value={"token": 7, "holder": f"stage-c-runner:{task.key}",
                                      "expires_at": (worker._now() + timedelta(minutes=30)).isoformat()}))
    db.commit()
    return task, run


def stage_stage_c_repo():
    return stage_c_worker.REPOSITORY


@pytest.mark.parametrize("stage", ["DETECTED", "PLANNED", "IMPLEMENTING", "TESTING"])
def test_interrupted_attempt_before_review_is_abandoned_not_recoded(stage, tmp_path):
    from app import stage_c
    db = _db()
    task, run = interrupted(db, stage)
    leftover = tmp_path / "jobs/TASK-0100/checks"; leftover.mkdir(parents=True)
    history = list(task.context["improvement"]["history"])
    runs = db.query(models.AgentRun).count()
    assert worker.recover_stale(db) == [task.key]
    db.refresh(task); db.refresh(run)
    imp = task.context["improvement"]
    assert imp["stage"] == "ABANDONED"
    assert imp["history"][:len(history)] == history                       # forensic history survives
    ev = imp["history"][-1]["evidence"]
    assert ev["reason"] == "worker_restart_before_stage_c_completion"
    assert ev["run_id"] == run.id and ev["last_stage"] == stage
    assert ev.get("base") == (BASE if stage in ("IMPLEMENTING", "TESTING") else None)
    assert ev.get("fingerprint") == (FINGERPRINT if stage == "TESTING" else None)
    assert task.status == enums.TaskStatus.CANCELLED and task.retry_count == 0   # not a coding failure
    assert run.status == enums.AgentRunStatus.FAILED and run.ended_at is not None
    assert "not a coding or test failure" in run.error
    assert run.tool_calls["stage_c"] is True and run.tool_calls["interrupted"] is True
    assert db.query(models.AgentRun).count() == runs                      # no new run, so no model call
    assert leftover.exists()                                              # artifacts are never deleted
    assert db.get(models.ControlState, stage_c.lease_key(stage_c_worker.REPOSITORY)).value == {"token": 7}
    assert worker.recover_stale(db) == []                                 # idempotent
    assert not (task.artifacts or {}).get("pr")                           # nothing published


def test_interrupted_before_any_lifecycle_requeues_without_a_retry():
    db = _db()
    task, run = interrupted(db, None)
    assert worker.recover_stale(db) == [task.key]
    db.refresh(task)
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0
    assert not (task.context or {}).get("improvement")


def test_interrupted_during_independent_review_resumes_only_the_exact_tested_diff():
    db = _db()
    task, run = interrupted(db, "INDEPENDENT_REVIEW")
    assert worker.recover_stale(db) == [task.key]
    db.refresh(task)
    imp = task.context["improvement"]
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0
    assert imp["stage"] == "INDEPENDENT_REVIEW"                           # review() re-checks the fingerprint
    assert imp["history"][-1]["evidence"]["fingerprint"] == FINGERPRINT   # or answers TAMPERED
    assert not (task.artifacts or {}).get("pr")


def test_a_published_attempt_is_never_abandoned_by_worker_loss():
    from app import stage_c
    db = _db()
    task, run = interrupted(db, "INDEPENDENT_REVIEW")
    stage_c.advance(db, task, "PR_OPEN", "stage-c-runner", {"pr": "https://github.com/x/y/pull/1"}); db.commit()
    assert worker.recover_stale(db) == [task.key]
    db.refresh(task)
    assert task.context["improvement"]["stage"] == "PR_OPEN"
    assert task.status == enums.TaskStatus.REVIEW and task.retry_count == 0


PR_URL = "https://github.com/seerxo/seerxo-os/pull/7"


def interrupted_repair(db, stage):
    """A published task whose CI failed, sent back to IMPLEMENTING for a repair, whose worker then died at
    `stage` (IMPLEMENTING: coder may or may not have run; TESTING: the repair's coder finished)."""
    from app import stage_c
    task, run = interrupted(db, "INDEPENDENT_REVIEW")
    stage_c.advance(db, task, "PR_OPEN", "stage-c-runner", {"pr": PR_URL, "commit": "c" * 40})
    stage_c.advance(db, task, "CI", "stage-c-ci", {"checks": "failure"})
    stage_c.advance(db, task, "IMPLEMENTING", "stage-c-ci", {"repair": 1, "base": BASE})
    if stage == "TESTING":
        stage_c.advance(db, task, "TESTING", "stage-c-runner", {"fingerprint": "e" * 64, "coder": "claude"})
    task.artifacts = {"pr": PR_URL, "commit": "c" * 40}
    db.commit()
    return task, run


@pytest.mark.parametrize("stage", ["IMPLEMENTING", "TESTING"])
def test_an_interrupted_ci_repair_keeps_its_pr_and_is_never_cancelled_or_recoded(stage):
    from app import stage_c
    db = _db()
    task, run = interrupted_repair(db, stage)
    history = list(task.context["improvement"]["history"])
    runs = db.query(models.AgentRun).count()
    assert worker.recover_stale(db) == [task.key]
    db.refresh(task); db.refresh(run)
    imp = task.context["improvement"]
    # Before the fix: ABANDONED + CANCELLED, and reconcile never looked at the open PR again.
    assert task.status == enums.TaskStatus.BLOCKED and task.status != enums.TaskStatus.CANCELLED
    assert task.error.startswith(stage_c_worker.REPAIR_INTERRUPTED)
    assert PR_URL in task.error
    assert imp["stage"] == stage and imp["history"] == history             # nothing rewritten, no ABANDONED
    assert task.artifacts["pr"] == PR_URL and task.retry_count == 0
    assert run.status == enums.AgentRunStatus.FAILED and run.tool_calls["interrupted"] is True
    assert db.query(models.AgentRun).count() == runs                      # no new run, so no model call
    assert db.get(models.ControlState, stage_c.lease_key(stage_c_worker.REPOSITORY)).value == {"token": 7}
    assert worker.recover_stale(db) == []                                 # idempotent


def test_reconcile_keeps_tracking_the_pr_of_an_interrupted_repair(monkeypatch):
    db = _db()
    task, _ = interrupted_repair(db, "IMPLEMENTING")
    worker.recover_stale(db)
    reads = []

    def closed(*a, **k):
        reads.append(a)
        return {"state": "closed", "merged": False}
    monkeypatch.setattr(stage_c_ci, "gh_facts", closed)
    stage_c_worker.reconcile(db)
    db.refresh(task)
    assert len(reads) == 1 and reads[0][1] == 7                           # this PR, looked up by number
    assert task.status == enums.TaskStatus.BLOCKED and "closed" in (task.error or "").lower()


def test_an_interrupted_repair_records_a_merge_outside_the_gate_and_stops_polling(monkeypatch):
    db = _db()
    task, _ = interrupted_repair(db, "IMPLEMENTING")
    worker.recover_stale(db)
    reads = []

    def merged(*a, **k):
        reads.append(1)
        return _merged_outside_gate("c" * 40)
    monkeypatch.setattr(stage_c_ci, "gh_facts", merged)
    stage_c_worker.reconcile(db)
    db.refresh(task)
    assert task.status == enums.TaskStatus.BLOCKED and "merged" in task.error
    assert not task.error.startswith(stage_c_worker.REPAIR_INTERRUPTED)
    stage_c_worker.reconcile(db)
    assert len(reads) == 1                                                # recorded once, not polled forever


def test_a_closed_pr_of_an_interrupted_repair_is_recorded_once(monkeypatch):
    db = _db()
    task, _ = interrupted_repair(db, "TESTING")
    worker.recover_stale(db)
    reads = []
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: reads.append(1) or {"state": "closed"})
    stage_c_worker.reconcile(db)
    stage_c_worker.reconcile(db)
    db.refresh(task)
    assert len(reads) == 1 and task.error.startswith("PR closed")


def test_an_interrupted_repair_never_reaches_a_coder_by_itself(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task, _ = interrupted_repair(db, "TESTING")
    worker.recover_stale(db)
    _coder_spy(monkeypatch)
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: {"state": "open", "merged": False})
    worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    db.refresh(task)
    assert CODER_CALLS == [] and task.status == enums.TaskStatus.BLOCKED


# --------------------------------------------------------------------------- attended pilot authorization

SHA_A, SHA_B = "a" * 40, "b" * 40


class NoModel(providers.Provider):
    """Healthy on paper, but any model call fails the test: validation must never reach a provider."""
    def __init__(self, name):
        super().__init__(name=name, binary=name, environ={"PATH": ""})

    def health_check(self):
        return providers.Health.AVAILABLE, None

    def _run(self, prompt, schema, **kw):
        raise AssertionError("a model was called")


def armed(monkeypatch, tmp_path):
    """Flag on, accepted, runtime ready, one admissible write task; the authorization is the only gap."""
    db = fully_accepted(monkeypatch, tmp_path, SHA_A)
    monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", True)
    monkeypatch.setattr(stage_c_runner, "_git", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no network")))
    runtime_report(db, SHA_A)
    return db, write_task(db), {n: NoModel(n) for n in ("claude", "codex")}


def authorization(db):
    return db.get(models.ControlState, "stage-c-pilot-authorization")


def tick(db, ps):
    out = worker.run_once(db, ps, SPECS)
    return out, {s["reason"] for s in out.get("skipped", [])}


def assert_untouched(db, task, out):
    assert out["model_calls"] == 0 and db.query(models.AgentRun).count() == 0
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0


def test_no_authorization_means_no_claim_and_no_model(monkeypatch, tmp_path):
    db, task, ps = armed(monkeypatch, tmp_path)
    out, skipped = tick(db, ps)
    assert skipped == {"stage_c_authorization_missing"}
    assert_untouched(db, task, out)


def test_the_global_flag_still_blocks_a_valid_authorization(monkeypatch, tmp_path):
    db, task, ps = armed(monkeypatch, tmp_path)
    control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    monkeypatch.setattr(worker, "ENABLE_AUTONOMOUS_CODE_WRITE", False)
    out, skipped = tick(db, ps)
    assert skipped == {"code_write_disabled"} and authorization(db).value["consumed_at"] is None
    assert_untouched(db, task, out)


def test_an_authorization_is_for_one_task_one_sha_and_a_short_time(monkeypatch, tmp_path):
    db, task, ps = armed(monkeypatch, tmp_path)
    other = _task(db, key="TASK-0200", status=enums.TaskStatus.BACKLOG)  # exists, but not runnable
    for label, issue in {
            "wrong task": lambda: control.authorize_pilot(db, other.key, SHA_A, founder=FOUNDER_ID),
            "wrong sha": lambda: control.authorize_pilot(db, task.key, SHA_B, founder=FOUNDER_ID),
            "expired": lambda: control.authorize_pilot(db, task.key, SHA_A, ttl=timedelta(minutes=5),
                                                       now=datetime.now(timezone.utc) - timedelta(hours=1), founder=FOUNDER_ID)}.items():
        issue()
        out, skipped = tick(db, ps)
        assert skipped & {"stage_c_authorization_invalid", "stage_c_authorization_expired"}, label
        assert authorization(db).value["consumed_at"] is None, label
        assert_untouched(db, task, out)


@pytest.mark.parametrize("value", [None, [], "yes", {}, {"task_key": "TASK-0100"},
                                   {"task_key": "TASK-0100", "repository": "seerxo/seerxo-os",
                                    "source_sha": SHA_A, "issued_by": "founder", "issued_at": "yesterday",
                                    "expires_at": "tomorrow", "consumed_at": None}])
def test_malformed_or_unknown_authorization_is_denied(monkeypatch, tmp_path, value):
    db, task, ps = armed(monkeypatch, tmp_path)
    db.add(models.ControlState(key="stage-c-pilot-authorization", value=value, updated_by="founder")); db.commit()
    out, skipped = tick(db, ps)
    assert skipped == {"stage_c_authorization_invalid"}
    assert_untouched(db, task, out)


def test_an_expiry_beyond_the_bound_is_refused_at_issue_and_at_use(monkeypatch, tmp_path):
    db, task, ps = armed(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        control.authorize_pilot(db, task.key, SHA_A, ttl=timedelta(hours=2), founder=FOUNDER_ID)
    value = control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    row = authorization(db)
    row.value = {**value, "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()}; db.commit()
    assert tick(db, ps)[1] == {"stage_c_authorization_invalid"}


def test_a_valid_authorization_is_spent_by_the_attempt_and_cannot_run_twice(monkeypatch, tmp_path):
    db, task, ps = armed(monkeypatch, tmp_path)
    control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    out = worker.run_once(db, ps, SPECS)
    assert out["task"] == task.key and out["run_id"]                      # claimed through normal admission
    value = authorization(db).value
    assert value["consumed_at"] and value["consumed_by_run_id"] == out["run_id"]
    task.status = enums.TaskStatus.READY; task.retry_count = 0; task.error = None; db.commit()
    runs = db.query(models.AgentRun).count()
    out2, skipped = tick(db, ps)                                          # same task, same SHA, same authorization
    assert skipped == {"stage_c_authorization_consumed"} and out2["model_calls"] == 0
    assert db.query(models.AgentRun).count() == runs
    assert control.consume_pilot_authorization(db, task.key, SHA_A, 999) == "stage_c_authorization_consumed"


def test_an_unfinished_job_directory_refuses_the_attempt_before_spending_the_authorization(monkeypatch, tmp_path):
    """Independent review P2-b of #388's fix: a retry set READY before the job directory was discarded must not burn
    the one-task authorization and end in RUNTIME_ERROR. It is refused first, BLOCKED, and retryable after."""
    db, task, ps = armed(monkeypatch, tmp_path)
    control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    job = stage_c_worker.jobs_root() / task.key
    job.mkdir(parents=True)
    (job / "request.json").write_text("{}")                               # an unfinished launcher request
    out = worker.run_once(db, ps, SPECS)
    assert out["verdict"] == "JOB_UNFINISHED" and out["model_calls"] == 0
    assert authorization(db).value["consumed_at"] is None                  # not spent
    db.refresh(task)
    assert task.status == enums.TaskStatus.BLOCKED and task.error.startswith(stage_c_worker.JOB_UNFINISHED)
    assert db.query(models.AgentRun).count() == 0


def test_a_restart_or_interrupted_recovery_never_recreates_the_authorization(monkeypatch, tmp_path):
    db, task, ps = armed(monkeypatch, tmp_path)
    control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    out = worker.run_once(db, ps, SPECS)
    task.status = enums.TaskStatus.IN_PROGRESS
    run = db.get(models.AgentRun, out["run_id"])
    run.status, run.ended_at = enums.AgentRunStatus.STARTED, None
    run.started_at = worker._now() - timedelta(hours=2); db.commit()
    consumed = dict(authorization(db).value)
    db.expire_all()                                                       # a fresh worker process sees the row only
    assert worker.recover_stale(db) == [task.key]
    assert authorization(db).value == consumed
    task.status = enums.TaskStatus.READY; db.commit()
    assert tick(db, ps)[1] == {"stage_c_authorization_consumed"}


def test_pause_readiness_and_host_acceptance_stay_absolute_stops(monkeypatch, tmp_path):
    db, task, ps = armed(monkeypatch, tmp_path)
    control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    control.set_agents_paused(db, True, actor="founder", reason="test")
    out = worker.run_once(db, ps, SPECS)
    assert out["paused"] is True and authorization(db).value["consumed_at"] is None
    control.set_agents_paused(db, False, actor="founder", reason="test")
    runtime_report(db, SHA_A, ready=False)
    out, skipped = tick(db, ps)
    assert skipped == {"stage_c_runtime_not_ready"} and authorization(db).value["consumed_at"] is None
    runtime_report(db, SHA_A)
    db.delete(db.get(models.ControlState, "stage-c-host-acceptance")); db.commit()
    out = worker.run_once(db, ps, SPECS)
    assert out.get("blocked") == "stage_c_host_not_accepted" and authorization(db).value["consumed_at"] is None
    assert_untouched(db, task, out)


def test_revoking_removes_the_authorization_and_is_audited(monkeypatch, tmp_path):
    db, task, ps = armed(monkeypatch, tmp_path)
    control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    assert control.revoke_pilot_authorization(db, actor="operator:local") is True and control.revoke_pilot_authorization(db, actor="operator:local") is False
    assert tick(db, ps)[1] == {"stage_c_authorization_missing"}
    actions = [a.action for a in db.query(models.AuditLog).filter_by(entity_key="stage-c-pilot-authorization")]
    assert actions == ["stage-c.authorization.issue", "stage-c.authorization.revoke"]


# --------------------------------------------------------------------------- claim-to-run crash window

def test_a_worker_dying_between_claim_and_run_leaves_no_permanent_orphan_stage_b():
    db = _db()
    task = _task(db)
    task.started_at = worker._now() - timedelta(days=3); db.commit()     # a retry keeps its first started_at
    assert worker.claim(db, task) is True                                # committed IN_PROGRESS ...
    # ... and the process dies before execute() creates the AgentRun
    assert worker.recover_stale(db) == []                                # not before the stale window
    task.updated_at = worker._now() - worker.STALE_AFTER - timedelta(minutes=1); db.commit()
    assert worker.recover_stale(db) == [task.key]
    db.refresh(task)
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0   # no attempt ever began
    assert db.query(models.AgentRun).count() == 0
    assert worker.recover_stale(db) == []


def test_that_window_for_stage_c_neither_spends_nor_restores_the_authorization(monkeypatch, tmp_path):
    db, task, ps = armed(monkeypatch, tmp_path)
    control.authorize_pilot(db, task.key, SHA_A, founder=FOUNDER_ID)
    before = dict(authorization(db).value)
    def die(*a, **k):
        raise KeyboardInterrupt("process died after claim")
    monkeypatch.setattr(stage_c_worker, "execute", die)
    with pytest.raises(KeyboardInterrupt):
        worker.run_once(db, ps, SPECS)
    db.expire_all()
    assert task.status == enums.TaskStatus.IN_PROGRESS and db.query(models.AgentRun).count() == 0
    task.updated_at = worker._now() - worker.STALE_AFTER - timedelta(minutes=1); db.commit()
    assert worker.recover_stale(db) == [task.key]
    db.refresh(task)
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0
    assert authorization(db).value == before                              # nothing consumed, nothing reissued
    assert not (task.context or {}).get("improvement")


def _stale(db, task):
    task.updated_at = worker._now() - worker.STALE_AFTER - timedelta(minutes=1)
    db.commit()


def test_an_autonomous_task_the_founder_moved_in_progress_is_never_recovered():
    """autonomous=true says what the task MAY do, not who moved it. The founder's move goes through the
    real task-status endpoint and leaves no worker claim, so no stale cutoff may requeue it."""
    from app import main, schemas
    db = _db()
    task = _task(db)
    main.update_task_status(task.key, schemas.TaskStatusUpdate(
        status=enums.TaskStatus.IN_PROGRESS, actor="founder", reason="working on it by hand"), db)
    _stale(db, task)
    assert worker.recover_stale(db) == []
    db.refresh(task)
    assert task.status == enums.TaskStatus.IN_PROGRESS


def test_a_founder_move_after_the_worker_claim_also_takes_ownership_away():
    from app import main, schemas
    db = _db()
    task = _task(db)
    assert worker.claim(db, task) is True
    main.update_task_status(task.key, schemas.TaskStatusUpdate(
        status=enums.TaskStatus.IN_PROGRESS, actor="founder", reason="took it over"), db)
    _stale(db, task)
    assert worker.recover_stale(db) == []
    assert task.status == enums.TaskStatus.IN_PROGRESS


def test_worker_claimed_task_with_only_historical_runs_is_recovered_and_a_current_run_is_not():
    db = _db()
    task = _task(db)
    db.add(models.AgentRun(task_id=task.id, provider="claude", status=enums.AgentRunStatus.FAILED,
                           ended_at=worker._now()))                       # an earlier attempt, long finished
    db.commit()
    assert worker.claim(db, task) is True
    _stale(db, task)
    assert worker.recover_stale(db) == [task.key]                         # history is not the current claim's run
    db.refresh(task)
    assert task.status == enums.TaskStatus.READY and task.retry_count == 0
    assert worker.recover_stale(db) == []                                 # the claim marker is spent
    assert worker.claim(db, task) is True                                 # a fresh claim, a fresh marker
    db.add(models.AgentRun(task_id=task.id, provider="claude", status=enums.AgentRunStatus.FAILED,
                           ended_at=worker._now()))                       # this claim's own run began and ended
    _stale(db, task)
    assert worker.recover_stale(db) == []                                 # the run machinery owns that, not us


def test_claim_recovery_leaves_unclaimed_in_progress_work_and_running_work_alone():
    db = _db()
    human = _task(db, key="TASK-0300", status=enums.TaskStatus.IN_PROGRESS)     # never claimed by the worker
    running = _task(db, key="TASK-0301")
    assert worker.claim(db, running) is True
    db.add(models.AgentRun(task_id=running.id, provider="claude", status=enums.AgentRunStatus.STARTED,
                           started_at=worker._now()))
    _stale(db, human); _stale(db, running)
    assert worker.recover_stale(db) == []
    assert human.status == running.status == enums.TaskStatus.IN_PROGRESS


def test_a_founder_change_landing_between_recovery_read_and_write_is_not_overwritten():
    """recover_stale reads 'latest audit == my claim', then writes READY. A person acting in between must
    win: the write is one conditional statement, not a read followed by an unconditional update."""
    from app import main, schemas
    for founder_move in (enums.TaskStatus.IN_PROGRESS, enums.TaskStatus.BLOCKED):   # a no-op re-assert, and a real move
        db = _db()
        task = _task(db)
        assert worker.claim(db, task) is True
        _stale(db, task)                                                   # stale, so only the founder's row stops it
        main.update_task_status(task.key, schemas.TaskStatusUpdate(
            status=founder_move, actor="founder", reason="acted after the recovery pass read the task"), db)
        assert worker._requeue_unstarted_claim(db, task.id) is False
        db.refresh(task)
        assert task.status == founder_move and task.retry_count == 0
        assert not db.query(models.AuditLog).filter_by(task_id=task.id, action="task.claim.recovered").count()


def test_two_recovery_passes_requeue_a_claim_once():
    db = _db()
    task = _task(db)
    assert worker.claim(db, task) is True
    _stale(db, task)
    assert worker._requeue_unstarted_claim(db, task.id) is True
    assert worker._requeue_unstarted_claim(db, task.id) is False
    assert db.query(models.AuditLog).filter_by(task_id=task.id, action="task.claim.recovered").count() == 1


CODER_CALLS = []


def _coder_spy(monkeypatch):
    CODER_CALLS.clear()

    def spy(db, task, spec, usable):
        CODER_CALLS.append(task.key)
        raise AssertionError("the coder must not run for this task")
    monkeypatch.setattr(stage_c_worker, "execute", spy)


def _published_then_repair(db, task, ps, monkeypatch):
    """Publish a PR, then leave the task READY at IMPLEMENTING exactly as a failed CI does."""
    worker.run_once(db, ps, SPECS)
    commit = task.artifacts["commit"]
    failed = {"state": "open", "merged": False, "head_sha": commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
              "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}
    assert ingest_ci(db, task, failed)["outcome"] == "REPAIR"
    task.status = enums.TaskStatus.READY
    db.commit()
    assert task.context["improvement"]["stage"] == "IMPLEMENTING" and task.status == enums.TaskStatus.READY
    return commit


def _merged_outside_gate(commit):
    return {"state": "closed", "merged": True, "merged_by": "semihbugrasezer", "merge_commit": "c" * 40,
            "base_ref": "main", "draft": False, "head_sha": commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
            "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}


def test_a_ready_implementing_task_whose_pr_was_merged_never_reaches_the_coder(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    commit = _published_then_repair(db, task, ps, monkeypatch)
    history = list(task.context["improvement"]["history"])
    _coder_spy(monkeypatch)
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: _merged_outside_gate(commit))
    out = worker.run_once(db, ps, SPECS)
    assert CODER_CALLS == []
    assert out.get("work") is None or out.get("blocked")  # refused before any model call
    assert task.status == enums.TaskStatus.BLOCKED
    assert task.context["improvement"]["stage"] == "IMPLEMENTING"
    assert task.context["improvement"]["history"] == history  # evidence kept, nothing rewritten
    assert "merged at IMPLEMENTING" in task.error


def test_a_failed_github_lookup_fails_closed_and_runs_no_coder(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    _published_then_repair(db, task, ps, monkeypatch)
    _coder_spy(monkeypatch)

    def unreachable(*a, **k):
        raise RuntimeError("GitHub read failed")
    monkeypatch.setattr(stage_c_ci, "gh_facts", unreachable)
    out = worker.run_once(db, ps, SPECS)
    assert CODER_CALLS == []
    assert out.get("blocked") == "pr_state_unverified"
    assert task.status == enums.TaskStatus.READY  # not blocked by a transient error: it simply waits


def test_a_merge_that_lands_between_reconcile_and_the_claim_is_still_refused(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    commit = _published_then_repair(db, task, ps, monkeypatch)
    _coder_spy(monkeypatch)
    calls = []

    def racing(*a, **k):
        calls.append(1)
        # reconcile() sees an open PR; the merge lands before the worker's pre-claim check.
        return _merged_outside_gate(commit) if len(calls) > 1 else {
            "state": "open", "merged": False, "head_sha": commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
            "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}
    monkeypatch.setattr(stage_c_ci, "gh_facts", racing)
    worker.run_once(db, ps, SPECS)
    assert len(calls) >= 2 and CODER_CALLS == []
    assert task.status == enums.TaskStatus.BLOCKED


def test_an_open_pr_during_repair_is_not_blocked_by_the_guard(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    commit = _published_then_repair(db, task, ps, monkeypatch)
    open_facts = {"state": "open", "merged": False, "head_sha": commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
                  "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: open_facts)
    assert stage_c_worker.published_guard(db, task) is None
    assert task.status == enums.TaskStatus.READY


def test_published_guard_supplies_repository_when_recording_an_eligible_founder_merge(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    commit = task.artifacts["commit"]
    facts = {"state": "open", "merged": False, "head_sha": commit,
             "head_ref": "task/TASK-0100", "head_repo": "seerxo/seerxo-os",
             "base_ref": "main", "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
             "checks": [{"name": "ci", "status": "completed", "conclusion": "success"}]}
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: facts)

    assert ingest_ci(db, task, facts, repository=stage_c_worker.REPOSITORY,
                             founder_login="semihbugrasezer", tracked_branch="main")["outcome"] == "READY_TO_MERGE"
    assert task.context["improvement"]["stage"] == "READY_TO_MERGE"

    facts.update(state="closed", merged=True, merged_by="semihbugrasezer", merge_commit="c" * 40)
    assert stage_c_worker.published_guard(db, task) == "merged:MERGED"
    assert task.context["improvement"]["stage"] == "MERGED"


def _launcher_must_not_run(monkeypatch):
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise AssertionError("the coder launcher must not run")
    monkeypatch.setattr(stage_c_runner, "launcher_coder", boom)
    return calls


def test_a_founder_status_change_during_the_github_lookup_is_never_overwritten(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    commit = _published_then_repair(db, task, ps, monkeypatch)

    def founder_cancels_then_merged(*a, **k):
        # The founder changes the task while the lookup is in flight; GitHub reports a merge.
        db.execute(models.Task.__table__.update().where(models.Task.id == task.id)
                   .values(status=enums.TaskStatus.CANCELLED))
        db.commit()
        return _merged_outside_gate(commit)
    monkeypatch.setattr(stage_c_ci, "gh_facts", founder_cancels_then_merged)
    assert stage_c_worker.published_guard(db, task) == "task_changed"
    db.expire_all()
    assert db.get(models.Task, task.id).status == enums.TaskStatus.CANCELLED


def test_a_merge_landing_after_the_claim_still_stops_before_the_coder(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    commit = _published_then_repair(db, task, ps, monkeypatch)
    open_facts = {"state": "open", "merged": False, "head_sha": commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
                  "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}
    reads = []

    def lookups(*a, **k):
        reads.append(1)
        # reconcile() and the pre-claim check see the PR open; the merge lands before the coder.
        return dict(open_facts) if len(reads) <= 2 else _merged_outside_gate(commit)
    monkeypatch.setattr(stage_c_ci, "gh_facts", lookups)
    launched = _launcher_must_not_run(monkeypatch)
    out = worker.run_once(db, ps, SPECS)
    assert launched == [] and len(reads) >= 3
    assert out.get("task_status") in (None, "READY") or task.status == enums.TaskStatus.BLOCKED
    assert task.status == enums.TaskStatus.BLOCKED and task.context["improvement"]["stage"] == "IMPLEMENTING"
    refused = db.query(models.AgentRun).filter_by(task_id=task.id).order_by(models.AgentRun.id.desc()).first()
    assert refused.status == enums.AgentRunStatus.FAILED and refused.tool_calls.get("capacity_failure") is True


def _founder_takes_over(db, task, actor="founder:access:founder@example.invalid"):
    """A founder assignment: the owner changes, the status and stage do not."""
    ceo = db.query(models.Agent).filter_by(key="ceo").one()
    task.assigned_agent_id = ceo.id
    db.add(models.AuditLog(actor=actor, action="task.assign", entity_type="task",
                           entity_key=task.key, task_id=task.id, after={"assigned_agent_id": ceo.id}))
    db.commit()
    return ceo.id


def test_a_same_status_founder_takeover_during_the_lookup_is_never_overwritten(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    commit = _published_then_repair(db, task, ps, monkeypatch)
    task.status = enums.TaskStatus.IN_PROGRESS  # the worker holds the claim
    db.commit()
    open_facts = {"state": "open", "merged": False, "head_sha": commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
                  "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}

    def founder_reasserts_in_progress(*a, **k):
        return dict(open_facts) if not _founder_takes_over(db, task) else dict(open_facts)
    monkeypatch.setattr(stage_c_ci, "gh_facts", founder_reasserts_in_progress)
    assert stage_c_worker.published_guard(db, task) == "task_changed"
    db.expire_all()
    fresh = db.get(models.Task, task.id)
    assert fresh.status == enums.TaskStatus.IN_PROGRESS
    assert fresh.assigned_agent_id == db.query(models.Agent).filter_by(key="ceo").one().id


def test_a_takeover_between_the_claim_and_the_coder_never_reaches_the_coder(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    commit = _published_then_repair(db, task, ps, monkeypatch)
    open_facts = {"state": "open", "merged": False, "head_sha": commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
                  "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}
    reads = []

    def lookups(*a, **k):
        reads.append(1)
        if len(reads) == 3:  # reconcile, pre-claim, then the coder boundary
            _founder_takes_over(db, task)
        return dict(open_facts)
    monkeypatch.setattr(stage_c_ci, "gh_facts", lookups)
    launched = _launcher_must_not_run(monkeypatch)
    out = worker.run_once(db, ps, SPECS)
    assert launched == [] and len(reads) >= 3
    attempt = db.query(models.AgentRun).filter_by(task_id=task.id).order_by(models.AgentRun.id.desc()).first()
    assert attempt.tool_calls.get("outcome") == "PUBLISHED_PR_REFUSED" and attempt.error == "task_changed"
    assert task.assigned_agent_id == db.query(models.Agent).filter_by(key="ceo").one().id


@pytest.mark.parametrize("role", [("FAIL", "the token can write seerxo/seerxo-os (push)"),
                                  ("UNKNOWN", "GitHub refused or failed the role read")])
def test_write_granted_after_admission_stops_the_push(monkeypatch, tmp_path, role):
    # Break caught (#192): admission trusts a preflight up to 15 min old; Write granted to the agent account in
    # that window let the attempt push upstream-capable credentials. The role is re-read at the push itself.
    hooks = {}
    remote = pipeline(monkeypatch, tmp_path, hooks)
    monkeypatch.setattr(stage_c_worker, "publication_role", lambda: role)
    db = _db()
    task = write_task(db)
    worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    pushed = subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "--verify", "-q", f"refs/heads/task/{task.key}"],
                            capture_output=True, text=True)
    assert pushed.returncode != 0                                                # nothing reached the remote
    attempt = db.query(models.AgentRun).filter_by(task_id=task.id).order_by(models.AgentRun.id.desc()).first()
    assert attempt.tool_calls.get("outcome") == "PUBLISHED_PR_REFUSED"
    assert attempt.error == "upstream_role_not_read_only"
    # A security event, not capacity: no silent READY loop; the founder sees why on the Desk.
    assert task.status == enums.TaskStatus.BLOCKED and task.error.startswith("upstream_role_not_read_only")


def test_takeover_after_the_pr_guard_but_before_publication_prevents_the_push(monkeypatch, tmp_path):
    hooks = {}
    remote = pipeline(monkeypatch, tmp_path, hooks)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    old_commit = _published_then_repair(db, task, ps, monkeypatch)
    hooks["before_publish"] = _founder_takes_over
    open_facts = {"state": "open", "merged": False, "head_sha": old_commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
                  "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: open_facts)

    worker.run_once(db, ps, SPECS)

    remote_head = subprocess.run(["git", "--git-dir", str(remote), "rev-parse", f"refs/heads/task/{task.key}"],
                                 check=True, capture_output=True, text=True).stdout.strip()
    assert remote_head == old_commit
    assert task.assigned_agent_id == db.query(models.Agent).filter_by(key="ceo").one().id
    attempt = db.query(models.AgentRun).filter_by(task_id=task.id).order_by(models.AgentRun.id.desc()).first()
    assert attempt.tool_calls.get("outcome") == "PUBLISHED_PR_REFUSED" and attempt.error == "task_changed"


def _recovered_and_claimed_again(db, task):
    """Worker-only ABA: another worker's stale recovery failed this run and requeued the task, then a new claim
    took it. Status, agent and owner version (worker actors only) are back to what the attempt started with."""
    run = db.query(models.AgentRun).filter_by(task_id=task.id).order_by(models.AgentRun.id.desc()).first()
    run.status = enums.AgentRunStatus.FAILED
    task.status = enums.TaskStatus.READY
    audit.record(db, actor="company-worker", action="task.claim.recovered", entity_type="task", entity_key=task.key,
                 before={"status": "IN_PROGRESS"}, after={"status": "READY"}, task_id=task.id)
    db.commit()
    assert worker.claim(db, task)


def test_aba_a_new_claim_before_publication_prevents_the_push(monkeypatch, tmp_path):
    hooks = {}
    remote = pipeline(monkeypatch, tmp_path, hooks)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    old_commit = _published_then_repair(db, task, ps, monkeypatch)
    hooks["before_publish"] = _recovered_and_claimed_again
    open_facts = {"state": "open", "merged": False, "head_sha": old_commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
                  "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: open_facts)

    worker.run_once(db, ps, SPECS)

    remote_head = subprocess.run(["git", "--git-dir", str(remote), "rev-parse", f"refs/heads/task/{task.key}"],
                                 check=True, capture_output=True, text=True).stdout.strip()
    assert remote_head == old_commit                  # the old attempt never pushed over the new claim
    attempt = db.query(models.AgentRun).filter_by(task_id=task.id).order_by(models.AgentRun.id.desc()).first()
    assert attempt.tool_calls.get("outcome") == "PUBLISHED_PR_REFUSED" and attempt.error == "task_changed"
    db.refresh(task)
    assert task.status == enums.TaskStatus.IN_PROGRESS  # the new claim is left exactly as it is
    assert worker.holds_attempt(db, worker._locked_task(db, task.id))


def test_a_cancel_after_the_capacity_cooldown_commit_is_never_overwritten(monkeypatch, tmp_path):
    """_cool commits (heartbeat). It must run before the ownership check, never between the check and the write:
    a founder cancel that was waiting on the row lock and lands at that commit stays CANCELLED."""
    from sqlalchemy import update
    pipeline(monkeypatch, tmp_path)

    def launcher_coder(**callbacks):
        def quota(*a, **k):
            callbacks["before_enqueue"]()
            callbacks["after_start"](True)
            raise RuntimeError("subscription usage limit reached")
        return quota
    monkeypatch.setattr(stage_c_runner, "launcher_coder", launcher_coder)
    db = _db()
    task = write_task(db)
    real_cool = worker._cool

    def cool_then_founder_cancels(db_, attempts):
        real_cool(db_, attempts)
        db_.execute(update(models.Task).where(models.Task.id == task.id)
                    .values(status=enums.TaskStatus.CANCELLED).execution_options(synchronize_session=False))
        audit.record(db_, actor="founder:access:founder@example.invalid", action="task.status", entity_type="task",
                     entity_key=task.key, before={"status": "IN_PROGRESS"}, after={"status": "CANCELLED"}, task_id=task.id)
        db_.commit()
    monkeypatch.setattr(worker, "_cool", cool_then_founder_cancels)
    worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    db.expire_all()
    assert db.get(models.Task, task.id).status == enums.TaskStatus.CANCELLED
    run = db.query(models.AgentRun).filter_by(task_id=task.id).one()
    assert run.status == enums.AgentRunStatus.FAILED and run.error.startswith("superseded:")
    assert db.query(models.AuditLog).filter_by(task_id=task.id, action="task.autonomous-run.superseded").count() == 1


def test_stale_recovery_never_touches_a_stage_c_task_claimed_again():
    db = _db()
    task, run = interrupted(db, "IMPLEMENTING")
    run.status = enums.AgentRunStatus.STARTED
    task.status = enums.TaskStatus.READY  # requeued and claimed again while the old run is still STARTED
    audit.record(db, actor="company-worker", action="task.claim.recovered", entity_type="task", entity_key=task.key,
                 before={"status": "IN_PROGRESS"}, after={"status": "READY"}, task_id=task.id)
    db.commit()
    assert worker.claim(db, task)
    stage = task.context["improvement"]["stage"]
    worker.recover_stale(db)
    db.refresh(task); db.refresh(run)
    assert run.status == enums.AgentRunStatus.FAILED and run.tool_calls.get("interrupted") is True
    assert task.status == enums.TaskStatus.IN_PROGRESS and task.context["improvement"]["stage"] == stage  # not abandoned


def test_takeover_before_the_coder_request_is_enqueued_runs_no_coder(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    launched = []

    def launcher_coder(**kw):
        def call(directory, job):
            _founder_takes_over(db, task)
            kw["before_enqueue"]()
            launched.append(job.task_key)
            kw["after_start"](True)
        return call

    monkeypatch.setattr(stage_c_runner, "launcher_coder", launcher_coder)
    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)

    assert launched == [] and out["model_calls"] == 0
    assert task.assigned_agent_id == db.query(models.Agent).filter_by(key="ceo").one().id
    # D1/D2: a genuine reassignment while the attempt held the task BLOCKs it for re-authorization (it used to
    # stay IN_PROGRESS with no live run, which nothing ever recovered).
    _assert_owner_block(db, task)
    assert not (tmp_path / "jobs" / task.key).exists()


def test_a_merge_during_review_stops_the_publication(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    worker.run_once(db, ps, SPECS)
    commit = task.artifacts["commit"]
    failed = {"state": "open", "merged": False, "head_sha": commit, "checks_complete": True, "statuses": dict(GREEN_STATUSES), "statuses_complete": True, "status_problems": [],
              "checks": [{"name": "ci", "status": "completed", "conclusion": "failure"}]}
    merged = _merged_outside_gate(commit)
    reads = []

    def lookups(*a, **k):
        reads.append(1)
        return dict(merged) if len(reads) >= 4 else dict(failed)  # the merge lands before the publish
    monkeypatch.setattr(stage_c_ci, "gh_facts", lookups)
    published = []
    monkeypatch.setattr(stage_c_runner, "publish", lambda *a, **k: published.append(1) or {"outcome": "PR_OPEN"})
    worker.run_once(db, ps, SPECS)
    assert published == [], "a merged PR must never receive a repair publication"
    assert task.status == enums.TaskStatus.BLOCKED


def test_a_takeover_at_the_real_enqueue_fence_refuses_the_launch_and_removes_the_attempt(monkeypatch, tmp_path):
    real_launcher_coder = stage_c_runner.launcher_coder
    pipeline(monkeypatch, tmp_path)
    monkeypatch.setattr(stage_c_runner, "launcher_coder", real_launcher_coder)
    db = _db()
    task = write_task(db)
    real_owner_state = stage_c_worker.owner_state
    taken_over = []
    request_path = tmp_path / "jobs" / task.key / "request.json"

    def founder_takes_over_at_enqueue(session, task_id, lock=False):
        if lock and not taken_over:
            assert not request_path.exists(), "the request must not be runnable at the takeover fence"
            _founder_takes_over(session, task)
            taken_over.append(True)
        return real_owner_state(session, task_id, lock=lock)

    monkeypatch.setattr(stage_c_worker, "owner_state", founder_takes_over_at_enqueue)
    ps = {n: Reviewer(n) for n in ("claude", "codex")}
    result = worker.run_once(db, ps, SPECS)
    db.expire_all()
    fresh = db.get(models.Task, task.id)
    attempt = db.query(models.AgentRun).filter_by(task_id=task.id).order_by(models.AgentRun.id.desc()).first()
    assert taken_over and result["model_calls"] == 0
    assert attempt.tool_calls.get("outcome") == "PUBLISHED_PR_REFUSED" and attempt.error == "task_changed"
    assert fresh.assigned_agent_id == db.query(models.Agent).filter_by(key="ceo").one().id
    assert not request_path.exists() and not request_path.parent.exists()


@pytest.mark.parametrize("error", ["RUNTIME_ERROR", "PUSH_FAILED",
                                   "PR_FAILED: read-only verification exhausted; founder must inspect the existing branch/PR"])
def test_any_blocked_repair_of_a_published_pr_keeps_its_pr_tracked(monkeypatch, error):
    # Review finding: resuming without discarding the job dir turned REPAIR_INTERRUPTED into RUNTIME_ERROR and
    # reconcile stopped looking at the PR again. Any BLOCKED pre-merge repair of a published PR is tracked.
    db = _db()
    task, _ = interrupted_repair(db, "IMPLEMENTING")
    worker.recover_stale(db)
    task.error = error
    db.commit()
    reads = []

    def merged(*a, **k):
        reads.append(1)
        return _merged_outside_gate("c" * 40)
    monkeypatch.setattr(stage_c_ci, "gh_facts", merged)
    stage_c_worker.reconcile(db)
    stage_c_worker.reconcile(db)
    db.refresh(task)
    assert reads == [1] and task.error.startswith(stage_c_ci.MERGE_NOT_RECORDED)   # recorded once, then quiet


def test_a_pr_failed_repair_has_one_owner_publication_recovery(monkeypatch):
    # An exact PR_FAILED belongs to _recover_publication (main's publication recovery); blocked_repair must not
    # also guard it, or one reconcile pass reads GitHub twice and a close/merge could overwrite the receipt.
    db = _db()
    task, _ = interrupted_repair(db, "INDEPENDENT_REVIEW")
    worker.recover_stale(db)
    task.error = "PR_FAILED"
    db.commit()
    # A valid receipt (as _publication_run would accept) makes publication recovery the owner.
    monkeypatch.setattr(stage_c_worker, "_publication_run", lambda db, t: object())
    assert not stage_c_worker.blocked_repair(db, task)
    owners = []
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: owners.append("published_guard") or {"state": "open"})
    monkeypatch.setattr(stage_c_worker, "_recover_publication",
                        lambda db, t: owners.append("publication_recovery") or db.commit())
    stage_c_worker.reconcile(db)
    db.refresh(task)
    assert owners == ["publication_recovery"] and task.error == "PR_FAILED"


def test_an_authorization_denial_reports_the_state_actually_persisted(monkeypatch, tmp_path):
    # Codex P2 on #370: a founder cancel lands after the denial's rollback and before the second owns_claim; the
    # guard keeps CANCELLED, so the result must report CANCELLED (the persisted state), never a literal READY.
    from sqlalchemy import update
    pipeline(monkeypatch, tmp_path)
    monkeypatch.setattr(control, "consume_write_authorization", lambda *a, **k: "stage_c_authorization_missing")
    real_owns_claim = worker.owns_claim
    calls = []

    def owns_claim(db_, task_):
        calls.append(1)
        if len(calls) == 2:
            db_.execute(update(models.Task).where(models.Task.id == task_.id)
                        .values(status=enums.TaskStatus.CANCELLED).execution_options(synchronize_session=False))
            audit.record(db_, actor="founder:access:founder@example.invalid", action="task.status",
                         entity_type="task", entity_key=task_.key, task_id=task_.id)
            db_.commit()
        return real_owns_claim(db_, task_)
    monkeypatch.setattr(worker, "owns_claim", owns_claim)
    db = _db()
    task = write_task(db)
    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    db.expire_all()
    persisted = db.get(models.Task, task.id).status
    assert persisted == enums.TaskStatus.CANCELLED and len(calls) == 2
    assert out["task_status"] == persisted.value


def test_repository_guardian_evidence_during_an_attempt_neither_refuses_nor_blocks_it(monkeypatch, tmp_path):
    # repo-guardian evidence rows are automation, not an owner change; a legitimate attempt still publishes.
    pipeline(monkeypatch, tmp_path)
    inner = stage_c_runner.launcher_coder

    def launcher_coder(**callbacks):
        call = inner(**callbacks)
        def evidence(directory, job):
            out = call(directory, job)
            db.add(models.AuditLog(actor="repo-guardian", action="task.guardian_evidence", entity_type="task",
                                   entity_key=task.key, task_id=task.id))
            db.commit()
            return out
        return evidence
    monkeypatch.setattr(stage_c_runner, "launcher_coder", launcher_coder)
    db = _db()
    task = write_task(db)
    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    assert out["verdict"] == "PR_OPEN" and task.status == enums.TaskStatus.REVIEW


def _assert_owner_block(db, task):
    db.expire_all()
    task = db.get(models.Task, task.id)
    assert (task.status, task.error) == (enums.TaskStatus.BLOCKED, worker.OWNER_CHANGED_BLOCK), (task.status, task.error)
    assert db.query(models.Event).filter_by(task_id=task.id, event_type="TASK_BLOCKED").count() == 1
    assert db.query(models.AgentRun).filter_by(task_id=task.id, status=enums.AgentRunStatus.STARTED).count() == 0
    worker.recover_stale(db)
    db.expire_all()
    assert db.get(models.Task, task.id).status == enums.TaskStatus.BLOCKED   # never requeued automatically


def _touch_after_coder(monkeypatch, act):
    inner = stage_c_runner.launcher_coder

    def launcher_coder(**callbacks):
        call = inner(**callbacks)
        def touched(directory, job):
            out = call(directory, job)
            act()
            return out
        return touched
    monkeypatch.setattr(stage_c_runner, "launcher_coder", launcher_coder)


def test_a_reassignment_while_the_coder_runs_blocks_the_task_with_an_event(monkeypatch, tmp_path):
    # D1/D2 Stage C: genuine reassignment after the enqueue fence passed. No review or publication, and the task
    # is BLOCKED under the finishing row lock, not left IN_PROGRESS with a closed run.
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)
    _touch_after_coder(monkeypatch, lambda: _founder_takes_over(db, task))
    published = []
    monkeypatch.setattr(stage_c_runner, "publish", lambda *a, **k: published.append(1) or {"outcome": "PR_OPEN"})
    worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    assert published == []
    _assert_owner_block(db, task)


@pytest.mark.parametrize("status", ["IN_PROGRESS", "CANCELLED"])
def test_a_founder_status_decision_during_a_stage_c_attempt_is_preserved_without_blocking(monkeypatch, tmp_path,
                                                                                            status):
    # D2: a status-only founder touch (or a cancel), even together with a reassignment, is the founder's state.
    pipeline(monkeypatch, tmp_path)
    db = _db()
    task = write_task(db)

    def founder():
        _founder_takes_over(db, task)
        task.status = enums.TaskStatus[status]
        db.add(models.AuditLog(actor="founder:access:founder@example.invalid", action="task.status",
                               entity_type="task", entity_key=task.key, task_id=task.id))
        db.commit()
    _touch_after_coder(monkeypatch, founder)
    worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    db.expire_all()
    fresh = db.get(models.Task, task.id)
    assert fresh.status == enums.TaskStatus[status]
    assert db.query(models.Event).filter_by(task_id=task.id, event_type="TASK_BLOCKED").count() == 0


def test_a_pr_failed_repair_without_a_valid_receipt_still_has_its_pr_tracked(monkeypatch):
    # Review V2 P2-2: an exact PR_FAILED whose receipt _publication_run cannot validate (here: none at all) is not
    # recovered by _recover_publication, so blocked_repair must keep guarding its PR or a merge is never recorded.
    db = _db()
    task, _ = interrupted_repair(db, "INDEPENDENT_REVIEW")
    worker.recover_stale(db)
    task.error = "PR_FAILED"
    db.commit()
    assert stage_c_worker._publication_run(db, task) is None
    reads = []
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: reads.append(1) or _merged_outside_gate("c" * 40))
    for _ in range(3):
        stage_c_worker.reconcile(db)
    db.refresh(task)
    assert reads == [1] and task.error.startswith(stage_c_ci.MERGE_NOT_RECORDED)   # recorded once, then quiet


def test_b5_worker_publishes_to_the_configured_fork_and_opens_the_pr_from_it(monkeypatch, tmp_path):
    from app import repo_guardian_github
    remote = pipeline(monkeypatch, tmp_path)
    monkeypatch.setattr(repo_guardian_github, "publish_repository",
                        lambda policy, repository: "seerxo-agent/seerxo-os" if repository == "seerxo/seerxo-os" else repository)
    seen, fixture_publish = [], stage_c_runner.publish

    def publish(db, task, job, diff, worktree, destination, open_pr, *args, **kwargs):
        seen.append((destination, job.repository))
        return fixture_publish(db, task, job, diff, worktree, "https://github.com/seerxo/seerxo-os.git", open_pr, *args, **kwargs)
    monkeypatch.setattr(stage_c_runner, "publish", publish)
    openers = []
    monkeypatch.setattr(stage_c_runner, "gh_pr_opener", lambda *a: openers.append(a) or (lambda *x: "unused"))
    monkeypatch.setattr(stage_c_runner, "gh_pr_lookup", lambda *a: openers.append(a) or (lambda *x: "unused"))
    db = _db()
    task = write_task(db)
    out = worker.run_once(db, {n: Reviewer(n) for n in ("claude", "codex")}, SPECS)
    assert seen == [("https://github.com/seerxo-agent/seerxo-os.git", "seerxo/seerxo-os")], out   # lease stays on upstream
    assert openers == [("seerxo/seerxo-os", "main", "seerxo-agent/seerxo-os")] * 2
    assert task.context["improvement"]["stage"] == "PR_OPEN"


@pytest.mark.parametrize("url", [
    "https://github.com/seerxo/os/pull/81",
    "https://github.com/attacker/seerxo-os/pull/81",
    "https://github.com/seerxo/seerxo-os/pull/81/extra",
    "https://github.com/seerxo/seerxo-os/pull/81?unexpected=1",
    "https://github.com/seerxo/seerxo-os/pull/0",
    "https://github.com/seerxo/seerxo-os/pull/abc",
    "https://github.com/seerxo/seerxo-os/pull/" + "9" * 5000,
])
def test_published_pr_identity_rejects_other_repositories_and_malformed_urls(url):
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    improvement = task.context["improvement"]
    history = [dict(row) for row in improvement["history"]]
    history[-1] = {**history[-1], "evidence": {**history[-1]["evidence"], "pr": url}}
    task.context = {**task.context, "improvement": {**improvement, "history": history}}
    db.commit()
    assert stage_c_worker.published_pr_number(task) is None


def test_old_private_pr_is_not_polled_against_new_public_repo(monkeypatch):
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    improvement = task.context["improvement"]
    history = [dict(row) for row in improvement["history"]]
    history[-1] = {**history[-1], "evidence": {**history[-1]["evidence"],
                                              "pr": "https://github.com/seerxo/os/pull/81"}}
    task.context = {**task.context, "improvement": {**improvement, "history": history}}
    db.commit()
    calls = []
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: calls.append(1))
    result = stage_c_worker.reconcile(db)
    assert calls == []
    assert result == [{"task": task.key, "outcome": "WAITING",
                       "reason": "published_pr_identity_mismatch"}]
    assert task.status == enums.TaskStatus.REVIEW


def test_oversized_pr_number_does_not_abort_reconcile(monkeypatch):
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    improvement = task.context["improvement"]
    history = [dict(row) for row in improvement["history"]]
    history[-1] = {**history[-1], "evidence": {**history[-1]["evidence"],
                                              "pr": "https://github.com/seerxo/seerxo-os/pull/" + "9" * 5000}}
    task.context = {**task.context, "improvement": {**improvement, "history": history}}
    db.commit()
    calls = []
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: calls.append(1))
    result = stage_c_worker.reconcile(db)
    assert calls == []
    assert result == [{"task": task.key, "outcome": "WAITING",
                       "reason": "published_pr_identity_mismatch"}]


def test_shared_pr_number_parser_rejects_oversized_numbers():
    # merge_recovery_block() parses PR_OPEN evidence with it before reconcile()'s identity guard.
    assert stage_c_ci.pr_number("https://github.com/seerxo/seerxo-os/pull/" + "9" * 5000) is None
    assert stage_c_ci.pr_number("https://github.com/seerxo/seerxo-os/pull/81") == 81


def test_malformed_history_does_not_abort_reconcile(monkeypatch):
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    improvement = task.context["improvement"]
    task.context = {**task.context, "improvement": {**improvement, "history": [*improvement["history"], None]}}
    db.commit()
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: pytest.fail("polled GitHub"))
    assert stage_c_worker.reconcile(db) == [{"task": task.key, "outcome": "WAITING",
                                             "reason": "published_pr_identity_mismatch"}]


def test_malformed_history_on_ready_repair_fails_closed_in_prepass(monkeypatch):
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    improvement = task.context["improvement"]
    task.context = {**task.context, "improvement": {**improvement, "history": [*improvement["history"], None]}}
    task.status = enums.TaskStatus.READY
    db.commit()
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: pytest.fail("polled GitHub"))
    assert stage_c_worker.reconcile(db) == [{"task": task.key, "guard": "pr_identity_unverified"}]
    assert stage_c_worker.published_guard(db, task) == "pr_identity_unverified"


def test_legacy_pr_url_does_not_strand_post_merge_verification(monkeypatch):
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    improvement = task.context["improvement"]
    history = [dict(row) for row in improvement["history"]]
    history[-1] = {**history[-1], "evidence": {**history[-1]["evidence"],
                                              "pr": "https://github.com/seerxo/os/pull/81"}}
    task.context = {**task.context, "improvement": {**improvement, "stage": "VERIFYING", "history": history}}
    db.commit()
    steps = []
    monkeypatch.setattr(stage_c_worker.stage_c_verify, "step",
                        lambda db, task, facts: steps.append(task.key) or {"outcome": "WAITING"})
    stage_c_worker.reconcile(db)
    assert steps == [task.key]


def test_current_public_pr_number_is_accepted():
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    assert stage_c_worker.published_pr_number(task) == 81


@pytest.mark.parametrize("bad", [
    {"improvement": ["bad"]},
    {"improvement": {"stage": "PR_OPEN", "history": "bad"}},
    {"improvement": {"stage": "PR_OPEN", "history": [{"stage": "PR_OPEN"}]}},
    {"improvement": {"stage": "PR_OPEN", "history": [{"stage": "PR_OPEN", "evidence": {"commit": "a" * 40}}]}},
])
def test_unreadable_publication_fails_closed(bad):
    # A PR_OPEN row without a PR URL, or an unreadable envelope, is never "unpublished".
    task = SimpleNamespace(context=bad)
    assert stage_c_worker.published_pr(task) == {"pr": None, "unreadable_history": True}
    assert stage_c_worker.published_pr_number(task) is None


def test_malformed_envelope_on_blocked_task_does_not_abort_reconcile():
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    task.status, task.error, task.context = enums.TaskStatus.BLOCKED, "RUNTIME_ERROR", {"improvement": ["bad"]}
    db.commit()
    assert stage_c_worker.blocked_repair(db, task) is False
    stage_c_worker.reconcile(db)  # must not raise


def test_b3_old_repository_pr_is_refused_before_github_lookup(monkeypatch):
    # The founder's B3 probe (artifacts/v1-closeout-2026-10-28/b3_identity_probe.py), kept as a regression.
    db = _db()
    task = _published_task_for_merge_reconciliation(db)
    improvement = task.context["improvement"]
    history = [dict(row) for row in improvement["history"]]
    history[-1] = {**history[-1], "evidence": {**history[-1]["evidence"],
                                              "pr": "https://github.com/seerxo/os/pull/81"}}
    task.context = {**task.context, "improvement": {**improvement, "history": history}}
    db.commit()
    calls = []
    monkeypatch.setattr(stage_c_ci, "gh_facts", lambda *a, **k: calls.append(a) or {"state": "open"})
    assert stage_c_worker.published_guard(db, task) == "pr_identity_unverified" and not calls
    before = task.context
    out = stage_c_ci.ingest(db, task, {"state": "closed", "merged": False, "head_sha": "b" * 40},
                            repository=stage_c_worker.REPOSITORY, tracked_branch="main", required_statuses=())
    assert out["outcome"] == "WAITING" and task.status == enums.TaskStatus.REVIEW and task.context == before
