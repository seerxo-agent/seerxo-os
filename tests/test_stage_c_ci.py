"""CI result -> improvement lifecycle: only the published commit counts; unknown is never success."""
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import audit, enums, models, stage_c, stage_c_ci

SHA = "a" * 40
OTHER = "b" * 40
FINGERPRINT = "f" * 64
REPOSITORY = "o/r"
OK = {"name": "test", "status": "completed", "conclusion": "success"}
BAD = {"name": "test", "status": "completed", "conclusion": "failure"}
PENDING = {"name": "test", "status": "in_progress", "conclusion": None}


def _task():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    db = Session(engine)
    t = models.Task(key="TASK-0070", title="fix", success_criteria="ci green", priority=enums.Priority.P1)
    db.add(t)
    db.flush()
    for s in ("DETECTED", "PLANNED", "IMPLEMENTING"):
        stage_c.advance(db, t, s, "stage-c-runner")
    stage_c.advance(db, t, "TESTING", "stage-c-runner", {"coder": "claude"})
    stage_c.advance(db, t, "INDEPENDENT_REVIEW", "stage-c-runner", {"fingerprint": FINGERPRINT})
    approval = {"fingerprint": FINGERPRINT,
                "review_stage_at": t.context["improvement"]["history"][-1]["at"],
                "reviewer": "codex", "coder": "claude", "findings": []}
    event = audit.record(db, actor="codex", action="improvement.review_approved", entity_type="task",
                         entity_key=t.key, after=approval, task_id=t.id)
    db.flush()
    approval["audit_id"] = event.id
    t.context = {**t.context, "improvement": {**t.context["improvement"], "approval": approval}}
    stage_c.advance(db, t, "PR_OPEN", "stage-c-runner",
                    {"branch": "task/TASK-0070", "commit": SHA, "fingerprint": FINGERPRINT,
                     "pr": "https://github.com/o/r/pull/81"})
    return db, t


REQUIRED = ("ci/circleci: python-tests", "ci/circleci: frontend-tests")
PUBLISHER = {"login": "circleci-app[bot]", "id": 127350680}
GREEN = {context: "success" for context in REQUIRED}


def facts(*checks, head=SHA, complete=True, state="open", merged=False, statuses=None):
    return {"state": state, "merged": merged, "head_sha": head, "head_ref": "task/TASK-0070",
            "head_repo": REPOSITORY, "base_ref": "main", "checks": list(checks), "checks_complete": complete,
            "statuses": dict(GREEN if statuses is None else statuses), "statuses_complete": True,
            "status_problems": []}


def _ci_ingest(db, task, facts, *args, **kwargs):
    return stage_c_ci.ingest(db, task, facts, *args, **{"required_statuses": REQUIRED, **kwargs})


def stage(t):
    return t.context["improvement"]["stage"]


def _ingest(db, task, facts, **kwargs):
    repository = kwargs.pop("repository", REPOSITORY)
    return _ci_ingest(db, task, facts, repository=repository,
                             tracked_branch=kwargs.pop("tracked_branch", "main"), **kwargs)


def test_green_ci_on_the_published_commit_is_ready_to_merge():
    db, t = _task()
    assert _ingest(db, t, facts())["outcome"] == "WAITING"  # nothing observed yet
    assert _ingest(db, t, facts(PENDING, complete=False))["outcome"] == "WAITING"
    assert stage(t) == "CI"
    assert _ingest(db, t, facts(OK))["outcome"] == "READY_TO_MERGE"
    ev = t.context["improvement"]["history"][-1]["evidence"]
    assert ev == {"pr_number": 81, "commit": SHA, "ci_state": "passed", "merge_eligibility": "eligible",
                  "fingerprint": FINGERPRINT, "reviewer": "codex", "coder": "claude",
                  "review_audit_id": t.context["improvement"]["approval"]["audit_id"]}


@pytest.mark.parametrize("case, repository, external_review", [
    ("missing_approval", REPOSITORY, None),
    ("self_review", REPOSITORY, None),
    ("stale_approval", REPOSITORY, None),
    ("published_mismatch", REPOSITORY, None),
    ("forged_audit_id", REPOSITORY, None),
    ("mismatched_audit_record", REPOSITORY, None),
    ("github_commented_is_not_approval", REPOSITORY, [{"state": "COMMENTED", "login": "chatgpt-codex-connector"}]),
])
def test_green_ci_does_not_advance_without_exact_independent_approval(case, repository, external_review):
    db, task = _task()
    improvement = deepcopy(task.context["improvement"])
    if case in ("missing_approval", "github_commented_is_not_approval"):
        improvement.pop("approval")
    elif case == "self_review":
        improvement["approval"]["reviewer"] = "claude"
    elif case == "stale_approval":
        improvement["approval"]["fingerprint"] = "0" * 64
    elif case == "published_mismatch":
        published = next(h for h in reversed(improvement["history"]) if h["stage"] == "PR_OPEN")
        published["evidence"]["fingerprint"] = "0" * 64
    elif case == "forged_audit_id":
        improvement["approval"]["audit_id"] = 9999
    elif case == "mismatched_audit_record":
        event = db.get(models.AuditLog, improvement["approval"]["audit_id"])
        event.after = {**event.after, "fingerprint": "0" * 64}
    task.context = {**task.context, "improvement": improvement}
    facts_with_review = {**facts(OK), "reviews": external_review} if external_review else facts(OK)

    out = _ingest(db, task, facts_with_review, repository=repository)

    assert out["outcome"] == "BLOCKED"
    assert task.status == enums.TaskStatus.BLOCKED
    assert stage(task) == "CI"
    entry = db.scalar(select(models.AuditLog).where(models.AuditLog.action == "improvement.blocked"))
    assert entry.after["merge_eligibility"] == "refused" and entry.after["reasons"]


def test_facts_for_another_repository_change_nothing():
    # B3: green facts asked about another repository's PR never touch the task (was: blocked it).
    db, task = _task()
    before, status = deepcopy(task.context), task.status
    out = _ingest(db, task, facts(OK), repository="other/repo")
    assert out == {"outcome": "WAITING", "reason": "pr_identity_mismatch"}
    assert task.status == status and task.context == before


def test_closed_pr_with_another_head_does_not_abandon():
    db, task = _task()
    before = deepcopy(task.context)
    out = _ingest(db, task, {**facts(OK), "state": "closed", "merged": False, "head_sha": "b" * 40},
                  repository=REPOSITORY)
    assert out == {"outcome": "WAITING", "reason": "closed_pr_head_mismatch"}
    assert task.context == before


def test_green_ci_without_repository_and_target_identity_fails_closed():
    db, task = _task()

    out = _ci_ingest(db, task, facts(OK))

    assert out["outcome"] == "BLOCKED"
    assert any("expected repository" in reason or "target branch" in reason for reason in out["reasons"])


def test_ci_for_a_moved_head_proves_nothing():
    db, t = _task()
    # Break caught: someone pushes to task/<KEY>; their green CI must not mark the reviewed diff ready.
    assert _ingest(db, t, facts(OK, head=OTHER))["outcome"] == "HEAD_MOVED"
    assert stage(t) == "PR_OPEN"


def test_incomplete_or_cancelled_is_not_success():
    db, t = _task()
    assert _ingest(db, t, facts(OK, complete=False))["outcome"] == "WAITING"
    cancelled = {"name": "test", "status": "completed", "conclusion": "cancelled"}
    assert _ingest(db, t, facts(cancelled))["outcome"] == "WAITING"
    assert stage(t) == "CI"


def test_failures_get_bounded_repairs_then_block_for_the_founder():
    db, t = _task()
    assert _ingest(db, t, facts(BAD)) == {"outcome": "REPAIR", "failed": ["test"], "repair": 1}
    assert stage(t) == "IMPLEMENTING"
    assert t.context["improvement"]["history"][-1]["evidence"]["repairs"] == "1/2"
    for _ in range(2):  # the runner repairs, re-reviews and re-publishes; CI fails again
        for s in ("TESTING", "INDEPENDENT_REVIEW", "PR_OPEN"):
            stage_c.advance(db, t, s, "stage-c-runner", {"commit": SHA, "pr": "https://github.com/o/r/pull/81"})
        out = _ingest(db, t, facts(BAD))
    assert out == {"outcome": "BLOCKED", "failed": ["test"], "repairs": 2}
    assert t.status == enums.TaskStatus.BLOCKED and "after 2 repair" in t.error
    assert stage(t) == "CI"  # no further automatic attempt
    db.flush()
    assert db.scalar(select(models.AuditLog).where(models.AuditLog.action == "improvement.blocked")) is not None



def test_a_fork_run_awaiting_workflow_approval_waits_and_is_never_a_repair():
    """B-15 (2026-10-23, PR #432): GitHub reports a fork PR's not-yet-approved run as completed/action_required.
    It never ran: it must wait for the founder's approval, not start a repair or later refuse the merge."""
    db, t = _task()
    awaiting = {"name": "test", "status": "completed", "conclusion": "action_required"}
    assert _ingest(db, t, facts(awaiting)) == {"outcome": "WAITING", "reason": "workflow approval required: test"}
    assert stage(t) == "CI" and t.status != enums.TaskStatus.BLOCKED
    assert stage_c_ci.repairs_used(t) == 0
    assert _ingest(db, t, facts(OK))["outcome"] == "READY_TO_MERGE"   # approved, ran, passed
    db, t = _task()   # a real failure next to an unapproved run is still a failure
    assert _ingest(db, t, facts(awaiting, BAD | {"name": "lint"})) == {"outcome": "REPAIR", "failed": ["lint"], "repair": 1}
    db, t = _task()   # a failed required commit status next to an unapproved run is a failure too
    out = _ingest(db, t, facts(awaiting, statuses={**GREEN, REQUIRED[0]: "failure"}))
    assert out["outcome"] == "REPAIR" and out["failed"] == [REQUIRED[0]]


MERGE = "c" * 40
FOUNDER = "semihbugrasezer"


def merged(head=SHA, by=FOUNDER, draft=False, base_ref="main", merge_commit=MERGE):
    return {**facts(OK, state="closed", merged=True, head=head), "merged_by": by, "draft": draft,
            "base_ref": base_ref, "merge_commit": merge_commit}


def _ready():
    db, t = _task()
    assert _ingest(db, t, facts(OK))["outcome"] == "READY_TO_MERGE"
    return db, t


def test_the_founders_merge_of_the_published_commit_is_recorded_from_github_evidence():
    db, t = _ready()
    assert _ingest(db, t, facts(OK), founder_login=FOUNDER, tracked_branch="main")["outcome"] == "WAITING"
    out = _ingest(db, t, merged(), founder_login=FOUNDER, tracked_branch="main")
    assert out == {"outcome": "MERGED"} and stage(t) == "MERGED"
    h = t.context["improvement"]["history"][-1]
    # The actor says it is the founder's act recorded by automation, never plain "founder".
    assert h["actor"] == "founder (github:semihbugrasezer, via founder_github)"
    assert h["evidence"]["merged_by"] == FOUNDER and h["evidence"]["merge_commit"] == MERGE
    assert h["evidence"]["merge_path"] == "founder_github"
    assert h["evidence"]["merge_authorization_id"] is None


def test_founder_merge_is_not_recorded_if_review_eligibility_was_tampered_after_ci():
    db, task = _ready()
    improvement = deepcopy(task.context["improvement"])
    improvement["approval"]["review_stage_at"] = "old-review"
    task.context = {**task.context, "improvement": improvement}

    out = _ingest(db, task, merged(), founder_login=FOUNDER)

    assert out["outcome"] == "MERGE_UNVERIFIED"
    assert task.status == enums.TaskStatus.BLOCKED and stage(task) == "READY_TO_MERGE"
    assert task.error.startswith(stage_c_ci.MERGE_NOT_RECORDED)
    event = db.scalar(select(models.AuditLog).where(models.AuditLog.action == "improvement.blocked"))
    assert event.after["merge_eligibility"] == "refused"


@pytest.mark.parametrize("name, kw, founder", [
    ("another login", {"by": "someone-else"}, FOUNDER),
    ("a bot", {"by": "github-actions[bot]"}, FOUNDER),
    ("no merged_by", {"by": None}, FOUNDER),
    ("no founder login configured", {}, None),
    ("a draft", {"draft": True}, FOUNDER),
    ("another base branch", {"base_ref": "release"}, FOUNDER),
    ("a different head than published", {"head": OTHER}, FOUNDER),
    ("no merge commit", {"merge_commit": None}, FOUNDER),
])
def test_a_merge_that_is_not_provably_the_founders_is_never_recorded(name, kw, founder):
    db, t = _ready()
    out = _ingest(db, t, merged(**kw), founder_login=founder, tracked_branch="main")
    # Break caught: automation declares a change merged on the founder's behalf without proof.
    assert out["outcome"] == "MERGE_UNVERIFIED", name
    assert stage(t) == "READY_TO_MERGE" and t.status == enums.TaskStatus.BLOCKED and "not recorded" in t.error


def test_a_merge_before_ci_passed_is_not_recorded():
    db, t = _task()
    out = _ingest(db, t, merged(), founder_login=FOUNDER, tracked_branch="main")
    assert out["outcome"] == "MERGE_UNVERIFIED" and "before CI passed" in out["problems"][0]
    assert stage(t) == "PR_OPEN"


def test_ci_completed_before_the_founders_merge_is_recognized_when_observed_late():
    db, task = _task()
    now = datetime.now(timezone.utc)
    evidence = {**merged(), "ci_completed_at": (now + timedelta(seconds=1)).isoformat(),
                "merged_at": (now + timedelta(seconds=5)).isoformat()}

    out = _ingest(db, task, evidence, founder_login=FOUNDER)

    assert out["outcome"] == "MERGED"
    assert stage(task) == "MERGED"
    ready = next(h for h in task.context["improvement"]["history"] if h["stage"] == "READY_TO_MERGE")
    assert ready["evidence"]["ci_observed_after_merge"] is True
    assert ready["evidence"]["ci_completed_at"] == evidence["ci_completed_at"]


def test_system_merge_block_recovers_only_after_complete_premerge_proof_arrives():
    db, task = _task()
    # The first poll sees the founder's merge before GitHub exposes its complete CI timing.
    blocked = _ingest(db, task, merged(), founder_login=FOUNDER)
    assert blocked["outcome"] == "MERGE_UNVERIFIED"
    assert task.status == enums.TaskStatus.BLOCKED and task.error.startswith(stage_c_ci.MERGE_NOT_RECORDED)
    blocked_event = db.scalar(select(models.AuditLog).where(
        models.AuditLog.entity_key == task.key, models.AuditLog.action == "improvement.blocked"))
    assert blocked_event.actor == stage_c_ci.ACTOR

    now = datetime.now(timezone.utc)
    complete = {**merged(), "ci_completed_at": (now + timedelta(seconds=1)).isoformat(),
                "merged_at": (now + timedelta(seconds=5)).isoformat()}
    out = _ingest(db, task, complete, founder_login=FOUNDER)

    assert out == {"outcome": "MERGED"}
    assert stage(task) == "MERGED" and task.status == enums.TaskStatus.REVIEW
    assert task.error is None
    recovery = db.scalar(select(models.AuditLog).where(
        models.AuditLog.entity_key == task.key,
        models.AuditLog.action == "improvement.merge_block_recovered"))
    assert recovery.actor == stage_c_ci.ACTOR
    assert recovery.after["blocked_audit_id"] == blocked_event.id


@pytest.mark.parametrize("case", ["missing_ci_time", "late_ci", "wrong_actor", "different_merge"])
def test_system_merge_block_stays_blocked_without_the_same_premerge_proof(case):
    db, task = _task()
    _ingest(db, task, merged(), founder_login=FOUNDER)
    now = datetime.now(timezone.utc)
    complete = {**merged(), "ci_completed_at": (now + timedelta(seconds=1)).isoformat(),
                "merged_at": (now + timedelta(seconds=5)).isoformat()}
    if case == "missing_ci_time":
        complete.pop("ci_completed_at")
    elif case == "late_ci":
        complete["ci_completed_at"] = (now + timedelta(seconds=6)).isoformat()
    elif case == "wrong_actor":
        complete["merged_by"] = "someone-else"
    elif case == "different_merge":
        complete["merge_commit"] = "d" * 40

    out = _ingest(db, task, complete, founder_login=FOUNDER)

    assert out["outcome"] in {"WAITING", "SKIPPED"}
    assert task.status == enums.TaskStatus.BLOCKED and stage(task) == "PR_OPEN"
    assert db.scalar(select(models.AuditLog).where(
        models.AuditLog.entity_key == task.key,
        models.AuditLog.action == "improvement.merge_block_recovered")) is None


def test_founder_reasserted_block_is_not_reopened_by_later_github_facts():
    db, task = _task()
    _ingest(db, task, merged(), founder_login=FOUNDER)
    system_error = task.error
    audit.record(db, actor="founder", action="task.status", entity_type="task",
                 entity_key=task.key, before={"status": "BLOCKED"},
                 after={"status": "BLOCKED", "error": system_error}, task_id=task.id)
    db.flush()
    now = datetime.now(timezone.utc)
    complete = {**merged(), "ci_completed_at": (now + timedelta(seconds=1)).isoformat(),
                "merged_at": (now + timedelta(seconds=5)).isoformat()}

    out = _ingest(db, task, complete, founder_login=FOUNDER)

    assert out["outcome"] == "SKIPPED"
    assert task.status == enums.TaskStatus.BLOCKED and task.error == system_error
    assert stage(task) == "PR_OPEN"
    assert db.scalar(select(models.AuditLog).where(
        models.AuditLog.entity_key == task.key,
        models.AuditLog.action == "improvement.merge_block_recovered")) is None


def test_system_merge_block_does_not_erase_an_earlier_manual_block():
    db, task = _task()
    audit.record(db, actor="founder", action="task.status", entity_type="task",
                 entity_key=task.key, before={"status": "REVIEW"},
                 after={"status": "BLOCKED"}, task_id=task.id)
    db.flush()
    stage_c_ci._block(db, task, stage_c_ci.MERGE_NOT_RECORDED + "merge facts need review", {
        "merge_problems": ["merged at PR_OPEN, before CI passed"], "stage": "PR_OPEN",
        "merged_by": FOUNDER, "merge_commit": MERGE, "pr_number": 81})

    now = datetime.now(timezone.utc)
    complete = {**merged(), "ci_completed_at": (now + timedelta(seconds=1)).isoformat(),
                "merged_at": (now + timedelta(seconds=5)).isoformat()}
    out = _ingest(db, task, complete, founder_login=FOUNDER)

    assert out["outcome"] == "SKIPPED"
    assert task.status == enums.TaskStatus.BLOCKED and stage(task) == "PR_OPEN"
    assert db.scalar(select(models.AuditLog).where(
        models.AuditLog.entity_key == task.key,
        models.AuditLog.action == "improvement.merge_block_recovered")) is None


def test_ready_to_merge_system_block_recovers_with_timestamped_proof():
    db, task = _ready()
    task.status = enums.TaskStatus.REVIEW
    stage_c_ci._block(db, task, stage_c_ci.MERGE_NOT_RECORDED + "eligibility was not available", {
        "merge_eligibility": "refused", "reasons": ["status evidence unavailable"],
        "merged_by": FOUNDER, "merge_commit": MERGE, "pr_number": 81})
    db.flush()
    now = datetime.now(timezone.utc)
    complete = {**merged(), "ci_completed_at": (now + timedelta(seconds=1)).isoformat(),
                "merged_at": (now + timedelta(seconds=5)).isoformat()}

    out = _ingest(db, task, complete, founder_login=FOUNDER)

    assert out["outcome"] == "MERGED"
    assert task.status == enums.TaskStatus.REVIEW and stage(task) == "MERGED"


@pytest.mark.parametrize("case", ["missing_ci_time", "missing_merge_time", "naive_time", "ci_after_merge",
                                 "pending_ci", "wrong_head", "untrusted_status", "review_after_merge",
                                 "forged_review", "wrong_actor", "blocked", "repair"])
def test_late_observation_never_substitutes_for_premerge_proof(case):
    db, task = _task()
    now = datetime.now(timezone.utc)
    evidence = {**merged(), "ci_completed_at": (now + timedelta(seconds=1)).isoformat(),
                "merged_at": (now + timedelta(seconds=5)).isoformat()}
    if case == "missing_ci_time":
        evidence.pop("ci_completed_at")
    elif case == "missing_merge_time":
        evidence.pop("merged_at")
    elif case == "naive_time":
        evidence["ci_completed_at"] = now.replace(tzinfo=None).isoformat()
    elif case == "ci_after_merge":
        evidence["ci_completed_at"] = (now + timedelta(seconds=6)).isoformat()
    elif case == "pending_ci":
        evidence["statuses"] = {**GREEN, REQUIRED[0]: "pending"}
    elif case == "wrong_head":
        evidence["head_sha"] = OTHER
    elif case == "untrusted_status":
        evidence["status_problems"] = ["untrusted publisher"]
    elif case == "review_after_merge":
        db.get(models.AuditLog, task.context["improvement"]["approval"]["audit_id"]).occurred_at = now + timedelta(seconds=6)
    elif case == "forged_review":
        db.get(models.AuditLog, task.context["improvement"]["approval"]["audit_id"]).actor = "claude"
    elif case == "wrong_actor":
        evidence["merged_by"] = "another-user"
    elif case == "blocked":
        task.status = enums.TaskStatus.BLOCKED
    elif case == "repair":
        stage_c.advance(db, task, "CI", "stage-c-ci")
        stage_c.advance(db, task, "IMPLEMENTING", "stage-c-ci")

    expected = "SKIPPED" if case == "blocked" else "MERGE_UNVERIFIED"
    assert _ingest(db, task, evidence, founder_login=FOUNDER)["outcome"] == expected
    assert task.status == enums.TaskStatus.BLOCKED and stage(task) != "MERGED"


def test_late_observation_can_resume_from_a_previously_observed_ci_stage():
    db, task = _task()
    stage_c.advance(db, task, "CI", "stage-c-ci")
    now = datetime.now(timezone.utc)
    evidence = {**merged(), "ci_completed_at": (now + timedelta(seconds=1)).isoformat(),
                "merged_at": (now + timedelta(seconds=5)).isoformat()}

    assert _ingest(db, task, evidence, founder_login=FOUNDER)["outcome"] == "MERGED"
    assert [h["stage"] for h in task.context["improvement"]["history"]].count("CI") == 1


def test_plain_automation_cannot_claim_the_founders_merge():
    db, t = _ready()
    with pytest.raises(PermissionError):
        stage_c.advance(db, t, "MERGED", "stage-c-ci", {"merged_by": FOUNDER, "merge_commit": MERGE})
    with pytest.raises(PermissionError):  # the founder label without the GitHub evidence
        stage_c.advance(db, t, "MERGED", "founder (github:x, via y)", {})
    with pytest.raises(PermissionError):  # a merge commit but no proof of who merged
        stage_c.advance(db, t, "MERGED", "founder (github:x, via y)", {"merge_commit": MERGE})


def test_closed_pr_is_abandoned():
    db, t = _task()
    assert _ingest(db, t, facts(state="closed"))["outcome"] == "ABANDONED"
    assert _ingest(db, t, facts(OK))["outcome"] == "SKIPPED"


def _status(context, state, id=1, creator=PUBLISHER):
    return {"id": id, "context": context, "state": state, "creator": {"id": creator["id"], "login": creator["login"]}}


@pytest.mark.parametrize("workflows", [set(), {".github/workflows/ci.yml"}])
@pytest.mark.parametrize("timestamps", [True, False])
def test_github_ci_completion_time_comes_from_all_latest_required_checks(workflows, timestamps):
    def run(argv, **kwargs):
        if "/pulls/" in argv[4]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({**merged(), "merged_at": "2026-10-14T20:19:21Z"}))
        if "/statuses" in argv[4]:
            rows = [{**_status(context, "success", id=i + 1),
                     **({"created_at": f"2026-10-14T20:19:1{i}Z"} if timestamps else {})}
                    for i, context in enumerate(REQUIRED)]
            return SimpleNamespace(returncode=0, stdout=json.dumps(rows))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"total_count": 1, "workflow_runs": [
            {"path": ".github/workflows/ci.yml", "name": "test", "head_sha": SHA, "status": "completed",
             "conclusion": "success", "run_number": 1, "run_attempt": 1, "updated_at": "2026-10-14T20:19:17Z",
             "head_repo": REPOSITORY, "run_repo": REPOSITORY, "head_branch": "task/TASK-0070",
             "event": "pull_request"}]}))

    result = stage_c_ci.gh_facts(REPOSITORY, 81, workflows, publisher=PUBLISHER,
                                status_contexts=REQUIRED, run=run)

    assert result["merged_at"] == "2026-10-14T20:19:21Z"
    assert result["ci_completed_at"] == (
        ("2026-10-14T20:19:17+00:00" if workflows else "2026-10-14T20:19:11+00:00") if timestamps else None)


def test_gh_facts_reads_only_the_configured_workflow_and_trusted_statuses_on_the_pr_head():
    calls = []
    def run(argv, **kw):
        calls.append(argv)
        assert argv[:4] == ["gh", "api", "--method", "GET"] and kw["timeout"] == 20
        if "/pulls/" in argv[4]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"state": "open", "merged": False,
                "head_sha": SHA, "head_ref": "task/TASK-0070", "head_repo": "o/r", "draft": False,
                "base_ref": "main", "merged_by": None, "merge_commit": "x"}))
        if "/statuses" in argv[4]:
            assert f"/commits/{SHA}/statuses?per_page=100" in argv[4]
            return SimpleNamespace(returncode=0, stdout=json.dumps([
                _status(REQUIRED[0], "failure", id=1), _status(REQUIRED[0], "success", id=2),
                _status(REQUIRED[1], "success", id=3)]))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"total_count": 3, "workflow_runs": [
            {"path": ".github/workflows/ci.yml", "name": "test", "head_sha": SHA, "status": "completed", "conclusion": "failure", "run_number": 1, "run_attempt": 1, "head_repo": "o/r", "run_repo": "o/r", "head_branch": "task/TASK-0070", "event": "pull_request"},
            {"path": ".github/workflows/ci.yml", "name": "test", "head_sha": SHA, "status": "completed", "conclusion": "success", "run_number": 1, "run_attempt": 2, "head_repo": "o/r", "run_repo": "o/r", "head_branch": "task/TASK-0070", "event": "pull_request"},
            {"path": ".github/workflows/other.yml", "name": "x", "head_sha": SHA, "status": "completed", "conclusion": "failure", "run_number": 9, "run_attempt": 1, "head_repo": "o/r"}]}))
    out = stage_c_ci.gh_facts("o/r", 81, {".github/workflows/ci.yml"}, publisher=PUBLISHER,
                              status_contexts=REQUIRED, run=run)
    assert out == {"state": "open", "merged": False, "head_sha": SHA,
                   "head_ref": "task/TASK-0070", "head_repo": "o/r", "checks_complete": True,
                   "draft": False, "base_ref": "main", "merged_by": None, "merge_commit": None,
                   "merged_at": None, "ci_completed_at": None,
                   "checks": [{"name": "test", "status": "completed", "conclusion": "success"},  # latest attempt wins
                              {"name": REQUIRED[0], "status": "completed", "conclusion": "success"},  # latest status wins
                              {"name": REQUIRED[1], "status": "completed", "conclusion": "success"}],
                   "statuses": GREEN, "statuses_complete": True, "status_problems": []}
    with pytest.raises(RuntimeError) as e:
        stage_c_ci.gh_facts("o/r", 81, {".github/workflows/ci.yml"}, publisher=PUBLISHER,
                            status_contexts=REQUIRED,
                            run=lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="token=secret"))
    assert "secret" not in str(e.value)


def test_github_repository_casing_matches_the_lowercase_identity(monkeypatch):
    """GitHub answers "Seerxo/os"; the gate compares against "seerxo/os" and must not refuse or misclassify."""
    def run(argv, **kw):
        if "/pulls/" in argv[4]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"state": "open", "merged": False,
                "head_sha": SHA, "head_ref": "task/TASK-0070", "head_repo": "Seerxo/os", "draft": False,
                "base_ref": "main", "merged_by": None, "merge_commit": None}))
        return SimpleNamespace(returncode=0, stdout=json.dumps([
            _status(REQUIRED[0], "success", id=1), _status(REQUIRED[1], "success", id=2)]))
    out = stage_c_ci.gh_facts("seerxo/os", 81, set(), publisher=PUBLISHER, status_contexts=REQUIRED, run=run)
    assert out["head_repo"] == "seerxo/os"

    from app import stage_c_runner
    monkeypatch.setattr(stage_c_runner.subprocess, "run", lambda *a, **k: SimpleNamespace(
        stdout="Creating pull request\nhttps://github.com/Seerxo/os/pull/12\n"))
    assert stage_c_runner.gh_pr_opener("seerxo/os", "main")("task/TASK-0070", "t", "b", SHA) == \
        "https://github.com/seerxo/os/pull/12"


def test_gh_facts_status_api_failure_fails_closed(monkeypatch):
    def run(argv, **kw):
        if "/pulls/" in argv[4]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"state": "open", "merged": False,
                "head_sha": SHA, "head_ref": "t", "head_repo": "o/r", "draft": False, "base_ref": "main",
                "merged_by": None, "merge_commit": None}))
        if "/statuses" in argv[4]:
            return SimpleNamespace(returncode=1, stdout="", stderr="rate limited token=secret")
        return SimpleNamespace(returncode=0, stdout=json.dumps({"total_count": 0, "workflow_runs": []}))
    with pytest.raises(RuntimeError, match="GitHub read failed") as e:
        stage_c_ci.gh_facts("o/r", 81, {".github/workflows/ci.yml"}, publisher=PUBLISHER,
                            status_contexts=REQUIRED, run=run)
    assert "secret" not in str(e.value)


def test_circleci_only_pr_observation_does_not_need_actions_permission():
    def run(argv, **kwargs):
        if "/pulls/" in argv[4]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({**facts(), "draft": False,
                "merged_by": None, "merge_commit": None}))
        if "/statuses" in argv[4]:
            return SimpleNamespace(returncode=0, stdout=json.dumps([
                _status(context, "success", id=i + 1) for i, context in enumerate(REQUIRED)]))
        pytest.fail("CircleCI-only observation must never query Actions")

    result = stage_c_ci.gh_facts(REPOSITORY, 81, set(), publisher=PUBLISHER,
                                status_contexts=REQUIRED, run=run)
    assert result["checks_complete"] is True and result["statuses"] == GREEN


@pytest.mark.parametrize("unused_statuses", [None, {"not": "a list"}, [None]])
def test_actions_only_pr_observation_does_not_read_unused_commit_statuses(unused_statuses):
    calls = []
    workflows = {".github/workflows/frontend.yml", ".github/workflows/python-tests.yml"}

    def run(argv, **kwargs):
        path = argv[4]
        calls.append(path)
        if "/pulls/" in path:
            return SimpleNamespace(returncode=0, stdout=json.dumps({**facts(), "draft": False,
                "merged_by": None, "merge_commit": None}))
        if "/statuses" in path:
            return SimpleNamespace(returncode=1 if unused_statuses is None else 0,
                                   stdout=json.dumps(unused_statuses))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"total_count": 2, "workflow_runs": [
            {"path": workflow, "name": workflow, "head_sha": SHA, "status": "completed", "conclusion": "success",
             "run_number": 1, "run_attempt": 1, "updated_at": "2026-10-14T20:19:17Z", "head_repo": REPOSITORY,
             "run_repo": REPOSITORY, "head_branch": "task/TASK-0070", "event": "pull_request"}
            for workflow in workflows]}))

    result = stage_c_ci.gh_facts(REPOSITORY, 81, workflows, publisher=PUBLISHER, status_contexts=(), run=run)
    assert result["checks_complete"] is True and result["ci_completed_at"] == "2026-10-14T20:19:17+00:00"
    assert result["statuses"] == {} and result["status_problems"] == []
    assert not any("/statuses" in path for path in calls)


def test_pr_observation_without_any_required_ci_source_is_refused():
    with pytest.raises(ValueError, match="required"):
        stage_c_ci.gh_facts(REPOSITORY, 81, set(), publisher=PUBLISHER, status_contexts=(),
                            run=lambda *args, **kwargs: pytest.fail("invalid policy must not query GitHub"))


@pytest.mark.parametrize("total", [-1, 0, 2, True, 100])
def test_pr_workflow_pages_must_be_complete_and_bounded(total):
    rows = [{"path": ".github/workflows/ci.yml", "name": "test", "head_sha": SHA, "status": "completed",
             "conclusion": "success", "run_number": 1, "run_attempt": 1, "updated_at": "2026-10-14T20:19:17Z"}]
    if total == 100:
        rows += [{**rows[0], "path": ".github/workflows/other.yml"} for _ in range(99)]
    def run(argv, **kwargs):
        body = {**facts(), "draft": False, "merged_by": None, "merge_commit": None} if "/pulls/" in argv[4] else {
            "total_count": total, "workflow_runs": rows}
        return SimpleNamespace(returncode=0, stdout=json.dumps(body))
    result = stage_c_ci.gh_facts(REPOSITORY, 81, {".github/workflows/ci.yml"},
                                publisher=PUBLISHER, status_contexts=(), run=run)
    assert result["checks_complete"] is False and result["ci_completed_at"] is None


def test_latest_status_is_chosen_by_id_so_a_newer_pending_or_failure_invalidates_success():
    raw = [_status(REQUIRED[0], "success", id=5), _status(REQUIRED[0], "pending", id=9),
           _status(REQUIRED[1], "success", id=2), _status(REQUIRED[1], "failure", id=7)]
    out = stage_c_ci.latest_statuses(raw, REQUIRED, PUBLISHER)
    assert out == {"statuses": {REQUIRED[0]: "pending", REQUIRED[1]: "failure"},
                   "status_ids": {REQUIRED[0]: 9, REQUIRED[1]: 7},
                   "status_problems": [], "statuses_complete": True}
    # Newest-first input (as GitHub lists them) gives the same answer.
    assert stage_c_ci.latest_statuses(list(reversed(raw)), REQUIRED, PUBLISHER) == out


def test_spoofed_status_for_a_required_context_is_a_problem_never_a_success():
    spoof = _status(REQUIRED[0], "success", id=99, creator={"id": 1, "login": "someone"})
    lookalike = _status(REQUIRED[0], "success", id=98, creator={"id": 127350680, "login": "circleci-app"})
    out = stage_c_ci.latest_statuses([_status(REQUIRED[0], "failure", id=1), spoof, lookalike], REQUIRED, PUBLISHER)
    assert out["statuses"] == {REQUIRED[0]: "failure"}  # the spoof did not overwrite the real failure
    assert len(out["status_problems"]) == 2


def test_unrelated_context_from_anyone_is_ignored_and_malformed_or_unknown_is_refused():
    other = _status("ci/other", "failure", id=4, creator={"id": 1, "login": "someone"})
    assert stage_c_ci.latest_statuses([other], REQUIRED, PUBLISHER) == {
        "statuses": {}, "status_ids": {}, "status_problems": [], "statuses_complete": True}
    bad = [{"id": True, "context": REQUIRED[0], "state": "success", "creator": PUBLISHER},  # bool id
           {"id": 3, "context": REQUIRED[0], "state": "weird", "creator": PUBLISHER},  # unknown state
           {"id": 4, "context": REQUIRED[0], "state": "success"},  # no creator
           "not-a-dict"]
    out = stage_c_ci.latest_statuses(bad, REQUIRED, PUBLISHER)
    assert out["statuses"] == {} and len(out["status_problems"]) == 4
    assert stage_c_ci.latest_statuses({"not": "a list"}, REQUIRED, PUBLISHER)["statuses_complete"] is False


def test_a_full_status_page_is_incomplete_so_it_is_refused():
    full = [_status(REQUIRED[0], "success", id=i) for i in range(1, 101)]
    out = stage_c_ci.latest_statuses(full, REQUIRED, PUBLISHER)
    assert out["statuses_complete"] is False and out["statuses"] == {REQUIRED[0]: "success"}


def _repaired_after_failed_ci():
    """A PR whose CI failed: the stage is back at IMPLEMENTING for a bounded repair."""
    db, t = _task()
    assert _ci_ingest(db, t, facts(BAD))["outcome"] == "REPAIR"
    assert stage(t) == "IMPLEMENTING" and t.status != enums.TaskStatus.BLOCKED
    return db, t


def test_a_merge_after_failed_ci_is_blocked_and_never_restarts_coding():
    db, t = _repaired_after_failed_ci()
    history_before = list(t.context["improvement"]["history"])
    out = _ci_ingest(db, t, merged(), founder_login=FOUNDER, tracked_branch="main")
    assert out["outcome"] == "MERGE_UNVERIFIED"
    assert t.status == enums.TaskStatus.BLOCKED and "merged at IMPLEMENTING" in t.error
    # The coding stage is not re-entered and the history is kept as evidence.
    assert stage(t) == "IMPLEMENTING"
    assert t.context["improvement"]["history"] == history_before


def test_the_exceptional_merge_is_blocked_once_and_its_evidence_is_audited():
    db, t = _repaired_after_failed_ci()
    _ci_ingest(db, t, merged(), founder_login=FOUNDER, tracked_branch="main")
    again = _ci_ingest(db, t, merged(), founder_login=FOUNDER, tracked_branch="main")
    assert again["outcome"] == "SKIPPED"
    rows = db.scalars(select(models.AuditLog).where(models.AuditLog.entity_key == t.key,
                                                    models.AuditLog.action == "improvement.blocked")).all()
    assert len(rows) == 1
    assert rows[0].after["merge_commit"] == MERGE and rows[0].after["merged_by"] == FOUNDER
    assert rows[0].after["stage"] == "IMPLEMENTING"


def test_a_valid_founder_merge_after_green_ci_is_still_recorded():
    db, t = _ready()
    out = _ci_ingest(db, t, merged(), repository=REPOSITORY, founder_login=FOUNDER,
                            tracked_branch="main")
    assert out == {"outcome": "MERGED"} and stage(t) == "MERGED"


def test_direct_founder_merge_after_pre_authorization_does_not_claim_script_execution():
    db, t = _ready()
    approval = t.context["improvement"]["approval"]
    authorization = audit.record(db, actor="scripts/merge-pr", action="improvement.merge_authorized",
                                 entity_type="task", entity_key=t.key, task_id=t.id,
                                 after={"repository": REPOSITORY, "pr_number": 81, "head_sha": SHA,
                                        "fingerprint": approval["fingerprint"],
                                        "review_audit_id": approval["audit_id"], "checks": list(OK)})
    db.flush()

    assert _ingest(db, t, merged(), repository=REPOSITORY, founder_login=FOUNDER,
                   tracked_branch="main")["outcome"] == "MERGED"
    evidence = t.context["improvement"]["history"][-1]["evidence"]
    assert evidence["merge_path"] == "founder_github"
    assert evidence["merge_authorization_id"] == authorization.id


def test_a_missing_or_pending_circleci_status_waits_even_when_actions_is_green():
    db, t = _task()
    assert _ci_ingest(db, t, facts(OK, statuses={REQUIRED[0]: "success"}), repository=REPOSITORY,
                      tracked_branch="main") == {"outcome": "WAITING",
                                                 "reason": "commit statuses pending: " + REQUIRED[1]}
    assert stage(t) == "CI"
    assert _ci_ingest(db, t, facts(OK, statuses={REQUIRED[0]: "success", REQUIRED[1]: "pending"}),
                      repository=REPOSITORY, tracked_branch="main")["outcome"] == "WAITING"
    assert stage(t) == "CI" and t.status != enums.TaskStatus.BLOCKED


def test_a_circleci_failure_is_a_bounded_repair_not_a_merge_candidate():
    db, t = _task()
    out = _ci_ingest(db, t, facts(OK, statuses={REQUIRED[0]: "failure", REQUIRED[1]: "success"}),
                     repository=REPOSITORY, tracked_branch="main")
    assert out == {"outcome": "REPAIR", "failed": [REQUIRED[0]], "repair": 1}
    assert stage(t) == "IMPLEMENTING"


def test_a_spoofed_circleci_status_blocks_for_the_founder_and_is_never_ready():
    db, t = _task()
    spoofed = {**facts(OK), "status_problems": [f"{REQUIRED[0]} was posted by an untrusted publisher"]}
    out = _ci_ingest(db, t, spoofed, repository=REPOSITORY, tracked_branch="main")
    assert out["outcome"] == "BLOCKED" and any("untrusted or malformed" in r for r in out["reasons"])
    assert t.status == enums.TaskStatus.BLOCKED and stage(t) == "CI"


def test_a_stale_circleci_success_cannot_stand_in_for_a_newer_failure():
    db, t = _task()
    raw = [_status(REQUIRED[0], "success", id=1), _status(REQUIRED[0], "failure", id=2),
           _status(REQUIRED[1], "success", id=3)]
    parsed = stage_c_ci.latest_statuses(raw, REQUIRED, PUBLISHER)
    out = _ci_ingest(db, t, facts(OK, statuses=parsed["statuses"]), repository=REPOSITORY, tracked_branch="main")
    assert out["outcome"] == "REPAIR" and out["failed"] == [REQUIRED[0]]


def test_a_green_run_from_another_head_repository_proves_nothing():
    # Break caught: gh_facts took any pull_request run on the head SHA; a fork running the same commit
    # (or any other repository's run GitHub lists for it) could supply the green required workflow.
    # scripts/merge-pr already requires head_repository == this repository; Stage C now does too.
    def run(argv, **kwargs):
        if "/pulls/" in argv[4]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"state": "open", "merged": False,
                "head_sha": SHA, "head_ref": "task/TASK-0070", "head_repo": "seerxo/os", "draft": False,
                "base_ref": "main", "merged_by": None, "merge_commit": None}))
        if "/statuses" in argv[4]:
            return SimpleNamespace(returncode=0, stdout="[]")
        base = {"path": ".github/workflows/ci.yml", "name": "test", "head_sha": SHA, "status": "completed",
                "run_attempt": 1, "updated_at": "2026-10-14T20:19:17Z",
                "run_repo": "seerxo/os", "head_branch": "task/TASK-0070", "event": "pull_request"}
        return SimpleNamespace(returncode=0, stdout=json.dumps({"total_count": 2, "workflow_runs": [
            {**base, "conclusion": "failure", "run_number": 1, "head_repo": "Seerxo/os"},
            {**base, "conclusion": "success", "run_number": 9, "head_repo": "attacker/os"}]}))

    out = stage_c_ci.gh_facts("seerxo/os", 81, {".github/workflows/ci.yml"}, publisher=PUBLISHER,
                              status_contexts=(), run=run)
    assert out["checks"] == [{"name": "test", "status": "completed", "conclusion": "failure"}]
    assert out["ci_completed_at"] is None


def test_b5_a_fork_pr_counts_only_the_forks_runs():
    def run(argv, **kwargs):
        if "/pulls/" in argv[4]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"state": "open", "merged": False,
                "head_sha": SHA, "head_ref": "task/TASK-0070", "head_repo": "Seerxo-Agent/os", "draft": False,
                "base_ref": "main", "merged_by": None, "merge_commit": None}))
        if "/statuses" in argv[4]:
            return SimpleNamespace(returncode=0, stdout="[]")
        base = {"path": ".github/workflows/ci.yml", "name": "test", "head_sha": SHA, "status": "completed",
                "run_attempt": 1, "updated_at": "2026-10-14T20:19:17Z",
                "run_repo": "seerxo/os", "head_branch": "task/TASK-0070", "event": "pull_request"}
        # Green runs on the same SHA from upstream and from a third fork prove nothing for a fork PR.
        return SimpleNamespace(returncode=0, stdout=json.dumps({"total_count": 3, "workflow_runs": [
            {**base, "conclusion": "failure", "run_number": 1, "head_repo": "seerxo-agent/os"},
            {**base, "conclusion": "success", "run_number": 9, "head_repo": "Seerxo/os"},
            {**base, "conclusion": "success", "run_number": 10, "head_repo": "attacker/os"}]}))

    out = stage_c_ci.gh_facts("seerxo/os", 81, {".github/workflows/ci.yml"}, publisher=PUBLISHER,
                              status_contexts=(), run=run)
    assert out["head_repo"] == "seerxo-agent/os"
    assert out["checks"] == [{"name": "test", "status": "completed", "conclusion": "failure"}]


@pytest.mark.parametrize("changed", [
    {"head_branch": "task/TASK-9999"},
    {"head_branch": None},
    {"run_repo": "attacker/os"},
    {"run_repo": None},
    {"event": "push"},
    {"event": None},
])
def test_b5_same_sha_green_run_with_wrong_or_missing_identity_is_not_evidence(changed):
    pr = {**facts(), "head_repo": "seerxo-agent/os", "draft": False,
          "merged_by": None, "merge_commit": None}
    row = {"path": ".github/workflows/ci.yml", "name": "test", "head_sha": SHA,
           "status": "completed", "conclusion": "success", "run_number": 1, "run_attempt": 1,
           "updated_at": "2026-10-14T20:19:17Z", "head_repo": "seerxo-agent/os",
           "run_repo": REPOSITORY, "head_branch": pr["head_ref"], "event": "pull_request", **changed}

    def run(argv, **kwargs):
        body = pr if "/pulls/" in argv[4] else {"total_count": 1, "workflow_runs": [row]}
        return SimpleNamespace(returncode=0, stdout=json.dumps(body))

    out = stage_c_ci.gh_facts(REPOSITORY, 81, {row["path"]}, publisher=PUBLISHER,
                              status_contexts=(), run=run)
    assert out["checks"] == []
    assert out["checks_complete"] is False and out["ci_completed_at"] is None


def test_b5_newer_green_run_on_another_branch_does_not_replace_the_tasks_failure():
    pr = {**facts(), "head_repo": "seerxo-agent/os", "draft": False,
          "merged_by": None, "merge_commit": None}
    row = {"path": ".github/workflows/ci.yml", "name": "test", "head_sha": SHA,
           "status": "completed", "conclusion": "failure", "run_number": 1, "run_attempt": 1,
           "updated_at": "2026-10-14T20:19:17Z", "head_repo": "seerxo-agent/os",
           "run_repo": REPOSITORY, "head_branch": pr["head_ref"], "event": "pull_request"}

    def run(argv, **kwargs):
        body = pr if "/pulls/" in argv[4] else {"total_count": 2, "workflow_runs": [
            row, {**row, "head_branch": "task/TASK-9999", "run_number": 9, "conclusion": "success"}]}
        return SimpleNamespace(returncode=0, stdout=json.dumps(body))

    out = stage_c_ci.gh_facts(REPOSITORY, 81, {row["path"]}, publisher=PUBLISHER,
                              status_contexts=(), run=run)
    assert out["checks"] == [{"name": "test", "status": "completed", "conclusion": "failure"}]
    assert out["ci_completed_at"] is None
