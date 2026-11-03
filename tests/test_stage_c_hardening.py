"""Stage C hardening (2026-11-03 review): what a public PR, the task history and a repair prompt may carry, and what
counts as checks having run. Break caught: reviewer findings stored unredacted; a JWT or a JSON "refresh_token" not
masked; task title / success criteria in the public PR or commit; a credential-shaped added line published; a changed
test file that never ran passing on the rest of the suite.
Fake credentials are assembled at runtime so no literal credential shape sits in the repository."""
import json
import subprocess

import pytest

from app import enums, stage_c_runner, worker
from tests.test_stage_c_worker import Reviewer, pipeline, write_task
from tests.test_worker import SPECS, _db

FORK = "seerxo-agent/seerxo-os"   # the repository policy publishes from the B5 fork
PAT = "github_pat_" + "A1b2C3" * 6
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiJ4In0xMjM0" + "." + "s1gnature" + "ABCDEFGH"
REFRESH = '"refresh_token": "' + "r" * 24 + '"'
SENSITIVE = {"title": "INTERNAL customer acme@private.example password=hunter2xyz",
             "success_criteria": f"verify with {PAT}", "objective": f"call the API with {JWT}"}
PRIVATE = ("INTERNAL", "acme@private.example", "hunter2xyz", PAT, JWT, "verify with", "call the API")


def _providers(cls=Reviewer):
    return {n: cls(n) for n in ("claude", "codex")}


def _coder(monkeypatch, text):
    def launcher_coder(**kw):
        def call(directory, job):
            kw["before_enqueue"]()
            kw["after_start"](True)
            (directory / "tests/test_metrics.py").write_text(text)
        return call
    monkeypatch.setattr(stage_c_runner, "launcher_coder", launcher_coder)


def _checks(monkeypatch, result):
    def checks(directory):
        (directory.parent / "done").mkdir(exist_ok=True)
        (directory.parent / "done" / "result.json").write_text('{"exit": 0}')
        return result
    monkeypatch.setattr(stage_c_runner, "launcher_checks", lambda repo, **kw: checks)


def _commit_message(remote, key="TASK-0100"):
    return subprocess.run(["git", "--git-dir", str(remote), "log", "-1", "--format=%B", f"task/{key}"],
                          capture_output=True, text=True, check=True).stdout


def test_redaction_masks_jwts_and_json_quoted_token_keys():
    text = stage_c_runner._redact_secrets(f'{{"access_token": "{"a" * 20}", {REFRESH}, "id_token": "{JWT}"}} {JWT}')
    assert JWT not in text and "a" * 20 not in text and "r" * 24 not in text


def test_reviewer_findings_are_stored_masked(monkeypatch, tmp_path):
    class Rejecting(Reviewer):
        def _run(self, prompt, schema, **kw):
            result = super()._run(prompt, schema, **kw)
            if schema == stage_c_runner.REVIEW_SCHEMA:
                result.output = {**result.output, "verdict": "REJECT", "findings": [f"leaked {JWT}", REFRESH]}
            return result
    pipeline(monkeypatch, tmp_path, publish_repository=FORK)
    db = _db()
    task = write_task(db)
    out = worker.run_once(db, _providers(Rejecting), SPECS)
    findings = task.context["improvement"]["history"][-1]["evidence"]["findings"]
    assert out["verdict"] == "REJECTED", out
    assert findings == [stage_c_runner._WITHHELD]   # a JWT anywhere withholds the whole list
    stored = json.dumps(task.context)
    assert JWT not in stored and "r" * 24 not in stored


def test_checks_summary_is_masked_before_history_and_feedback(monkeypatch, tmp_path):
    pipeline(monkeypatch, tmp_path, publish_repository=FORK)
    _checks(monkeypatch, {"passed": False, "summary": f"1 failed token={PAT}", "failures": [f"E  {JWT}"]})
    db = _db()
    task = write_task(db)
    assert worker.run_once(db, _providers(), SPECS)["verdict"] == "CHECKS_FAILED"
    stored = json.dumps(task.context)
    assert PAT not in stored and JWT not in stored


@pytest.mark.parametrize("passed_files", [[], ["tests/test_other.py"], None, "tests/test_metrics.py"])
def test_checks_fail_closed_unless_every_changed_test_file_reported_a_pass(monkeypatch, tmp_path, passed_files):
    pipeline(monkeypatch, tmp_path, publish_repository=FORK)
    _checks(monkeypatch, {"passed": True, "summary": "5 passed in 0.1s", "passed_files": passed_files})
    db = _db()
    task = write_task(db)
    out = worker.run_once(db, _providers(), SPECS)
    evidence = task.context["improvement"]["history"][-1]["evidence"]
    assert out["verdict"] == "CHECKS_FAILED", out
    assert evidence["checks_passed"] is False
    assert evidence["checks"] == "changed test files reported no passed test: tests/test_metrics.py"


def test_public_pr_and_commit_carry_no_task_text(monkeypatch, tmp_path):
    hooks = {"opened": []}
    remote = pipeline(monkeypatch, tmp_path, hooks, publish_repository=FORK)
    db = _db()
    task = write_task(db, **SENSITIVE)
    out = worker.run_once(db, _providers(), SPECS)
    assert out["verdict"] == "PR_OPEN", out
    (branch, title, body, _commit), = hooks["opened"]
    message = _commit_message(remote)
    assert branch == "task/TASK-0100" and title == "TASK-0100: Stage C change"
    assert message.startswith("TASK-0100: Stage C change\n\nFingerprint: ")
    for text in (title, body, message):
        assert not any(value in text for value in PRIVATE), text
    assert task.context["improvement"]["approval"]["fingerprint"] in body


def test_recovery_opens_the_missing_pr_with_the_same_public_text(monkeypatch, tmp_path):
    failing = {"on": True}

    def during_open_pr(db, task):
        if failing["on"]:
            raise RuntimeError("fork-only token cannot open the upstream PR")
    hooks = {"opened": [], "during_open_pr": during_open_pr}
    remote = pipeline(monkeypatch, tmp_path, hooks, publish_repository=FORK)
    monkeypatch.setattr(stage_c_runner, "gh_pr_lookup",
                        lambda *a, **k: (lambda branch, commit: (_ for _ in ()).throw(RuntimeError("no PR"))))
    monkeypatch.setattr(stage_c_runner, "gh_pr_absent", lambda *a, **k: (lambda branch: True))
    db = _db()
    task = write_task(db, **SENSITIVE)
    assert worker.run_once(db, _providers(), SPECS)["verdict"] == "PR_FAILED"
    failing["on"] = False
    task.status, task.error = enums.TaskStatus.READY, None
    db.commit()
    out = worker.run_once(db, _providers(), SPECS)
    assert out["verdict"] == "PR_OPEN", out
    assert len(hooks["opened"]) == 2 and hooks["opened"][0][:3] == hooks["opened"][1][:3]
    _branch, title, body, _commit = hooks["opened"][1]
    for text in (title, body, _commit_message(remote)):
        assert not any(value in text for value in PRIVATE), text


@pytest.mark.parametrize("key, approval", [
    ("TASK-0100; rm", {"fingerprint": "f" * 64, "reviewer": "codex"}),
    ("TASK-0100", {"fingerprint": "f" * 64, "reviewer": "gemini"}),
    ("TASK-0100", {"fingerprint": "f" * 64, "reviewer": ["codex"]}),
    ("TASK-0100", {"fingerprint": "F" * 64, "reviewer": "codex"}),
    ("TASK-0100", {"fingerprint": None, "reviewer": "codex"}),
])
def test_public_text_refuses_unvalidated_identifiers(key, approval):
    with pytest.raises(ValueError):
        stage_c_runner._public_text(key, approval)


def test_a_credential_shaped_added_line_stops_publication(monkeypatch, tmp_path):
    hooks = {"opened": []}
    remote = pipeline(monkeypatch, tmp_path, hooks, publish_repository=FORK)
    _coder(monkeypatch, f'TOKEN = "{PAT}"\n\n\ndef test_metric():\n    assert 1 == 1\n')
    db = _db()
    task = write_task(db)
    out = worker.run_once(db, _providers(), SPECS)
    # Stopped before review now (the reviewer never sees it); publish() keeps its own scan as the second line.
    assert out["verdict"] == "REJECTED", out
    assert hooks["opened"] == []
    assert subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "--verify", "-q", "task/TASK-0100"],
                          capture_output=True).returncode != 0   # nothing pushed


def test_outgoing_scan_reads_every_added_line_including_forged_headers():
    diff = (f"diff --git a/tests/a.py b/tests/a.py\n--- a/tests/a.py\n+++ b/tests/a.py\n@@ -1 +1,2 @@\n x\n"
            f"+++ {PAT}\n").encode()
    assert stage_c_runner._outgoing_credentials(diff) == ["tests/a.py"]
    assert stage_c_runner._outgoing_credentials(b"diff --git a/t.py b/t.py\n+token = acquire(db)\n") == []


def _b64(obj) -> str:
    import base64
    return base64.urlsafe_b64encode(json.dumps(obj, indent=None).encode()).decode().rstrip("=")


# Valid JWTs the old `eyJ...{8,}` shape missed: tiny claims, empty claims, formatted JSON, alg=none (no signature).
ODD_JWTS = [_b64({"alg": "HS256"}) + "." + _b64({"a": 1}) + ".c2ln",
            _b64({"alg": "HS256"}) + "." + _b64({}) + ".c2lnbmF0dXJl",
            "ewogICJhbGciOiAiSFMyNTYiCn0" + "." + "ewogICJzdWIiOiAieCIKfQ" + ".c2ln",
            _b64({"alg": "none"}) + "." + _b64({"sub": "x"}) + "."]


@pytest.mark.parametrize("jwt", ODD_JWTS)
def test_any_valid_jwt_is_masked_and_stops_publication(jwt):
    assert jwt not in stage_c_runner._redact_secrets(f"found x.{jwt} here")
    assert stage_c_runner._outgoing_credentials(f"diff --git a/t.py b/t.py\n+X = '{jwt}'\n".encode()) == ["t.py"]


def test_dotted_code_is_not_a_jwt():
    text = "os.path.join(a.b.c, self.db.session.query) v1.2.3"
    assert stage_c_runner._redact_secrets(text) == text
    assert stage_c_runner._outgoing_credentials(f"diff --git a/t.py b/t.py\n+{text}\n".encode()) == []


@pytest.mark.parametrize("sep", ["\r", "\x0b", " ", "\x1c", "\x85"])
def test_a_credential_after_an_embedded_line_separator_is_still_caught(sep):
    """Break caught: splitlines() split inside an added line and dropped the `+` before the credential."""
    diff = f"diff --git a/t.py b/t.py\n+# note{sep}# credential = {PAT}\n".encode()
    assert stage_c_runner._outgoing_credentials(diff) == ["t.py"]


def test_a_jwt_split_over_adjacent_literals_or_lines_is_caught():
    jwt = ODD_JWTS[0]
    head, rest = jwt.split(".", 1)
    diff = f'diff --git a/t.py b/t.py\n+VALUE = ("{head}."\n+         "{rest}")\n'.encode()
    assert stage_c_runner._outgoing_credentials(diff) == ["t.py"]
    assert jwt.split(".")[1] not in stage_c_runner._redact_secrets(f"token part {head}.\n{rest}")
    padded = _b64({"alg": "HS256"}) + "==." + _b64({"sub": "x"}) + "=.c2ln"
    assert stage_c_runner._outgoing_credentials(f"diff --git a/t.py b/t.py\n+X = '{padded}'\n".encode()) == ["t.py"]


@pytest.mark.parametrize("prefix", ["", "r", "b", "f", "br", "rb", "fr", "rf", "R", "B", "F"])
def test_prefixed_adjacent_literals_are_detected_before_redaction(prefix):
    head, rest = ODD_JWTS[0].split(".", 1)
    text = f'VALUE = ({prefix}"{head}."\n {prefix}"{rest}")'
    diff = "diff --git a/t.py b/t.py\n" + "\n".join("+" + line for line in text.split("\n")) + "\n"
    assert stage_c_runner._outgoing_credentials(diff.encode()) == ["t.py"]
    assert stage_c_runner._redact_secrets(text) == "[withheld: credential-shaped content]"


def test_wrapped_token_is_withheld_before_its_header_is_masked():
    head, rest = ODD_JWTS[0].split(".", 1)
    assert stage_c_runner._redact_secrets(f"token={head}.\n{rest}") == "[withheld: credential-shaped content]"


def test_adjacent_literals_with_a_wrapping_comment_are_detected():
    head, rest = ODD_JWTS[0].split(".", 1)
    text = f'VALUE = ("{head}." # wrapped literal\n "{rest}")'
    diff = "diff --git a/t.py b/t.py\n" + "\n".join("+" + line for line in text.split("\n")) + "\n"
    assert stage_c_runner._outgoing_credentials(diff.encode()) == ["t.py"]
    assert stage_c_runner._redact_secrets(text) == "[withheld: credential-shaped content]"


def test_jwt_header_with_leading_json_whitespace_is_detected():
    import base64
    head = base64.urlsafe_b64encode(b'  {"alg":"HS256"}').decode().rstrip("=")
    jwt = head + "." + _b64({"sub": "synthetic"}) + ".c2ln"
    text = f'VALUE = "{jwt}"'
    assert stage_c_runner._outgoing_credentials(f"diff --git a/t.py b/t.py\n+{text}\n".encode()) == ["t.py"]
    assert jwt not in stage_c_runner._redact_secrets(text)


@pytest.mark.parametrize("name", ["task-repository-guardian", "task-notification-worker"])
def test_ordinary_task_names_are_not_credentials(name):
    text = f'branch = "{name}"'
    assert stage_c_runner._outgoing_credentials(f"diff --git a/t.py b/t.py\n+{text}\n".encode()) == []
    assert stage_c_runner._redact_secrets(text) == text


@pytest.mark.parametrize("text", ["a" * (1 << 20), ("e30." * (1 << 18)), ("a." * (1 << 19)),
                                  " " * (1 << 20), "\t" * (1 << 20),
                                  '"' + " " * (1 << 20) + "!", "token" + " " * (1 << 20) + "!"],
                         ids=["letters", "json-dotted", "dotted", "spaces", "tabs", "literal-spaces", "key-spaces"])
def test_jwt_scanning_stays_linear_on_hostile_megabyte_inputs(text):
    import time
    import signal
    def timed_out(*_):
        raise AssertionError("credential scanning exceeded five seconds")
    previous = signal.signal(signal.SIGALRM, timed_out)
    signal.setitimer(signal.ITIMER_REAL, 5)
    started = time.monotonic()
    try:
        stage_c_runner._redact_secrets(text)
        stage_c_runner._outgoing_credentials(("diff --git a/t.py b/t.py\n+" + text + "\n").encode())
        assert time.monotonic() - started < 5   # was over 4 s for 16 KiB of "a" alone
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.mark.parametrize("literal", ['(r"{h}."\n+ r"{r}")', '(b"{h}."\n+ b"{r}")', '(f"{h}."\n+ f"{r}")',
                                     '("{h}." + "{r}")', "'{h}=.' \\\n+ '{r}'"])
def test_a_jwt_written_as_any_split_literal_is_caught(literal):
    head, rest = ODD_JWTS[0].split(".", 1)
    diff = ("diff --git a/t.py b/t.py\n+VALUE = " + literal.format(h=head, r=rest) + "\n").encode()
    assert stage_c_runner._outgoing_credentials(diff) == ["t.py"]


def test_text_holding_a_jwt_header_is_withheld_whole():
    head, rest = ODD_JWTS[0].split(".", 1)
    out = stage_c_runner._redact_secrets(f"token={head}.\n{rest}")
    assert head not in out and rest not in out


@pytest.mark.parametrize("name", ["task-repository-guardian", "task-notification-worker-abcdef", "disk-usage-report-abc"])
def test_ordinary_names_do_not_block_publication(name):
    diff = f'diff --git a/t.py b/t.py\n+branch = "{name}"\n'.encode()
    assert stage_c_runner._outgoing_credentials(diff) == []


@pytest.mark.parametrize("text", ['" #' * (1 << 18), '"\n"' * (1 << 18), "ghp_" * (1 << 18),
                                  " " * (1 << 20), "\t \n" * (1 << 18), "token" + " " * (1 << 20), "token:" * (1 << 17),
                                  "'" + " " * (1 << 20) + "'", "A" * (1 << 20), ("abcdefgh " * (1 << 17))])
def test_scanning_stays_linear_on_hostile_blank_and_word_runs(text):
    import time
    started = time.monotonic()
    stage_c_runner._redact_secrets(text)
    stage_c_runner._outgoing_credentials(("diff --git a/t.py b/t.py\n+" + text + "\n").encode())
    assert time.monotonic() - started < 5


def test_a_jwt_wrapped_across_failure_lines_or_findings_is_withheld_whole():
    head, rest = ODD_JWTS[0].split(".", 1)
    lines = ["E   AssertionError: bad token " + head + ".", "E   " + rest, "FAILED tests/test_x.py::test_y"]
    out = stage_c_runner._bounded_failures(lines)
    assert out == [stage_c_runner._WITHHELD] and rest not in json.dumps(out)
    assert stage_c_runner._redact_items([f"see {head}.", rest]) == [stage_c_runner._WITHHELD]
    assert stage_c_runner._redact_items(["plain finding", "token=abcdefghijklmnop"]) == ["plain finding", "***"]


def test_a_private_key_body_never_survives_redaction():
    body = ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + str(i) * 32 for i in range(5)]
    mark = "RSA " + "PRIVATE" + " KEY-----"   # built, so no key-shaped literal sits in the public repo
    pem = ["-----BEGIN " + mark, *body, "-----END " + mark]
    assert stage_c_runner._bounded_failures(["E   ValueError: bad key"] + ["E   " + l for l in pem]) == [stage_c_runner._WITHHELD]
    assert stage_c_runner._bounded_failures(["E   " + l for l in body[2:] + pem[-1:]]) == [stage_c_runner._WITHHELD]
    assert stage_c_runner._redact_secrets("\n".join(pem)) == stage_c_runner._WITHHELD
    diff = ("diff --git a/k.py b/k.py\n+" + "\n+".join(["-----BEGIN OPENSSH " + "PRIVATE" + " KEY-----"] + body) + "\n").encode()
    assert stage_c_runner._outgoing_credentials(diff) == ["k.py"]   # the base scanner blocks the BEGIN marker


def _scan(*lines):
    return stage_c_runner._outgoing_credentials(("diff --git a/t.py b/t.py\n" + "".join("+" + l + "\n" for l in lines)).encode())


def test_a_putty_key_is_withheld_from_kept_text_but_publication_keeps_the_base_precision():
    lines = ["PuTTY-User-" + "Key-File-3: ssh-ed25519", "Private-" + "Lines: 1", "AAAA"]
    assert stage_c_runner._redact_items(lines) == [stage_c_runner._WITHHELD]
    assert _scan('assert header.startswith("PuTTY-User-' + 'Key-File-3:")') == []   # a format check is not a key


@pytest.mark.parametrize("lines", [
    ['TOKEN = "fixture-only-token-value"'], ["token = acquire(db)"], ['API_KEY = os.environ["API_KEY"]'],
    ['url = "ssh://git@github.com/org/repo"'], ['PASSWORD_FIELD = "password"'],
    ['DB_API_KEY = os.environ.get("DB_API_KEY")'], ['DB_PASSWORD_FIELD = "database_password"'],
    ["AWS_SECRET_" + "ACCESS_KEY=" + "wJalrXUt" + "nFEMIK7MDENGbPxRfiCYzz9q8a7b6c5d"],   # masked, never a blocker
])
def test_ordinary_code_still_publishes(lines):
    assert _scan(*lines) == []


def test_a_large_x5c_jwt_header_is_detected():
    import base64
    big = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "x5c": ["A" * 1700]}).encode()).decode().rstrip("=")
    assert len(big) > 2048 and stage_c_runner._redact_secrets("X = '" + big + ".e30.c2ln'") == stage_c_runner._WITHHELD


@pytest.mark.parametrize("text", ['PASSWORD="myStrong@Password#2026"', '"DB_PASSWORD": "' + "abcdefgh" + "ijklmnopqrstuvwx" + '"',
                                  "AWS_SECRET_" + "ACCESS_KEY=" + "wJalrXUt" + "nFEMIK7MDENGbPxRfiCYzz9q8a7b6c5d",
                                  "API_" + "KEY=" + "abcdefgh" + "ijklmnop", "TOKEN=testingProduction2026"])
def test_credential_assignments_are_masked_with_their_whole_value(text):
    value = text.split("=", 1)[1] if "=" in text and ":" not in text.split("=", 1)[0] else text.split(":", 1)[1]
    assert value.strip(' "') not in stage_c_runner._redact_secrets(text)


PG = "postgresql" + "://"   # built, so no URL-shaped literal sits in the public repo


@pytest.mark.parametrize("line", ['url = f"' + PG + '{user}:{password}@{host}/{db}"',
                                  'url = "' + PG + '$USER:$PASSWORD@db/app"', 'url = "redis://%(user)s:%(pw)s@h"',
                                  'url = "' + PG + '<user>:<password>@db/app"'])
def test_url_templates_publish(line):
    assert _scan(line) == []


def test_a_credential_in_the_change_never_reaches_the_reviewer(monkeypatch, tmp_path):
    seen = []

    class Capturing(Reviewer):
        def _run(self, prompt, schema, **kw):
            seen.append(prompt)
            return super()._run(prompt, schema, **kw)
    pipeline(monkeypatch, tmp_path, publish_repository=FORK)
    _coder(monkeypatch, "# key " + "sk-ant-" + "oat01-" + "A1b2C3d4" * 6 + "\n\n\ndef test_metric():\n    assert 1 == 1\n")
    db = _db()
    task = write_task(db)
    worker.run_once(db, _providers(Capturing), SPECS)
    assert not any("sk-ant-" in str(p) for p in seen)
    assert any("credential-shaped content" in f for h in task.context["improvement"]["history"]
               for f in (h.get("evidence") or {}).get("findings", []))


def test_feedback_for_a_credential_in_the_change_never_repeats_it():
    pat = "github_pat_" + "A1b2C3" * 6
    diff = f"diff --git a/tests/{pat}.py b/tests/{pat}.py\n+X = '{pat}'\n".encode()
    leaked = stage_c_runner._outgoing_credentials(diff)
    assert leaked and pat not in stage_c_runner._redact(f"credential-shaped content in {', '.join(leaked)}")


def test_an_underscore_before_a_token_does_not_hide_it():
    token = "sk-ant-" + "oat01-" + "A1b2C3d4" * 6
    assert _scan(f"# diagnostic _{token}") == ["t.py"]
    assert token not in stage_c_runner._redact_secrets(f"diagnostic _{token}")


def test_a_bare_public_jose_header_publishes():
    header = _b64({"alg": "HS256"})
    assert _scan(f'assert encode_header({{"alg": "HS256"}}) == "{header}"') == []
    assert _scan(f'X = "{header}." + "{_b64({"sub": "x"})}.c2ln"') == ["t.py"]   # a header opening a token still counts


@pytest.mark.parametrize("prefix", ["x", "0", "_", "-"])
def test_no_prefix_hides_the_coder_token_or_a_jwt(prefix):
    token = "sk-ant-" + "oat01-" + "A1b2C3d4" * 6
    assert _scan(f"# note {prefix}{token}") == ["t.py"]
    assert token not in stage_c_runner._redact_secrets(f"note {prefix}{token}")
    jwt = ODD_JWTS[0]   # the coder never holds a JWT; kept text still withholds a glued one
    assert stage_c_runner._redact_secrets(f"X = '{prefix}{jwt}'") == stage_c_runner._WITHHELD


@pytest.mark.parametrize("line", ['u = "http://localhost:8000?email=user@example.com"',
                                  'u = "https://example.com:443/#contact=a@b.c"'])
def test_query_and_fragment_urls_publish(line):
    assert _scan(line) == []


def test_a_token_assembled_from_adjacent_literals_is_caught():
    rest = "oat01-" + "A1b2C3d4" * 4
    assert _scan('KEY = "sk-" "ant-' + rest + '"') == ["t.py"]
    assert _scan("KEY = 'sk-' + 'ant-" + rest + "'") == ["t.py"]
    assert ("ant-" + rest) not in stage_c_runner._redact_secrets('KEY = "sk-" "ant-' + rest + '"')


@pytest.mark.parametrize("line", ["def validate_github_pat_permissions(token):", "ghp_settings_cache = {}",
                                  'assert token.startswith("' + _b64({"alg": "HS256"}) + '.")'])
def test_names_and_public_headers_publish(line):
    assert _scan(line) == []


@pytest.mark.parametrize("line", ["def validate_github_pat_permissions_for_v2(token):",
                                  'assert token.startswith("' + _b64({"alg": "HS256"}) + '.eyJ")',
                                  'URL = "postgresql+psycopg://company:company@company-postgres:5432/company"'])
def test_base_scanner_accepted_code_still_publishes(line):
    assert _scan(line) == []


def test_url_userinfo_is_masked_not_blocked():
    url = "postgresql://app:" + "s3cr3tvalue@db.internal/app"
    assert _scan(f'DATABASE_URL = "{url}"') == []
    assert "s3cr3tvalue" not in stage_c_runner._redact_secrets(f"connect {url} failed")


def test_a_jwt_glued_after_a_word_is_withheld_from_findings():
    jwt = ODD_JWTS[0]
    assert stage_c_runner._redact_items([f"diagnostic log_{jwt}"]) == [stage_c_runner._WITHHELD]


def test_an_escaped_alg_key_still_reads_as_a_jose_header():
    import base64
    head = base64.urlsafe_b64encode(b'{"\\u0061lg":"RS256"}').decode().rstrip("=")
    jwt = head + "." + _b64({"sub": "x"}) + ".c2ln"
    assert stage_c_runner._redact_secrets(f"token {jwt}") == stage_c_runner._WITHHELD
    assert _scan(f"X = '{jwt}'") == ["t.py"]


def test_a_branch_name_shaped_like_the_token_prefix_publishes():
    assert _scan('BRANCH = "task-ant-job01-notification-worker"') == []


def test_credential_rejection_is_recorded_as_a_worker_actor():
    import inspect
    src = inspect.getsource(stage_c_runner.review)
    assert '"stage-c-runner"' in src and '"control-plane"' not in src
    from app import stage_c_worker
    assert "stage-c-runner" in stage_c_worker.NOT_AN_OWNER_CHANGE


@pytest.mark.parametrize("name", ["task-ant-job01-build-Linux-amd64", "task-ant-oat01-short"])
def test_job_names_shaped_like_the_token_prefix_publish(name):
    assert _scan(f'BRANCH = "{name}"') == []


def test_a_descriptive_branch_with_a_real_token_kind_publishes():
    assert _scan('BRANCH = "task-ant-api01-build-Linux-amd64-release-production-candidate"') == []


@pytest.mark.parametrize("text", ["DB_PASSWORD=hunter2hunter2,Tr0ub4dor3xyz", "my_token: val1234567,second987",
                                  "(db_password:abcdefgh;qrstuvwxyz"])
def test_masking_keeps_the_base_scanners_whole_value(text):
    tail = text.replace(";", ",").split(",")[-1]
    assert tail not in stage_c_runner._redact_secrets(text)


def test_a_token_glued_after_a_word_tail_is_caught():
    token = "sk-ant-" + "oat01-" + "AbCdEfGh" * 6
    assert _scan(f"v = 'ab{token}'") == ["t.py"]
    assert token not in stage_c_runner._redact_secrets(f"E   ab{token}")


def _rs256_like():
    import base64, os
    b = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    head = _b64({"alg": "RS256", "typ": "JWT", "kid": "k" * 40})
    return head, b(os.urandom(280)), b(os.urandom(256))


@pytest.mark.parametrize("cut", [40, 76])
def test_a_jwt_split_across_findings_cannot_be_rebuilt(cut):
    head, pay, sig = _rs256_like()
    jwt = f"{head}.{pay}.{sig}"
    first, rest = jwt[:cut], jwt[cut:]
    items = [f"see {first}"] + [rest[i:i + 280] for i in range(0, len(rest), 280)]
    out = stage_c_runner._redact_items(items)
    glued = "".join(out)
    assert out == [stage_c_runner._WITHHELD] and pay not in glued and sig not in glued


def test_a_jwt_wrapped_in_pytest_lines_is_withheld_from_failures():
    head, pay, sig = _rs256_like()
    jwt = f"{head}.{pay}.{sig}"
    lines = ["E   AssertionError: token"] + ["E   " + jwt[i:i + 76] for i in range(0, len(jwt), 76)]
    assert stage_c_runner._bounded_failures(lines) == [stage_c_runner._WITHHELD]
