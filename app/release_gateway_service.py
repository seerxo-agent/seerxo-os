"""Release gateway service (G3): turns new commits on main into signed release manifests, with no human step for
low-risk changes. Design: docs/security/RELEASE_GATEWAY.md. Standard library only, like app/release_gateway.py.

Runs as its own Unix user outside Docker (host condition H2), from a timer:  python3 -m app.release_gateway_service
Each tick, at most one candidate (origin/main):

  fetch -> nothing new? stop -> diff, changed paths, payload digest from its own clone
        -> trusted checks (its own offline container) -> signed review via company-review-signer (fresh nonce)
        -> manifest -> LOW: gateway_approve + sign -> outbox      HIGH: founder queue (unsigned draft)

Never trusted: GitHub workflow results, merge identities, PostgreSQL rows. Every refusal is recorded with its
reason. Attempts per commit are bounded (MAX_ATTEMPTS); a commit that was checked, reviewed and failed is not
retried, so a model call is never repeated for the same content. The host verifier re-checks everything.
"""
import fcntl
import http.client
import json
import socket
import os
import secrets
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import release_gateway as rg

MAX_ATTEMPTS = 3                     # per candidate commit, for infrastructure failures only
IDENTITY_MAX_AGE = timedelta(minutes=15)
MANIFEST_LIFETIME = timedelta(hours=2)
REVIEW_TIMEOUT_S = 900


class Config:
    """Founder-owned config (root-owned file, readable by the gateway user). Paths only, never a secret value."""

    def __init__(self, raw: dict):
        need = {"repository", "branch", "clone", "fetch_url", "policy", "policy_sig", "founder_key", "gateway_key",
                "ledger", "state", "outbox", "founder_queue", "review_signer_socket", "checks_command",
                "identity_report"}
        if not isinstance(raw, dict) or set(raw) != need:
            raise rg.Refused(f"gateway config must have exactly {sorted(need)}")
        self.__dict__.update(raw)
        for key in ("clone", "policy", "policy_sig", "founder_key", "gateway_key", "ledger", "state", "outbox",
                    "founder_queue", "identity_report"):
            setattr(self, key, Path(raw[key]))
        if not isinstance(self.checks_command, list) or not all(isinstance(a, str) and a for a in self.checks_command):
            raise rg.Refused("checks_command must be a non-empty argv list")


def _git(cfg: Config, *args: str) -> str:
    # The clone holds agent-written content: never run its hooks. It must be the gateway user's own (0700).
    return subprocess.run(["git", "-C", str(cfg.clone), "-c", "core.hooksPath=/dev/null", *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def _write_json(path: Path, obj) -> None:
    """Durable: the file and its directory are fsynced, so a counted attempt or a decision survives a crash."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    with open(tmp, "w") as f:
        f.write(json.dumps(obj, sort_keys=True, indent=1))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _read_state(path: Path) -> dict:
    """The gateway's own memory. Missing is empty; anything unreadable or mistyped is refused (fail closed)."""
    try:
        state = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raise rg.Refused("gateway state is unreadable; the founder must restore it") from None
    if not isinstance(state, dict) or not all(isinstance(state.get(k, {}), dict)
                                              for k in ("attempts", "done", "rejected_on")):
        raise rg.Refused("gateway state is malformed; the founder must restore it")
    return state


def default_checks(cfg: Config, sha: str) -> dict:
    """The gateway's own checks: the commit's tree exported by git, run by the founder-approved checks command
    (an offline, read-only container, H5). Exit 0 is the only pass. Output is summarised, never stored raw."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="gateway-checks-") as d:
        archive = subprocess.run(["git", "-C", str(cfg.clone), "archive", "--format=tar", sha], check=True,
                                 capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", d], input=archive, check=True, capture_output=True)
        try:
            r = subprocess.run([*cfg.checks_command, d], capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            return {"passed": False, "summary": "checks timed out"}
        return {"passed": r.returncode == 0, "summary": f"exit {r.returncode}"}


class ReviewNotAsked(RuntimeError):
    """The signer certainly did not ask the reviewer model (no socket, refused connection, or it declined the request
    before review: 400/403/409/503). Only this is retried as infrastructure; any other failure is an unknown outcome."""


NOT_ASKED_STATUSES = {400, 403, 409, 503}


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("review-signer", timeout=timeout)
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def default_review(cfg: Config, packet: dict) -> dict:
    """POST /review to company-review-signer over its Unix socket, signed with the gateway key so no one else can
    obtain a signed verdict. The signer asks the reviewer itself. Any transport or HTTP error is an infrastructure
    failure (raise); a 200 answer is still verified by the caller."""
    asked_at = datetime.now(timezone.utc).isoformat()
    body = json.dumps({"packet": packet, "issued_at": asked_at, "request_signature": rg.sign(
        rg.review_request(packet, asked_at), cfg.gateway_key, rg.NS_REVIEW_REQUEST)}).encode()
    conn = _UnixConnection(cfg.review_signer_socket, REVIEW_TIMEOUT_S + 120)
    try:
        try:
            conn.connect()
        except OSError as error:                       # nothing was sent: the model was not asked
            raise ReviewNotAsked(f"review signer unreachable: {type(error).__name__}") from None
        conn.request("POST", "/review", body=body, headers={"content-type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
    finally:
        conn.close()
    if resp.status in NOT_ASKED_STATUSES:
        raise ReviewNotAsked(f"review signer declined before review: HTTP {resp.status}")
    if resp.status != 200:
        raise RuntimeError(f"review signer answered HTTP {resp.status}")
    return json.loads(data)


def tick(cfg: Config, *, now: datetime | None = None, clock=None, checks=None, review=None, fetch=True) -> dict:
    """One gateway step under an exclusive lock (two overlapping ticks would lose each other's decisions).
    Returns {"outcome": ..., ...}; every outcome is also kept in the gateway state file."""
    cfg.state.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg.state.with_name(cfg.state.name + ".lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            return _tick(cfg, now=now, clock=clock, checks=checks, review=review, fetch=fetch)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _tick(cfg: Config, *, now, clock, checks, review, fetch) -> dict:
    clock = clock or (lambda: datetime.now(timezone.utc))
    now = now or clock()
    checks = checks or (lambda sha: default_checks(cfg, sha))
    review = review or (lambda packet: default_review(cfg, packet))
    founder_key = cfg.founder_key.read_text().strip()
    ledger = rg.read_ledger(cfg.ledger)
    policy = rg.load_policy(cfg.policy.read_bytes(), cfg.policy_sig.read_text(), founder_key,
                            min_version=ledger.get("min_policy_version", 1))
    if (cfg.repository, cfg.branch) != (policy["repository"], policy["branch"]):
        raise rg.Refused("gateway config and policy name different repositories or branches")
    state = _read_state(cfg.state)

    def record(outcome: str, **extra) -> dict:
        entry = {"outcome": outcome, "at": now.isoformat(), **extra}
        _write_json(cfg.state, {**state, "last": entry})
        return entry

    if ledger.get("pending"):
        return record("WAITING", reason="host has an unreconciled pending release")
    running, parent = ledger.get("last_sha"), rg.chain_parent(ledger)   # differ only right after a rebase
    if not running:
        return record("WAITING", reason="host is not bootstrapped: the founder must sign the production baseline")
    identity = production_identity(cfg, running, now)
    if identity:
        return record("WAITING", reason=identity)
    if fetch:
        _git(cfg, "fetch", "--no-tags", "--quiet", cfg.fetch_url, f"+refs/heads/{cfg.branch}:refs/remotes/origin/{cfg.branch}")
    sha = _git(cfg, "rev-parse", f"refs/remotes/origin/{cfg.branch}^{{commit}}")
    if sha == parent:
        return record("IDLE", sha=sha)
    if sha in state.get("done", {}):
        return record("ALREADY_DECIDED", sha=sha, decision=state["done"][sha])
    attempts = state.get("attempts", {}).get(sha, 0)
    if attempts >= MAX_ATTEMPTS:
        return record("GIVEN_UP", sha=sha, reason=f"{attempts} infrastructure failures; the founder decides")
    try:
        subprocess.run(["git", "-C", str(cfg.clone), "merge-base", "--is-ancestor", parent, sha], check=True,
                       capture_output=True)
    except subprocess.CalledProcessError:
        return _decide(cfg, state, sha, "REFUSED", "main does not descend from the applied release", now)
    scope = rg.diff_scope(ledger)               # the host computes the same: from what runs, payload-only after a rebase
    try:
        paths = rg.git_changed_paths(cfg.clone, running, sha, scope)
        diff = rg.git_release_diff(cfg.clone, running, sha, scope)
        digest = rg.payload_digest(rg.payload_listing(cfg.clone, sha))
        nonregular = rg.git_nonregular_paths(cfg.clone, running, sha, scope)
    except subprocess.CalledProcessError:      # e.g. a submodule entry: counted, bounded, never silent
        return _infra(cfg, state, sha, attempts, "could not compute the release content", now)
    try:
        rg.release_archive(cfg.clone, sha)      # never sign bytes that would ship differently from those reviewed
    except rg.Refused as refused:
        return _decide(cfg, state, sha, "REFUSED", str(refused), now)
    except subprocess.CalledProcessError:
        return _infra(cfg, state, sha, attempts, "could not build the release archive", now)
    risk = rg.classify(paths, policy)
    if nonregular:                              # a symlink or submodule entry is never low risk
        risk = "high"
    migration = any(p.startswith("migrations/") for p in paths)
    # After the reviewer rejected a candidate on this release base, later candidates on the same base go to the
    # founder: a trivial new commit must not buy a fresh roll of the reviewer.
    reviewer_already_rejected = state.get("rejected_on", {}).get(parent, 0) > 0

    # The attempt is recorded durably BEFORE the checks and the reviewer run: whatever fails afterwards (the
    # founder-queue or outbox write, signing, a crash) has already been counted, so the model is asked at most
    # MAX_ATTEMPTS times per commit. A final decision (_decide) supersedes the count; _infra writes the same count.
    state = {**state, "attempts": {**state.get("attempts", {}), sha: attempts + 1}}
    _write_json(cfg.state, state)
    try:
        result = checks(sha)
    except Exception as error:   # infrastructure, not a verdict on the code
        return _infra(cfg, state, sha, attempts, f"checks runner failed: {type(error).__name__}", now)
    passed = isinstance(result, dict) and result.get("passed") is True
    if not passed:
        return _decide(cfg, state, sha, "CHECKS_FAILED", str((result or {}).get("summary", ""))[:200], now)
    nonce = secrets.token_hex(16)
    packet = rg.review_packet(cfg.repository, running, sha, diff, nonce)   # the diff's own base: what runs
    try:
        answer = review(packet)
    except ReviewNotAsked as error:
        return _infra(cfg, state, sha, attempts, f"reviewer not asked: {error}", now)
    except Exception as error:   # the model may have answered: never buy a fresh roll, count it as a rejection
        answer = None
        unknown = f"review outcome unknown: {type(error).__name__}"
    else:
        unknown = None if isinstance(answer, dict) and "attestation" in answer else "reviewer gave no signed verdict"
    if unknown:
        state = {**state, "rejected_on": {**state.get("rejected_on", {}), parent: state.get("rejected_on", {}).get(parent, 0) + 1}}
        return _decide(cfg, state, sha, "REVIEW_UNKNOWN", unknown, now)
    now = clock()   # the review may take many minutes: freshness and the manifest's lifetime start now
    evidence = {"trusted_checks": {"runner": "gateway", "sha": sha, "payload_digest": digest, "passed": True},
                "review": {"nonce": nonce, "attestation": answer["attestation"], "signature": answer.get("signature")}}
    try:
        rg.verify_review(evidence["review"], packet, policy, now)
    except rg.Refused as refused:
        state = {**state, "rejected_on": {**state.get("rejected_on", {}), parent: state.get("rejected_on", {}).get(parent, 0) + 1}}
        return _decide(cfg, state, sha, "REVIEW_REFUSED", str(refused), now)

    base = {"version": rg.MANIFEST_VERSION, "repository": cfg.repository, "branch": cfg.branch, "sha": sha,
            "parent_sha": parent, "payload_digest": digest, "changed_paths": paths,
            "sequence": ledger.get("last_sequence", 0) + 1, "issued_at": now.isoformat(),
            "expires_at": (now + MANIFEST_LIFETIME).isoformat(), "policy_version": policy["version"],
            "migration_to": ""}
    if risk != "low" or migration or not policy["auto_release"] or reviewer_already_rejected or ledger.get("chain_base"):
        draft = {**base, "approver": "founder", "evidence": evidence}
        _write_json(cfg.founder_queue / f"{base['sequence']:06d}-{sha}.json", draft)
        why = ("the first release after a rebase" if ledger.get("chain_base") else
               "automatic release is off" if not policy["auto_release"] else
               "the reviewer rejected an earlier candidate on this release base" if reviewer_already_rejected
               else "high-risk change")
        return _decide(cfg, state, sha, "FOUNDER_REQUIRED", why, now, queued=True)
    manifest = {**base, "approver": "gateway", "evidence": evidence}
    try:
        rg.gateway_approve(manifest, policy, now=now, diff=diff)
    except rg.Refused as refused:
        return _decide(cfg, state, sha, "REFUSED", str(refused), now)
    raw = rg.canonical(manifest)
    signature = rg.sign(raw, cfg.gateway_key, rg.NS_RELEASE)
    name = f"{base['sequence']:06d}-{sha}"
    cfg.outbox.mkdir(parents=True, exist_ok=True)
    (cfg.outbox / f".{name}.sig").write_text(signature)
    (cfg.outbox / f".{name}.json").write_bytes(raw)
    os.replace(cfg.outbox / f".{name}.sig", cfg.outbox / f"{name}.sig")
    os.replace(cfg.outbox / f".{name}.json", cfg.outbox / f"{name}.json")   # the host picks up .json last
    return _decide(cfg, state, sha, "SIGNED", name, now)


def production_identity(cfg: Config, last_sha: str, now: datetime) -> str | None:
    """The host (root) verifies what runs; the gateway only READS that verdict and can never repair it. Missing,
    stale, failing, pending, or about another release: no candidate is prepared."""
    try:
        report = json.loads(cfg.identity_report.read_text())
        checked = datetime.fromisoformat(report["checked_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return "production identity is not verified by the host"
    if not isinstance(report, dict) or checked.tzinfo is None:
        return "production identity report is malformed"
    if not (timedelta(minutes=-1) <= now - checked <= IDENTITY_MAX_AGE):
        return "production identity report is stale"
    if report.get("ok") is not True or report.get("pending") is not False or report.get("last_sha") != last_sha:
        return f"production is not exactly the recorded release: {report.get('problem') or 'mismatch'}"
    return None


def _decide(cfg, state, sha, outcome, detail, now, **extra) -> dict:
    """A final decision for this commit: recorded, never re-run (no repeated checks or model calls)."""
    entry = {"outcome": outcome, "sha": sha, "detail": detail, "at": now.isoformat(), **extra}
    _write_json(cfg.state, {**state, "last": entry, "done": {**state.get("done", {}), sha: outcome}})
    return entry


def _infra(cfg, state, sha, attempts, detail, now) -> dict:
    """An infrastructure failure: counted toward MAX_ATTEMPTS, retried on a later tick."""
    entry = {"outcome": "RETRY_LATER", "sha": sha, "detail": detail, "attempt": attempts + 1, "at": now.isoformat()}
    _write_json(cfg.state, {**state, "last": entry, "attempts": {**state.get("attempts", {}), sha: attempts + 1}})
    return entry


def main() -> int:
    path = Path(os.environ.get("RELEASE_GATEWAY_CONFIG", "/etc/release-gateway/config.json"))
    try:
        out = tick(Config(json.loads(path.read_text())))
    except (rg.Refused, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"release-gateway: refused: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
