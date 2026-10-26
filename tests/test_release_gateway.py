"""Independent release gateway: every attack in docs/security/RELEASE_GATEWAY.md is refused, with real ssh-keygen
signatures from throwaway keys (no real credential is used or needed)."""
import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import release_gateway as rg

pytestmark = pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen not installed")

ROOT = Path(__file__).parents[1]
NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
PARENT, SHA, OTHER = "1" * 40, "2" * 40, "3" * 40
DIGEST = rg.payload_digest("aa  docs/HANDOFF.md\nbb  docs/runbooks/x.md\n")
LOW = ["docs/HANDOFF.md", "docs/runbooks/x.md"]
DIFF = "diff --git a/docs/HANDOFF.md b/docs/HANDOFF.md\n--- a/docs/HANDOFF.md\n+++ b/docs/HANDOFF.md\n@@ -1 +1 @@\n-old\n+new\n"
NONCE = "ab" * 16
KEYS = {}


def keypair(directory: Path, name: str) -> tuple[Path, str]:
    key = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True)
    return key, (directory / f"{name}.pub").read_text().strip()


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    KEYS.update({name: keypair(d, name) for name in ("founder", "gateway", "agent", "reviewer")})
    return KEYS


@pytest.fixture(autouse=True)
def _keys(keys):
    return keys


def signed_review(*, reviewer="codex", key="reviewer", diff=DIFF, nonce=NONCE, sha=SHA, base=PARENT,
                  output=None, issued=NOW, att_over=None):
    """What company-reasoner returns for one release review: an attestation signed with its reviewer key."""
    packet = rg.review_packet("seerxo/os", base, sha, diff, nonce)
    out = output or {"verdict": "APPROVE", "fingerprint": packet["fingerprint"], "findings": []}
    att = rg.attestation(reviewer, packet, out, issued.isoformat()) | (att_over or {})
    return {"nonce": nonce, "attestation": att, "signature": rg.sign(rg.canonical(att), KEYS[key][0], rg.NS_REVIEW)}


def policy_doc(keys, **over):
    doc = json.loads((ROOT / "agents/release_policy.json").read_text())
    return doc | {"gateway_key": keys["gateway"][1], "reviewer_keys": {"codex": keys["reviewer"][1]}} | over


def signed_policy(keys, signer="founder", **over):
    raw = rg.canonical(policy_doc(keys, **over))
    return raw, rg.sign(raw, keys[signer][0], rg.NS_POLICY)


@pytest.fixture
def policy(keys):
    raw, sig = signed_policy(keys)
    return rg.load_policy(raw, sig, keys["founder"][1])


def manifest(**over):
    m = {"version": 1, "repository": "seerxo/os", "branch": "main", "sha": SHA, "parent_sha": PARENT,
         "payload_digest": DIGEST, "changed_paths": LOW, "sequence": 7, "issued_at": NOW.isoformat(),
         "expires_at": (NOW + timedelta(hours=2)).isoformat(), "policy_version": 1, "migration_to": "",
         "approver": "gateway",
         "evidence": {"trusted_checks": {"runner": "gateway", "sha": SHA, "payload_digest": DIGEST, "passed": True},
                      "review": signed_review()}}
    return m | over


def facts(**over):
    return {"repository": "seerxo/os", "branch": "main", "sha": SHA, "payload_digest": DIGEST, "changed_paths": LOW,
            "ancestor_of_parent": True, "diff": DIFF} | over


def image(component: str, sha: str) -> str:
    return "sha256:" + __import__("hashlib").sha256(f"{component}@{sha}".encode()).hexdigest()


def images(sha: str) -> dict:
    return {c: image(c, sha) for c in rg.COMPONENTS}


def config(component: str) -> str:
    return __import__("hashlib").sha256(f"compose:{component}".encode()).hexdigest()


def configs() -> dict:
    return {c: config(c) for c in rg.COMPONENTS}


class Production:
    """What root reads from Docker on the host: per component, the content-addressed image ID and the running SHA."""

    def __init__(self, sha=PARENT):
        self.running = {c: {"image": image(c, sha), "config": config(c), "git_sha": sha} for c in rg.COMPONENTS}

    def observe(self):
        return json.loads(json.dumps(self.running))

    def deploy(self, sha):
        self.running = {c: {"image": image(c, sha), "config": config(c), "git_sha": sha} for c in rg.COMPONENTS}


STATE = {"last_sequence": 6, "last_sha": PARENT, "seen": [], "images": images(PARENT), "configs": configs()}


def transact(keys, ledger, m, signer="gateway", *, policy_over=None, min_version=None, apply=lambda m: None,
             host=None, prod=None):
    raw = rg.canonical(m)
    praw, psig = signed_policy(keys, **(policy_over or {}))
    prod = prod or Production(json.loads(ledger.read_text()).get("last_sha", PARENT) if ledger.exists()
                              and ledger.read_text().startswith("{\"") else PARENT)

    def deploy(manifest):
        apply(manifest)                    # the driver; raising leaves production unchanged and the ledger pending
        prod.deploy(manifest["sha"])
    return rg.release_transaction(ledger, raw, rg.sign(raw, keys[signer][0], rg.NS_RELEASE), policy_bytes=praw,
                                  policy_sig=psig, founder_key=keys["founder"][1], host_facts=host or facts(),
                                  now=NOW, apply=deploy, observe=prod.observe)


def release(keys, policy, m, signer="gateway", *, host=None, state=None, namespace=rg.NS_RELEASE, raw=None):
    raw = raw if raw is not None else rg.canonical(m)
    sig = rg.sign(raw, keys[signer][0], namespace)
    return rg.verify_release(raw, sig, policy=policy, founder_key=keys["founder"][1], host_facts=host or facts(),
                             state=STATE if state is None else state, now=NOW)


def refused(match, fn, *args, **kwargs):
    with pytest.raises(rg.Refused, match=match):
        fn(*args, **kwargs)


# --------------------------------------------------------------------------- the autonomous path works

def test_a_low_risk_release_signed_by_the_gateway_is_accepted_and_recorded(keys, policy, tmp_path):
    m = manifest()
    rg.gateway_approve(m, policy, now=NOW, diff=DIFF)
    assert release(keys, policy, m)["sha"] == SHA
    ledger, applied = tmp_path / "ledger.json", []
    ledger.write_text(json.dumps(STATE))
    transact(keys, ledger, m, apply=applied.append)
    state = json.loads(ledger.read_text())
    assert applied == [m] and "pending" not in state
    assert state["last_sequence"] == 7 and state["last_sha"] == SHA and len(state["seen"]) == 1


def test_a_high_risk_or_migration_release_signed_by_the_founder_is_accepted(keys, policy):
    paths = ["migrations/versions/x.py", ".github/workflows/ci.yml"]
    m = manifest(changed_paths=paths, migration_to="abcdef012345", approver="founder")
    assert release(keys, policy, m, "founder", host=facts(changed_paths=paths))["migration_to"] == "abcdef012345"


# --------------------------------------------------------------------------- replay and ordering

def test_replaying_an_applied_manifest_is_refused(keys, policy, tmp_path):
    m = manifest()
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(STATE))
    transact(keys, ledger, m)
    state = json.loads(ledger.read_text()) | {"last_sha": PARENT, "last_sequence": 6}   # even if sequence is reset
    refused("replay", release, keys, policy, m, state=state)
    refused("replay", transact, keys, ledger, m)


@pytest.mark.parametrize("sequence", [6, 5, 1])
def test_a_sequence_at_or_below_the_last_release_is_refused(keys, policy, sequence):
    refused("sequence", release, keys, policy, manifest(sequence=sequence))


def test_a_release_that_does_not_continue_from_the_applied_one_is_refused(keys, policy):
    refused("does not continue", release, keys, policy, manifest(parent_sha=OTHER))
    refused("does not descend", release, keys, policy, manifest(), host=facts(ancestor_of_parent=False))


# --------------------------------------------------------------------------- tampering and wrong content

def test_a_manifest_changed_after_signing_is_refused(keys, policy):
    m = manifest()
    raw = rg.canonical(m)
    sig = rg.sign(raw, keys["gateway"][0], rg.NS_RELEASE)
    forged = rg.canonical(m | {"sha": OTHER})
    refused("not signed", rg.verify_release, forged, sig, policy=policy, founder_key=keys["founder"][1],
            host_facts=facts(sha=OTHER), state=STATE, now=NOW)


def test_a_non_canonical_encoding_is_refused(keys, policy):
    refused("canonical", release, keys, policy, manifest(), raw=json.dumps(manifest(), indent=1).encode())


def test_the_host_recomputes_content_and_refuses_any_mismatch(keys, policy):
    refused("different commit", release, keys, policy, manifest(), host=facts(sha=OTHER))
    refused("payload digest", release, keys, policy, manifest(), host=facts(payload_digest="0" * 64))
    refused("another repository", release, keys, policy, manifest(), host=facts(repository="evil/os"))


def test_understating_the_changed_paths_cannot_hide_a_high_risk_change(keys, policy):
    # The manifest lists only harmless paths; the host's own diff also touches the deploy workflow.
    refused("changed paths differ", release, keys, policy, manifest(),
            host=facts(changed_paths=[*LOW, ".github/workflows/ci.yml"]))


# --------------------------------------------------------------------------- who may approve what

@pytest.mark.parametrize("path", ["app/api_auth/__init__.py", "app/__init__.py", "app/models.py",
                                  "app/api_auth.cpython-312-x86_64-linux-gnu.so", "skills/x/SKILL.md", "tests/conftest.py",
                                  "desk/src/App.tsx", "app/static/desk.html", "docs/security/RELEASE_GATEWAY.md",
                                  "docs/../scripts/x.sh", "./docs/x.md", "docs/\u00e9.md", '"docs/x.md"', "docs//x.md",
                                  ".github/workflows/ci.yml", "agents/release_policy.json", "scripts/deploy-company-os.sh",
                                  "app/release_gateway.py", "app/stage_c_worker.py", "migrations/versions/x.py",
                                  "docker-compose.yml", "requirements.txt", "CLAUDE.md", "app/api_auth.py"])
def test_the_gateway_cannot_release_a_high_risk_path(keys, policy, path):
    paths = [*LOW, path]
    m = manifest(changed_paths=paths)
    refused("founder", rg.gateway_approve, m, policy, now=NOW, diff=DIFF)
    refused("high-risk", release, keys, policy, m, host=facts(changed_paths=paths))   # even with a stolen gateway key


def test_the_gateway_cannot_authorize_a_migration(keys, policy):
    m = manifest(migration_to="abcdef012345")
    refused("founder", rg.gateway_approve, m, policy, now=NOW, diff=DIFF)
    refused("migration", release, keys, policy, m)


def test_an_agent_key_or_the_wrong_role_key_is_refused(keys, policy):
    refused("not signed by the gateway", release, keys, policy, manifest(), "agent")
    refused("not signed by the founder", release, keys, policy, manifest(approver="founder"), "gateway")


def test_a_signature_from_another_namespace_is_refused(keys, policy):
    # A founder policy signature must never double as a release approval.
    refused("not signed", release, keys, policy, manifest(approver="founder"), "founder", namespace=rg.NS_POLICY)


def test_turning_off_automatic_release_leaves_only_founder_releases(keys):
    raw, sig = signed_policy(keys, auto_release=False)
    policy = rg.load_policy(raw, sig, keys["founder"][1])
    refused("switched off", rg.gateway_approve, manifest(), policy, now=NOW, diff=DIFF)
    refused("switched off", release, keys, policy, manifest())
    assert release(keys, policy, manifest(approver="founder"), "founder")


# --------------------------------------------------------------------------- evidence

@pytest.mark.parametrize("checks", [
    None,
    {"runner": "github-actions", "sha": SHA, "payload_digest": DIGEST, "passed": True},   # agent-editable CI
    {"runner": "gateway", "sha": OTHER, "payload_digest": DIGEST, "passed": True},
    {"runner": "gateway", "sha": SHA, "payload_digest": "0" * 64, "passed": True},
    {"runner": "gateway", "sha": SHA, "payload_digest": DIGEST, "passed": False},
])
def test_without_passing_trusted_checks_for_this_exact_payload_nothing_ships(keys, policy, checks):
    m = manifest()
    m["evidence"] = m["evidence"] | {"trusted_checks": checks}
    refused("trusted checks", rg.gateway_approve, m, policy, now=NOW, diff=DIFF)
    refused("trusted checks", release, keys, policy, m)


@pytest.mark.parametrize("review, why", [
    (lambda: None, "independent review missing"),
    (lambda: ["x"], "independent review missing"),
    (lambda: signed_review() | {"nonce": "zz"}, "independent review missing"),
    (lambda: signed_review(key="agent"), "not signed by the enrolled reviewer"),          # the worker forging it
    (lambda: signed_review(key="founder"), "not signed by the enrolled reviewer"),
    (lambda: signed_review(reviewer="claude"), "not signed by a reviewer identity enrolled"),
    (lambda: signed_review(reviewer="Codex "), "not signed by a reviewer identity enrolled"),
    (lambda: signed_review(nonce="cd" * 16) | {"nonce": NONCE}, "another diff"),         # reused for another request
    (lambda: signed_review(diff=DIFF + "+sneaked in\n"), "another diff"),                  # reviewed a different diff
    (lambda: signed_review(sha=OTHER), "another diff"),
    (lambda: signed_review(base=OTHER), "another diff"),
    (lambda: signed_review(output={"verdict": "REJECT", "fingerprint": rg.review_packet(
        "seerxo/os", PARENT, SHA, DIFF, NONCE)["fingerprint"], "findings": ["no"]}), "does not approve"),
    (lambda: signed_review(output={"verdict": "APPROVE", "fingerprint": "f" * 64, "findings": []}), "does not approve"),
    (lambda: signed_review(att_over={"prompt_sha256": "0" * 64}), "other instructions"),
    (lambda: signed_review(issued=NOW - timedelta(days=2)), "stale"),
    (lambda: signed_review(issued=NOW + timedelta(hours=1)), "future"),
    (lambda: signed_review(att_over={"extra": 1}), "fields"),
])
def test_a_signed_independent_review_of_this_exact_diff_is_required(keys, policy, review, why):
    m = manifest()
    m["evidence"] = m["evidence"] | {"review": review()}
    refused(why, rg.gateway_approve, m, policy, now=NOW, diff=DIFF)
    refused(why, release, keys, policy, m)


def test_a_signed_review_cannot_be_moved_onto_a_tampered_signature(keys, policy):
    review = signed_review()
    review["attestation"] = review["attestation"] | {"verdict": "APPROVE", "issued_at": NOW.isoformat()}
    review["signature"] = signed_review(output={"verdict": "REJECT", "fingerprint": "x", "findings": []})["signature"]
    m = manifest()
    m["evidence"] = m["evidence"] | {"review": review}
    refused("not signed by the enrolled reviewer", release, keys, policy, m)


def test_the_host_reviews_its_own_diff_not_the_gateways(keys, policy):
    # The gateway (or a stolen gateway key) cannot pair a harmless reviewed diff with different shipped content.
    refused("another diff", release, keys, policy, manifest(), host=facts(diff=DIFF.replace("+new", "+evil")))
    refused("could not compute", release, keys, policy, manifest(), host=facts(diff=None))


def test_even_a_founder_signed_release_needs_the_independent_review(keys, policy):
    m = manifest(approver="founder")
    m["evidence"] = m["evidence"] | {"review": signed_review(key="founder")}
    refused("not signed by the enrolled reviewer", release, keys, policy, m, "founder")


# --------------------------------------------------------------------------- time and policy binding

@pytest.mark.parametrize("over, why", [
    ({"expires_at": (NOW - timedelta(seconds=1)).isoformat()}, "expired"),
    ({"issued_at": (NOW + timedelta(hours=1)).isoformat()}, "future"),
    ({"issued_at": (NOW - timedelta(days=2)).isoformat(), "expires_at": (NOW + timedelta(hours=1)).isoformat()},
     "lifetime"),
    ({"expires_at": "2026-10-17T14:00:00"}, "timezone"),
    ({"policy_version": 2}, "policy version"),
])
def test_stale_future_or_other_policy_manifests_are_refused(keys, policy, over, why):
    refused(why, release, keys, policy, manifest(**over))


def test_only_a_founder_signed_policy_counts(keys):
    raw, sig = signed_policy(keys, signer="gateway")
    refused("founder key", rg.load_policy, raw, sig, keys["founder"][1])
    raw, sig = signed_policy(keys)
    tampered = rg.canonical(json.loads(raw) | {"auto_release": True, "high_risk_paths": []})
    refused("founder key", rg.load_policy, tampered, sig, keys["founder"][1])


@pytest.mark.parametrize("over, why", [
    ({"require_trusted_checks": False}, "switch off"),
    ({"require_independent_review": False}, "switch off"),
    ({"extra": 1}, "fields"),
    ({"auto_release": "false"}, "true or false"),
    ({"high_risk_paths": []}, "malformed"),
    ({"require_trusted_checks": "yes"}, "switch off"),
    ({"max_changed_paths": "40"}, "positive integer"),
    ({"max_changed_paths": 0}, "positive integer"),
    ({"gateway_key": None}, "non-empty strings"),
    ({"reviewer_keys": {}}, "disjoint"),
    ({"coders": ["codex"]}, "disjoint"),
    ({"reviewer_keys": {"founder": "ssh-ed25519 AAAA"}}, "disjoint"),
    ({"reviewer_keys": {"codex": ""}}, "disjoint"),
])
def test_even_a_founder_signed_policy_cannot_remove_the_floor(keys, over, why):
    raw, sig = signed_policy(keys, **over)
    refused(why, rg.load_policy, raw, sig, keys["founder"][1])


def test_the_gateway_key_cannot_be_the_founder_key(keys):
    raw, sig = signed_policy(keys, gateway_key=keys["founder"][1])
    refused("must differ", rg.load_policy, raw, sig, keys["founder"][1])


@pytest.mark.parametrize("over, why", [
    ({"sha": "ABC"}, "40 lowercase"), ({"migration_to": "zz"}, "12 lowercase"), ({"sequence": 0}, "positive"),
    ({"approver": "agent"}, "approver"), ({"version": 2}, "version"), ({"payload_digest": "x"}, "sha256"),
    ({"sequence": True}, "positive"), ({"policy_version": True}, "integer"), ({"repository": ["seerxo/os"]}, "strings"),
    ({"issued_at": 5}, "ISO-8601"), ({"issued_at": "yesterday"}, "ISO-8601"), ({"evidence": ["x"]}, "object"),
])
def test_malformed_manifests_are_refused_before_any_signature_work(keys, policy, over, why):
    refused(why, release, keys, policy, manifest(**over))


def test_classification_fails_closed(policy):
    assert rg.classify(LOW, policy) == "low"
    assert rg.classify([], policy) == "high"                                          # unknown change set
    assert rg.classify([f"desk/{i}.ts" for i in range(policy["max_changed_paths"] + 1)], policy) == "high"


def test_verify_never_raises_on_garbage(keys):
    assert rg.verify(b"x", "not a signature", keys["gateway"][1], rg.NS_RELEASE) is False
    assert rg.verify(b"x", "", "not-a-key", rg.NS_RELEASE) is False


# --------------------------------------------------------------------------- first release, lost ledger, crashes

def test_without_a_bootstrapped_baseline_nothing_is_released_not_even_by_the_founder(keys, policy, tmp_path):
    for state in ({}, {"last_sequence": 0}):
        refused("not bootstrapped", release, keys, policy, manifest(), state=state)
        refused("not bootstrapped", release, keys, policy, manifest(approver="founder"), "founder", state=state)


def test_deleting_the_ledger_does_not_reopen_automatic_release(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(STATE))
    transact(keys, ledger, manifest())
    ledger.unlink()
    refused("not bootstrapped", transact, keys, ledger, manifest(sequence=8, parent_sha=SHA))
    refused("not bootstrapped", transact, keys, ledger, manifest(sequence=8, parent_sha=SHA, approver="founder"),
            "founder")


def test_an_unreadable_ledger_refuses_everything(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text("{not json")
    refused("unreadable", transact, keys, ledger, manifest(approver="founder"), "founder")


def test_a_crash_or_failure_during_apply_fails_closed(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(STATE))

    def boom(m):
        raise RuntimeError("deploy driver died")

    with pytest.raises(RuntimeError):
        transact(keys, ledger, manifest(), apply=boom)
    assert json.loads(ledger.read_text())["pending"]
    refused("reconcile", transact, keys, ledger, manifest())                          # not even a retry of itself
    refused("reconcile", transact, keys, ledger, manifest(sequence=9, approver="founder"), "founder")


def test_an_older_founder_signed_policy_cannot_be_replayed(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(STATE))
    transact(keys, ledger, manifest(policy_version=2), policy_over={"version": 2})
    assert json.loads(ledger.read_text())["min_policy_version"] == 2
    refused("older than the newest", transact, keys, ledger, manifest(sequence=8, parent_sha=SHA))


def test_the_transaction_holds_one_lock_for_verify_apply_and_record(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(STATE))
    seen = []

    def apply(m):
        # While this release is applying, a second process cannot even read the ledger to verify.
        import fcntl
        with open(ledger.with_name(ledger.name + ".lock"), "a") as other:
            with pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        seen.append(m["sha"])

    transact(keys, ledger, manifest(), apply=apply)
    assert seen == [SHA]


# --------------------------------------------------------------------------- the host's own diff

def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def test_the_host_diff_lists_both_sides_of_a_rename_and_never_quotes_a_path(tmp_path, policy):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@t")
    git(repo, "config", "user.name", "t")
    (repo / "scripts").mkdir()
    (repo / "scripts/deploy.sh").write_text("echo deploy\n")
    (repo / "docs").mkdir()
    (repo / "docs/a.md").write_text("a\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "mv", "scripts/deploy.sh", "docs/deploy.md")                  # hide a high-risk file by renaming it
    (repo / "docs/\u00e9.md").write_text("x\n")                               # a name git would C-quote
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "change")
    paths = rg.git_changed_paths(repo, base, git(repo, "rev-parse", "HEAD"))
    assert "scripts/deploy.sh" in paths and "docs/deploy.md" in paths and "docs/\u00e9.md" in paths
    assert rg.classify(paths, policy) == "high"
    assert rg.classify(["docs/deploy.md"], policy) == "low"                 # the rename alone would have looked low


@pytest.mark.parametrize("who", ["founder", "gateway"])
def test_a_reviewer_key_cannot_be_the_founder_or_gateway_key(keys, who):
    raw, sig = signed_policy(keys, reviewer_keys={"codex": keys[who][1]})
    refused("must differ", rg.load_policy, raw, sig, keys["founder"][1])


# --------------------------------------------------------------------------- production identity (host, under the lock)

def bootstrapped(tmp_path, sha=PARENT):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({**STATE, "last_sha": sha, "images": images(sha)}))
    return ledger


@pytest.mark.parametrize("drift", [
    lambda p: p.running["worker"].update(git_sha=OTHER),                       # components disagree on the SHA
    lambda p: p.running["reasoner"].update(image=image("reasoner", OTHER)),  # one image swapped
    lambda p: p.deploy(OTHER),                                                 # legacy CI/SSH deploy happened
    lambda p: p.running.pop("reasoner"),                                       # a component not observable
    lambda p: p.running["api"].update(image="company-os-api:latest"),         # a tag is not identity
])
def test_production_that_is_not_exactly_the_recorded_release_blocks_everything(keys, tmp_path, drift):
    ledger, prod = bootstrapped(tmp_path), Production(PARENT)
    drift(prod)
    before = ledger.read_text()
    refused("BLOCKED", transact, keys, ledger, manifest(), prod=prod)
    refused("BLOCKED", transact, keys, ledger, manifest(approver="founder"), "founder", prod=prod)
    assert ledger.read_text() == before and not rg.read_history(ledger)        # nothing written, not even pending


def test_a_ledger_without_recorded_image_identity_blocks(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({k: v for k, v in STATE.items() if k != "images"}))
    refused("no trusted image identity", transact, keys, ledger, manifest())


def test_production_must_run_exactly_the_release_after_apply_or_the_ledger_stays_pending(keys, tmp_path):
    ledger, prod = bootstrapped(tmp_path), Production(PARENT)

    def half_deployed(m):
        prod.deploy(m["sha"])
        prod.running["reasoner"] = {"image": image("reasoner", PARENT), "git_sha": PARENT}   # one did not switch
    with pytest.raises(RuntimeError, match="does not run the release after apply"):
        rg.release_transaction(ledger, rg.canonical(manifest()), rg.sign(rg.canonical(manifest()),
                               keys["gateway"][0], rg.NS_RELEASE), policy_bytes=signed_policy(keys)[0],
                               policy_sig=signed_policy(keys)[1], founder_key=keys["founder"][1],
                               host_facts=facts(), now=NOW, apply=half_deployed, observe=prod.observe)
    assert json.loads(ledger.read_text())["pending"] and not rg.read_history(ledger)


def test_an_applied_release_records_the_new_image_identity(keys, tmp_path):
    ledger, prod = bootstrapped(tmp_path), Production(PARENT)
    transact(keys, ledger, manifest(), prod=prod)
    state = json.loads(ledger.read_text())
    assert state["last_sha"] == SHA and state["images"] == images(SHA)
    assert [e["event"] for e in rg.read_history(ledger)] == ["applied"]


# --------------------------------------------------------------------------- founder bootstrap

HOST = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def statement(keys, kind="bootstrap", *, signer="founder", namespace=None, **over):
    praw = signed_policy(keys)[0]
    base = {"kind": kind, "host_id": HOST, "repository": "seerxo/os", "branch": "main", "nonce": "cd" * 16,
            "images": images(PARENT), "configs": configs(), "issued_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(hours=1)).isoformat()}
    if kind == "bootstrap":
        base |= {"policy_sha256": __import__("hashlib").sha256(praw).hexdigest(), "release_sha": PARENT}
    raw = rg.canonical(base | over)
    ns = namespace or (rg.NS_BOOTSTRAP if kind == "bootstrap" else rg.NS_RECOVERY)
    return raw, rg.sign(raw, keys[signer][0], ns)


def do_bootstrap(keys, ledger, raw_sig, prod=None, host=HOST):
    praw, psig = signed_policy(keys)
    return rg.bootstrap(ledger, raw_sig[0], raw_sig[1], founder_key=keys["founder"][1], policy_bytes=praw,
                        policy_sig=psig, host_id=host, observe=(prod or Production(PARENT)).observe, now=NOW)


def test_a_founder_signed_bootstrap_matching_production_establishes_the_baseline(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    state = do_bootstrap(keys, ledger, statement(keys))
    assert state["last_sha"] == PARENT and state["images"] == images(PARENT) and state["last_sequence"] == 0
    assert [e["event"] for e in rg.read_history(ledger)] == ["bootstrap"]
    assert transact(keys, ledger, manifest(sequence=1))["sha"] == SHA               # the gateway may now release


@pytest.mark.parametrize("make, why", [
    (lambda k: statement(k, signer="gateway"), "not signed by the pinned founder"),
    (lambda k: statement(k, namespace=rg.NS_POLICY), "not signed by the pinned founder"),
    (lambda k: statement(k, namespace=rg.NS_RECOVERY), "not signed by the pinned founder"),
    (lambda k: statement(k, host_id="ffff" * 8), "another host"),
    (lambda k: statement(k, repository="evil/os"), "another repository"),
    (lambda k: statement(k, policy_sha256="0" * 64), "different policy"),
    (lambda k: statement(k, expires_at=(NOW - timedelta(seconds=1)).isoformat()), "expired"),
    (lambda k: statement(k, issued_at=(NOW + timedelta(hours=1)).isoformat()), "future"),
    (lambda k: statement(k, release_sha=OTHER), "does not match the bootstrap"),       # production runs PARENT
    (lambda k: statement(k, images=images(OTHER)), "does not match the bootstrap"),
    (lambda k: statement(k, images={"api": image("api", PARENT)}), "image ID"),
    (lambda k: statement(k, nonce="1"), "nonce"),
    (lambda k: statement(k, extra=1), "shape"),
])
def test_an_invalid_bootstrap_is_refused_and_writes_nothing(keys, tmp_path, make, why):
    ledger = tmp_path / "ledger.json"
    refused(why, do_bootstrap, keys, ledger, make(keys))
    assert not ledger.exists() and not rg.history_path(ledger).exists()


def test_bootstrap_without_a_host_identity_is_refused(keys, tmp_path):
    refused("machine-id", do_bootstrap, keys, tmp_path / "ledger.json", statement(keys), host="")


def test_bootstrap_cannot_run_twice_or_reset_a_ledger(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    st = statement(keys)
    do_bootstrap(keys, ledger, st)
    refused("cannot reset", do_bootstrap, keys, ledger, st)                          # replay
    ledger.unlink()                                                                  # "reset" by deletion
    refused("cannot reset", do_bootstrap, keys, ledger, statement(keys, nonce="ef" * 16))
    refused("not bootstrapped", transact, keys, ledger, manifest(sequence=1))         # and nothing auto-releases


# --------------------------------------------------------------------------- founder recovery of a lost ledger

def lose_ledger_after_one_release(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    do_bootstrap(keys, ledger, statement(keys))
    m = manifest(sequence=1)
    prod = Production(PARENT)
    transact(keys, ledger, m, prod=prod)
    ledger.unlink()
    return ledger, m, prod


def recovery(keys, ledger, prod, **over):
    digest = __import__("hashlib").sha256(rg.history_path(ledger).read_bytes()).hexdigest()
    raw_sig = statement(keys, "recovery", **({"history_sha256": digest, "last_sha": SHA, "last_sequence": 1,
                                              "images": images(SHA)} | over))
    praw, psig = signed_policy(keys)
    return raw_sig, lambda: rg.recover(ledger, raw_sig[0], raw_sig[1], founder_key=keys["founder"][1],
                                       policy_bytes=praw, policy_sig=psig, host_id=HOST, observe=prod.observe,
                                       now=NOW)


def test_recovery_rebuilds_seen_and_the_sequence_floor_so_nothing_replays(keys, tmp_path):
    ledger, m, prod = lose_ledger_after_one_release(keys, tmp_path)
    _, run = recovery(keys, ledger, prod)
    state = run()
    assert state["last_sha"] == SHA and state["last_sequence"] == 1 and state["images"] == images(SHA)
    refused("replay", transact, keys, ledger, m, prod=prod)                          # the applied manifest stays used
    assert [e["event"] for e in rg.read_history(ledger)] == ["bootstrap", "applied", "recovery"]


@pytest.mark.parametrize("over, why", [
    ({"history_sha256": "0" * 64}, "different release history"),
    ({"last_sequence": 0}, "lower the release sequence"),
    ({"last_sha": PARENT, "images": images(PARENT)}, "does not match the recovery"),   # production runs SHA
    ({"host_id": "ffff" * 8}, "another host"),
])
def test_an_invalid_recovery_is_refused(keys, tmp_path, over, why):
    ledger, _, prod = lose_ledger_after_one_release(keys, tmp_path)
    _, run = recovery(keys, ledger, prod, **over)
    refused(why, run)
    assert not ledger.exists()


def test_recovery_needs_its_own_founder_authorization_and_is_single_use(keys, tmp_path):
    ledger, _, prod = lose_ledger_after_one_release(keys, tmp_path)
    digest = __import__("hashlib").sha256(rg.history_path(ledger).read_bytes()).hexdigest()
    body = {"history_sha256": digest, "last_sha": SHA, "last_sequence": 1, "images": images(SHA)}
    raw, sig = statement(keys, "recovery", namespace=rg.NS_BOOTSTRAP, **body)       # bootstrap authority is not enough
    praw, psig = signed_policy(keys)
    args = dict(founder_key=keys["founder"][1], policy_bytes=praw, policy_sig=psig, host_id=HOST,
                observe=prod.observe, now=NOW)
    refused("not signed by the pinned founder", rg.recover, ledger, raw, sig, **args)
    (raw, sig), run = recovery(keys, ledger, prod)
    run()
    refused("intact", rg.recover, ledger, raw, sig, **args)                          # not over an intact ledger
    ledger.write_text("{corrupt")
    refused("different release history", rg.recover, ledger, raw, sig, **args)       # history moved on: no replay


def test_bootstrap_or_recovery_cannot_run_on_unreadable_history(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    rg.history_path(ledger).write_text("not json\n")
    refused("cannot reset", do_bootstrap, keys, ledger, statement(keys))
    _, run = recovery(keys, ledger, Production(SHA))
    refused("unreadable", run)


# --------------------------------------------------------------------------- S1 mutation survivors (2026-10-17)

def test_identity_needs_a_recorded_image_for_every_component():
    prod = Production(PARENT)
    partial = {c: v for c, v in images(PARENT).items() if c != "reasoner"}
    assert "no trusted image identity" in rg.identity_problem(prod.observe(), PARENT, partial, configs())
    assert "no trusted image identity" in rg.identity_problem(prod.observe(), PARENT, None, configs())


def test_identity_refuses_a_tag_or_malformed_image_even_if_it_matches_the_record():
    observed = {c: {"image": "company-os-api:latest", "config": config(c), "git_sha": PARENT} for c in rg.COMPONENTS}
    recorded = {c: "company-os-api:latest" for c in rg.COMPONENTS}
    assert "identity unavailable" in rg.identity_problem(observed, PARENT, recorded, configs())


def test_bootstrap_refuses_a_host_that_has_a_ledger_even_without_history(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text("{}")
    refused("cannot reset", do_bootstrap, keys, ledger, statement(keys))
    assert not rg.history_path(ledger).exists()


def test_bootstrap_needs_a_full_release_sha_even_if_production_reports_the_same_string(keys, tmp_path):
    prod = Production(PARENT)
    for c in rg.COMPONENTS:
        prod.running[c]["git_sha"] = "main"
    ledger = tmp_path / "ledger.json"
    refused("40-hex", do_bootstrap, keys, ledger, statement(keys, release_sha="main"), prod=prod)
    assert not ledger.exists()


def test_bootstrap_needs_the_founder_signed_policy(keys, tmp_path):
    praw, _ = signed_policy(keys)
    ledger = tmp_path / "ledger.json"
    with pytest.raises(rg.Refused, match="release policy is not signed"):
        rg.bootstrap(ledger, *statement(keys), founder_key=keys["founder"][1], policy_bytes=praw,
                     policy_sig=rg.sign(praw, keys["gateway"][0], rg.NS_POLICY), host_id=HOST,
                     observe=Production(PARENT).observe, now=NOW)
    assert not ledger.exists() and not rg.history_path(ledger).exists()


def test_a_bootstrap_statement_must_say_bootstrap_and_be_canonical(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    body = json.loads(statement(keys)[0])
    for raw, why in ((rg.canonical(body | {"kind": "recovery"}), "wrong shape"),
                     (json.dumps(body, indent=1).encode(), "not canonical")):       # same content, other bytes
        refused(why, do_bootstrap, keys, ledger, (raw, rg.sign(raw, keys["founder"][0], rg.NS_BOOTSTRAP)))
    assert not ledger.exists() and not rg.history_path(ledger).exists()


def test_a_statement_valid_for_longer_than_the_maximum_is_refused(keys, tmp_path):
    over = {"issued_at": (NOW - timedelta(days=2)).isoformat(), "expires_at": (NOW + timedelta(hours=1)).isoformat()}
    refused("too long-lived", do_bootstrap, keys, tmp_path / "ledger.json", statement(keys, **over))


def test_a_statement_must_name_well_formed_image_ids(keys, tmp_path):
    refused("image ID", do_bootstrap, keys, tmp_path / "ledger.json",
            statement(keys, images={c: f"company-os-{c}:latest" for c in rg.COMPONENTS}))


def test_recovery_without_any_history_is_refused_cleanly(keys, tmp_path):
    praw, psig = signed_policy(keys)
    raw, sig = statement(keys, "recovery", history_sha256="0" * 64, last_sha=SHA, last_sequence=1,
                         images=images(SHA))
    refused("no release history", rg.recover, tmp_path / "ledger.json", raw, sig, founder_key=keys["founder"][1],
            policy_bytes=praw, policy_sig=psig, host_id=HOST, observe=Production(SHA).observe, now=NOW)


def test_recovery_keeps_every_applied_digest_and_the_policy_floor_from_history(keys, tmp_path):
    ledger, m, prod = lose_ledger_after_one_release(keys, tmp_path)
    path = rg.history_path(ledger)
    events = rg.read_history(ledger)
    path.write_bytes(b"".join(rg.canonical(e | {"policy_version": 2}) + b"\n" for e in events))   # floor is now 2
    _, run = recovery(keys, ledger, prod)
    refused("older than the newest", run)                                           # a v1 policy cannot recover
    path.write_bytes(b"".join(rg.canonical(e) + b"\n" for e in events))
    _, run = recovery(keys, ledger, prod)
    state = run()
    assert __import__("hashlib").sha256(rg.canonical(m)).hexdigest() in state["seen"]


def test_recovery_needs_a_full_release_sha_even_if_production_reports_the_same_string(keys, tmp_path):
    ledger, _, prod = lose_ledger_after_one_release(keys, tmp_path)
    for c in rg.COMPONENTS:
        prod.running[c]["git_sha"] = "main"
    _, run = recovery(keys, ledger, prod, last_sha="main")
    refused("40-hex", run)
    assert not ledger.exists()


def test_nothing_the_release_ships_is_low_risk_under_the_proposed_policy():
    # The gateway may sign only what never reaches a running image or the host: every shipped path (DEPLOY_PATHS,
    # the deploy script's PATHS) must classify HIGH, so widening low_risk_paths into them fails here first.
    policy = json.loads((Path(__file__).parents[1] / "agents/release_policy.json").read_text())
    directories = {"app", "migrations", "scripts", "agents", "skills", "tests"}
    assert directories < set(rg.DEPLOY_PATHS)
    for root in rg.DEPLOY_PATHS:
        inside = (f"{root}/x.py", f"{root}/sub/README.md", f"{root}/__init__.py") if root in directories else ()
        for path in (root, *inside):
            assert rg.classify([path], policy) == "high", path
    assert rg.classify(["docs/HANDOFF.md"], policy) == "low"


# --------------------------------------------------------------------------- P1-3: the reviewer judges, policy classifies

HIGH = ["migrations/versions/x.py", "app/api_auth.py", "scripts/deploy-company-os.sh"]
REJECTED = {"verdict": "REJECT", "fingerprint": rg.review_packet("seerxo/os", PARENT, SHA, DIFF, NONCE)["fingerprint"],
            "findings": ["drops a column without a backup"]}


def test_the_reviewer_is_told_to_judge_the_diff_not_its_category_or_its_approval():
    prompt = rg.RELEASE_REVIEW_PROMPT.lower()
    assert "reject auth, billing" not in prompt                         # no category veto: HIGH can be approved
    assert "migration" in prompt and "rollback" in prompt               # ...but named for extra care
    assert "signature" in prompt and "never a reason to approve" in prompt
    assert rg.REVIEW_PROMPT_SHA256 == __import__("hashlib").sha256(rg.RELEASE_REVIEW_PROMPT.encode()).hexdigest()
    # The packet carries no approval or risk state the reviewer could lean on.
    assert rg.PACKET_FIELDS == {"kind", "repository", "base", "sha", "nonce", "fingerprint", "diff"}


def test_high_risk_with_founder_signature_and_reviewer_approve_is_accepted(keys, policy):
    m = manifest(changed_paths=HIGH, migration_to="abcdef012345", approver="founder")
    assert rg.classify(HIGH, policy) == "high"                          # deterministic, by policy, never the model
    assert release(keys, policy, m, "founder", host=facts(changed_paths=HIGH))["sha"] == SHA


def test_high_risk_without_the_founder_signature_is_refused(keys, policy):
    refused("founder signature required", release, keys, policy, manifest(changed_paths=HIGH),
            host=facts(changed_paths=HIGH))
    refused("not signed by the founder", release, keys, policy, manifest(changed_paths=HIGH, approver="founder"),
            "gateway", host=facts(changed_paths=HIGH))


@pytest.mark.parametrize("review, why", [
    (lambda: signed_review(output=REJECTED), "does not approve"),       # a founder signature never overrides REJECT
    (lambda: signed_review(key="agent"), "not signed by the enrolled reviewer"),
    (lambda: signed_review(key="founder"), "not signed by the enrolled reviewer"),
    (lambda: signed_review(diff=DIFF + "+more\n"), "another diff"),
    (lambda: signed_review(att_over={"prompt_sha256": "0" * 64}), "other instructions"),
    (lambda: None, "independent review missing"),
])
def test_high_risk_founder_signed_but_without_a_valid_approving_review_is_refused(keys, policy, review, why):
    m = manifest(changed_paths=HIGH, migration_to="abcdef012345", approver="founder")
    m["evidence"] = m["evidence"] | {"review": review()}
    refused(why, release, keys, policy, m, "founder", host=facts(changed_paths=HIGH))


def test_a_rollback_to_an_older_commit_is_refused_even_founder_signed(keys, policy):
    target = OTHER                                                      # not a descendant of the applied release
    # Rolling back is a new reviewed commit that descends from the applied release (a revert). Pointing production
    # at an older tree directly, trusted history or not, never verifies: no emergency bypass.
    m = manifest(sha=target, approver="founder")
    refused("descend|different commit|continue", release, keys, policy, m, "founder",
            host=facts(sha=target, ancestor_of_parent=False))


# --------------------------------------------------------------------------- P2-4: configuration is identity

@pytest.mark.parametrize("recorded", [None, {"api": "0" * 64}, {c: "not-a-digest" for c in rg.COMPONENTS}])
def test_identity_needs_a_recorded_configuration_for_every_component(recorded):
    assert "no trusted container configuration" in rg.identity_problem(Production(PARENT).observe(), PARENT,
                                                                       images(PARENT), recorded)


def test_the_same_image_with_another_configuration_is_blocked(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(STATE))
    prod = Production(PARENT)
    prod.running["worker"]["config"] = "f" * 64                     # e.g. recreated privileged or with docker.sock
    refused("BLOCKED: worker: container configuration", transact, keys, ledger, manifest(), prod=prod)
    assert "pending" not in json.loads(ledger.read_text())


def test_the_configuration_after_apply_is_recorded_from_observation(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(STATE))
    transact(keys, ledger, manifest())
    state = json.loads(ledger.read_text())
    assert state["configs"] == configs() and rg.read_history(ledger)[-1]["configs"] == configs()


def test_bootstrap_records_the_observed_configuration(keys, tmp_path):
    state = do_bootstrap(keys, tmp_path / "ledger.json", statement(keys))
    assert state["configs"] == configs()


# --------------------------------------------------------------------------- V3-3: the founder attests configuration

@pytest.mark.parametrize("bad, why", [
    ({"api": "0" * 64}, "configuration digest"),                               # the statement itself is checked
    ({c: "not-hex" for c in rg.COMPONENTS}, "configuration digest"),
    ({**configs(), "worker": "f" * 64}, "does not match the bootstrap"),       # production runs another config
])
def test_the_bootstrap_statement_must_name_the_running_configuration(keys, tmp_path, bad, why):
    ledger = tmp_path / "ledger.json"
    refused(why, do_bootstrap, keys, ledger, statement(keys, configs=bad))
    assert not ledger.exists()


def test_the_recovery_statement_must_name_the_running_configuration(keys, tmp_path):
    ledger, _, prod = lose_ledger_after_one_release(keys, tmp_path)
    _, run = recovery(keys, ledger, prod, configs={**configs(), "api": "e" * 64})
    refused("does not match the recovery", run)
    assert not ledger.exists()


# --------------------------------------------------------------------------- V3-11: history file handling

def test_history_is_never_written_through_a_link(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    victim = tmp_path / "victim"
    rg.history_path(ledger).symlink_to(victim)                     # dangling: exists() is False
    with pytest.raises(OSError):
        do_bootstrap(keys, ledger, statement(keys))
    assert not victim.exists() and not ledger.exists()


def test_history_takes_the_shared_mode_and_the_directory_group(tmp_path):
    other = next((g for g in os.getgroups() if g != os.stat(tmp_path).st_gid), None)
    ledger = tmp_path / "ledger.json"
    path = rg.history_path(ledger)
    path.write_text("")
    path.chmod(0o644)                                              # an older, wider file
    if other is not None:
        os.chown(tmp_path, -1, other)                              # the directory's group is the gateway's group
    rg._append_history(ledger, {"event": "x"})
    assert path.stat().st_mode & 0o777 == 0o640
    if other is not None:
        assert path.stat().st_gid == other


# --------------------------------------------------------------------------- F4: founder reconcile of `pending`

def pending_after_failed_apply(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    do_bootstrap(keys, ledger, statement(keys))
    m = manifest(sequence=1)
    prod = Production(PARENT)

    def fail(_):
        raise RuntimeError("driver exited 1")
    with pytest.raises(RuntimeError):
        transact(keys, ledger, m, apply=fail, prod=prod)
    digest = __import__("hashlib").sha256(rg.canonical(m)).hexdigest()
    assert json.loads(ledger.read_text())["pending"] == digest
    return ledger, m, digest, prod


def reconcile_statement(keys, digest, *, outcome="failed", release_sha=PARENT, namespace=None, **over):
    body = {"kind": "reconcile", "host_id": HOST, "repository": "seerxo/os", "branch": "main", "nonce": "ef" * 16,
            "pending_digest": digest, "outcome": outcome, "release_sha": release_sha, "images": images(release_sha),
            "configs": configs(), "issued_at": NOW.isoformat(), "expires_at": (NOW + timedelta(hours=1)).isoformat()}
    raw = rg.canonical(body | over)
    return raw, rg.sign(raw, keys["founder"][0], namespace or rg.NS_RECONCILE)


def do_reconcile(keys, ledger, raw_sig, prod):
    praw, psig = signed_policy(keys)
    return rg.reconcile(ledger, raw_sig[0], raw_sig[1], founder_key=keys["founder"][1], policy_bytes=praw,
                        policy_sig=psig, host_id=HOST, observe=prod.observe, now=NOW)


@pytest.mark.parametrize("outcome", ["failed", "abandoned"])
def test_reconcile_a_failed_release_keeps_the_old_release_and_burns_the_manifest(keys, tmp_path, outcome):
    ledger, m, digest, prod = pending_after_failed_apply(keys, tmp_path)
    state = do_reconcile(keys, ledger, reconcile_statement(keys, digest, outcome=outcome), prod)
    assert "pending" not in state and state["last_sha"] == PARENT and state["last_sequence"] == 1
    assert digest in state["seen"] and state["images"] == images(PARENT) and state["configs"] == configs()
    assert rg.read_history(ledger)[-1]["event"] == "reconcile" and rg.read_history(ledger)[-1]["outcome"] == outcome
    refused("replay|sequence", transact, keys, ledger, m, prod=prod)            # the same manifest never applies


def test_reconcile_an_applied_release_records_what_runs(keys, tmp_path):
    ledger, m, digest, prod = pending_after_failed_apply(keys, tmp_path)
    prod.deploy(SHA)                                                      # it did switch, the record failed
    state = do_reconcile(keys, ledger, reconcile_statement(keys, digest, outcome="applied", release_sha=SHA), prod)
    assert state["last_sha"] == SHA and state["last_sequence"] == 1 and state["images"] == images(SHA)


@pytest.mark.parametrize("make, why", [
    (lambda k, d: reconcile_statement(k, d, namespace=rg.NS_RECOVERY), "not signed by the pinned founder"),
    (lambda k, d: reconcile_statement(k, d, namespace=rg.NS_BOOTSTRAP), "not signed by the pinned founder"),
    (lambda k, d: reconcile_statement(k, "0" * 64), "another pending"),
    (lambda k, d: reconcile_statement(k, d, outcome="ok"), "outcome"),
    (lambda k, d: reconcile_statement(k, d, outcome="applied"), "pending release"),        # PARENT is not the manifest
    (lambda k, d: reconcile_statement(k, d, outcome="applied", release_sha=SHA), "does not match"),  # still PARENT
    (lambda k, d: reconcile_statement(k, d, release_sha=SHA), "previously recorded"),
    (lambda k, d: reconcile_statement(k, d, configs={**configs(), "api": "e" * 64}), "does not match"),
    (lambda k, d: reconcile_statement(k, d, host_id="ffff" * 8), "another host"),
    (lambda k, d: reconcile_statement(k, d, expires_at=(NOW - timedelta(seconds=1)).isoformat()), "expired"),
])
def test_an_invalid_reconcile_is_refused_and_changes_nothing(keys, tmp_path, make, why):
    ledger, _, digest, prod = pending_after_failed_apply(keys, tmp_path)
    before = ledger.read_text()
    refused(why, do_reconcile, keys, ledger, make(keys, digest), prod)
    assert ledger.read_text() == before


def test_reconcile_is_single_use_and_needs_a_pending_release(keys, tmp_path):
    ledger, _, digest, prod = pending_after_failed_apply(keys, tmp_path)
    st = reconcile_statement(keys, digest)
    do_reconcile(keys, ledger, st, prod)
    refused("nothing is pending", do_reconcile, keys, ledger, st, prod)


@pytest.mark.parametrize("current_policy_version", [2, 3])
def test_applied_reconcile_keeps_the_verified_pending_policy_floor(keys, tmp_path, current_policy_version):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({**STATE, "min_policy_version": 1}))
    prod = Production(PARENT)
    m = manifest(sequence=7, policy_version=2, approver="founder")

    def switch_then_fail(_):
        prod.deploy(SHA)
        raise RuntimeError("record failed after switch")
    with pytest.raises(RuntimeError):
        transact(keys, ledger, m, "founder", policy_over={"version": 2, "auto_release": False},
                 prod=prod, apply=switch_then_fail)
    digest = __import__("hashlib").sha256(rg.canonical(m)).hexdigest()
    raw, signature = reconcile_statement(keys, digest, outcome="applied", release_sha=SHA)
    policy_raw, policy_signature = signed_policy(keys, version=current_policy_version, auto_release=False)
    state = rg.reconcile(ledger, raw, signature, founder_key=keys["founder"][1], policy_bytes=policy_raw,
                         policy_sig=policy_signature, host_id=HOST, observe=prod.observe, now=NOW)
    assert state["min_policy_version"] == 2
    assert rg.read_history(ledger)[-1]["policy_version"] == 2
    old, old_signature = signed_policy(keys, version=1, auto_release=True)
    refused("policy is older", rg.load_policy, old, old_signature, keys["founder"][1],
            min_version=state["min_policy_version"])


@pytest.mark.parametrize("missing", [None, True, 0])
def test_applied_reconcile_refuses_an_unknown_pending_policy_floor(keys, tmp_path, missing):
    ledger, _, digest, prod = pending_after_failed_apply(keys, tmp_path)
    state = json.loads(ledger.read_text())
    state["pending_policy_version"] = missing
    ledger.write_text(json.dumps(state))
    before = ledger.read_bytes()
    prod.deploy(SHA)
    refused("pending policy", do_reconcile, keys, ledger,
            reconcile_statement(keys, digest, outcome="applied", release_sha=SHA), prod)
    assert ledger.read_bytes() == before


# --------------------------------------------------------------------------- V3-1: the ledger lock

def _lock(ledger):
    return ledger.with_name(ledger.name + ".lock")


def test_the_lock_is_created_root_only_and_corrected_if_wider(tmp_path):
    ledger = tmp_path / "ledger.json"
    with rg._locked(ledger):
        assert _lock(ledger).stat().st_mode & 0o777 == 0o600            # never 0644
    _lock(ledger).chmod(0o644)
    with rg._locked(ledger):
        assert _lock(ledger).stat().st_mode & 0o777 == 0o600


def test_a_symlinked_or_hard_linked_lock_is_refused_and_its_target_untouched(tmp_path):
    ledger = tmp_path / "ledger.json"
    victim = tmp_path / "victim"
    victim.write_text("x")
    victim.chmod(0o644)
    _lock(ledger).symlink_to(victim)
    with pytest.raises((OSError, rg.Refused)):
        with rg._locked(ledger):
            pass
    _lock(ledger).unlink()
    os.link(victim, _lock(ledger))
    with pytest.raises(rg.Refused, match="lock"):
        with rg._locked(ledger):
            pass
    assert victim.stat().st_mode & 0o777 == 0o644 and victim.read_text() == "x"


def test_a_lock_owned_by_someone_else_or_in_a_writable_directory_is_refused(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.json"
    with rg._locked(ledger):
        pass
    monkeypatch.setattr(rg.os, "geteuid", lambda: 4242)                # the lock now belongs to "the gateway"
    with pytest.raises(rg.Refused, match="lock"):
        with rg._locked(ledger):
            pass
    monkeypatch.undo()
    tmp_path.chmod(0o770)                                              # group-writable directory: swappable lock
    try:
        with pytest.raises(rg.Refused, match="lock"):
            with rg._locked(ledger):
                pass
    finally:
        tmp_path.chmod(0o700)


def test_a_held_lock_is_a_bounded_clean_refusal_with_nothing_written(keys, tmp_path, monkeypatch):
    import fcntl
    import time
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(STATE))
    before = ledger.read_text()
    with rg._locked(ledger):
        pass
    holder = os.open(_lock(ledger), os.O_RDONLY)                       # someone holds it (another open file)
    fcntl.flock(holder, fcntl.LOCK_EX)
    monkeypatch.setattr(rg, "LOCK_TIMEOUT_S", 0.3)
    applied = []
    started = time.monotonic()
    try:
        refused("lock is busy", transact, keys, ledger, manifest(), apply=applied.append)
    finally:
        os.close(holder)
    assert time.monotonic() - started < 5 and applied == [] and ledger.read_text() == before
    assert not rg.history_path(ledger).exists()
    assert rg.LOCK_TIMEOUT_S > 0                                        # production value is finite as well


# --------------------------------------------------------------------------- G4: a declared rollback (founder 2026-10-19)

def applied_event(sha=OTHER, **over):
    """What release_transaction records for an applied release: the trusted evidence a rollback is checked against."""
    return {"event": "applied", "digest": "d" * 64, "sha": sha, "sequence": 3, "payload_digest": DIGEST,
            "images": images(sha), "configs": configs(), "policy_version": 1, "at": NOW.isoformat()} | over


def rollback(keys, policy, history, signer="founder", **over):
    m = manifest(approver=signer, rollback_to=OTHER) | over
    raw = rg.canonical(m)
    return rg.verify_release(raw, rg.sign(raw, keys[signer][0], rg.NS_RELEASE), policy=policy,
                             founder_key=keys["founder"][1], host_facts=facts(), state=STATE, now=NOW,
                             history=history)


def test_a_declared_rollback_with_full_evidence_still_refuses_until_images_are_proven(keys, policy):
    # Every evidence check passes; it refuses at the last step because rebuilt images cannot equal the recorded ones.
    events = [applied_event(), applied_event(PARENT, payload_digest="e" * 64)]
    refused("running images cannot yet be proven", rollback, keys, policy, lambda: events)


def test_a_rollback_needs_the_founder_and_the_reviewer(keys, policy):
    refused("rollback needs the founder", rollback, keys, policy, lambda: [applied_event()], signer="gateway")
    refused("rollback needs the founder", rg.gateway_approve, manifest(rollback_to=OTHER), policy, now=NOW,
            diff=DIFF)
    evidence = manifest()["evidence"] | {"review": signed_review(output={"verdict": "REJECT", "fingerprint": rg.review_packet(
        "seerxo/os", PARENT, SHA, DIFF, NONCE)["fingerprint"], "findings": ["no"]})}
    refused("does not approve", rollback, keys, policy, lambda: [applied_event()], evidence=evidence)


@pytest.mark.parametrize("why,history", [
    ("not a previously applied release", lambda: []),
    ("not a previously applied release", lambda: [applied_event(PARENT)]),
    ("not a previously applied release", lambda: [applied_event(event="bootstrap")]),       # baseline, not applied
    ("not a previously applied release", lambda: [applied_event(event="reconcile")]),
    ("payload differs", lambda: [applied_event(payload_digest="e" * 64)]),                  # same name, other tree
    ("no recorded payload", lambda: [{k: v for k, v in applied_event().items() if k != "payload_digest"}]),
    ("no recorded image", lambda: [{k: v for k, v in applied_event().items() if k != "images"}]),
    ("no recorded image", lambda: [applied_event(images={"api": images(OTHER)["api"]})]),
    ("no recorded image", lambda: [applied_event(images={c: "company-os-api:latest" for c in rg.COMPONENTS})]),
    ("no recorded image", lambda: [applied_event(configs={c: "x" for c in rg.COMPONENTS})]),
    ("history is unavailable", None),
])
def test_a_rollback_without_matching_trusted_evidence_is_refused(keys, policy, why, history):
    refused(why, rollback, keys, policy, history)


def test_a_rollback_uses_the_latest_applied_record_of_its_target(keys, policy):
    # The same commit name applied twice: the newest record is the evidence, an older matching one is not enough.
    events = [applied_event(), applied_event(payload_digest="e" * 64)]
    refused("payload differs", rollback, keys, policy, lambda: events)


def test_a_malformed_or_current_rollback_target_is_refused(keys, policy):
    refused("rollback_to", rollback, keys, policy, lambda: [applied_event()], rollback_to="main")
    refused("already running", rollback, keys, policy, lambda: [applied_event(PARENT)], rollback_to=PARENT)


def test_an_unreadable_history_refuses_a_rollback(keys, policy):
    def broken():
        raise rg.Refused("release history is unreadable; the founder must restore it")
    refused("history is unreadable", rollback, keys, policy, broken)


def test_an_applied_release_records_its_payload_digest_for_later_rollbacks(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(STATE))
    transact(keys, ledger, manifest())
    event, = rg.read_history(ledger)
    assert event["event"] == "applied" and event["sha"] == SHA and event["payload_digest"] == DIGEST


# --------------------------------------------------------------------------- founder rebase onto a new repository

NEW_REPO, BASE, TREE_RUNNING = "seerxo/seerxo-os", "4" * 40, "5" * 40


def rebase_policy(keys, version=2, repository=NEW_REPO):
    return signed_policy(keys, version=version, repository=repository)


def applied_once(keys, tmp_path):
    ledger = tmp_path / "ledger.json"
    do_bootstrap(keys, ledger, statement(keys))
    prod = Production(PARENT)
    transact(keys, ledger, manifest(sequence=1), prod=prod)       # production runs SHA, sequence 1
    return ledger, prod


def provenance(**over):
    return lambda base, old: {"old_repository": "seerxo/os", "base_on_branch": True, "base_tree": TREE_RUNNING,
                              "old_tree": TREE_RUNNING} | over


def rebase_statement(keys, ledger, *, signer="founder", namespace=rg.NS_REBASE, policy=None, **over):
    praw = (policy or rebase_policy(keys))[0]
    body = {"kind": "rebase", "host_id": HOST, "repository": NEW_REPO, "branch": "main", "nonce": "ee" * 16,
            "old_repository": "seerxo/os", "old_last_sha": SHA, "old_last_sequence": 1,
            "history_sha256": __import__("hashlib").sha256(rg.history_path(ledger).read_bytes()).hexdigest(),
            "base_sha": BASE, "base_tree": TREE_RUNNING,
            "policy_sha256": __import__("hashlib").sha256(praw).hexdigest(),
            "images": images(SHA), "configs": configs(), "issued_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(hours=1)).isoformat()} | over
    raw = rg.canonical(body)
    return raw, rg.sign(raw, keys[signer][0], namespace)


def do_rebase(keys, ledger, prod, raw_sig, *, policy=None, facts_over=None):
    praw, psig = policy or rebase_policy(keys)
    return rg.rebase(ledger, raw_sig[0], raw_sig[1], founder_key=keys["founder"][1], policy_bytes=praw,
                     policy_sig=psig, host_id=HOST, observe=prod.observe, provenance=provenance(**(facts_over or {})),
                     now=NOW)


def new_repo_manifest(**over):
    m = manifest(repository=NEW_REPO, parent_sha=BASE, sequence=2, policy_version=2)
    packet = rg.review_packet(NEW_REPO, BASE, SHA, DIFF, NONCE)
    out = {"verdict": "APPROVE", "fingerprint": packet["fingerprint"], "findings": []}
    att = rg.attestation("codex", packet, out, NOW.isoformat())
    m["evidence"]["review"] = {"nonce": NONCE, "attestation": att,
                               "signature": rg.sign(rg.canonical(att), KEYS["reviewer"][0], rg.NS_REVIEW)}
    return m | over


def test_a_rebase_moves_the_chain_without_deploying_and_the_next_release_continues_from_the_base(keys, tmp_path):
    ledger, prod = applied_once(keys, tmp_path)
    before = json.loads(ledger.read_text())
    state = do_rebase(keys, ledger, prod, rebase_statement(keys, ledger))
    assert state["last_sha"] == SHA and state["last_sequence"] == 1 and state["chain_base"] == BASE
    assert state["min_policy_version"] == 2 and set(before["seen"]) < set(state["seen"])
    copy, = ledger.parent.glob("ledger.json.pre-rebase-1-*")
    assert json.loads(copy.read_text()) == before
    assert [e["event"] for e in rg.read_history(ledger)] == ["bootstrap", "applied", "rebase"]
    assert prod.observe() == Production(SHA).observe()                                  # nothing deployed

    old = manifest(sequence=2, parent_sha=SHA, sha=OTHER)                              # the old chain is closed
    refused("older than the newest", transact, keys, ledger, old, prod=prod)            # v1 policy is below the floor
    refused("does not continue", transact, keys, ledger, old | {"repository": NEW_REPO, "policy_version": 2},
            prod=prod, policy_over={"version": 2, "repository": NEW_REPO})
    m = new_repo_manifest(sha=OTHER)
    m["evidence"]["trusted_checks"]["sha"] = OTHER
    host = facts(repository=NEW_REPO, sha=OTHER)
    m["evidence"]["review"] = new_repo_manifest()["evidence"]["review"]
    packet = rg.review_packet(NEW_REPO, BASE, OTHER, DIFF, NONCE)
    att = rg.attestation("codex", packet, {"verdict": "APPROVE", "fingerprint": packet["fingerprint"],
                                            "findings": []}, NOW.isoformat())
    m["evidence"]["review"] = {"nonce": NONCE, "attestation": att,
                               "signature": rg.sign(rg.canonical(att), keys["reviewer"][0], rg.NS_REVIEW)}
    assert transact(keys, ledger, m, prod=prod, host=host,
                    policy_over={"version": 2, "repository": NEW_REPO})["sha"] == OTHER
    after = json.loads(ledger.read_text())
    assert after["last_sha"] == OTHER and "chain_base" not in after and after["last_sequence"] == 2


@pytest.mark.parametrize("make, why", [
    (lambda k, l: rebase_statement(k, l, namespace=rg.NS_RECOVERY), "not signed by the pinned founder"),
    (lambda k, l: rebase_statement(k, l, namespace=rg.NS_RELEASE), "not signed by the pinned founder"),
    (lambda k, l: rebase_statement(k, l, signer="gateway"), "not signed by the pinned founder"),
    (lambda k, l: rebase_statement(k, l, kind="recovery"), "wrong shape"),
    (lambda k, l: rebase_statement(k, l, repository="seerxo/os"), "another repository"),   # not the new policy's
    (lambda k, l: rebase_statement(k, l, policy_sha256="0" * 64), "different policy"),
    (lambda k, l: rebase_statement(k, l, old_last_sha=PARENT), "another applied release"),
    (lambda k, l: rebase_statement(k, l, old_last_sequence=0), "another applied release"),
    (lambda k, l: rebase_statement(k, l, old_last_sequence=True), "another applied release"),
    (lambda k, l: rebase_statement(k, l, history_sha256="0" * 64), "different release history"),
    (lambda k, l: rebase_statement(k, l, images=images(PARENT)), "does not match the rebase"),
    (lambda k, l: rebase_statement(k, l, old_repository="evil/os"), "another old repository"),
    (lambda k, l: rebase_statement(k, l, base_sha="main"), "40-hex"),
    (lambda k, l: rebase_statement(k, l, base_tree="6" * 40), "tree is not exactly"),
    (lambda k, l: rebase_statement(k, l, expires_at=(NOW - timedelta(seconds=1)).isoformat()), "expired"),
    (lambda k, l: rebase_statement(k, l, host_id="ffff" * 8), "another host"),
])
def test_an_invalid_rebase_is_refused_and_writes_nothing(keys, tmp_path, make, why):
    ledger, prod = applied_once(keys, tmp_path)
    before, history = ledger.read_text(), rg.history_path(ledger).read_text()
    refused(why, do_rebase, keys, ledger, prod, make(keys, ledger))
    assert ledger.read_text() == before and rg.history_path(ledger).read_text() == history
    assert not list(ledger.parent.glob("ledger.json.pre-rebase-*"))


@pytest.mark.parametrize("facts_over, why", [
    ({"base_on_branch": False}, "not on main"),
    ({"base_tree": "6" * 40}, "tree is not exactly"),                   # the base is not the reviewed source
    ({"old_tree": "6" * 40}, "tree is not exactly"),                    # production runs another tree
    ({"base_tree": None}, "tree is not exactly"),                       # unknown commit
    ({"old_repository": "evil/os"}, "another old repository"),
])
def test_the_host_git_evidence_must_prove_the_base_is_the_running_tree(keys, tmp_path, facts_over, why):
    ledger, prod = applied_once(keys, tmp_path)
    refused(why, do_rebase, keys, ledger, prod, rebase_statement(keys, ledger), facts_over=facts_over)
    assert "chain_base" not in json.loads(ledger.read_text())


def test_a_rebase_needs_a_newer_policy_a_settled_ledger_and_matching_production(keys, tmp_path):
    ledger, prod = applied_once(keys, tmp_path)
    same = rebase_policy(keys, version=1)
    refused("older than the newest", do_rebase, keys, ledger, prod, rebase_statement(keys, ledger, policy=same),
            policy=same)                                                     # same policy version: no new authority
    refused("different policy", do_rebase, keys, ledger, prod, rebase_statement(keys, ledger),
            policy=rebase_policy(keys, version=3))                          # signed for v2, host holds v3
    drifted = Production(SHA)
    drifted.running["api"]["image"] = image("api", OTHER)
    refused("does not match the rebase", do_rebase, keys, ledger, drifted, rebase_statement(keys, ledger))
    state = json.loads(ledger.read_text())
    ledger.write_text(json.dumps(state | {"pending": "ab" * 32}))
    refused("pending", do_rebase, keys, ledger, prod, rebase_statement(keys, ledger))


def test_a_rebase_statement_is_single_use_and_a_rebase_back_needs_a_still_newer_policy(keys, tmp_path):
    ledger, prod = applied_once(keys, tmp_path)
    st = rebase_statement(keys, ledger)
    do_rebase(keys, ledger, prod, st)
    refused("older than the newest|replay|different release history", do_rebase, keys, ledger, prod, st)
    v3 = rebase_policy(keys, version=3, repository="seerxo/os")
    back = rebase_statement(keys, ledger, policy=v3, repository="seerxo/os", base_sha=SHA, nonce="ff" * 16)
    state = do_rebase(keys, ledger, prod, back, policy=v3)
    assert state["chain_base"] == SHA and state["min_policy_version"] == 3
    assert [e["event"] for e in rg.read_history(ledger)][-2:] == ["rebase", "rebase"]


def test_a_failed_first_release_after_a_rebase_keeps_the_new_chain(keys, tmp_path):
    ledger, prod = applied_once(keys, tmp_path)
    do_rebase(keys, ledger, prod, rebase_statement(keys, ledger))
    state = json.loads(ledger.read_text())
    ledger.write_text(json.dumps(state | {"pending": "ab" * 32, "pending_sha": OTHER, "pending_sequence": 2,
                                          "pending_policy_version": 2}))
    praw, psig = rebase_policy(keys)
    body = {"kind": "reconcile", "host_id": HOST, "repository": NEW_REPO, "branch": "main", "nonce": "dd" * 16,
            "pending_digest": "ab" * 32, "outcome": "failed", "release_sha": SHA, "images": images(SHA),
            "configs": configs(), "issued_at": NOW.isoformat(), "expires_at": (NOW + timedelta(hours=1)).isoformat()}
    raw = rg.canonical(body)
    new = rg.reconcile(ledger, raw, rg.sign(raw, keys["founder"][0], rg.NS_RECONCILE), founder_key=keys["founder"][1],
                       policy_bytes=praw, policy_sig=psig, host_id=HOST, observe=prod.observe, now=NOW)
    assert new["chain_base"] == BASE and new["last_sha"] == SHA and new["last_sequence"] == 2


def test_recovering_a_lost_ledger_right_after_a_rebase_keeps_the_new_chain(keys, tmp_path):
    ledger, prod = applied_once(keys, tmp_path)
    do_rebase(keys, ledger, prod, rebase_statement(keys, ledger))
    ledger.unlink()
    digest = __import__("hashlib").sha256(rg.history_path(ledger).read_bytes()).hexdigest()
    raw, sig = statement(keys, "recovery", history_sha256=digest, last_sha=SHA, last_sequence=1, images=images(SHA),
                         repository=NEW_REPO)
    praw, psig = rebase_policy(keys)
    state = rg.recover(ledger, raw, sig, founder_key=keys["founder"][1], policy_bytes=praw, policy_sig=psig,
                       host_id=HOST, observe=prod.observe, now=NOW)
    assert state["chain_base"] == BASE and state["last_sha"] == SHA and state["min_policy_version"] == 2


def test_recovery_after_a_release_on_the_new_chain_has_no_chain_base(keys, tmp_path):
    ledger, m, prod = lose_ledger_after_one_release(keys, tmp_path)
    _, run = recovery(keys, ledger, prod)
    assert "chain_base" not in run()
