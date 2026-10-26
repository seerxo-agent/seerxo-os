"""Production host release entry (G1): the only path by which a commit is applied, decided on the host itself.

Design: docs/security/RELEASE_GATEWAY.md. Standard library only. Installed root-owned OUTSIDE the deploy payload
(founder step), with the founder's public key pinned at install, and run by root from a timer:
    python3 -m app.release_host

Each step takes the next manifest (gateway outbox: low risk, gateway-signed; founder inbox: founder-signed),
fetches the named commit into the host's own clone with a read-only credential, computes every fact itself
(commit, payload digest, changed paths, release diff, ancestry), and runs release_gateway.release_transaction.
Apply builds the same three artifacts the staged deploy transport ships (src.tgz, main.sha256 and the deploy
driver's root-side script) from that clone and runs the existing driver synchronously: its exit code decides.
A failure leaves the ledger `pending`, and no later release is applied until the founder reconciles the host.
No GitHub workflow, runner or SSH key is involved, so none of them can change production.
"""
import gzip
import hashlib
import io
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app import release_gateway as rg

REMOTE_START, REMOTE_END = "<<'REMOTE'\n", "\nREMOTE\n"
# The deploy driver accepts only RELEASE_DIR =~ ^/run/company-os-deploy/[0-9a-f]{40}\.[A-Za-z0-9]{8}$ (F3).
RUN_ROOT_PRODUCTION = Path("/run/company-os-deploy")
RUN_ROOT = RUN_ROOT_PRODUCTION                       # tests point this elsewhere; the config must name it exactly
# The compose file the driver deploys from (it runs in /opt/company-os); tests point this elsewhere.
HOST_COMPOSE = Path("/opt/company-os/docker-compose.yml")
# The ledger path the deploy driver reads to recognise a bootstrapped host (verify-release-manifest, B6 step 8).
LEDGER_PRODUCTION = Path("/var/lib/release-host/ledger/ledger.json")
LEDGER = LEDGER_PRODUCTION                           # tests point this elsewhere; the config must name it exactly


class RetryLater(RuntimeError):
    """Infrastructure, not the manifest: fetch, git, an unreadable policy. Nothing is moved; the next step retries."""


class Config:
    def __init__(self, raw: dict):
        need = {"repository", "branch", "clone", "fetch_url", "policy", "policy_sig", "founder_key", "ledger",
                "inboxes", "rejected", "run_root", "identity_report"}
        if not isinstance(raw, dict) or set(raw) != need:
            raise rg.Refused(f"host release config must have exactly {sorted(need)}")
        self.__dict__.update(raw)
        for key in ("clone", "policy", "policy_sig", "founder_key", "ledger", "rejected", "run_root", "identity_report"):
            setattr(self, key, Path(raw[key]))
        if not isinstance(raw["inboxes"], list) or not raw["inboxes"]:
            raise rg.Refused("inboxes must list the gateway outbox and the founder inbox")
        self.inboxes = [Path(p) for p in raw["inboxes"]]
        if self.run_root != RUN_ROOT:
            raise rg.Refused(f"run_root must be {RUN_ROOT}: the deploy driver refuses any other RELEASE_DIR")
        if self.ledger != LEDGER:
            raise rg.Refused(f"ledger must be {LEDGER}: the deploy driver reads only that path to know the host is bootstrapped")


def _release_dir_name(sha: str) -> str:
    """<sha>.<8 hex>: exactly what the driver's RELEASE_DIR check accepts (tempfile suffixes may contain "_")."""
    return f"{sha}.{secrets.token_hex(4)}"


# refs/replace/* in a clone could make git answer about other objects than the ones named: never honoured here.
os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"


def _git(cfg: Config, *args: str, text=True):
    return subprocess.run(["git", "-C", str(cfg.clone), *args], check=True, capture_output=True, text=text).stdout


MAX_INBOX_FILE = 1 << 20     # a manifest or signature is a few KiB; nothing bigger is read by root


def _read_inbox(path: Path) -> bytes:
    """Read a file the gateway (or anyone with inbox access) can write, as root: never through a symlink, never a
    FIFO or device, and bounded, so a planted link cannot make root read /dev/zero or a root-only file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INBOX_FILE:
            raise rg.Refused(f"{path.name} is not a regular file of at most {MAX_INBOX_FILE} bytes")
        if info.st_nlink != 1:
            raise rg.Refused(f"{path.name} has another hard link; root reads only a file with one name")
        data = os.read(fd, MAX_INBOX_FILE + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_INBOX_FILE:
        raise rg.Refused(f"{path.name} is not a regular file of at most {MAX_INBOX_FILE} bytes")
    return data


def untrusted_path(path: Path, *, writable_leaf: bool = False) -> str | None:
    """Why root must not use `path`, or None. Every existing component must be a real directory (no symlink),
    owned by root (or this process's user, for tests) and not group- or world-writable, so nobody else can swap a
    component for a link. An inbox (`writable_leaf`) may itself be owned and written by the gateway, but must still
    be a real directory under trusted parents. A missing tail is created by root later, under a trusted parent."""
    if not path.is_absolute():
        return f"untrusted path: {path} is not absolute"
    trusted = {0, os.geteuid()}
    current = Path(path.anchor)
    for i, part in enumerate(path.parts):
        current = current / part if i else current
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return None
        leaf = current == path
        if not stat.S_ISDIR(info.st_mode):
            return f"untrusted path: {current} is not a real directory"
        if leaf and writable_leaf:
            continue
        if info.st_uid not in trusted or info.st_mode & 0o022:
            return f"untrusted path: {current} is owned by uid {info.st_uid} or group/world-writable"
    return None


def _regular(path: Path) -> bool:
    """Only regular files are queue entries. A directory, FIFO or symlink named like a manifest is skipped, never
    moved into root's rejected/ (a moved gateway directory would wedge the queue on the next same-named file)."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def untrusted_layout(cfg: Config) -> str | None:
    """Every directory root reads, moves or writes in, checked before anything is touched: the ledger's and the
    identity report's (strict), rejected/ and run_root (strict), each inbox (may be gateway-writable itself)."""
    checks = [(cfg.ledger.parent, False), (cfg.identity_report.parent, False), (cfg.rejected, False),
              (cfg.run_root, False), *[(box, True) for box in cfg.inboxes]]
    for path, writable in checks:
        problem = untrusted_path(path, writable_leaf=writable)
        if problem:
            return problem
    return None


def candidates(cfg: Config) -> list[tuple[int, Path]]:
    """Manifests waiting in the inboxes, lowest sequence first. Names are only a hint; the content decides.
    Dot-files are the gateway's in-flight writes (renamed into place last) and are never picked up."""
    found = []
    for box in cfg.inboxes:
        for path in sorted(p for p in box.glob("*.json") if not p.name.startswith(".") and _regular(p)) \
                if box.is_dir() else []:
            try:
                seq = json.loads(_read_inbox(path)).get("sequence")
            except (OSError, ValueError, AttributeError, rg.Refused):
                seq = None
            found.append((seq if isinstance(seq, int) and not isinstance(seq, bool) else 10**12, path))
    return sorted(found)


# The driver line that enforces #192 F4; a candidate whose driver lacks it never gets a gateway apply.
DRIVER_HOLDS_IMAGES = '[ "${PENDING_APPROVER:-founder}" = founder ] || HOLD_IMAGES=yes'


def host_facts(cfg: Config, manifest: dict, ledger: dict) -> dict:
    """Everything verify_release compares, computed here from the host's own clone."""
    sha, parent = manifest.get("sha"), manifest.get("parent_sha")
    if not (isinstance(sha, str) and rg.SHA.fullmatch(sha) and isinstance(parent, str) and rg.SHA.fullmatch(parent)):
        raise rg.Refused("manifest names no valid commit")
    try:
        _git(cfg, "fetch", "--no-tags", "--quiet", cfg.fetch_url,
             f"+refs/heads/{cfg.branch}:refs/remotes/origin/{cfg.branch}")
    except (OSError, subprocess.CalledProcessError) as error:
        raise RetryLater(f"fetch failed: {type(error).__name__}") from None
    on_branch = subprocess.run(["git", "-C", str(cfg.clone), "merge-base", "--is-ancestor", sha,
                                f"refs/remotes/origin/{cfg.branch}"], capture_output=True).returncode == 0
    if not on_branch:
        raise rg.Refused(f"commit {sha} is not on {cfg.branch} (another repository or branch, or unknown)")
    last = rg.chain_parent(ledger)
    descends = bool(last) and subprocess.run(["git", "-C", str(cfg.clone), "merge-base", "--is-ancestor", last, sha],
                                             capture_output=True).returncode == 0
    rg.release_archive(cfg.clone, sha)                 # shipped bytes == hashed bytes, refused BEFORE pending
    try:
        host_compose = hashlib.sha256(HOST_COMPOSE.read_bytes()).hexdigest()
    except OSError:
        host_compose = None
    try:                                               # #192 F4: does this release's own driver hold gateway images?
        holds = DRIVER_HOLDS_IMAGES in _git(cfg, "show", f"{sha}:scripts/deploy-company-os.sh")
    except (OSError, subprocess.CalledProcessError):
        holds = False
    return {"repository": cfg.repository if on_branch else None, "branch": cfg.branch if on_branch else None,
            "sha": sha, "payload_digest": rg.payload_digest(rg.payload_listing(cfg.clone, sha)),
            "changed_paths": rg.git_changed_paths(cfg.clone, parent, sha), "ancestor_of_parent": descends,
            "diff": rg.git_release_diff(cfg.clone, parent, sha),
            "compose": {"host": host_compose, "parent": rg.git_blob_sha256(cfg.clone, parent, "docker-compose.yml"),
                        "release": rg.git_blob_sha256(cfg.clone, sha, "docker-compose.yml")},
            "migration_heads": sorted(rg.alembic_heads(cfg.clone, sha)),
            "parent_migration_heads": sorted(rg.alembic_heads(cfg.clone, parent)),
            "nonregular_paths": rg.git_nonregular_paths(cfg.clone, parent, sha), "driver_holds_images": holds}


def deploy_acknowledgements(manifest: dict, facts: dict) -> str:
    """B-7/B-8, decided BEFORE `pending`. Returns the driver's ACK_COMPOSE ("" when compose is unchanged).
    - The host's docker-compose.yml must be exactly the applied release's (parent_sha): anything else is a manual
      change nobody signed, so nothing is applied (BLOCKED, the manifest stays).
    - A compose change ships only in a founder-signed release (signature checked in the transaction; compose is
      always HIGH, rg.FOUNDER_ONLY_PATHS). The driver then gets the host file's own short hash, which it recomputes
      and compares itself; the new file's bytes are bound by payload_digest.
    - A symlink or submodule entry anywhere in the diff needs the founder's signature, whatever its path.
    - A release that moves the Alembic head must name, in migration_to, the single head the host reads at that
      commit; a migration_to that is not that head is refused too (the driver would abort after `pending`)."""
    if manifest.get("approver") != "founder" and facts.get("driver_holds_images") is not True:
        # A candidate whose own driver predates the hold would rebuild and ship whatever a cold cache fetches.
        raise rg.Refused("this release's deploy driver does not hold a gateway release to the running images "
                         "(#192 F4): a founder-signed release is required")
    if facts["nonregular_paths"] and manifest.get("approver") != "founder":
        raise rg.Refused("a symlink or submodule change needs the founder's signature: "
                         + ", ".join(facts["nonregular_paths"])[:200])
    compose = facts["compose"]
    if not compose["host"] or compose["host"] != compose["parent"]:
        raise rg.Refused("BLOCKED: the host's docker-compose.yml is not the applied release's; "
                         "the founder reconciles the host before any release")
    ack = ""
    if compose["release"] != compose["parent"]:
        if manifest.get("approver") != "founder":
            raise rg.Refused("a docker-compose.yml change needs the founder's signature")
        ack = compose["host"][:12]
    migration_to = manifest.get("migration_to")
    schema_change = facts["migration_heads"] != facts["parent_migration_heads"]
    if (schema_change or migration_to) and facts["migration_heads"] != [migration_to]:
        raise rg.Refused(f"migration_to must be the single Alembic head at this commit "
                         f"({', '.join(facts['migration_heads']) or 'none'}), signed by the founder")
    return ack


def build_release(cfg: Config, sha: str, directory: Path) -> None:
    """The staged transport's three files, from the host clone at exactly `sha` (same commands as the driver)."""
    try:
        tar = rg.release_archive(cfg.clone, sha)      # checked in host_facts already; again here, after pending
    except rg.Refused as error:
        raise RuntimeError(str(error)) from None      # after `pending`: APPLY_FAILED, never a silent reject
    listing = rg.payload_listing(cfg.clone, sha)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(tar)
    (directory / "src.tgz").write_bytes(buf.getvalue())
    (directory / "main.sha256").write_text(listing)
    driver = _git(cfg, "show", f"{sha}:scripts/deploy-company-os.sh")
    if REMOTE_START not in driver or REMOTE_END not in driver:
        raise rg.Refused("the deploy driver at this commit has no root-side script")
    remote = driver[driver.index(REMOTE_START) + len(REMOTE_START):driver.index(REMOTE_END)]
    (directory / "company-os-deploy.sh").write_text(remote + "\n")
    for name in ("src.tgz", "main.sha256", "company-os-deploy.sh"):
        os.chmod(directory / name, 0o600)


CONTAINERS = {"api": "company-api", "worker": "company-worker", "reasoner": "company-reasoner"}
# What may differ between two runs of the same container without changing what it can do. Everything else in
# Config and HostConfig is identity. Hostname is the container ID, Image is a tag name (the ID is identity already),
# Labels are compose bookkeeping, Attach*/Tty/OpenStdin are console wiring. Env is identity but only as a digest.
VOLATILE_CONFIG = ("Hostname", "Image", "Labels", "Env", "AttachStdin", "AttachStdout", "AttachStderr", "Tty",
                   "OpenStdin", "StdinOnce")
VOLATILE_HOST_CONFIG = ("ContainerIDFile",)
# Lists whose order carries no meaning: sorted before hashing so a reordering never blocks a release.
SET_LIKE = {"Binds", "CapAdd", "CapDrop", "SecurityOpt", "Dns", "DnsOptions", "DnsSearch", "ExtraHosts", "GroupAdd",
            "Devices", "DeviceCgroupRules", "DeviceRequests", "VolumesFrom", "MaskedPaths", "ReadonlyPaths", "Links",
            "Ulimits", "Env"}


def _normalise(key, value):
    """None, [], {} and "" are the same absence; set-like lists are sorted; dict keys are canonical anyway."""
    if value in (None, [], {}, ""):
        return None
    if isinstance(value, dict):
        return {k: v for k, v in ((k, _normalise(k, v)) for k, v in value.items()) if v is not None} or None
    if isinstance(value, list):
        items = [_normalise(None, v) for v in value]
        return sorted(items, key=lambda v: rg.canonical(v)) if key in SET_LIKE else items
    return value


def security_config(info: dict) -> str:
    """Digest of everything that decides what a container can do: all of Config and HostConfig except the short
    VOLATILE lists above, every mount (all fields), the names of the networks it is attached to (addresses are
    volatile), and the environment as a digest of the sorted NAME=value list (LD_PRELOAD, PYTHONPATH...). Values
    are never stored; only this combined digest is. A change of .env therefore changes identity (founder recovery)."""
    config, host_config = info.get("Config") or {}, info.get("HostConfig") or {}
    env = sorted(e for e in config.get("Env") or [] if isinstance(e, str))
    doc = {"Config": _normalise(None, {k: v for k, v in config.items() if k not in VOLATILE_CONFIG}),
           "HostConfig": _normalise(None, {k: v for k, v in host_config.items() if k not in VOLATILE_HOST_CONFIG}),
           "Mounts": sorted((_normalise(None, m) for m in info.get("Mounts") or [] if isinstance(m, dict)),
                            key=lambda m: rg.canonical(m)),
           "Networks": sorted(((info.get("NetworkSettings") or {}).get("Networks") or {})),
           "Env": hashlib.sha256(rg.canonical(env)).hexdigest()}
    return hashlib.sha256(rg.canonical(doc)).hexdigest()


def observe_production(run=subprocess.run) -> dict:
    """What actually runs, read by root from Docker on this host: per component the content-addressed image ID
    (`.Image`, immutable), the security_config digest, and COMPANY_OS_GIT_SHA from the container's config (a
    consistency check, not identity). `--type container`: an image with the same name is never inspected.
    A component that cannot be inspected is left out, so the identity check fails closed."""
    observed = {}
    for name, container in CONTAINERS.items():
        try:
            out = run(["docker", "inspect", "--type", "container", "--format", "{{json .}}", container],
                      capture_output=True, text=True, timeout=30, check=True).stdout
            info = json.loads(out)
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
        if not isinstance(info, dict):
            continue
        env = dict(e.split("=", 1) for e in (info.get("Config") or {}).get("Env") or [] if "=" in e)
        if (info.get("State") or {}).get("Running") is True:
            observed[name] = {"image": info.get("Image"), "config": security_config(info),
                              "git_sha": env.get("COMPANY_OS_GIT_SHA")}
    return observed


def host_id() -> str:
    try:
        return Path("/etc/machine-id").read_text().strip()
    except OSError:
        return ""


def write_identity_report(cfg: Config, now: datetime, observed: dict) -> dict:
    """Root's own verdict on production identity, for the gateway to READ (never write): fresh, and whether
    production is exactly the ledger's release. The gateway cannot fix a mismatch; only the founder can."""
    try:
        ledger = rg.read_ledger(cfg.ledger)
        problem = (rg.identity_problem(observed, ledger.get("last_sha"), ledger.get("images"), ledger.get("configs"))
                   if ledger.get("last_sha") else "host is not bootstrapped")
    except rg.Refused as error:
        ledger, problem = {}, str(error)
    report = {"checked_at": now.isoformat(), "ok": problem is None, "problem": problem,
              "last_sha": ledger.get("last_sha"), "pending": bool(ledger.get("pending"))}
    rg._write_atomic(cfg.identity_report, report)
    return report


def default_run(env: dict, script: Path) -> int:
    """The existing root-side deploy, attached (not DETACH): its exit code is the release result."""
    return subprocess.run(["bash", str(script)], env={**os.environ, **env}).returncode


def step(cfg: Config, *, now: datetime | None = None, run=default_run, observe=observe_production) -> dict:
    """Apply at most one release. Returns {"outcome": ...}. A refused manifest is moved to `rejected` with its
    reason, so it is never retried; an apply failure leaves it in place and the ledger pending."""
    now = now or datetime.now(timezone.utc)
    founder_key = cfg.founder_key.read_text().strip()
    problem = untrusted_layout(cfg)
    if problem:
        # Root would read, move or write through a link or a directory someone else controls: nothing is touched,
        # not even the identity report.
        return {"outcome": "BLOCKED", "reason": problem}
    report = write_identity_report(cfg, now, observe())
    if not report["ok"] and not report["pending"]:
        # Production is not exactly the recorded release (or there is no baseline): nothing is applied, moved or
        # discarded; the founder investigates (a legacy deploy, a manual change) and recovers or bootstraps.
        return {"outcome": "BLOCKED", "reason": report["problem"]}
    if rg.read_ledger(cfg.ledger).get("pending"):
        # A started release was never recorded: nothing else is applied, and nothing is moved or discarded.
        return {"outcome": "WAITING_FOR_FOUNDER", "reason": "a previous release is pending reconciliation"}
    queue = candidates(cfg)
    if not queue:
        return {"outcome": "IDLE"}
    _, path = queue[0]
    sig_path = path.with_suffix(".sig")
    raw = None
    try:
        try:
            raw = _read_inbox(path)
            signature = _read_inbox(sig_path).decode()
        except OSError as error:                          # missing or unreadable entry: the entry is invalid
            raise rg.Refused(f"manifest or signature unreadable: {type(error).__name__}") from None
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            raise rg.Refused("manifest is not an object")
        ledger = rg.read_ledger(cfg.ledger)
        facts = host_facts(cfg, manifest, ledger)
        ack_compose = deploy_acknowledgements(manifest, facts)
        try:
            policy_bytes, policy_sig = cfg.policy.read_bytes(), cfg.policy_sig.read_text()
        except OSError as error:
            raise RetryLater(f"release policy unreadable: {type(error).__name__}") from None

        # Named before the transaction marks it pending (pending_release_dir): the driver accepts only this directory.
        d = cfg.run_root / _release_dir_name(str(manifest.get("sha", "")))

        def apply(m: dict) -> None:
            if d.name.split(".")[0] != m["sha"]:                # verified manifest == the one the name was chosen for
                raise RuntimeError("staged directory was named for another release")
            cfg.run_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            d.mkdir(mode=0o700)                                  # fresh, root-only; never an existing path
            try:
                build_release(cfg, m["sha"], d)
                code = run({"SHA": m["sha"], "APPLY": "--apply", "DETACH": "", "AUTOMATIC": "true",
                            "ALLOW_MIGRATION": m["migration_to"], "ACK_OVERRIDES": "", "ACK_COMPOSE": ack_compose,
                            "RELEASE_DIR": str(d)}, d / "company-os-deploy.sh")
            finally:
                if d.exists():                                   # the driver removes it itself when it ends
                    shutil.rmtree(d)
            if code != 0:
                raise RuntimeError(f"deploy driver exited {code}")

        m = rg.release_transaction(cfg.ledger, raw, signature, policy_bytes=policy_bytes, policy_sig=policy_sig,
                                   founder_key=founder_key, host_facts=facts, now=now, apply=apply, observe=observe,
                                   release_dir=str(d))
    except Exception as error:
        # F2: once `pending` names this manifest, whatever went wrong (driver, build, cleanup, the record itself)
        # is an apply failure. The manifest and its signature stay where they are as evidence; the founder reconciles.
        if raw is not None and _pending_is(cfg, raw):
            write_identity_report(cfg, now, observe())
            return {"outcome": "APPLY_FAILED", "manifest": path.name, "reason": f"{type(error).__name__}: {error}"[:500]}
        if isinstance(error, rg.LockBusy):
            return {"outcome": "RETRY_LATER", "manifest": path.name, "reason": str(error)}
        if isinstance(error, rg.Refused) and str(error).startswith(("BLOCKED", "host is not bootstrapped")):
            # Identity changed between the report and the lock: nothing applied, the manifest stays for later.
            write_identity_report(cfg, now, observe())
            return {"outcome": "BLOCKED", "reason": str(error)}
        if isinstance(error, (rg.Refused, ValueError)):
            return _reject(cfg, path, sig_path, error)           # the manifest itself is invalid: never retried
        # Infrastructure before pending (fetch, git, policy file, anything unexpected): retried, nothing moved.
        return {"outcome": "RETRY_LATER", "manifest": path.name, "reason": f"{type(error).__name__}: {error}"[:500]}
    os.replace(path, path.with_suffix(".applied"))
    write_identity_report(cfg, now, observe())
    return {"outcome": "APPLIED", "sha": m["sha"], "sequence": m["sequence"], "approver": m["approver"]}


def _pending_is(cfg: Config, raw: bytes) -> bool:
    try:
        return rg.read_ledger(cfg.ledger).get("pending") == hashlib.sha256(raw).hexdigest()
    except rg.Refused:
        return True                                      # unreadable ledger after a start: treat as pending (fail closed)


def _reject(cfg: Config, path: Path, sig_path: Path, error: Exception) -> dict:
    cfg.rejected.mkdir(parents=True, exist_ok=True)
    reason = f"{type(error).__name__}: {error}"[:500]
    os.replace(path, cfg.rejected / path.name)
    if sig_path.exists():
        os.replace(sig_path, cfg.rejected / sig_path.name)
    # Written to a fresh file and renamed into place: a planted symlink at the name is replaced, never followed.
    fd, tmp = tempfile.mkstemp(dir=cfg.rejected, prefix=f".{path.stem}.reason.")
    with os.fdopen(fd, "w") as f:
        f.write(reason + "\n")
    os.replace(tmp, cfg.rejected / f"{path.stem}.reason")
    return {"outcome": "REJECTED", "manifest": path.name, "reason": reason}


def founder_statement(cfg: Config, kind: str, statement: Path, signature: Path, *, now=None,
                      observe=observe_production, machine_id=None) -> dict:
    """`bootstrap`, `recover` or `reconcile`, each with its own founder signature namespace; never run by a timer.
    After a reconcile, the pending manifest is renamed .applied or .failed (abandoned counts as failed)."""
    action = {"bootstrap": rg.bootstrap, "recover": rg.recover, "reconcile": rg.reconcile}[kind]
    problem = untrusted_layout(cfg)
    if problem:
        raise rg.Refused(problem)
    pending = rg.read_ledger(cfg.ledger).get("pending") if kind == "reconcile" else None
    state = action(cfg.ledger, statement.read_bytes(), signature.read_text(),
                   founder_key=cfg.founder_key.read_text().strip(), policy_bytes=cfg.policy.read_bytes(),
                   policy_sig=cfg.policy_sig.read_text(), host_id=host_id() if machine_id is None else machine_id,
                   observe=observe, now=now or datetime.now(timezone.utc))
    if pending:
        outcome = json.loads(statement.read_bytes())["outcome"]
        for box in cfg.inboxes:
            for path in (p for p in box.glob("*.json") if _regular(p)) if box.is_dir() else []:
                try:
                    match = hashlib.sha256(_read_inbox(path)).hexdigest() == pending
                except (OSError, rg.Refused):
                    match = False
                if match:
                    os.replace(path, path.with_suffix(".applied" if outcome == "applied" else ".failed"))
    write_identity_report(cfg, now or datetime.now(timezone.utc), observe())
    return {"outcome": kind.upper() + "_DONE", "last_sha": state["last_sha"]}


def rebase_provenance(cfg: Config, old: Config):
    """The host's own git evidence for a rebase: the new clone (this config, freshly fetched) holds the base commit on
    its branch; the old clone (the previous config) holds the running release. Trees are compared, never trusted."""
    def facts(base_sha: str, old_sha: str) -> dict:
        try:
            _git(cfg, "fetch", "--no-tags", "--quiet", cfg.fetch_url,
                 f"+refs/heads/{cfg.branch}:refs/remotes/origin/{cfg.branch}")
        except (OSError, subprocess.CalledProcessError) as error:
            raise RetryLater(f"fetch failed: {type(error).__name__}") from None

        def tree(c: Config, sha: str) -> str | None:
            try:
                return _git(c, "rev-parse", "--verify", "--quiet", f"{sha}^{{tree}}").strip() or None
            except subprocess.CalledProcessError:
                return None
        on_branch = subprocess.run(["git", "-C", str(cfg.clone), "merge-base", "--is-ancestor", base_sha,
                                    f"refs/remotes/origin/{cfg.branch}"], capture_output=True).returncode == 0
        return {"old_repository": old.repository, "base_on_branch": on_branch, "base_tree": tree(cfg, base_sha),
                "old_tree": tree(old, old_sha)}
    return facts


def rebase_statement(cfg: Config, old: Config, statement: Path, signature: Path, *, now=None,
                     observe=observe_production, machine_id=None) -> dict:
    """`rebase STATEMENT SIG OLD_CONFIG`: run after this config (and its new policy) names the new repository; the
    old config still names the old clone. Never run by a timer. Nothing is deployed."""
    problem = untrusted_layout(cfg) or untrusted_path(old.clone) or untrusted_path(cfg.clone)
    if problem:
        raise rg.Refused(problem)
    if old.ledger != cfg.ledger:
        raise rg.Refused("the old and new host configs must name the same ledger")
    now = now or datetime.now(timezone.utc)
    state = rg.rebase(cfg.ledger, statement.read_bytes(), signature.read_text(),
                      founder_key=cfg.founder_key.read_text().strip(), policy_bytes=cfg.policy.read_bytes(),
                      policy_sig=cfg.policy_sig.read_text(), host_id=host_id() if machine_id is None else machine_id,
                      observe=observe, provenance=rebase_provenance(cfg, old), now=now)
    write_identity_report(cfg, now, observe())
    return {"outcome": "REBASE_DONE", "last_sha": state["last_sha"], "chain_base": state["chain_base"]}


def main() -> int:
    path = Path(os.environ.get("RELEASE_HOST_CONFIG", "/etc/release-host/config.json"))
    try:
        cfg = Config(json.loads(path.read_text()))
        if sys.argv[1:] == ["observe"]:                # read-only: what a founder statement must name
            print(json.dumps(observe_production(), sort_keys=True))
            return 0
        if len(sys.argv) == 5 and sys.argv[1] == "rebase":
            old = Config(json.loads(Path(sys.argv[4]).read_text()))
            print(json.dumps(rebase_statement(cfg, old, Path(sys.argv[2]), Path(sys.argv[3])), sort_keys=True))
            return 0
        if len(sys.argv) == 4 and sys.argv[1] in ("bootstrap", "recover", "reconcile"):
            out = founder_statement(cfg, sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))
            print(json.dumps(out, sort_keys=True))
            return 0
        out = step(cfg)
    except (rg.Refused, OSError, ValueError) as error:
        print(f"release-host: refused: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(out, sort_keys=True))
    return 0 if out["outcome"] in ("IDLE", "APPLIED") else 1


if __name__ == "__main__":
    sys.exit(main())
