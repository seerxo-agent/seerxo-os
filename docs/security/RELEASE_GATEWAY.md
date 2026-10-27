# Independent release gateway

Status: **implemented and in use.** Production applies only release manifests that the host-side verifier
(`app/release_host.py`) accepts against the founder-signed policy and the release ledger. The legacy SSH deploy
job is retired; the remaining `ci.yml` is a readiness check that deploys nothing.

## Goal

Agents write code and open pull requests from a fork; the agent account has read-only access to the upstream
repository, so merging stays with the owner. Low-risk changes reach production with no human step. High-risk changes need the founder. And no agent, no repository
change and no GitHub login can put an unapproved commit on production. GitHub Free, no new subscription.

## Trust boundary

| Side | Holds | Can be changed by agents? |
|---|---|---|
| `Seerxo/os` repository, its workflows and CI results | code, tests, PRs | **yes**: untrusted input to a release |
| Stage C worker, coder container, PostgreSQL rows they write | task state, Stage C review records | **yes**: untrusted |
| `company-reasoner` (separate container: no database, no GitHub token, no Docker socket) | model CLIs only; answers the signer's review request like any /run call. Holds **no** key | reachable by the worker over /run (by design, for Stage B) |
| `company-review-signer` (F1: own uid 10002, no model CLI, no Docker socket, read-only, no route out) | the reviewer signing key; builds the release review itself, validates the answer strictly, signs it | **no**, required (H6) |
| Gateway service (separate Unix user on the host, outside Docker) | gateway private key; its own clone; checks runner | **no**, required (host condition H1–H4) |
| Host verifier + ledger (root-owned, outside the payload) | pinned founder public key; founder-signed policy; release ledger | **no**, required |
| Founder | founder private key (hardware-backed) | **no** |

A merged PR, a green workflow and a `merged_by` login are all on the agent side of the line, so none of them is
release evidence here.

## Keys and when the founder is involved

| Key | Signs | When |
|---|---|---|
| Founder | the policy (which enrols the gateway public key); HIGH-risk releases; migrations; rollbacks; the production baseline (`seerxo-bootstrap`); a ledger recovery (`seerxo-ledger-recovery`) | install, policy change, critical operations: not per release |
| Gateway | LOW-risk releases, after `gateway_approve` passes | automatically, 24/7 |
| Reviewer key (in `company-review-signer`) | review attestations: verdict + fingerprint of one exact release diff and nonce | per release, automatically |
| Agent keys | nothing the host accepts | — |

The founder key need not be touched for a low-risk release.

**Who decides what (P1-3, founder-approved 2026-10-17).** Risk is classified only by the founder-signed policy,
never by a model: migration, auth, deploy and rollback paths stay HIGH. Every release needs all gateway checks and an
independent reviewer APPROVE of the exact diff; HIGH additionally needs the founder's signature. The reviewer judges
correctness and safety of the diff (no category veto, so a correct migration can be approved); it is told that risk
class, signatures and approvals are irrelevant, and its packet carries none of them. A reviewer REJECT cannot be
overridden by a founder signature (no override exists). Missing or ambiguous evidence, an untrusted diff or a failed
verification refuses. Rollback is a new reviewed commit that descends from the applied release (a revert); pointing
production at an older tree is refused for every signer, so no emergency bypass exists. Changing the prompt changes
`REVIEW_PROMPT_SHA256`, which invalidates attestations made under the old instructions.

**Risk is an allow-list.** A change is LOW only if every path is plain normalised ASCII, matches the policy's
`low_risk_paths` and no `high_risk_paths` pattern. Everything else is HIGH. A deny-list protects file names, not
behaviour: a new `app/api_auth/__init__.py` package or a compiled `.so` shadows `app/api_auth.py`, and
`app/__init__.py`, `app/models.py` or `tests/*` reach high-risk code by import or execution. The proposed v1
policy therefore auto-releases `docs/*` only. Widening it (Desk, backend modules) is a founder-signed policy
change, and needs a reason the widened paths cannot reach privileged code: the Desk runs in the founder's
Access-authenticated browser, so a Desk change can act as the founder unless approval routes re-authenticate. A stolen gateway key still cannot ship a high-risk
path or a migration, because the host re-classifies the change from its own diff.

## Release flow

1. Agent merges a PR to `main` (allowed; merging is not releasing).
2. Gateway fetches the exact commit into its own clone, computes the payload digest with the same file list and
   `sha256  path` listing as `deploy-company-os.sh`, and the changed paths since the last applied release.
3. Gateway runs the checks itself in an offline container from its own image (reuses the Stage C checks container:
   `--network=none`, read-only), never trusting the repository's workflow results.
4. Gateway asks `company-review-signer` over its Unix socket (`POST /review`, gateway-signed, fresh, single-use
   nonce) to review the exact diff from the applied release. The signer builds the prompt itself
   (`RELEASE_REVIEW_PROMPT` + packet), asks `company-reasoner` /run on review-net, accepts only an answer with the
   exact schema, a known verdict and this packet's fingerprint, and signs an attestation (namespace `seerxo-review`)
   binding reviewer, packet digest (diff, commits, nonce), instruction digest, verdict and fingerprint. A caller can
   send no verdict, no prompt and no extra field. The gateway builds the manifest and calls `gateway_approve`.
   Low risk → signs with namespace `seerxo-release`. High risk → queues for the founder.
5. `release_transaction` on the host, under one exclusive lock: refuse unless bootstrapped and production runs
   exactly the ledger's release (BLOCKED, nothing written); load the founder-signed policy (no older than the
   newest applied), `verify_release` against the host's own fetch (`git_changed_paths`: `--no-renames -z`, so a
   rename lists both paths and no name is C-quoted), mark the ledger `pending`, apply with the existing driver,
   require production to run exactly the new release, append to the history, record. A crash, a failed apply or a
   wrong post-apply identity leaves `pending`: every later release is refused until the founder reconciles.

## What the host verifier refuses (each has a test)

| Attack | Refused because |
|---|---|
| Replay an applied manifest | its digest is in the ledger; sequence must exceed the last |
| No baseline, or ledger deleted/lost | not bootstrapped → nothing releases, founder-signed releases included; only a founder-signed bootstrap (new host) or recovery (host with history) re-opens it; unreadable ledger refuses all |
| Production changed outside the gateway (legacy deploy, manual `docker compose up`, retag) | running image IDs differ from the ledger → BLOCKED before verify, nothing written |
| Driver says success but production did not switch | post-apply identity must be exactly the new release on api, worker and reasoner, else the ledger stays `pending` |
| Replay a bootstrap or recovery statement, or use one on another host/policy/history | single use (digest in history), bound to machine-id, policy digest or history digest, 24 h maximum validity |
| Crash between apply and record | `pending` marker refuses every later release until the founder reconciles |
| Two releases at once | one `flock` spans verify, apply and record |
| Replay an older founder-signed policy | ledger keeps `min_policy_version`; older policies refused |
| Shadowing module, import-reachable file, test or skill change, odd or quoted path, rename hiding a file | allow-list + normalisation + host diff with both sides of a rename |
| Forged or replayed review: agent/founder key, reviewer not enrolled or a coder identity, another diff/commit/base/nonce, REJECT, wrong fingerprint, other instructions, stale or future attestation, extra fields, signature swapped between attestations | `verify_review`: enrolled reviewer key in the founder-signed policy, packet rebuilt from the verifier's own diff, fixed instruction digest |
| Founder-signed release without a review | the signed independent review is required for every approver |
| Ill-typed policy (`"false"`, `"40"`, `[]`, `null`) or ill-typed manifest (`True` as 1, numbers as timestamps) | strict types; refused, never coerced |
| Reorder / roll back / fork | `parent_sha` must equal the applied release and the commit must descend from it |
| Edit the manifest after signing | signature over canonical bytes fails; non-canonical encodings refused |
| Wrong commit, wrong payload, other repo/branch | host recomputes SHA, digest, repository, branch |
| Hide a high-risk file in the change list | host diff must equal the manifest's paths |
| Gateway-signed high-risk path or migration | host re-classifies; migrations are founder-only |
| Policy listing infrastructure as low risk | `docker-compose.yml`, `migrations/*`, `Dockerfile`, `scripts/*` and `ops/*` are always HIGH (`FOUNDER_ONLY_PATHS`) |
| Compose change or schema migration through the host | before `pending`: the host's `docker-compose.yml` must equal the applied release's file, otherwise BLOCKED until the founder reconciles the host (fail closed); a founder-signed compose change passes the host file's own hash as `ACK_COMPOSE`; `migration_to` must equal the single Alembic head the host reads at that commit |
| Migration file the host cannot read exactly | every `migrations/versions/*.py` must assign a 12-hex `revision` and a literal `down_revision` once at top level and nowhere else; helper modules, other revision formats and subdirectories are refused, so such a file must never reach an applied release through a legacy deploy (it would block every gateway release after it) |
| Agent key, wrong role key, policy signature reused as release | per-role key and per-purpose namespace |
| CI from repository workflows as test evidence | only `runner: gateway` checks bound to SHA and digest count |
| Reviewer = author; review of another commit; founder approving own change | independent, exact-commit review required |
| Expired, future-dated, over-long or naive-time manifest | time checks with bounded skew and lifetime |
| Policy signed by the gateway, tampered policy, policy disabling checks or review, gateway key = founder key | policy must be founder-signed and cannot lower the floor |

Mutation check: removing any one of twenty checks (eleven verifier checks, nine hardening checks from the
independent review) fails at least one test.

## Production identity, bootstrap and recovery (eaec910)

**Identity is what root reads from Docker, never what anyone claims.** `release_host.observe_production` runs
`docker inspect` on `company-api`, `company-worker` and `company-reasoner` and takes each running container's
content-addressed image ID (`.Image`, `sha256:` + 64 hex). Tags, labels and `Config.Image` never count (a tag can be
moved by anyone with the Docker socket). `COMPANY_OS_GIT_SHA` from the container's env is a consistency check only.
A stopped, missing or uninspectable component is left out, so the check fails closed.
Identity also includes a digest of each container's configuration (`release_host.security_config`), read with
`docker inspect --type container`: all of `Config` and `HostConfig` except a short documented volatile list
(container hostname, image tag, labels, console wiring), every mount with all its fields, the names of the attached
networks, and the environment as a digest of the sorted `NAME=value` list (so `LD_PRELOAD` or `PYTHONPATH` count;
values are never stored, only the combined digest). Set-like lists are sorted and null/[]/{} are one absence, so a
reordering never blocks. The same image run privileged, with `/var/run/docker.sock` or `/` mounted, as uid 0, on an
extra network, with other sysctls, devices or DNS, or with another command is not the recorded release. Because the
environment counts, rotating a secret in `.env` and recreating a container BLOCKs until the founder re-baselines.
Bootstrap and recovery statements name the configuration digests (`configs`) the founder attests, printed read-only
by `python3 -m app.release_host observe`; production must match them. An apply records the configuration observed
after it (from the released compose file, which is high risk).
**What the lock does not cover:** Docker is not under the ledger lock. The guarantee is: identical before (else
BLOCKED) and identical to the new release after (else pending); a Docker-socket holder could change a container
between observations, which the next step detects. H1 is what excludes that.
`release_gateway.identity_problem` compares that with the ledger's `last_sha` and `images`: all three components,
well-formed IDs, equal IDs, equal SHA, or a reason.

**Where it is enforced.**
- `release_transaction`: before verify (mismatch → `Refused("BLOCKED: …")`, ledger untouched, manifest kept in the
  inbox) and after apply (anything but exactly the new SHA's images on all three → `RuntimeError`, ledger stays
  `pending`). The recorded `images` come from that post-apply observation, not from the manifest.
- `release_host.step`: writes the identity report first; mismatch and not pending → `BLOCKED`, nothing applied, moved
  or discarded.
- Append-only history (`<ledger>.history`, one canonical JSON object per line, opened `O_APPEND`): every `bootstrap`,
  `applied` and `recovery` event with digest, SHA, sequence, images and policy floor; an `applied` event also records
  the release's verified `payload_digest` (G4 rollback evidence). It is what recovery rebuilds from. It is not hash-chained; its integrity rests on root ownership and on the founder reviewing the exact history
  whose digest the recovery statement signs.

**Bootstrap (`seerxo-bootstrap`, founder only).** No ledger means not bootstrapped: nothing releases, a
founder-signed release included. `release_host bootstrap <statement> <sig>` (never from the timer) accepts one
canonical statement `{kind: bootstrap, host_id, repository, branch, policy_sha256, release_sha, images, nonce,
issued_at, expires_at}` signed by the pinned founder key in its own namespace, bound to this host's
`/etc/machine-id`, the exact policy bytes, the release SHA and the three image IDs, valid at most 24 h, and only if
production runs exactly that right now. It refuses on any host that has a ledger **or** a history file, so it can
never reset an existing host.

**Recovery (`seerxo-ledger-recovery`, founder only, separate key purpose).** For a lost or unreadable ledger on a
host with history. The statement `{kind: recovery, host_id, repository, branch, history_sha256, last_sha,
last_sequence, images, nonce, issued_at, expires_at}` is bound to the digest of the exact history file the founder
reviewed. `seen`, the sequence floor and the policy floor are rebuilt from that history, so a recovery can never make
an applied manifest valid again or lower the sequence or the policy version; the statement's digest is recorded, so
it is single use; production must run exactly the stated release. It refuses an intact ledger.

**Re-baselining after an out-of-band change.** After a legacy deploy or a manual change the host is BLOCKED and
stays so: bootstrap refuses (ledger and history exist) and recovery refuses (ledger intact). The founder, as root,
moves the ledger aside (`mv <ledger> <ledger>.blocked-<date>`, kept as evidence), inspects what runs, and signs a
recovery statement for the current history digest naming the SHA and image IDs that now run and a `last_sequence`
at or above every manifest still in the inboxes.

**Reconcile of `pending` (F4, `seerxo-ledger-reconcile`, founder only).** `release_host reconcile <statement>
<sig>` closes exactly one started, unrecorded release. The statement `{kind: reconcile, host_id, repository, branch,
pending_digest, outcome, release_sha, images, configs, nonce, issued_at, expires_at}` names the pending digest and
what happened: `applied` (production runs the pending manifest's commit: the record failed after the switch) or
`failed`/`abandoned` (production still runs the previously recorded release). The named release, image IDs and
configuration digests must be what runs now (`release_host observe`). The pending digest joins `seen` and the
sequence floor rises to the pending manifest's, so that manifest can never be applied again; the manifest is renamed
`.applied` or `.failed`; a `reconcile` event is appended to the history. It applies nothing and reviews nothing (an
`applied` outcome only records a release the host verified, with its review, before marking it pending); it is single
use (pending is cleared) and expires within 24 h. A host in any other state (production runs neither release) needs
the re-baselining recovery above.

An applied reconcile retains the policy version verified before `pending`, in both ledger and history; a missing
pending policy version refuses instead of allowing an older policy to be replayed after an interrupted release.

**Rebase onto another repository (`seerxo-ledger-rebase`, founder only).** Moves the release chain to a repository
with a different history (for example a sanitized public copy) without deploying anything and without changing the
old repository: the histories need not share a commit or a tree. The founder points a new host config at the new
repository and a new policy that names it, the running commit is fetched (pinned) into the new clones, then
`release_host rebase <statement> <sig> <old config>` runs. The statement `{kind: rebase, host_id, repository, branch,
old_repository, old_last_sha, old_last_sequence, old_payload_digest, history_sha256, base_sha, policy_sha256, images,
configs, nonce, issued_at, expires_at}` is checked against:

- the running release: the intact, settled ledger (no `pending`), its applied release and sequence, the exact history
  file, the recorded image and configuration identity (which must also be what runs now), and `old_payload_digest`,
  which must equal both the payload digest the host recorded when it applied that release and the host's own
  recomputation from the old clone;
- the new policy, whose version must be **above** every policy applied so far;
- the new chain: `base_sha` is on the new repository's branch and the running commit is present in the new clone.

The effect is append-only: a `ledger.json.pre-rebase-<sequence>-<digest prefix>` copy, a `rebase` history event,
`last_sha`, the sequence floor and `seen` kept, the policy floor raised, `chain_base = base_sha` as the parent the next
manifest must name.

**The first release after a rebase** is computed and reviewed from what **runs**, not from `base_sha`: the host and
the gateway diff `last_sha` (the old history's running commit) against the candidate, restricted to the deployed
payload (`DEPLOY_PATHS`; files outside it are never shipped). Every byte that changes in production is therefore in
the reviewed diff, and the manifest still binds the candidate's full payload digest. Until it is applied, only the
founder may sign (the gateway refuses to sign and the host refuses a gateway signature). Applying it replaces
`chain_base`; a failed or abandoned reconcile keeps it; recovering a lost ledger restores it when the history's last
move is that rebase. Going back before the first new release is a second rebase with a still newer policy, checked
the same way. The diff is computed and reviewed on the host only; nothing from the old repository is published.

**Identity report: the gateway reads, never repairs.** Each `release_host` step (and each bootstrap/recovery) writes
`identity_report` (`{checked_at, ok, problem, last_sha, pending}`) atomically, root-owned, mode 0640 with the directory's group. The gateway
service only reads it and prepares no candidate unless it is fresh (at most 15 min old, at most 1 min in the
future, timezone-aware), `ok` is `true`, `pending` is `false` and `last_sha` is the ledger's release. A missing,
malformed, stale, failing or foreign report means WAITING. The gateway has no code path that writes the ledger,
the history or the report, holds no founder key, and cannot bootstrap or recover: a mismatch needs the founder.

Mutation check (2026-10-17, S1, measured at commit 8bd7a8c, before P2-4 changed identity_problem): 57 single-guard mutations of identity, transaction, bootstrap, statement,
recovery, host step/report and the gateway's report reader, each run against the gateway, service and host suites.
39 were killed at first; 18 survived and each got a test (missing component in the recorded images, tag instead of
image ID, ledger-without-history bootstrap, non-hex release SHA, unsigned policy at bootstrap, statement kind,
canonical bytes, lifetime, image ID format, recovery without history, seen digests and policy floor rebuilt from
history, non-hex recovery SHA, report `pending` and post-apply refresh, future-dated and naive reports) and is now
killed. One survivor is equivalent: the recovery replay check (`digest in seen`) cannot fire, because a used
statement is bound to a history digest that its own recovery event has already changed; it stays as defence in
depth. The S1 defect found: files written by `_write_atomic` were 0600 (mkstemp), so the gateway user could never
read the ledger or report; now 0640 with the directory's group (regression test asserts the mode and group).

## Host conditions required for automatic releases

- H1 Agent containers have no Docker socket, no root on the host, no `CAP_SYS_ADMIN`, and cannot write the
  verifier, ledger, policy, `allowed_signers` or the gateway user's home. Any of these false → **BLOCKED**.
- H2 The gateway runs as its own Unix user outside Docker; its private key is readable only by that user.
- H3 The deploy path accepts only a verified manifest: no repository secret or agent credential can open a shell
  on production.
- H4 The host fetches the commit with a read-only credential of its own.
- H5 The trusted checks image is built by the gateway from a founder-approved Dockerfile digest, not taken from the
  repository's latest build.
- H6 (F1) The reviewer private key exists only in `company-review-signer`: `/etc/review-signer/key` on the host,
  owned by uid 10002 with mode 0600, mounted read-only; the signer refuses a key readable by others, a symlink, or a
  missing gateway public key (`/etc/review-signer/gateway.pub`). The signer runs no model CLI, has no Docker socket,
  drops all capabilities, is read-only, and sits only on the internal `review-net` with `company-reasoner`; the
  worker is not on that network and no agent container mounts `/etc/review-signer` or `/run/review-signer-socket`.
  The socket (0660) is shared only with the gateway user's group. Host checks: `stat` of the key and socket,
  `docker inspect company-review-signer` (User, Mounts, NetworkSettings, CapDrop, ReadonlyRootfs), no
  `docker exec` for agent identities. `app/reasoner.py`, `app/providers.py` and `app/review_signer.py` are high risk.
- H7 (identity) The ledger, its history and the identity report are root-owned and written only by
  `release_host` (0640, group = the gateway's group via the directory, `root:<gateway group>` 2750: the gateway
  user must read the ledger and the report, and every parent directory must be traversable by it; others get nothing); the gateway user cannot write them or their directories. `/etc/machine-id` is stable. The three
  identity containers keep the names `company-api`, `company-worker`, `company-reasoner`, and no agent can run
  `docker` (H1), since a Docker-socket holder could recreate a container with the recorded image ID.
  Not covered by identity: `company-review-signer`, `company-reasoner-egress`, `company-postgres`, `cloudflared`,
  the host's `.env` and cron. The deploy driver does not recreate `company-review-signer`, so how the signer image is
  updated and pinned is UNKNOWN (H6 relies on it).
- H8 (root-side layout) Before anything is read or written, every step and every founder bootstrap/recover
  command checks (`untrusted_layout`) that each of these is a real directory (no symlink in any existing component),
  owned by root and not group- or world-writable, as are all its parents: the ledger's directory
  (`root:<gateway group>` 2750: group-readable, not group-writable), the identity report's directory, `rejected/`
  and `run_root` (`/run/company-os-deploy`, root 0700). Each inbox may itself be owned and written by the gateway,
  but its parents must pass the same check (the founder pre-creates the outbox inside a root-owned parent so the
  gateway cannot replace it with a link). Any failure answers BLOCKED with nothing touched, not even the identity
  report. Inbox entries: only regular files with one hard link, at most 1 MiB, opened without following links; a
  directory, FIFO or symlink entry is skipped and never moved. The ledger lock is root-only (0600).
- H9 (install) The timer and the `bootstrap`/`recover` commands run with `WorkingDirectory` set to the root-owned
  install directory: `python3 -m app.release_host` resolves `app` from the current directory, so running it from
  `/opt/company-os` would import the deploy payload as root.
- H6 residual: the worker can still call `company-reasoner` /run with the same instructions and get an unsigned
  verdict, i.e. it can tune a diff against the reviewer model offline. That cannot be removed while Stage B uses the
  same reasoner; it is bounded by "a rejected base goes to the founder", by the allow-list (docs/* only) and by
  the signer accepting only gateway requests. Widening the allow-list must weigh this.

## Known gaps (not closed by this change)

- G1 (done in code, 2026-10-17): `app/release_host.py`, run by root on the production host from a timer. It takes
  the lowest-sequence manifest from the gateway outbox or the founder inbox, fetches main into the host's own clone
  (read-only credential), computes commit-on-main, payload digest, changed paths, release diff and ancestry itself,
  and runs `release_transaction`. Apply builds the staged transport's three files (src.tgz, main.sha256, the
  driver's root-side script) from that clone and runs the existing driver attached: exit 0 or the ledger stays
  `pending` and nothing else is applied. Refused manifests move to `rejected/` with their reason; a pending host
  never moves or discards anything. No workflow, runner or SSH key takes part.
  It is installed root-owned outside the payload, with the pinned founder key, a timer and a read-only clone
  credential. `tests/test_trust_boundary.py` keeps two strict xfail markers documenting that the GitHub-identity
  checks of the readiness workflow are not the release authority.
- G2 (done in code, 2026-10-17; key moved to company-review-signer by F1): reviews are signed by a key that only the signer holds and are bound to
  the exact release diff and a gateway nonce; database review rows are no longer evidence. The reviewer public key is enrolled in the signed policy.
- G3 (done in code, 2026-10-17): `app/release_gateway_service.py`, one candidate per tick: fetch main into its own
  clone; stop unless main descends from the applied release; changed paths, diff and payload digest
  (`payload_listing`, the deploy script's exact file list) from its own clone; its own checks; a signed review with
  a fresh nonce; LOW → `gateway_approve` + sign → outbox (`.json` renamed in last); HIGH, migration or auto-release
  off → unsigned draft in the founder queue. Each commit is decided once (no repeated checks or model calls);
  infrastructure failures retry at most `MAX_ATTEMPTS` times; a pending host release or no applied release stops it.
  After the reviewer rejects a candidate, every later candidate on the same release base goes to the founder (a
  trivial new commit does not buy a new review). A review whose outcome is unknown (a transport error or a 502/500 after the signer may have
  asked the model) counts the same as a rejection on that base and decides the commit (REVIEW_UNKNOWN); only a review
  that was certainly not asked (no socket, connect error, signer 400/403/409/503) is retried, bounded. The state file
  is fsynced with its directory, and the attempt is counted before checks and review run. Ticks hold an exclusive lock; a malformed state file refuses;
  freshness of the review and the manifest's lifetime start after the review, not at the start of the tick; git
  runs without hooks or textconv. The systemd timer, the gateway user, its clone credential (the
  clone must be the gateway user's own, mode 0700) and its checks container are set up by the owner on the host (H2, H4, H5). A signed manifest the host has not applied before it expires needs the founder.
- Host liveness (F2–F4, founder-approved 2026-10-18, done in code): F2 every failure once `pending` names the
  manifest is APPLY_FAILED with the manifest and signature kept; an invalid entry is REJECTED; infrastructure before
  pending (fetch, git, unreadable policy) is RETRY_LATER with nothing moved. F3 the release directory is
  `<sha>.<8 hex>` under the pinned `run_root` `/run/company-os-deploy`, exactly what the driver accepts. F4 founder
  reconcile (above).
- Documented, not fixed (founder decision pending): `release_host.default_run` runs the driver with no timeout, so a
  hung driver holds the ledger lock and the timer's next step forever (fail closed: nothing else is applied). The
  gateway's own checks (`default_checks`) still export the tree with `git archive`, so its checks could run on
  `.gitattributes`-substituted bytes; the host now refuses to ship such an archive (P2-5), so this can only make a
  check disagree, never ship different bytes. The legacy client-side driver has the same `git archive` behaviour.
- G4 Rollback (founder rule, 2026-10-18): only as a NEW, auditable, forward release: a commit on main that
  descends from the applied release (normally a revert) and goes through the full path, reviewer APPROVE of its exact
  diff plus the founder's signature whenever it touches shipped code (every shipped path is HIGH, P2-7). Pointing
  production at an older tree directly is refused for every signer (`commit does not descend`), and there is no
  emergency bypass and no automatic rollback. A release that declares itself a rollback (founder rule, 2026-10-19)
  carries the optional manifest field `rollback_to` (40-hex SHA of the earlier release it restores) and is verified
  on the host, after every check above, against its own trusted history (`<ledger>.history`, read under the ledger
  lock): it must be founder-signed (`gateway_approve` and the host both refuse a gateway-signed rollback, whatever
  its paths); `rollback_to` must not be the release already running; the newest `applied` event for that SHA must
  exist (a `bootstrap`, `recovery` or `reconcile` event is not evidence); that event's recorded `payload_digest`
  must equal the payload digest the host computed for the new commit (the shipped tree, DEPLOY_PATHS, is the same,
  not merely the commit name); and that event must record a well-formed image ID and configuration digest for api,
  worker and reasoner. Any missing, malformed or different piece, or an unreadable history, refuses. Releases
  applied before payload digests were recorded and the bootstrap baseline cannot be rollback targets. **Until the
  running images can be proven to be the target's recorded image IDs, every declared rollback refuses after these
  checks** (founder, 2026-10-20: rebuilt images get new IDs, and a rollback whose images are not the recorded ones is
  not a verified rollback; redeploying images by recorded ID is a separate deploy-driver change). A revert that does
  not declare `rollback_to` is an ordinary forward release judged by the reviewer and the founder on its exact diff,
  and is never reported as a verified rollback.
