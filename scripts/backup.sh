#!/usr/bin/env bash
# Company OS backup (§76, §158, §159).
#
# A backup is NOT successful because a file reached R2. Every target must pass all of:
#   dump -> local integrity check -> checksum -> R2 upload -> R2 round-trip verify
# Any failed leg is reported to Company OS, which emits BACKUP_FAILED and pages the
# founder over Telegram. Silence is never treated as success.
#
# Runs on the host (needs docker access to dump other containers). R2 upload is
# delegated to the company-api container so the host needs no AWS tooling.
#
# Usage: backup.sh [target ...]     (default: all targets)
set -uo pipefail

ENV_FILE=${ENV_FILE:-/opt/company-os/.env}
[ -f "$ENV_FILE" ] && set -a && . "$ENV_FILE" && set +a

BACKUP_LOCAL_DIR=${BACKUP_LOCAL_DIR:-/opt/company-os/backups}
COMPANY_API=${COMPANY_API:-http://company-api:8000}
API_CONTAINER=${API_CONTAINER:-company-api}
# R2 credentials live only in the host .env (sourced above). They are passed to the one
# `docker exec` that needs them, never stored in the API container's environment.
R2_ENV=(-e R2_ACCOUNT_ID -e R2_ACCESS_KEY_ID -e R2_SECRET_ACCESS_KEY -e R2_BUCKET -e R2_ENDPOINT -e R2_PREFIX)
RETENTION_DAILY=${BACKUP_RETENTION_DAILY:-14}
RETENTION_WEEKLY=${BACKUP_RETENTION_WEEKLY:-8}
RETENTION_MONTHLY=${BACKUP_RETENTION_MONTHLY:-12}
# Off-site (R2) retention, kept inside the 10 GB free tier (TASK-0022). One full run is
# ~0.3 GB without renders and ~0.7 GB with them: 7 daily + 4 weekly + 3 monthly, plus
# a single weekly/monthly copy of the regenerable renders, settles near 5 GB.
R2_KEEP_DAILY=${R2_KEEP_DAILY:-7}
R2_KEEP_WEEKLY=${R2_KEEP_WEEKLY:-4}
R2_KEEP_MONTHLY=${R2_KEEP_MONTHLY:-3}
UPLOADED=()   # targets whose off-site copy succeeded this run; only these are pruned
# Targets that carry other systems' secrets (Coolify's app env vars, the host .env files).
# With BACKUP_AGE_RECIPIENT (an `age1...` public key) set, they leave the host only as
# .age files. The private key is never on this host: an R2 leak and a host leak are then
# two different keys. Generate it off-host (`age-keygen`), keep it in the password manager.
# In production (the default) an unset recipient fails these targets instead of uploading.
ENCRYPT_TARGETS=" coolify-db config "

STAMP=$(date -u +%Y-%m-%dT%H%M%SZ)
DAY=$(date -u +%Y-%m-%d)
# Retention class: 1st of month is monthly, Sunday is weekly, everything else daily.
if [ "$(date -u +%d)" = "01" ]; then CLASS=monthly
elif [ "$(date -u +%u)" = "7" ]; then CLASS=weekly
else CLASS=daily; fi

mkdir -p "$BACKUP_LOCAL_DIR"
LOG=$BACKUP_LOCAL_DIR/backup.log
exec_log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

FAILED=0

# --------------------------------------------------------------------- reporting

report() {  # report <target> <dest> <size> <checksum> <uploaded> <verified> <ok> <error> [expected]
  local target=$1 dest=$2 size=$3 sum=$4 uploaded=$5 verified=$6 ok=$7 err=$8 expected=${9:-0}
  # `company-api` is a Docker network name the host cannot resolve, and publishing a port
  # just for this would violate §110. The report goes in through the container instead.
  local json
  json=$(TARGET="$target" DEST="$dest" SIZE="$size" SUM="$sum" UP="$uploaded" \
         VER="$verified" OK="$ok" ERR="$err" EXP="$expected" python3 -c 'import json, os
size = os.environ["SIZE"]
print(json.dumps({
    "target": os.environ["TARGET"], "destination": os.environ["DEST"] or None,
    "size_bytes": int(size) if size.isdigit() else None,
    "checksum": os.environ["SUM"] or None,
    "uploaded": os.environ["UP"] == "1",
    "integrity_verified": os.environ["VER"] == "1",
    "ok": os.environ["OK"] == "1",
    "error": os.environ["ERR"] or None,
    "expected": os.environ["EXP"] == "1",
}))')
  printf '%s' "$json" | docker exec -i "$API_CONTAINER" \
      curl -fsS -o /dev/null -X POST http://localhost:8000/backups \
           -H 'content-type: application/json' --data-binary @- \
    || { FAILED=1; exec_log "WARN could not report '$target' to Company OS"; }
}

fail() {  # fail <target> <message>
  FAILED=1
  exec_log "FAIL $1: $2"
  report "$1" "" "" "" 0 0 0 "$2"
}

# --------------------------------------------------------------------- R2 helpers

r2() { docker exec -i "${R2_ENV[@]}" "$API_CONTAINER" python -m scripts.r2 "$@"; }

r2_configured() {
  r2 check >/dev/null 2>&1
  local rc=$?
  [ $rc -eq 0 ] && return 0
  [ $rc -eq 10 ] && return 10
  return 1
}

# --------------------------------------------------------------------- one target

finish_target() {  # finish_target <target> <file> <integrity_ok>
  local target=$1 file=$2 integrity=$3
  local size sum key rc
  size=$(stat -c %s "$file")
  sum=$(sha256sum "$file" | cut -d' ' -f1)
  key="$target/$CLASS/$(basename "$file")"

  if [ "$integrity" != "1" ]; then
    fail "$target" "local integrity check failed for $(basename "$file")"
    return 1
  fi

  r2_configured; rc=$?
  if [ $rc -eq 10 ]; then
    # Credentials not issued yet. The dump and its integrity check DID pass, but the
    # off-site leg is missing, so this is reported as NOT ok — §158 is not satisfied
    # by a copy that lives on the same disk it would restore.
    exec_log "LOCAL_ONLY $target: dump+integrity ok, R2 not configured"
    # expected=1: the missing off-site leg is a known pending state, not news.
    report "$target" "local:$file" "$size" "$sum" 0 1 0 \
      "R2 not configured — off-site copy missing (dump and integrity verified locally)" 1
    return 0
  elif [ $rc -ne 0 ]; then
    report "$target" "local:$file" "$size" "$sum" 0 1 0 "R2 reachability check failed"
    FAILED=1
    return 1
  fi

  if [[ "$ENCRYPT_TARGETS" == *" $target "* ]]; then
    if [ -n "${BACKUP_AGE_RECIPIENT:-}" ]; then
      # age runs in company-api (same /backups bind mount as the R2 helper); the local
      # plaintext copy stays on the host that already holds these secrets.
      if ! docker exec "$API_CONTAINER" age -r "$BACKUP_AGE_RECIPIENT" \
             -o "/backups/${file#"$BACKUP_LOCAL_DIR"/}.age" "/backups/${file#"$BACKUP_LOCAL_DIR"/}" 2>>"$LOG"; then
        report "$target" "local:$file" "$size" "$sum" 0 1 0 "age encryption failed"
        FAILED=1
        return 1
      fi
      file="$file.age"; key="$key.age"
      size=$(stat -c %s "$file")
      sum=$(sha256sum "$file" | cut -d' ' -f1)
    elif [ "${ENVIRONMENT:-production}" = production ]; then
      # Fail closed: a plaintext copy of other systems' secrets never leaves the host. The
      # local dump stays, and BACKUP_FAILED pages until the recipient is configured.
      report "$target" "local:$file" "$size" "$sum" 0 1 0 \
        "BACKUP_AGE_RECIPIENT unset: $target carries secrets and is not uploaded unencrypted"
      FAILED=1
      return 1
    else
      exec_log "WARN $target carries secrets; BACKUP_AGE_RECIPIENT unset, uploading unencrypted ($ENVIRONMENT)"
    fi
  fi

  if ! r2 upload "/backups/${file#"$BACKUP_LOCAL_DIR"/}" "$key" >>"$LOG" 2>&1; then
    report "$target" "r2:$key" "$size" "$sum" 0 1 0 "R2 upload failed"
    FAILED=1
    return 1
  fi
  if ! r2 verify "/backups/${file#"$BACKUP_LOCAL_DIR"/}" "$key" >>"$LOG" 2>&1; then
    report "$target" "r2:$key" "$size" "$sum" 1 1 0 "R2 round-trip verification failed"
    FAILED=1
    return 1
  fi

  exec_log "OK $target -> r2:$key ($size bytes)"
  report "$target" "r2:$key" "$size" "$sum" 1 1 1 ""
  UPLOADED+=("$target")
}

# --------------------------------------------------------------------- targets

dump_pg() {  # dump_pg <target> <container> <user> <db> [extra env]
  local target=$1 container=$2 user=$3 db=$4 pw=${5:-}
  local out="$BACKUP_LOCAL_DIR/${DAY}-${target}-${STAMP}.dump"
  local envopt=()
  [ -n "$pw" ] && envopt=(-e "PGPASSWORD=$pw")

  if ! docker inspect "$container" >/dev/null 2>&1; then
    fail "$target" "container $container not found"
    return
  fi
  # -Fc keeps the dump restorable selectively and lets pg_restore read it back as an
  # integrity check without touching a live database.
  if ! docker exec "${envopt[@]}" "$container" pg_dump -U "$user" -d "$db" -Fc > "$out" 2>>"$LOG"; then
    fail "$target" "pg_dump failed"
    rm -f "$out"
    return
  fi
  # Read the WHOLE archive (every data block, rendered to /dev/null), not only its table of
  # contents: a dump cut off near its end still passes `pg_restore --list`, then restores with
  # tables silently empty. The reader is the pg_restore of the container that wrote the dump, so
  # its version always matches (company-api ships an older client than PostgreSQL 18).
  local integrity=0
  if docker exec -i "$container" pg_restore --file=/dev/null < "$out" 2>>"$LOG"; then
    integrity=1
  fi
  finish_target "$target" "$out" "$integrity"
}

# Disk fit for the streamed render archive. It is never written to this disk (dump_renders), so the only
# local need is room for logs and the reporting path: RENDER_STREAM_MARGIN (1 GiB) free. The archive's own
# size no longer matters here; the old rule (last archive + 15% growth on top of the 85% line, ~31 GB) could
# not be met on this host once the renders reached 17 GB.
RENDER_STREAM_MARGIN=$((1024 ** 3))
render_fits() {  # render_fits <avail_bytes>
  [ "$1" -ge "$RENDER_STREAM_MARGIN" ]
}

require_render_space() {  # require_render_space <target>
  # Fail closed: an unreadable or malformed measurement refuses the render instead of guessing.
  local dfraw avail
  dfraw=$(df -B1 --output=avail "$BACKUP_LOCAL_DIR" 2>>"$LOG") \
    || { fail "$1" "disk measurement failed (df); render refused, nothing written"; return 1; }
  avail=$(printf '%s\n' "$dfraw" | tail -1)
  [[ ${avail:-} =~ ^[0-9]+$ && ${#avail} -le 16 ]] \
    || { fail "$1" "disk measurement unreadable (df '$avail'); render refused, nothing written"; return 1; }
  avail=$((10#$avail))
  if ! render_fits "$avail"; then
    fail "$1" "render archive refused: only $(( avail / 1048576 )) MiB free, $(( RENDER_STREAM_MARGIN / 1048576 )) MiB needed; nothing written"
    return 1
  fi
}

dump_renders() {  # dump_renders <volume>
  # tar -> gzip -> SHA-256 -> R2 multipart in one process (scripts/r2.py stream-tar), run from the API image
  # with the volume read-only: no local archive, memory bounded by one 64 MiB part. Recorded ok only after a
  # full re-read of the object matches the streamed SHA-256 and size and decompresses to the same file count.
  local target=renders vol=$1 key image out sum size files rc
  docker volume inspect "$vol" >/dev/null 2>&1 || { fail "$target" "volume $vol not found"; return 1; }
  require_render_space "$target" || return 1
  r2_configured; rc=$?
  # No local copy exists to fall back on, so R2 not configured is a failure here, not LOCAL_ONLY.
  [ $rc -eq 0 ] || { fail "$target" "R2 not available (rc=$rc); renders are streamed off-site only"; return 1; }
  key="$target/$CLASS/${DAY}-${target}-${STAMP}.tar.gz"
  image=$(docker inspect "$API_CONTAINER" --format '{{.Config.Image}}' 2>>"$LOG") \
    || { fail "$target" "cannot resolve the API image"; return 1; }
  out=$(docker run --rm "${R2_ENV[@]}" --read-only --security-opt no-new-privileges --memory 512m \
          -v "$vol:/src:ro" --entrypoint python "$image" -m scripts.r2 stream-tar /src "$key" 2>>"$LOG"); rc=$?
  # rc 3: the archive object was completed but its manifest was not written. The object is kept and recorded as
  # uploaded but unverified, never as aborted. Any other failure aborted the multipart upload.
  if [ $rc -ne 0 ] && [ $rc -ne 3 ]; then
    fail "$target" "streamed render upload failed (rc=$rc); multipart aborted, nothing recorded"
    return 1
  fi
  read -r sum size files <<<"$out"
  [[ ${sum:-} =~ ^[0-9a-f]{64}$ && ${size:-} =~ ^[0-9]+$ && ${files:-} =~ ^[0-9]+$ ]] \
    || { fail "$target" "streamed render upload returned malformed output (rc=$rc)"; return 1; }
  if [ $rc -eq 3 ]; then
    report "$target" "r2:$key" "$size" "$sum" 1 0 0 "archive completed but its manifest upload failed; object kept"
    FAILED=1
    return 1
  fi
  if ! r2 verify-remote "$key" "$sum" "$size" "$files" >>"$LOG" 2>&1; then
    report "$target" "r2:$key" "$size" "$sum" 1 0 0 "R2 round-trip verification failed"
    FAILED=1
    return 1
  fi
  exec_log "OK $target -> r2:$key ($size bytes, $files files, streamed)"
  report "$target" "r2:$key" "$size" "$sum" 1 1 1 ""
  UPLOADED+=("$target")
}

dump_volumes() {  # dump_volumes <target> <volume>...
  local target=$1; shift
  local out="$BACKUP_LOCAL_DIR/${DAY}-${target}-${STAMP}.tar.gz"
  local vols=("$@")
  local args=() v
  for v in "${vols[@]}"; do
    if docker volume inspect "$v" >/dev/null 2>&1; then
      args+=(-v "$v:/src/$v:ro")
    else
      exec_log "WARN volume $v not found, skipped"
    fi
  done
  if [ ${#args[@]} -eq 0 ]; then fail "$target" "no volumes found"; return; fi
  if ! docker run --rm "${args[@]}" -v "$BACKUP_LOCAL_DIR:/out" alpine:3.20 \
        tar czf "/out/$(basename "$out")" -C /src . 2>>"$LOG"; then
    fail "$target" "volume tar failed"
    rm -f "$out"
    return
  fi
  local integrity=0
  tar tzf "$out" >/dev/null 2>>"$LOG" && integrity=1
  finish_target "$target" "$out" "$integrity"
}

dump_config() {
  # Coolify holds every app's env vars in its database (covered by coolify-db), but the
  # host-side config is not in any database and is not in git either.
  local target=config
  local out="$BACKUP_LOCAL_DIR/${DAY}-${target}-${STAMP}.tar.gz"
  local paths=()
  for p in /opt/youtube-auto /opt/company-os/.env /opt/company-os/docker-compose.yml /opt/company-os/facts \
           /etc/cron.d/youtube-auto /etc/cron.d/company-os /root/.ssh/authorized_keys; do
    [ -e "$p" ] && paths+=("$p")
  done
  if [ ${#paths[@]} -eq 0 ]; then fail "$target" "no config paths found"; return; fi
  # Excludes keep the archive small; node_modules and renders are reproducible.
  if ! tar czf "$out" --warning=no-file-changed \
        --exclude='*/node_modules' --exclude='*/output/*' --exclude='*/uretim/*' \
        "${paths[@]}" 2>>"$LOG"; then
    # tar exits 1 on "file changed as we read it", which is not a corrupt archive.
    tar tzf "$out" >/dev/null 2>&1 || { fail "$target" "config tar failed"; rm -f "$out"; return; }
  fi
  local integrity=0
  tar tzf "$out" >/dev/null 2>>"$LOG" && integrity=1
  finish_target "$target" "$out" "$integrity"
}

# --------------------------------------------------------------------- retention

prune_local_target() {  # Keep the newest N backup stamps per class for one verified target.
  local target=$1 f name day stamp calendar class keep count last_stamp=
  local daily=0 weekly=0 monthly=0
  while IFS= read -r -d '' f; do
    name=${f##*/}
    [[ $name =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2})-([a-z-]+)-([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}Z)\.(dump|tar\.gz)(\.age)?$ ]] || continue
    day=${BASH_REMATCH[1]}
    [ "${BASH_REMATCH[2]}" = "$target" ] || continue
    stamp=${BASH_REMATCH[3]}
    [ "${stamp:0:10}" = "$day" ] || continue
    calendar=$(date -u -d "$day" +%d-%u 2>/dev/null) || continue
    if [[ $calendar == 01-* ]]; then class=monthly; keep=$RETENTION_MONTHLY
    elif [[ $calendar == *-7 ]]; then class=weekly; keep=$RETENTION_WEEKLY
    else class=daily; keep=$RETENTION_DAILY; fi
    [[ $keep =~ ^[1-9][0-9]*$ ]] || { exec_log "WARN invalid $class local retention=$keep; no $class copies pruned"; continue; }
    if [ "$stamp" != "$last_stamp" ]; then
      case $class in
        daily)   ((daily+=1)); count=$daily ;;
        weekly)  ((weekly+=1)); count=$weekly ;;
        monthly) ((monthly+=1)); count=$monthly ;;
      esac
      last_stamp=$stamp
    fi
    if [ "$count" -gt "$keep" ]; then
      rm -f -- "$f" && exec_log "pruned local $name ($class count > $keep)"
    fi
  done < <(find "$BACKUP_LOCAL_DIR" -maxdepth 1 -type f \( -name '*.dump' -o -name '*.tar.gz' -o -name '*.age' \) -print0 | sort -zr)
}

prune_local() {
  local t f keep
  for t in "${UPLOADED[@]}"; do
    [ "$t" = renders ] || prune_local_target "$t"
  done
  # A verified replacement in R2 is required before dropping an older local render archive.
  for t in "${UPLOADED[@]}"; do
    [ "$t" = renders ] || continue
    keep=${LOCAL_KEEP_RENDERS:-1}
    [[ $keep =~ ^[1-9][0-9]*$ ]] || { exec_log "WARN invalid LOCAL_KEEP_RENDERS=$keep; no local renders pruned"; break; }
    find "$BACKUP_LOCAL_DIR" -maxdepth 1 -type f -name '*-renders-*.tar.gz' | sort |
      awk -v k="$keep" '{ a[NR] = $0 } END { for (i = 1; i <= NR - k; i++) print a[i] }' |
      while IFS= read -r f; do rm -f -- "$f" && exec_log "pruned local $(basename "$f") (older renders)"; done
    break
  done
}

prune_r2() {
  # Only targets that uploaded and verified this run: a failing run never shrinks the
  # window of good copies it failed to replace.
  local t keep output line
  for t in "${UPLOADED[@]}"; do
    case $CLASS in
      daily) keep=$R2_KEEP_DAILY ;;
      weekly) keep=$R2_KEEP_WEEKLY ;;
      monthly) keep=$R2_KEEP_MONTHLY ;;
    esac
    # ponytail: render archives are never pruned from R2 until the founder decides their retention
    # (R2 is above the free tier and no R2 object may be deleted without that decision).
    [ "$t" = renders ] && { exec_log "R2 prune skipped for renders (retention pending founder decision)"; continue; }
    if output=$(r2 prune "$t/$CLASS" "$keep" 2>>"$LOG"); then
      if [ -n "$output" ]; then
        while IFS= read -r line; do exec_log "$line"; done <<< "$output"
      fi
    else
      if [ -n "$output" ]; then
        while IFS= read -r line; do exec_log "$line"; done <<< "$output"
      fi
      exec_log "ERROR R2 prune failed for $t/$CLASS; retention was not confirmed"
      FAILED=1
    fi
  done
  if [ ${#UPLOADED[@]} -gt 0 ]; then
    if output=$(r2 usage 2>>"$LOG"); then
      if [ -n "$output" ]; then
        while IFS= read -r line; do exec_log "$line"; done <<< "$output"
      fi
    else
      if [ -n "$output" ]; then
        while IFS= read -r line; do exec_log "$line"; done <<< "$output"
      fi
      exec_log "ERROR R2 usage query failed after pruning"
      FAILED=1
    fi
  fi
}

# --------------------------------------------------------------------- main

exec_log "=== backup start class=$CLASS stamp=$STAMP ==="

TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(company-db coolify-db standalone-postgres volumes renders config)

for t in "${TARGETS[@]}"; do
  case $t in
    # The Company OS database is the company brain (§159) — first, always.
    company-db)          dump_pg company-db company-postgres "${POSTGRES_USER:-company}" \
                                 "${POSTGRES_DB:-company}" "${POSTGRES_PASSWORD:-}" ;;
    # Holds every Coolify-managed app's environment variables and deploy config.
    coolify-db)          dump_pg coolify-db coolify-db coolify coolify ;;
    standalone-postgres) dump_pg standalone-postgres ml4g2g209u0j36wcnzgzewck postgres postgres ;;
    # State volumes are small and irreplaceable: youtube-auto-state holds the 74-video
    # history and the Flow session; pb-data is labubu's entire database.
    volumes)             dump_volumes volumes youtube-auto-state pb-data ;;
    # Render output (~17 GB, regenerable) is archived weekly/monthly rather than daily (§156),
    # streamed straight to R2 because it no longer fits on this disk twice.
    renders)             if [ "$CLASS" = "daily" ]; then
                           exec_log "SKIP renders (daily class; weekly/monthly only)"
                         else
                           dump_renders youtube-auto-production
                         fi ;;
    config)              dump_config ;;
    *)                   exec_log "WARN unknown target $t" ;;
  esac
done

prune_local
prune_r2
exec_log "=== backup end failed=$FAILED ==="
exit $FAILED
