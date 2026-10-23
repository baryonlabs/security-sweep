#!/usr/bin/env bash
# security-sweep: sweep.sh
#
# targets.json 의 프로젝트, ssh 서버, 컨테이너 이미지를 스캐너로 훑어 OUT/raw/ 아래에 원본 결과를 남긴다.
# Runs scanners over the projects in targets.json plus optional ssh servers and container
# images, writing raw results under OUT/raw/ and tool status rows to OUT/tools.txt.
#
# Read-only: never modifies scanned projects, never installs anything, never uses sudo.
# Portable: macOS bash 3.2 / BSD userland and Linux GNU userland. Needs python3 (stdlib).
# Exit codes: 0 = sweep finished (scanner findings or individual scanner errors are recorded,
#             not fatal), 1 = execution error (bad arguments, unreadable targets, no python3).

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: sweep.sh [--targets OUT/targets.json] [OPTIONS]

Options:
  --targets FILE      targets.json from discover.sh (optional if only servers/images)
  --server HOST       ssh target (user@host or ssh alias); repeatable
  --image NAME        container image to scan with trivy; repeatable
  --running-images    also scan images of running containers (docker ps, read-only)
  --no-secrets        trivy fs runs misconfig only (no secret scanning)
  --out OUT           output directory (default: directory of --targets, else
                      ./security-sweep-YYYYMMDD-HHMM)
  --jobs N            projects scanned in parallel (default 4)
  --dry-run           print the planned commands, run nothing, write nothing
  -h, --help          show this help

Environment:
  ELIXIR_AUDIT_SCAN   path to elixir-security-audit scripts/scan.sh (otherwise searched
                      under ~/.claude/plugins and ~/.claude/skills)

Writes OUT/raw/{osv,trivy-fs,elixir,govulncheck,image,server}/... and OUT/tools.txt
(tool<TAB>status<TAB>note; status is ok|available|missing|error|skipped).
EOF
}

warn() { printf '[sweep] WARN: %s\n' "$*" >&2; }
info() { printf '[sweep] %s\n' "$*" >&2; }

TARGETS=""
OUT_DIR=""
JOBS=4
DRY_RUN=0
NO_SECRETS=0
RUNNING_IMAGES=0
SERVERS=()
IMAGES=()

need_arg() { if [ "$2" -lt 2 ]; then warn "$1 requires a value"; exit 1; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --targets) need_arg "$1" $#; TARGETS="$2"; shift ;;
    --targets=*) TARGETS="${1#--targets=}" ;;
    --server) need_arg "$1" $#; SERVERS+=("$2"); shift ;;
    --server=*) SERVERS+=("${1#--server=}") ;;
    --image) need_arg "$1" $#; IMAGES+=("$2"); shift ;;
    --image=*) IMAGES+=("${1#--image=}") ;;
    --running-images) RUNNING_IMAGES=1 ;;
    --no-secrets) NO_SECRETS=1 ;;
    --out) need_arg "$1" $#; OUT_DIR="$2"; shift ;;
    --out=*) OUT_DIR="${1#--out=}" ;;
    --jobs) need_arg "$1" $#; JOBS="$2"; shift ;;
    --jobs=*) JOBS="${1#--jobs=}" ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) warn "unknown argument: $1"; usage >&2; exit 1 ;;
  esac
  shift
done

case "$JOBS" in ''|*[!0-9]*|0) warn "--jobs must be a positive integer: $JOBS"; exit 1 ;; esac
command -v python3 >/dev/null 2>&1 || { warn "python3 is required"; exit 1; }

if [ -n "$TARGETS" ] && [ ! -r "$TARGETS" ]; then warn "cannot read targets: $TARGETS"; exit 1; fi
if [ -z "$TARGETS" ] && [ ${#SERVERS[@]} -eq 0 ] && [ ${#IMAGES[@]} -eq 0 ] && [ $RUNNING_IMAGES -eq 0 ]; then
  warn "nothing to scan: give --targets, --server, --image or --running-images"; usage >&2; exit 1
fi

if [ -z "$OUT_DIR" ]; then
  if [ -n "$TARGETS" ]; then OUT_DIR=$(dirname "$TARGETS")
  else OUT_DIR="./security-sweep-$(date +%Y%m%d-%H%M)"; fi
fi

if [ $DRY_RUN -eq 0 ]; then
  mkdir -p "$OUT_DIR" || { warn "cannot create $OUT_DIR"; exit 1; }
  OUT_DIR=$(cd "$OUT_DIR" && pwd) || { warn "cannot resolve $OUT_DIR"; exit 1; }
  RAW="$OUT_DIR/raw"; LOGS="$OUT_DIR/logs"; TOOLS="$OUT_DIR/tools.txt"
  mkdir -p "$RAW/osv" "$RAW/trivy-fs" "$RAW/elixir" "$RAW/govulncheck" "$RAW/image" "$RAW/server" "$LOGS" \
    || { warn "cannot create $RAW"; exit 1; }
  : >"$TOOLS" || { warn "cannot write $TOOLS"; exit 1; }
else
  RAW="$OUT_DIR/raw"; LOGS="$OUT_DIR/logs"; TOOLS="/dev/null"
fi

# ---------------------------------------------------------------- helpers

# tool_row TOOL STATUS NOTE — one short line; O_APPEND keeps parallel writers intact.
tool_row() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" | tr -d '\r' >>"$TOOLS"; }

safe_name() { printf '%s' "$1" | LC_ALL=C sed 's/[^A-Za-z0-9._-]/_/g'; }

# show_cmd OUTFILE CMD... — dry-run printer (shell-quoted).
show_cmd() {
  local out="$1"; shift
  local s="" a
  for a in "$@"; do s="$s $(printf '%q' "$a")"; done
  if [ -n "$out" ]; then printf '%s > %s\n' "${s# }" "$(printf '%q' "$out")"
  else printf '%s\n' "${s# }"; fi
}

valid_json() { python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" >/dev/null 2>&1; }

# strip_secret_code FILE — drop Results[].Secrets[].Code from trivy JSON in place. trivy masks the
# matched line but keeps surrounding context lines verbatim, so no raw secret text is kept on disk.
strip_secret_code() {
  python3 - "$1" <<'PY' >/dev/null 2>&1
import json, os, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    doc = json.load(f)
changed = False
for r in doc.get("Results") or []:
    for sec in r.get("Secrets") or []:
        if "Code" in sec:
            del sec["Code"]; changed = True
if changed:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)
    os.replace(tmp, path)
PY
}

have() { command -v "$1" >/dev/null 2>&1; }

TRIVY_SKIP_DIRS="**/node_modules,**/deps,**/_build,**/.venv,**/venv,**/target,**/vendor,**/dist,**/.git"

# ---------------------------------------------------------------- tool inventory

HAVE_OSV=0; HAVE_TRIVY=0; HAVE_GOVULN=0; ELIXIR_SCAN=""

if have osv-scanner; then
  HAVE_OSV=1; tool_row osv-scanner available "$(osv-scanner --version 2>/dev/null | head -1)"
else
  tool_row osv-scanner missing "install: brew install osv-scanner | go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"
fi
if have trivy; then
  HAVE_TRIVY=1; tool_row trivy available "$(trivy --version 2>/dev/null | head -1)"
else
  tool_row trivy missing "install: brew install trivy | https://trivy.dev/latest/getting-started/installation/"
fi
if have govulncheck; then
  HAVE_GOVULN=1; tool_row govulncheck available "$(govulncheck -version 2>/dev/null | grep -i 'scanner' | head -1)"
else
  tool_row govulncheck missing "install: go install golang.org/x/vuln/cmd/govulncheck@latest"
fi

if [ -n "${ELIXIR_AUDIT_SCAN:-}" ]; then
  if [ -f "$ELIXIR_AUDIT_SCAN" ]; then ELIXIR_SCAN="$ELIXIR_AUDIT_SCAN"
  else warn "ELIXIR_AUDIT_SCAN not a file: $ELIXIR_AUDIT_SCAN"; fi
fi
if [ -z "$ELIXIR_SCAN" ]; then
  for base in "$HOME/.claude/plugins" "$HOME/.claude/skills"; do
    [ -d "$base" ] || continue
    ELIXIR_SCAN=$(find -L "$base" -maxdepth 9 -type f -path '*/elixir-security-audit/scripts/scan.sh' 2>/dev/null | head -1)
    [ -n "$ELIXIR_SCAN" ] && break
  done
fi
if [ -n "$ELIXIR_SCAN" ]; then
  tool_row elixir-security-audit available "$ELIXIR_SCAN"
else
  tool_row elixir-security-audit missing "set ELIXIR_AUDIT_SCAN or install the elixir-security-audit plugin"
fi

# ---------------------------------------------------------------- projects

# Emit one record per project, fields separated by \037 (non-whitespace, so empty fields survive read):
# name, path, ecosystems(,), lockfiles(\036), trivy-skip(,)
# Nested projects are skipped in the parent's trivy fs run to avoid duplicate findings.
# If a name had to be sanitized or de-duplicated, targets.json is rewritten (unless --dry-run) so
# raw/<tool>/<name>.json stems always equal projects[].name for the analysis scripts.
project_records() {
  python3 - "$1" "$DRY_RUN" <<'PY'
import json, os, re, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
renamed = False
ps = doc.get("projects") or []
paths = [os.path.abspath(p.get("path", "")) for p in ps]
used = set()
for p, path in zip(ps, paths):
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", p.get("name") or os.path.basename(path)).strip("._") or "project"
    base, n = name, 2
    while name in used:
        name = "%s-%d" % (base, n); n += 1
    used.add(name)
    if name != p.get("name"):
        sys.stderr.write("[sweep] WARN: project name %r -> %r\n" % (p.get("name"), name))
        p["name"] = name; renamed = True
    nested = []
    for other in paths:
        if other != path and other.startswith(path.rstrip("/") + "/"):
            nested.append(os.path.relpath(other, path))
    fields = [name, path, ",".join(p.get("ecosystems") or []),
              "\036".join(p.get("lockfiles") or []), ",".join(nested)]
    if any(("\037" in f or "\036" in f or "\n" in f) for f in fields):
        sys.stderr.write("[sweep] WARN: skipping project with control characters in path: %r\n" % path)
        continue
    print("\037".join(fields))
if renamed and sys.argv[2] != "1":
    tmp = sys.argv[1] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, sys.argv[1])
PY
}

scan_osv() { # name path lockfiles
  local name="$1" path="$2" locks="$3" out="$RAW/osv/$1.json" log="$LOGS/osv-$1.log"
  [ $HAVE_OSV -eq 1 ] || return 0
  if [ -z "$locks" ]; then tool_row osv-scanner skipped "$name: no lockfile (manifest only)"; return 0; fi
  local args=() l old_ifs="$IFS"
  IFS=$'\036'
  for l in $locks; do args+=(-L "$l"); done
  IFS="$old_ifs"
  if [ $DRY_RUN -eq 1 ]; then
    show_cmd "" osv-scanner scan source --format json --output-file "$out" "${args[@]}"; return 0
  fi
  osv-scanner scan source --format json --output-file "$out" "${args[@]}" >"$log" 2>&1
  local rc=$?
  case $rc in
    0|1|128)
      if ! valid_json "$out"; then
        if [ $rc -eq 128 ]; then printf '{"results": []}\n' >"$out"
        else tool_row osv-scanner error "$name: exit $rc but output not valid JSON (see logs/osv-$name.log)"; return 0; fi
      fi
      case $rc in
        0) tool_row osv-scanner ok "$name: exit 0 (no vulns)" ;;
        1) tool_row osv-scanner ok "$name: exit 1 (vulns found)" ;;
        128) tool_row osv-scanner ok "$name: exit 128 (no packages)" ;;
      esac ;;
    *) tool_row osv-scanner error "$name: exit $rc (see logs/osv-$name.log)" ;;
  esac
}

scan_trivy_fs() { # name path nested
  local name="$1" path="$2" nested="$3" out="$RAW/trivy-fs/$1.json" log="$LOGS/trivy-fs-$1.log"
  [ $HAVE_TRIVY -eq 1 ] || return 0
  local scanners="secret,misconfig" skip="$TRIVY_SKIP_DIRS"
  [ $NO_SECRETS -eq 1 ] && scanners="misconfig"
  [ -n "$nested" ] && skip="$skip,$nested"
  local cmd=(trivy fs --scanners "$scanners" --format json --output "$out" --quiet --timeout 10m
             --skip-version-check --skip-dirs "$skip" "$path")
  if [ $DRY_RUN -eq 1 ]; then show_cmd "" "${cmd[@]}"; return 0; fi
  "${cmd[@]}" >"$log" 2>&1
  local rc=$?
  if [ $rc -eq 0 ] && valid_json "$out"; then strip_secret_code "$out"; tool_row trivy ok "$name: fs $scanners"
  else tool_row trivy error "$name: fs exit $rc (see logs/trivy-fs-$name.log)"; fi
}

scan_elixir() { # name path
  local name="$1" path="$2" out="$RAW/elixir/$1" log="$LOGS/elixir-$1.log"
  [ -n "$ELIXIR_SCAN" ] || { tool_row elixir-security-audit skipped "$name: scan.sh not found"; return 0; }
  if [ $DRY_RUN -eq 1 ]; then show_cmd "" bash "$ELIXIR_SCAN" --no-deps-fetch --out "$out" "$path"; return 0; fi
  mkdir -p "$out"
  bash "$ELIXIR_SCAN" --no-deps-fetch --out "$out" "$path" >"$log" 2>&1
  local rc=$?
  case $rc in
    0) tool_row elixir-security-audit ok "$name" ;;
    2) tool_row elixir-security-audit skipped "$name: not an Elixir project (exit 2)" ;;
    *) tool_row elixir-security-audit error "$name: exit $rc (see logs/elixir-$name.log)" ;;
  esac
}

scan_govuln() { # name path
  local name="$1" path="$2" out="$RAW/govulncheck/$1.json" log="$LOGS/govulncheck-$1.log"
  [ $HAVE_GOVULN -eq 1 ] || { tool_row govulncheck skipped "$name: govulncheck not installed"; return 0; }
  if [ $DRY_RUN -eq 1 ]; then printf 'cd %q && govulncheck -json ./... > %q\n' "$path" "$out"; return 0; fi
  (cd "$path" && govulncheck -json ./...) >"$out" 2>"$log"
  local rc=$?
  # -json exits 0 even when vulnerabilities are found; non-zero means it could not analyze.
  if [ $rc -eq 0 ]; then tool_row govulncheck ok "$name"
  else tool_row govulncheck error "$name: exit $rc (see logs/govulncheck-$name.log)"; fi
}

scan_project() { # name path ecosystems lockfiles nested
  local name="$1" path="$2" ecos="$3" locks="$4" nested="$5"
  if [ ! -d "$path" ]; then tool_row sweep error "$name: path missing: $path"; return 0; fi
  [ $DRY_RUN -eq 1 ] || info "project $name ($ecos)"
  scan_osv "$name" "$path" "$locks"
  scan_trivy_fs "$name" "$path" "$nested"
  case ",$ecos," in *,hex,*) scan_elixir "$name" "$path" ;; esac
  case ",$ecos," in *,go,*) scan_govuln "$name" "$path" ;; esac
  return 0
}

wait_for_slot() {
  while [ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$JOBS" ]; do sleep 1; done
}

N_PROJECTS=0
if [ -n "$TARGETS" ]; then
  RECORDS=$(project_records "$TARGETS") || { warn "cannot parse $TARGETS"; exit 1; }
  if [ -n "$RECORDS" ]; then
    while IFS=$'\037' read -r p_name p_path p_ecos p_locks p_nested; do
      [ -n "$p_name" ] || continue
      N_PROJECTS=$((N_PROJECTS + 1))
      if [ $DRY_RUN -eq 1 ] || [ "$JOBS" -eq 1 ]; then
        scan_project "$p_name" "$p_path" "$p_ecos" "$p_locks" "$p_nested" </dev/null
      else
        wait_for_slot
        scan_project "$p_name" "$p_path" "$p_ecos" "$p_locks" "$p_nested" </dev/null &
      fi
    done <<EOF
$RECORDS
EOF
    wait
  fi
  [ $DRY_RUN -eq 1 ] || info "$N_PROJECTS projects done"
fi

# ---------------------------------------------------------------- images

if [ $RUNNING_IMAGES -eq 1 ]; then
  if have docker; then
    if [ $DRY_RUN -eq 1 ]; then show_cmd "" docker ps --format '{{.Image}}'; fi
    RUNNING=$(docker ps --format '{{.Image}}' 2>/dev/null)
    rc=$?
    if [ $rc -ne 0 ]; then tool_row docker error "docker ps failed (exit $rc; daemon not running?)"
    else
      tool_row docker ok "running images: $(printf '%s\n' "$RUNNING" | grep -c . | tr -d ' ')"
      while IFS= read -r img; do [ -n "$img" ] && IMAGES+=("$img"); done <<EOF
$(printf '%s\n' "$RUNNING" | sort -u)
EOF
    fi
  else
    tool_row docker missing "--running-images needs the docker CLI"
  fi
fi

N_IMAGES=0
for img in ${IMAGES[@]+"${IMAGES[@]}"}; do
  # skip duplicates (an image given with --image and also running)
  case " ${SEEN_IMAGES:-} " in *" $img "*) continue ;; esac
  SEEN_IMAGES="${SEEN_IMAGES:-} $img"
  N_IMAGES=$((N_IMAGES + 1))
  sname=$(safe_name "$img"); out="$RAW/image/$sname.json"; log="$LOGS/image-$sname.log"
  if [ $HAVE_TRIVY -eq 0 ]; then tool_row trivy-image skipped "$img: trivy not installed"; continue; fi
  scanners="vuln,secret"; [ $NO_SECRETS -eq 1 ] && scanners="vuln"
  cmd=(trivy image --scanners "$scanners" --format json --output "$out" --quiet --timeout 10m --skip-version-check "$img")
  if [ $DRY_RUN -eq 1 ]; then show_cmd "" "${cmd[@]}"; continue; fi
  info "image $img"
  "${cmd[@]}" >"$log" 2>&1
  rc=$?
  if [ $rc -eq 0 ] && valid_json "$out"; then strip_secret_code "$out"; tool_row trivy-image ok "$img"
  else tool_row trivy-image error "$img: exit $rc ($(tail -1 "$log" 2>/dev/null | cut -c1-160))"; fi
done

# ---------------------------------------------------------------- servers

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)

# Package inventory script run remotely via `sh -s` (POSIX sh; no sudo, no writes).
# shellcheck disable=SC2016  # expands on the remote host, not locally
PKG_SCRIPT='
if [ -r /etc/os-release ]; then . /etc/os-release; echo "# os: ID=${ID:-} VERSION_ID=${VERSION_ID:-}"; else echo "# os: unknown"; fi
if command -v dpkg-query >/dev/null 2>&1; then
  echo "# pm: dpkg"; dpkg-query -W -f="\${Package}\t\${Version}\n"
elif command -v rpm >/dev/null 2>&1; then
  echo "# pm: rpm"; rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\n"
elif command -v apk >/dev/null 2>&1; then
  echo "# pm: apk"; apk info -v
else
  echo "# pm: none"
fi
'
REMOTE_TRIVY='trivy rootfs --scanners vuln --format json --quiet --timeout 15m --skip-version-check --skip-dirs /proc,/sys,/dev,/run /'

N_SERVERS=0
for host in ${SERVERS[@]+"${SERVERS[@]}"}; do
  N_SERVERS=$((N_SERVERS + 1))
  sname=$(safe_name "${host##*@}"); out="$RAW/server/$sname.json"; log="$LOGS/server-$sname.log"
  if ! have ssh; then tool_row ssh missing "$host: ssh client not installed"; continue; fi
  if [ $DRY_RUN -eq 1 ]; then
    show_cmd "" ssh "${SSH_OPTS[@]}" "$host" 'command -v trivy'
    show_cmd "$out" ssh "${SSH_OPTS[@]}" "$host" "$REMOTE_TRIVY"
    printf '# if remote trivy is missing:\n'
    show_cmd "$RAW/server/$sname.packages.txt" ssh "${SSH_OPTS[@]}" "$host" 'sh -s'
    continue
  fi
  info "server $host"
  ssh "${SSH_OPTS[@]}" "$host" 'command -v trivy' >"$log" 2>&1 </dev/null
  rc=$?
  if [ $rc -eq 255 ]; then
    tool_row ssh error "$host: connection failed (exit 255: $(tail -1 "$log" | cut -c1-160))"; continue
  fi
  tool_row ssh ok "$host: connected"
  if [ $rc -eq 0 ]; then
    # shellcheck disable=SC2029  # REMOTE_TRIVY is a fixed local string by design
    ssh "${SSH_OPTS[@]}" "$host" "$REMOTE_TRIVY" >"$out" 2>>"$log" </dev/null
    rc=$?
    if [ $rc -eq 0 ] && valid_json "$out"; then tool_row trivy ok "$host: rootfs /"; continue; fi
    tool_row trivy error "$host: remote trivy rootfs exit $rc; falling back to package list"
    rm -f "$out"
  else
    tool_row trivy missing "$host: no trivy on server; collected package list only. To install (manually, with approval): https://trivy.dev/latest/getting-started/installation/"
  fi
  pkgs="$RAW/server/$sname.packages.txt"
  rc=1
  { printf '# host: %s\n' "$host"; printf '%s' "$PKG_SCRIPT" | ssh "${SSH_OPTS[@]}" "$host" 'sh -s' 2>>"$log"; rc=$?; } >"$pkgs"
  if [ "$rc" -eq 0 ]; then tool_row ssh ok "$host: package list ($(grep -vc '^#' "$pkgs" | tr -d ' ') packages)"
  else tool_row ssh error "$host: package list exit $rc"; fi
done

# ---------------------------------------------------------------- summary

if [ $DRY_RUN -eq 1 ]; then
  info "dry-run: $N_PROJECTS projects, ${N_IMAGES} images, ${N_SERVERS} servers planned; nothing executed"
  exit 0
fi

{
  printf '[sweep] done: %d projects, %d images, %d servers -> %s\n' "$N_PROJECTS" "$N_IMAGES" "$N_SERVERS" "$OUT_DIR"
  awk -F '\t' '{ k = $1 " " $2; c[k]++ } END { for (k in c) printf "[sweep]   %-32s %d\n", k, c[k] }' "$TOOLS" | sort
} >&2
exit 0
