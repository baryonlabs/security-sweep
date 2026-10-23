#!/usr/bin/env bash
# security-sweep: discover.sh
#
# 하나 이상의 ROOT 아래에서 프로젝트(매니페스트/락파일이 있는 디렉터리)를 찾아 OUT/targets.json 을 만든다.
# Finds projects (directories holding a manifest or lockfile) under one or more roots
# and writes OUT/targets.json. Read-only: never writes inside the scanned roots.
#
# Portable: macOS bash 3.2 / BSD userland and Linux GNU userland. Needs python3 (stdlib).
# Exit codes: 0 = done (even with zero projects), 1 = usage or execution error.

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: discover.sh ROOT... [--max-depth N] [--out OUT]

Find projects under each ROOT and write OUT/targets.json.

Options:
  --max-depth N   Deepest project directory to consider, relative to ROOT (default 4)
  --out OUT       Output directory (default ./security-sweep-YYYYMMDD-HHMM)
  -h, --help      Show this help

A project is any directory containing one of:
  lockfiles  package-lock.json pnpm-lock.yaml yarn.lock requirements*.txt poetry.lock
             uv.lock Pipfile.lock mix.lock go.mod Cargo.lock composer.lock Gemfile.lock
             pom.xml gradle.lockfile
  manifests  package.json pyproject.toml Pipfile setup.py mix.exs Cargo.toml composer.json
             Gemfile build.gradle build.gradle.kts
Pruned: node_modules deps _build vendor .venv venv target dist build .git .tox .next .nuxt
        bower_components, .claude/worktrees (agent worktree copies) and previous security-sweep-* / security-audit output directories.
EOF
}

warn() { printf '[discover] WARN: %s\n' "$*" >&2; }
info() { printf '[discover] %s\n' "$*" >&2; }

MAX_DEPTH=4
OUT_DIR=""
ROOTS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --max-depth)
      if [ $# -lt 2 ]; then warn "--max-depth requires a number"; exit 1; fi
      MAX_DEPTH="$2"; shift ;;
    --max-depth=*) MAX_DEPTH="${1#--max-depth=}" ;;
    --out)
      if [ $# -lt 2 ]; then warn "--out requires a directory"; exit 1; fi
      OUT_DIR="$2"; shift ;;
    --out=*) OUT_DIR="${1#--out=}" ;;
    -h|--help) usage; exit 0 ;;
    --) shift; while [ $# -gt 0 ]; do ROOTS+=("$1"); shift; done; break ;;
    -*) warn "unknown option: $1"; usage >&2; exit 1 ;;
    *) ROOTS+=("$1") ;;
  esac
  shift
done

case "$MAX_DEPTH" in
  ''|*[!0-9]*) warn "--max-depth must be a non-negative integer: $MAX_DEPTH"; exit 1 ;;
esac
if [ ${#ROOTS[@]} -eq 0 ]; then warn "at least one ROOT is required"; usage >&2; exit 1; fi
command -v python3 >/dev/null 2>&1 || { warn "python3 is required"; exit 1; }

# Resolve roots to absolute paths (no readlink -f on macOS).
ABS_ROOTS=()
for r in "${ROOTS[@]}"; do
  if [ ! -d "$r" ]; then warn "not a directory, skipped: $r"; continue; fi
  a=$(cd "$r" && pwd -P) || { warn "cannot resolve, skipped: $r"; continue; }
  ABS_ROOTS+=("$a")
done
if [ ${#ABS_ROOTS[@]} -eq 0 ]; then warn "no usable ROOT"; exit 1; fi

[ -n "$OUT_DIR" ] || OUT_DIR="./security-sweep-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUT_DIR" || { warn "cannot create $OUT_DIR"; exit 1; }
OUT_DIR=$(cd "$OUT_DIR" && pwd) || { warn "cannot resolve $OUT_DIR"; exit 1; }

LIST=$(mktemp "${TMPDIR:-/tmp}/discover.XXXXXX") || { warn "mktemp failed"; exit 1; }
trap 'rm -f "$LIST"' EXIT

# Files live one level below the project dir, so files go to depth MAX_DEPTH+1.
FILE_DEPTH=$((MAX_DEPTH + 1))
for root in "${ABS_ROOTS[@]}"; do
  info "scanning $root (max-depth $MAX_DEPTH)"
  find "$root" -maxdepth "$FILE_DEPTH" \
    \( -type d \( -name node_modules -o -name deps -o -name _build -o -name vendor \
                 -o -name .venv -o -name venv -o -name target -o -name dist -o -name build \
                 -o -name .git -o -name .tox -o -name .next -o -name .nuxt -o -name bower_components \
                 -o -name 'security-sweep-*' -o -name security-audit \
                 -o -path '*/.claude/worktrees' \) -prune \) \
    -o \( -type f \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \
                 -o -name 'requirements*.txt' -o -name poetry.lock -o -name uv.lock \
                 -o -name Pipfile.lock -o -name mix.lock -o -name go.mod -o -name Cargo.lock \
                 -o -name composer.lock -o -name Gemfile.lock -o -name pom.xml \
                 -o -name gradle.lockfile \
                 -o -name package.json -o -name pyproject.toml -o -name Pipfile -o -name setup.py \
                 -o -name mix.exs -o -name Cargo.toml -o -name composer.json -o -name Gemfile \
                 -o -name build.gradle -o -name build.gradle.kts \) -print0 \) \
    2>/dev/null >>"$LIST"
done

python3 - "$OUT_DIR/targets.json" "$LIST" "${ABS_ROOTS[@]}" <<'PY'
import datetime, hashlib, json, os, re, sys

out_path, list_path, roots = sys.argv[1], sys.argv[2], sys.argv[3:]

LOCKFILES = {
    "package-lock.json": "npm", "pnpm-lock.yaml": "npm", "yarn.lock": "npm",
    "poetry.lock": "pypi", "uv.lock": "pypi", "Pipfile.lock": "pypi",
    "mix.lock": "hex", "go.mod": "go", "Cargo.lock": "cargo",
    "composer.lock": "packagist", "Gemfile.lock": "rubygems",
    "pom.xml": "maven", "gradle.lockfile": "maven",
}
MANIFESTS = {
    "package.json": "npm", "pyproject.toml": "pypi", "Pipfile": "pypi", "setup.py": "pypi",
    "mix.exs": "hex", "Cargo.toml": "cargo", "composer.json": "packagist",
    "Gemfile": "rubygems", "build.gradle": "maven", "build.gradle.kts": "maven",
}
ECO_ORDER = ["npm", "pypi", "hex", "go", "cargo", "packagist", "rubygems", "maven"]
REQ_RE = re.compile(r"^requirements.*\.txt$")

with open(list_path, "rb") as f:
    files = [p.decode("utf-8", "surrogateescape") for p in f.read().split(b"\0") if p]

projects = {}  # dir -> {"eco": set, "lock": set, "manifest": set}
for path in files:
    base = os.path.basename(path)
    d = os.path.dirname(path)
    entry = projects.setdefault(d, {"eco": set(), "lock": set(), "manifest": set()})
    if base in LOCKFILES:
        entry["eco"].add(LOCKFILES[base]); entry["lock"].add(path)
    elif REQ_RE.match(base):
        entry["eco"].add("pypi"); entry["lock"].add(path)
    elif base in MANIFESTS:
        entry["eco"].add(MANIFESTS[base]); entry["manifest"].add(path)

def in_git(d):
    cur = d
    while True:
        if os.path.exists(os.path.join(cur, ".git")):
            return True
        parent = os.path.dirname(cur)
        if parent == cur:
            return False
        cur = parent

def safe(s):
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._") or "project"
    return s[:80]

used = set()
result = []
for d in sorted(projects):
    e = projects[d]
    name = safe(os.path.basename(d))
    if name in used:
        parent = safe(os.path.basename(os.path.dirname(d)))
        name = safe(parent + "-" + name)
    if name in used:
        name = safe(os.path.basename(d)) + "-" + hashlib.sha1(d.encode("utf-8", "surrogateescape")).hexdigest()[:6]
    used.add(name)
    result.append({
        "path": d,
        "name": name,
        "ecosystems": [x for x in ECO_ORDER if x in e["eco"]],
        "lockfiles": sorted(e["lock"]),
        "manifests": sorted(e["manifest"]),
        "git": in_git(d),
    })

doc = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
    "roots": roots,
    "projects": result,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(doc, f, ensure_ascii=False, indent=2)
    f.write("\n")

counts = {}
for p in result:
    for x in p["ecosystems"]:
        counts[x] = counts.get(x, 0) + 1
no_lock = sum(1 for p in result if not p["lockfiles"])
summary = ", ".join("%s=%d" % (x, counts[x]) for x in ECO_ORDER if x in counts) or "none"
sys.stderr.write("[discover] %d projects (%s); %d without lockfile\n" % (len(result), summary, no_lock))
sys.stderr.write("[discover] wrote %s\n" % out_path)
PY
rc=$?
[ $rc -eq 0 ] || { warn "python helper failed (exit $rc)"; exit 1; }
printf '%s\n' "$OUT_DIR/targets.json"
exit 0
