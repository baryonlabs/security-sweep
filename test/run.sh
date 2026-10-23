#!/usr/bin/env bash
# Integration test: runs the full security-sweep pipeline on test/fixtures and
# checks the result against test/expected.txt.
#
#   bash test/run.sh            # keep nothing (OUT is removed on success)
#   KEEP_OUT=1 bash test/run.sh # keep OUT for inspection
#
# Requires osv-scanner, trivy and python3 on PATH. Network is needed for the
# OSV verification checks; when api.osv.dev is unreachable those are skipped.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$ROOT/skills/security-sweep/scripts"
FIXTURES="$ROOT/test/fixtures"
EXPECTED="$ROOT/test/expected.txt"
# Junk body of the fake private key in fixtures/with-secret; must never leak.
SECRET_MARKER="SWEEPFAKEJUNKBODY"

OUT="$(mktemp -d "${TMPDIR:-/tmp}/security-sweep-test.XXXXXX")"
CACHE="$OUT.cache"
fail=0

cleanup() {
  if [[ $fail -eq 0 && -z "${KEEP_OUT:-}" ]]; then
    rm -rf "$OUT" "$CACHE"
  else
    echo "OUT kept at: $OUT" >&2
  fi
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
die() { echo "FAIL: $*" >&2; fail=1; exit 1; }

for tool in osv-scanner trivy python3; do
  command -v "$tool" >/dev/null || die "$tool not found on PATH"
done
for s in discover.sh sweep.sh verify_cves.py reachability.py report.py; do
  [[ -f "$SCRIPTS/$s" ]] || die "missing $SCRIPTS/$s"
done

online=0
if curl -fsS -m 10 -o /dev/null https://api.osv.dev/v1/vulns/GHSA-qpmc-wprv-x746 2>/dev/null; then
  online=1
fi
verify_args=(--cache "$CACHE")
[[ $online -eq 1 ]] || verify_args+=(--offline)

step "discover"
bash "$SCRIPTS/discover.sh" "$FIXTURES" --out "$OUT" || die "discover.sh failed"
[[ -s "$OUT/targets.json" ]] || die "targets.json not written"

step "sweep"
bash "$SCRIPTS/sweep.sh" --targets "$OUT/targets.json" --out "$OUT" || die "sweep.sh failed"

step "verify_cves (online=$online)"
python3 -I "$SCRIPTS/verify_cves.py" "$OUT" "${verify_args[@]}" || die "verify_cves.py failed"

step "reachability"
python3 -I "$SCRIPTS/reachability.py" "$OUT" || die "reachability.py failed"

step "report"
python3 -I "$SCRIPTS/report.py" "$OUT" || die "report.py failed"

step "assert findings"
python3 -I - "$OUT" "$EXPECTED" "$FIXTURES" <<'PY' || fail=1
import json, os, sys

out, expected_path, fixtures = sys.argv[1:4]
errors = []

for f in ("findings.json", "REPORT.md", "REPORT.html"):
    if not os.path.isfile(os.path.join(out, f)):
        errors.append(f"missing {f}")

with open(os.path.join(out, "targets.json")) as fh:
    names = {p["name"] for p in json.load(fh).get("projects", [])}
wanted = {d for d in os.listdir(fixtures) if os.path.isdir(os.path.join(fixtures, d))}
for d in sorted(wanted - names):
    errors.append(f"discover.sh did not report fixture {d}")

try:
    with open(os.path.join(out, "findings.json")) as fh:
        findings = json.load(fh)
except (OSError, ValueError) as e:
    findings = []
    errors.append(f"cannot read findings.json: {e}")
if isinstance(findings, dict):  # tolerate {"findings": [...]}
    findings = findings.get("findings", [])

def ids_of(f):
    return {f.get("id") or ""} | set(f.get("aliases") or [])

with open(expected_path) as fh:
    for lineno, line in enumerate(fh, 1):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        fixture, vid, reach = line.split("\t")
        mine = [f for f in findings if f.get("name") == fixture]
        if vid == "SECRET":
            if not any(f.get("kind") == "secret" for f in mine):
                errors.append(f"{fixture}: no secret finding")
            continue
        hits = [f for f in mine if vid in ids_of(f)]
        if not hits:
            errors.append(f"{fixture}: {vid} not in findings")
            continue
        allowed = set(reach.split(","))
        got = {f.get("reach") for f in hits}
        if not got & allowed:
            errors.append(f"{fixture}: {vid} reach={sorted(got)} expected one of {sorted(allowed)}")
        else:
            print(f"ok  {fixture:12} {vid:22} reach={'/'.join(sorted(got))}")

for e in errors:
    print("FAIL:", e, file=sys.stderr)
sys.exit(1 if errors else 0)
PY
[[ $fail -eq 0 ]] || die "findings assertions failed"

step "secret is masked"
for needle in "$SECRET_MARKER" "BEGIN RSA PRIVATE KEY"; do
  if grep -rlF "$needle" "$OUT" >/dev/null 2>&1; then
    grep -rlF "$needle" "$OUT" >&2
    die "raw secret content ($needle) leaked into OUT (files above)"
  fi
done
echo "ok  secret body and PEM header absent from OUT"

step "fake ID is rejected by OSV verification"
if [[ $online -eq 1 ]]; then
  FAKE="$OUT/fake-id"
  mkdir -p "$FAKE/raw/osv"
  # Minimal osv-scanner-shaped result carrying a non-existent CVE.
  cat > "$FAKE/raw/osv/fake.json" <<'JSON'
{"results": [{"source": {"path": "/fake/package-lock.json", "type": "lockfile"},
  "packages": [{"package": {"name": "fakepkg", "version": "1.0.0", "ecosystem": "npm"},
    "vulnerabilities": [{"id": "CVE-2099-00001", "aliases": []}], "groups": []}]}]}
JSON
  python3 -I "$SCRIPTS/verify_cves.py" "$FAKE" --cache "$CACHE" || die "verify_cves.py failed on fake input"
  python3 -I - "$FAKE/verified.json" <<'PY' || die "CVE-2099-00001 was not marked exists:false"
import json, sys
v = json.load(open(sys.argv[1])).get("CVE-2099-00001")
print("CVE-2099-00001 ->", v and {"exists": v.get("exists")})
sys.exit(0 if v is not None and v.get("exists") is False else 1)
PY
  echo "ok  CVE-2099-00001 exists=false"
else
  echo "skip: api.osv.dev unreachable"
fi

printf '\nALL PASSED\n'
