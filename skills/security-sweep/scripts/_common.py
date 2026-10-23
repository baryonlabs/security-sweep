"""Shared helpers for verify_cves.py, reachability.py and report.py.

Python 3.9+ standard library only. Every scanner output under OUT/raw is
treated as untrusted data: it is parsed defensively and never executed.
Secret values (trivy `Match` / `Code`, elixir snippets) are never read into
the normalized records.
"""

import glob
import json
import os
import re
import sys
import tempfile

SEVERITIES = ("critical", "high", "medium", "low", "unknown")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

EXCLUDE_DIRS = {"node_modules", "deps", "_build", "vendor", ".venv", "venv",
                "target", "dist", "build", ".git"}

# osv-scanner / OSV ecosystem names -> internal key
OSV_ECOSYSTEMS = {
    "npm": "npm", "pypi": "pypi", "hex": "hex", "go": "go",
    "crates.io": "cargo", "packagist": "packagist", "rubygems": "rubygems",
    "maven": "maven",
}
# trivy lang-pkgs Type -> internal key
TRIVY_LANG_TYPES = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm", "node-pkg": "npm",
    "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "uv": "pypi",
    "python-pkg": "pypi", "conda-pkg": "pypi",
    "hex": "hex", "gomod": "go", "gobinary": "go",
    "cargo": "cargo", "rust-binary": "cargo",
    "composer": "packagist", "composer-vendor": "packagist",
    "bundler": "rubygems", "gemspec": "rubygems",
    "pom": "maven", "gradle": "maven", "jar": "maven", "sbt": "maven",
}

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,80}$")
VULN_ID_RE = re.compile(
    r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|"
    r"(?:EEF-CVE|PYSEC|RUSTSEC|GO|OSV|MAL)-\d{4}-[\w-]+)\b")

# Last-resort masking for anything that looks like a credential. Primary
# protection is that secret matches are never read at all.
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]


def warn(msg):
    print("[security-sweep] " + msg, file=sys.stderr)


def mask_secrets(text):
    if not text:
        return text
    s = str(text)
    for pat in _SECRET_PATTERNS:
        s = pat.sub("****", s)
    return s


def load_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def load_json_stream(path):
    """Parse a file holding a sequence of JSON values (govulncheck -json)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    dec = json.JSONDecoder()
    out, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            obj, j = dec.raw_decode(text, i)
        except ValueError:
            nl = text.find("\n", i)
            if nl < 0:
                break
            i = nl + 1
            continue
        out.append(obj)
        i = j
    return out


def write_json(path, data):
    # Unique temp name: concurrent writers of the same cache entry must not collide.
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=".tmp",
                               dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def as_dict(v):
    return v if isinstance(v, dict) else {}


def as_list(v):
    return v if isinstance(v, list) else []


def norm_sev(value):
    s = str(value or "").strip().lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    if s in ("moderate", "med"):
        return "medium"
    if s in ("important",):
        return "high"
    if s in ("negligible", "minor", "info", "informational", "none"):
        return "low"
    try:
        return score_to_sev(float(s))
    except ValueError:
        return "unknown"


def score_to_sev(score):
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def max_sev(*sevs):
    best = "unknown"
    for s in sevs:
        s = norm_sev(s)
        if s == "unknown":
            continue
        if best == "unknown" or SEV_RANK[s] < SEV_RANK[best]:
            best = s
    return best


def norm_pkg(ecosystem, name):
    n = str(name or "").strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", n).lower()
    if ecosystem in ("go", "maven"):
        return n
    return n.lower()


def norm_version(v):
    s = str(v or "").strip().lstrip("vV")
    while re.search(r"\.0$", s) and s.count(".") > 0:
        s = s[:-2]
    return s


def version_key(v):
    key = []
    for tok in re.findall(r"\d+|[A-Za-z]+", str(v or "")):
        key.append((1, int(tok), "") if tok.isdigit() else (0, 0, tok.lower()))
    return key


def pick_fixed(installed, candidates):
    """Smallest fixed version greater than installed (else smallest)."""
    cands = sorted({str(c).strip() for c in candidates if c and str(c).strip()},
                   key=version_key)
    if not cands:
        return ""
    ik = version_key(installed)
    for c in cands:
        if version_key(c) > ik:
            return c
    return cands[-1]


def record_fixed(record, ecosystem, package):
    """Fixed versions for `package` from an OSV record's affected ranges."""
    out = []
    want = norm_pkg(ecosystem, package)
    for aff in as_list(as_dict(record).get("affected")):
        aff = as_dict(aff)
        pk = as_dict(aff.get("package"))
        if pk and want and norm_pkg(ecosystem, pk.get("name")) != want:
            continue
        for rng in as_list(aff.get("ranges")):
            rng = as_dict(rng)
            if str(rng.get("type", "")).upper() == "GIT":
                continue
            for ev in as_list(rng.get("events")):
                fx = as_dict(ev).get("fixed")
                if fx:
                    out.append(str(fx))
    return out


def ids_in(text):
    return list(dict.fromkeys(VULN_ID_RE.findall(str(text or ""))))


# ---------------------------------------------------------------------------
# Targets / tools
# ---------------------------------------------------------------------------

def load_targets(out):
    data = as_dict(load_json(os.path.join(out, "targets.json"), {}))
    projects = {}
    for p in as_list(data.get("projects")):
        p = as_dict(p)
        name = str(p.get("name") or os.path.basename(str(p.get("path", ""))))
        if name:
            projects[name] = p
    return data, projects


def load_tools(out):
    rows = []
    try:
        with open(os.path.join(out, "tools.txt"), "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.split("\t")
                rows.append({"tool": parts[0].strip(),
                             "status": parts[1].strip() if len(parts) > 1 else "",
                             "note": mask_secrets("\t".join(parts[2:]).strip())})
    except OSError:
        pass
    return rows


# ---------------------------------------------------------------------------
# Raw scanner output -> normalized records
# ---------------------------------------------------------------------------

def _rec(**kw):
    base = {"target": "project", "name": "", "path_or_host": "", "kind": "vuln",
            "id": "", "aliases": [], "package": "", "version": "", "ecosystem": "",
            "fixed_candidates": [], "severity": "unknown", "source": "",
            "location": "", "message": "", "record": None, "reach_hint": None}
    base.update(kw)
    base["message"] = mask_secrets(base["message"])
    return base


def _stem(path):
    return os.path.splitext(os.path.basename(path))[0]


def _rel(path, root):
    path = str(path or "")
    if root and path.startswith(str(root).rstrip("/") + "/"):
        return path[len(str(root).rstrip("/")) + 1:]
    return path


def parse_osv_scanner(path, name, proj_path):
    out = []
    data = as_dict(load_json(path, {}))
    for res in as_list(data.get("results")):
        res = as_dict(res)
        src = as_dict(res.get("source"))
        loc = _rel(src.get("path", ""), proj_path)
        for pk in as_list(res.get("packages")):
            pk = as_dict(pk)
            pinfo = as_dict(pk.get("package"))
            eco = OSV_ECOSYSTEMS.get(str(pinfo.get("ecosystem", "")).split(":")[0].lower(),
                                     str(pinfo.get("ecosystem", "")).lower())
            gmeta = {}
            for g in as_list(pk.get("groups")):
                g = as_dict(g)
                gids = [str(x) for x in as_list(g.get("ids")) + as_list(g.get("aliases")) if x]
                for gid in as_list(g.get("ids")):
                    gmeta[str(gid)] = (gids, g.get("max_severity"))
            for v in as_list(pk.get("vulnerabilities")):
                v = as_dict(v)
                vid = str(v.get("id") or "")
                if not vid:
                    continue
                gids, gsev = gmeta.get(vid, ([], None))
                aliases = [str(a) for a in as_list(v.get("aliases")) + gids if a and str(a) != vid]
                out.append(_rec(
                    target="project", name=name, path_or_host=proj_path or "",
                    id=vid, aliases=list(dict.fromkeys(aliases)),
                    package=str(pinfo.get("name", "")), version=str(pinfo.get("version", "")),
                    ecosystem=eco,
                    fixed_candidates=record_fixed(v, eco, pinfo.get("name")),
                    severity=norm_sev(gsev) if gsev else norm_sev(as_dict(v.get("database_specific")).get("severity")),
                    source="osv-scanner", location=loc,
                    message=str(v.get("summary") or str(v.get("details", ""))[:160]),
                    record=v))
    return out


def parse_trivy(path, target, name, path_or_host):
    out = []
    data = as_dict(load_json(path, {}))
    if target == "image" and data.get("ArtifactName"):
        name = path_or_host = str(data["ArtifactName"])
    for res in as_list(data.get("Results")):
        res = as_dict(res)
        tgt = str(res.get("Target", ""))
        cls = str(res.get("Class", ""))
        typ = str(res.get("Type", ""))
        if cls == "os-pkgs":
            eco = "os:" + typ
        else:
            eco = TRIVY_LANG_TYPES.get(typ, typ)
        for v in as_list(res.get("Vulnerabilities")):
            v = as_dict(v)
            vid = str(v.get("VulnerabilityID") or "")
            if not vid:
                continue
            fixed = [x.strip() for x in str(v.get("FixedVersion") or "").split(",") if x.strip()]
            out.append(_rec(
                target=target, name=name, path_or_host=path_or_host, id=vid,
                aliases=[str(a) for a in as_list(v.get("VendorIDs")) if a],
                package=str(v.get("PkgName", "")), version=str(v.get("InstalledVersion", "")),
                ecosystem=eco, fixed_candidates=fixed, severity=norm_sev(v.get("Severity")),
                source="trivy", location=tgt, message=str(v.get("Title") or "")))
        # Secrets: only RuleID / Category / Severity / Title / line. Never Match/Code.
        for s in as_list(res.get("Secrets")):
            s = as_dict(s)
            line = s.get("StartLine")
            out.append(_rec(
                target=target, name=name, path_or_host=path_or_host, kind="secret",
                id=str(s.get("RuleID") or "secret"),
                severity=norm_sev(s.get("Severity")), source="trivy",
                location="%s:%s" % (tgt, line) if line else tgt,
                message="%s (%s) — 값은 마스킹됨" % (s.get("Title") or "secret", s.get("Category") or "")))
        for m in as_list(res.get("Misconfigurations")):
            m = as_dict(m)
            if str(m.get("Status", "FAIL")).upper() != "FAIL":
                continue
            cm = as_dict(m.get("CauseMetadata"))
            line = cm.get("StartLine")
            out.append(_rec(
                target=target, name=name, path_or_host=path_or_host, kind="misconfig",
                id=str(m.get("ID") or m.get("AVDID") or "misconfig"),
                severity=norm_sev(m.get("Severity")), source="trivy",
                location="%s:%s" % (tgt, line) if line else tgt,
                message=str(m.get("Title") or "")))
    return out


def parse_govulncheck(path, name, proj_path):
    objs = load_json_stream(path)
    records, agg = {}, {}
    for o in objs:
        o = as_dict(o)
        if isinstance(o.get("osv"), dict):
            rec = o["osv"]
            if rec.get("id"):
                records[str(rec["id"])] = rec
        f = as_dict(o.get("finding"))
        if not f.get("osv"):
            continue
        vid = str(f["osv"])
        trace = [as_dict(t) for t in as_list(f.get("trace"))]
        t0 = trace[0] if trace else {}
        level = "called" if t0.get("function") else ("imported" if t0.get("package") else "not-imported")
        a = agg.setdefault(vid, {"level": "not-imported", "module": t0.get("module", ""),
                                 "version": t0.get("version", ""), "fixed": set(), "evidence": []})
        order = {"called": 0, "imported": 1, "not-imported": 2}
        if order[level] < order[a["level"]]:
            a["level"] = level
        if f.get("fixed_version"):
            a["fixed"].add(str(f["fixed_version"]).lstrip("v"))
        if level == "called":
            for t in trace[1:] or trace:
                pos = as_dict(t.get("position"))
                if pos.get("filename"):
                    fn = ".".join(x for x in (t.get("package", "").rsplit("/", 1)[-1],
                                              t.get("receiver", ""), t.get("function", "")) if x)
                    ev = "%s:%s %s" % (_rel(pos["filename"], proj_path), pos.get("line", 0), fn)
                    if ev not in a["evidence"] and len(a["evidence"]) < 5:
                        a["evidence"].append(ev)
    out = []
    for vid, a in agg.items():
        rec = records.get(vid)
        out.append(_rec(
            target="project", name=name, path_or_host=proj_path or "", id=vid,
            aliases=[str(x) for x in as_list(as_dict(rec).get("aliases"))],
            package=a["module"] or "", version=str(a["version"] or "").lstrip("v"),
            ecosystem="go", fixed_candidates=sorted(a["fixed"]),
            severity="unknown", source="govulncheck", location="go.mod",
            message=str(as_dict(rec).get("summary") or ""), record=rec,
            reach_hint={"status": a["level"], "evidence": a["evidence"], "method": "govulncheck"}))
    return out


_DEP_MSG = re.compile(r"^(\S+) (\S+): (.*?) \[([^\]]*)\]")


def parse_elixir(path, name, proj_path):
    out = []
    data = load_json(path, [])
    if isinstance(data, dict):
        data = data.get("findings", [])
    for f in as_list(data):
        f = as_dict(f)
        fid = str(f.get("id") or "")
        if not fid:
            continue
        msg = str(f.get("message") or "")
        file_, line = str(f.get("file") or ""), f.get("line") or 0
        loc = "%s:%s" % (file_, line) if line else file_
        if fid == "EXS-DEP-001":
            m = _DEP_MSG.match(msg)
            ids = ids_in(m.group(4) if m else msg)
            if ids:
                out.append(_rec(
                    target="project", name=name, path_or_host=proj_path or "",
                    id=ids[0], aliases=ids[1:],
                    package=m.group(1) if m else "", version=m.group(2) if m else "",
                    ecosystem="hex", severity=norm_sev(f.get("severity")),
                    source=str(f.get("tool") or "elixir-security-audit"),
                    location=loc, message=m.group(3) if m else msg))
                continue
        # Code / config findings: the snippet is deliberately dropped (may hold secrets).
        out.append(_rec(
            target="project", name=name, path_or_host=proj_path or "", kind="code",
            id=fid, severity=norm_sev(f.get("severity")),
            source=str(f.get("tool") or "elixir-security-audit"),
            location=loc, message=msg[:300]))
    return out


def load_raw(out):
    """Return (records, notes). notes: list of {target,name,message}."""
    raw = os.path.join(out, "raw")
    _, projects = load_targets(out)

    def ppath(name):
        return str(as_dict(projects.get(name)).get("path", ""))

    recs, notes = [], []
    for p in sorted(glob.glob(os.path.join(raw, "osv", "*.json"))):
        n = _stem(p)
        recs += parse_osv_scanner(p, n, ppath(n))
    for p in sorted(glob.glob(os.path.join(raw, "trivy-fs", "*.json"))):
        n = _stem(p)
        recs += parse_trivy(p, "project", n, ppath(n))
    for p in sorted(glob.glob(os.path.join(raw, "govulncheck", "*.json"))):
        n = _stem(p)
        recs += parse_govulncheck(p, n, ppath(n))
    seen_elixir = set()
    for pat in ("*/findings.json", "*/security-audit/findings.json"):
        for p in sorted(glob.glob(os.path.join(raw, "elixir", pat))):
            n = os.path.relpath(p, os.path.join(raw, "elixir")).split(os.sep)[0]
            if n in seen_elixir:
                continue
            seen_elixir.add(n)
            recs += parse_elixir(p, n, ppath(n))
    for p in sorted(glob.glob(os.path.join(raw, "image", "*.json"))):
        n = _stem(p)
        recs += parse_trivy(p, "image", n, n)
    for p in sorted(glob.glob(os.path.join(raw, "server", "*.json"))):
        n = _stem(p)
        recs += parse_trivy(p, "server", n, n)
    for p in sorted(glob.glob(os.path.join(raw, "server", "*.packages.txt"))):
        host = os.path.basename(p)[:-len(".packages.txt")]
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                count = sum(1 for ln in fh if ln.strip() and not ln.startswith("#"))
        except OSError:
            count = 0
        notes.append({"target": "server", "name": host,
                      "message": "패키지 목록만 수집됨 (trivy 미설치) — %d개 패키지, 취약점 판정 안 함" % count})
    return recs, notes


def vuln_ids(records):
    ids = []
    for r in records:
        if r["kind"] == "vuln" and ID_RE.match(r["id"]):
            ids.append(r["id"])
    return list(dict.fromkeys(ids))
