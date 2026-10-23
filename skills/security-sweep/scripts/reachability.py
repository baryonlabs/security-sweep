#!/usr/bin/env python3
"""Judge whether each vulnerable package is actually used by project code.

usage: reachability.py OUT

Reads OUT/targets.json, OUT/raw/*, OUT/verified.json and writes OUT/reach.json:
  {"<project>": {"<normalized package>": {"<vuln id>":
      {"status": "called|imported|not-imported|unknown",
       "evidence": ["file:line ..."], "method": "govulncheck|symbol-grep|import-grep|none",
       "note": "..."}}}}
Order: govulncheck result > symbol grep (verified.functions) > import grep.
not-imported never means "safe": a transitive dependency is used through others.
Server / image OS packages are not judged here (report.py marks them n/a).
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (EXCLUDE_DIRS, as_dict, as_list, load_json, load_raw,  # noqa: E402
                     load_targets, norm_pkg, warn, write_json)

MAX_FILES = 20000
MAX_FILE_BYTES = 1024 * 1024
MAX_EVIDENCE = 5

EXTS = {
    "npm": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"),
    "pypi": (".py",),
    "hex": (".ex", ".exs", ".heex", ".eex", ".erl"),
    "go": (".go",),
    "cargo": (".rs",),
    "packagist": (".php",),
    "rubygems": (".rb", ".rake"),
    "maven": (".java", ".kt", ".kts", ".scala", ".groovy"),
}

# PyPI distribution name -> import name(s) where they differ.
PYPI_IMPORTS = {
    "pyyaml": ["yaml"], "beautifulsoup4": ["bs4"], "pillow": ["PIL"],
    "scikit-learn": ["sklearn"], "scikit-image": ["skimage"],
    "python-dateutil": ["dateutil"], "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"], "pycryptodome": ["Crypto"],
    "pycryptodomex": ["Cryptodome"], "pyjwt": ["jwt"], "python-jose": ["jose"],
    "protobuf": ["google.protobuf"], "attrs": ["attr", "attrs"],
    "setuptools": ["setuptools", "pkg_resources"], "psycopg2-binary": ["psycopg2"],
    "typing-extensions": ["typing_extensions"], "dnspython": ["dns"],
    "pyopenssl": ["OpenSSL"], "msgpack-python": ["msgpack"], "pymongo": ["pymongo", "bson"],
    "python-multipart": ["multipart", "python_multipart"], "pyzmq": ["zmq"],
    "google-api-python-client": ["googleapiclient"], "pysaml2": ["saml2"],
    "djangorestframework": ["rest_framework"], "python-ldap": ["ldap"],
    "mysqlclient": ["MySQLdb"], "pywin32": ["win32api", "win32con"],
}

# Elixir packages whose module name is not plain CamelCase of the package.
HEX_MODULES = {
    "phoenix_html": ["Phoenix.HTML"], "phoenix_live_view": ["Phoenix.LiveView", "Phoenix.Component"],
    "ecto_sql": ["Ecto.Adapters.SQL", "Ecto.Migration"], "postgrex": ["Postgrex"],
    "plug_cowboy": ["Plug.Cowboy"], "jose": ["JOSE"], "httpoison": ["HTTPoison"],
    "ex_aws": ["ExAws"], "joken": ["Joken"], "earmark": ["Earmark"],
}


def camel(seg):
    return seg[:1].upper() + seg[1:]


def py_import_names(pkg):
    n = norm_pkg("pypi", pkg)
    names = list(PYPI_IMPORTS.get(n, []))
    names.append(n.replace("-", "_"))
    if n.startswith("python-"):
        names.append(n[len("python-"):].replace("-", "_"))
    return list(dict.fromkeys(names))


def import_regex(eco, pkg):
    """Compiled regex matching an import/use of `pkg`, or None."""
    if eco == "npm":
        p = re.escape(pkg)
        q = r"""['"]%s(?:/[^'"]*)?['"]""" % p
        return re.compile(r"(?:require\s*\(\s*%s|from\s+%s|import\s+%s|import\s*\(\s*%s)" % (q, q, q, q))
    if eco == "pypi":
        alts = "|".join(re.escape(n) for n in py_import_names(pkg))
        return re.compile(r"^\s*(?:from\s+(?:%s)(?:\.[\w.]+)?\s+import\b|import\s+(?:[\w.]+\s*,\s*)*(?:%s)(?:[.\s,]|$))"
                          % (alts, alts), re.M | re.I)
    if eco == "hex":
        segs = [s for s in str(pkg).split("_") if s]
        mods = list(HEX_MODULES.get(pkg, []))
        mods += [".".join(camel(s) for s in segs), "".join(camel(s) for s in segs)]
        alts = "|".join(re.escape(m) for m in dict.fromkeys(mods) if m)
        return re.compile(r"(?<![\w.])(?:%s)(?=[.\s,(]|$)|(?<![\w]):%s\." % (alts, re.escape(pkg)), re.M)
    if eco == "go":
        return re.compile(r"""^\s*(?:import\s+)?(?:[\w.]+\s+)?"%s(?:/[^"]*)?"\s*$""" % re.escape(pkg), re.M)
    if eco == "cargo":
        c = re.escape(str(pkg).replace("-", "_"))
        return re.compile(r"(?:\buse\s+(?:::)?%s\b|\bextern\s+crate\s+%s\b|(?<![\w:])%s::)" % (c, c, c))
    if eco == "packagist":
        tail = str(pkg).split("/")[-1].replace("-", "").replace("_", "")
        if not tail:
            return None
        return re.compile(r"^\s*use\s+\\?[\w\\]*%s[\w\\]*" % re.escape(tail), re.M | re.I)
    if eco == "rubygems":
        alts = {pkg, str(pkg).replace("-", "/"), str(pkg).replace("-", "_")}
        return re.compile(r"""\brequire(?:_relative)?\s*\(?\s*['"](?:%s)(?:/[^'"]*)?['"]"""
                          % "|".join(re.escape(a) for a in alts))
    if eco == "maven":
        group = str(pkg).split(":")[0]
        cands = [group]
        if group.count(".") >= 2:
            cands.append(group.rsplit(".", 1)[0])
        return re.compile(r"^\s*import\s+(?:static\s+)?(?:%s)[.;]" % "|".join(re.escape(c) for c in cands), re.M)
    return None


def symbol_regexes(eco, pkg, symbols):
    """Regexes for vulnerable function/symbol calls."""
    out = []
    for entry in symbols:
        entry = as_dict(entry)
        path = str(entry.get("path") or "")
        for sym in as_list(entry.get("symbols")):
            sym = re.sub(r"/\d+$", "", str(sym)).strip()  # Elixir arity
            if not sym:
                continue
            parts = [p for p in re.split(r"[.#:]+", sym) if p]
            if eco == "go":
                if len(parts) == 1:
                    last = (path or pkg).rstrip("/").split("/")[-1]
                    last = re.sub(r"\.v\d+$", "", last).replace("-", "_")
                    out.append(re.compile(r"\b%s\.%s\s*\(" % (re.escape(last), re.escape(parts[0]))))
                else:
                    out.append(re.compile(r"\.%s\s*\(" % re.escape(parts[-1])))
            elif len(parts) >= 2:
                out.append(re.compile(r"\b%s\s*\.\s*%s\b" % (re.escape(parts[-2]), re.escape(parts[-1]))))
            else:
                out.append(re.compile(r"\b%s\s*\(" % re.escape(parts[0])))
    return out


class Project:
    def __init__(self, root):
        self.root = root
        self.files = {}
        self.truncated = False
        self._text = {}

    def files_for(self, eco):
        if eco in self.files:
            return self.files[eco]
        exts = EXTS.get(eco, ())
        found = []
        if exts and os.path.isdir(self.root):
            for d, dirs, files in os.walk(self.root):
                dirs[:] = [x for x in dirs if x not in EXCLUDE_DIRS and not os.path.islink(os.path.join(d, x))]
                for f in files:
                    if f.endswith(exts):
                        found.append(os.path.join(d, f))
                        if len(found) >= MAX_FILES:
                            self.truncated = True
                            break
                if self.truncated:
                    break
        self.files[eco] = sorted(found)
        return self.files[eco]

    def text(self, path):
        if path not in self._text:
            try:
                if os.path.islink(path) or os.path.getsize(path) > MAX_FILE_BYTES:
                    self._text[path] = ""
                else:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        self._text[path] = fh.read()
            except OSError:
                self._text[path] = ""
        return self._text[path]

    def grep(self, regexes, files, limit=MAX_EVIDENCE):
        hits, hit_files = [], []
        for path in files:
            text = self.text(path)
            if not text or not any(r.search(text) for r in regexes):
                continue
            hit_files.append(path)
            for i, line in enumerate(text.splitlines(), 1):
                if any(r.search(line) for r in regexes):
                    if len(hits) < limit:
                        hits.append("%s:%d: %s" % (os.path.relpath(path, self.root), i, line.strip()[:160]))
        return hits, hit_files


def bundler_require(proj):
    for path in proj.files_for("rubygems"):
        if path.endswith(os.path.join("config", "application.rb")):
            for i, line in enumerate(proj.text(path).splitlines(), 1):
                if "Bundler.require" in line:
                    return "%s:%d: %s" % (os.path.relpath(path, proj.root), i, line.strip()[:160])
    return None


def judge(proj, eco, pkg, symbols):
    """(status, evidence, method, note) for one package / vuln."""
    if eco not in EXTS:
        return "unknown", [], "none", "지원하지 않는 생태계 (%s)" % eco
    if eco == "go" and pkg == "stdlib":
        return "unknown", [], "none", "Go 표준 라이브러리 — govulncheck 결과 필요"
    files = proj.files_for(eco)
    if not files:
        return "unknown", [], "none", "소스 파일을 찾지 못함"
    rx = import_regex(eco, pkg)
    if rx is None:
        return "unknown", [], "none", "패키지명에서 import 이름을 추정할 수 없음"
    imp_ev, imp_files = proj.grep([rx], files)
    note = "파일 수 상한(%d) 도달 — 일부만 검사" % MAX_FILES if proj.truncated else ""
    if not imp_ev and eco == "rubygems":
        ev = bundler_require(proj)
        if ev:
            return "imported", [ev], "import-grep", "Bundler.require 로 Gemfile 의 gem 이 모두 로드됨"
    if symbols and imp_files:
        srx = symbol_regexes(eco, pkg, symbols)
        if srx:
            sym_ev, _ = proj.grep(srx, imp_files)
            if sym_ev:
                return "called", sym_ev, "symbol-grep", "취약 심볼 이름 일치 (정적 grep — 호출 경로 미검증)"
    if imp_ev:
        return "imported", imp_ev, "import-grep", note
    msg = "직접 import 없음 — 전이 의존성일 수 있어 안전을 의미하지 않음"
    return "not-imported", [], "import-grep", (msg + "; " + note) if note else msg


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0].startswith("-"):
        print(__doc__.strip().split("\n")[2], file=sys.stderr)
        return 1
    out = os.path.abspath(argv[0])
    if not os.path.isdir(out):
        warn("OUT not found: %s" % out)
        return 1
    _, projects = load_targets(out)
    verified = as_dict(load_json(os.path.join(out, "verified.json"), {}))
    records, _ = load_raw(out)

    reach = {}
    projs = {}
    stats = {}
    for r in records:
        if r["target"] != "project" or r["kind"] != "vuln" or r["ecosystem"].startswith("os:"):
            continue
        name, eco = r["name"], r["ecosystem"]
        pkey = norm_pkg(eco, r["package"])
        slot = reach.setdefault(name, {}).setdefault(pkey, {})
        hint = r.get("reach_hint")
        if hint:
            slot[r["id"]] = dict(hint, note="")
            continue
        if r["id"] in slot:
            continue
        root = str(as_dict(projects.get(name)).get("path") or r.get("path_or_host") or "")
        if not root or not os.path.isdir(root):
            slot[r["id"]] = {"status": "unknown", "evidence": [], "method": "none",
                             "note": "프로젝트 경로를 찾지 못함"}
            continue
        proj = projs.setdefault(root, Project(root))
        symbols = []
        for vid in [r["id"]] + list(r.get("aliases") or []):
            symbols += as_list(as_dict(verified.get(vid)).get("symbols"))
        status, ev, method, note = judge(proj, eco, r["package"], symbols)
        slot[r["id"]] = {"status": status, "evidence": ev, "method": method, "note": note}

    for pkgs in reach.values():
        for ids in pkgs.values():
            for v in ids.values():
                stats[v["status"]] = stats.get(v["status"], 0) + 1

    write_json(os.path.join(out, "reach.json"), reach)
    print("reach: " + ", ".join("%s %d" % kv for kv in sorted(stats.items())) if stats else "reach: 0 items")
    return 0


if __name__ == "__main__":
    sys.exit(main())
