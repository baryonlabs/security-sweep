#!/usr/bin/env python3
"""Collect explicit venv metadata without executing it; query exported inventories locally."""
import argparse
import datetime
import email.parser
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import ID_RE, mask_secrets, norm_pkg, write_json

MAX_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 100000
OSV_QUERY = "https://api.osv.dev/v1/query"
STATUSES = {"inventory-only", "permission-denied", "failed", "unsupported"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def text(value, field, limit=4096):
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError("invalid " + field)
    return value


def read_regular(path, limit=MAX_BYTES):
    """Reject links and special files; bound reads even if the file grows."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise ValueError("not a regular file")
        body = fh.read(limit + 1)
    if len(body) > limit:
        raise ValueError("file exceeds size limit")
    return body


def no_links(path):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("symlink paths are not collected")
    return path


def collect_venv(path):
    env = {"path": os.path.abspath(path), "ecosystem": "PyPI", "packages": [],
           "status": "inventory-only", "reason": "metadata collected; not yet analysed"}
    try:
        root = no_links(path)
        if not root.is_dir():
            raise FileNotFoundError("venv directory missing")
        sites = []
        # Explicit CPython layouts only; do not recursively traverse arbitrary homes.
        for libname in ("lib", "lib64", "Lib"):
            lib = root / libname
            if lib.is_symlink():
                # Common lib64 -> lib alias is redundant, never traverse it.
                if libname == "lib64" and (root / "lib").is_dir():
                    continue
                raise ValueError("symlink library directory")
            if not lib.exists():
                continue
            candidates = [lib / "site-packages"] if libname == "Lib" else [
                p / "site-packages" for p in lib.iterdir() if re.fullmatch(r"python\d+\.\d+", p.name)]
            for site in candidates:
                no_links(site)
                if site.is_dir():
                    sites.append(site)
        if not sites:
            env.update(status="unsupported", reason="no supported site-packages directory")
            return env
        packages = {}
        for site in sites:
            for dist in site.iterdir():
                if not dist.name.endswith((".dist-info", ".egg-info")):
                    continue
                no_links(dist)
                meta = dist / ("METADATA" if dist.name.endswith(".dist-info") else "PKG-INFO") if dist.is_dir() else dist
                no_links(meta)
                headers = email.parser.BytesHeaderParser().parsebytes(read_regular(meta, 1024 * 1024))
                name = text(headers.get("Name"), "package name", 256)
                version = text(headers.get("Version"), "package version", 256)
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
                    raise ValueError("invalid Python package name")
                key = (norm_pkg("pypi", name), version)
                packages[key] = {"name": name, "version": version, "location": str(meta.relative_to(root))}
                if len(packages) > MAX_PACKAGES:
                    raise ValueError("too many packages")
        env["packages"] = [packages[k] for k in sorted(packages)]
    except PermissionError:
        env.update(status="permission-denied", reason="cannot read requested metadata")
    except (OSError, ValueError) as exc:
        env.update(status="failed", reason=mask_secrets(str(exc))[:300])
    return env


def validate(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("inventory schema_version must be 1")
    text(doc.get("host"), "host")
    stamp = text(doc.get("collected_at"), "collected_at")
    try:
        if datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("timestamp requires timezone")
    except ValueError as exc:
        raise ValueError("invalid collected_at timestamp") from exc
    envs = doc.get("environments")
    if not isinstance(envs, list) or not 0 < len(envs) <= 1000:
        raise ValueError("environments must contain 1..1000 entries")
    seen = set()
    total = 0
    for env in envs:
        if not isinstance(env, dict):
            raise ValueError("environment must be an object")
        path = text(env.get("path"), "environment path")
        eco = text(env.get("ecosystem"), "ecosystem", 100)
        if (path, eco) in seen:
            raise ValueError("duplicate environment")
        seen.add((path, eco))
        if env.get("status") not in STATUSES:
            raise ValueError("invalid inventory collection status")
        packages = env.get("packages")
        if not isinstance(packages, list):
            raise ValueError("packages must be a list")
        total += len(packages)
        if total > MAX_PACKAGES:
            raise ValueError("too many packages")
        for pkg in packages:
            if not isinstance(pkg, dict):
                raise ValueError("package must be an object")
            name = text(pkg.get("name"), "package name", 256)
            text(pkg.get("version"), "package version", 256)
            if eco == "PyPI" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
                raise ValueError("invalid Python package name")
    return doc


def query_package(name, version):
    body = json.dumps({"package": {"ecosystem": "PyPI", "name": name}, "version": version}).encode()
    req = urllib.request.Request(OSV_QUERY, data=body, headers={"Content-Type": "application/json",
                                 "User-Agent": "security-sweep/inventory"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("OSV response exceeds limit")
    doc = json.loads(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get("vulns", []), list):
        raise ValueError("invalid OSV query response")
    vulns = doc.get("vulns", [])
    for vuln in vulns:
        if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) or not ID_RE.fullmatch(vuln["id"]):
            raise ValueError("invalid OSV advisory")
    return vulns


def import_inventory(doc, out, offline=False, query=None):
    validate(doc)
    out = Path(out)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError("import requires a new or empty output directory (prevents stale findings)")
    out.mkdir(parents=True, exist_ok=True)
    raw = out / "raw" / "inventory"
    raw.mkdir(parents=True)
    query = query or query_package
    entries, cache = [], {}
    started = now()
    for env in doc["environments"]:
        identity = doc["host"] + "\0" + env["ecosystem"] + "\0" + env["path"]
        key = hashlib.sha256(identity.encode()).hexdigest()
        # Include environment in name: report merging must not merge distinct venvs.
        name = doc["host"] + ":" + env["path"]
        entry = {"target": "server", "name": name, "path_or_host": doc["host"],
                 "component": "inventory:" + env["ecosystem"] + ":" + env["path"],
                 "status": env["status"], "reason": "collection incomplete",
                 "collected_at": doc["collected_at"], "scope_complete": False,
                 "package_count": len(env["packages"]), "queried_count": 0}
        matches = []
        if env["status"] == "inventory-only":
            if env["ecosystem"] != "PyPI":
                entry.update(status="unsupported", reason="inventory retained; no matcher for this ecosystem")
            elif offline:
                entry.update(reason="offline: inventory retained; packages not queried")
            else:
                errors = 0
                for pkg in env["packages"]:
                    pair = (norm_pkg("pypi", pkg["name"]), pkg["version"])
                    try:
                        if pair not in cache:
                            cache[pair] = query(*pair)
                        vulns = cache[pair]
                        if not isinstance(vulns, list):
                            raise ValueError("query did not return an advisory list")
                        entry["queried_count"] += 1
                        matches.append({"package": {"name": pair[0], "version": pair[1], "ecosystem": "PyPI"},
                                        "vulnerabilities": vulns})
                    except (OSError, ValueError):
                        errors += 1
                entry.update(status="failed" if errors else "scanned", scope_complete=not errors,
                             reason=("%d package queries failed" % errors if errors else
                                     "all collected packages queried; coverage limited to exported metadata"))
        payload = {"schema_version": 1, "host": doc["host"], "name": name,
                   "environment": env["path"], "source": "osv-inventory", "packages": matches,
                   "query_endpoint": OSV_QUERY, "queried_at": started}
        write_json(str(raw / (key + ".json")), payload)
        entries.append(entry)
    # Retain only the validated package inventory, never supplied advisory claims.
    clean = {"schema_version": 1, "host": doc["host"], "collected_at": doc["collected_at"],
             "environments": [{"path": e["path"], "ecosystem": e["ecosystem"], "status": e["status"],
                               "packages": [{"name": p["name"], "version": p["version"]} for p in e["packages"]]}
                              for e in doc["environments"]]}
    write_json(str(out / "inventory.json"), clean)
    coverage = {"schema_version": 1, "generated_at": now(), "entries": entries}
    write_json(str(out / "inventory.coverage.json"), coverage)
    write_json(str(out / "inventory.manifest.json"), {"schema_version": 1, "started_at": started,
               "finished_at": now(), "offline": offline, "query_endpoint": OSV_QUERY,
               "inventory_sha256": hashlib.sha256(json.dumps(clean, sort_keys=True).encode()).hexdigest(),
               "python_version": sys.version.split()[0]})
    return coverage


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect", help="read metadata from explicitly named venvs")
    collect.add_argument("--host", required=True, help="stable asset identifier; no SSH is performed")
    collect.add_argument("--venv", action="append", required=True)
    collect.add_argument("--output", required=True)
    imp = sub.add_parser("import", help="query PyPI inventory against OSV on this machine")
    imp.add_argument("inventory")
    imp.add_argument("--out", required=True, help="new or empty output directory")
    imp.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            doc = {"schema_version": 1, "host": args.host, "collected_at": now(),
                   "environments": [collect_venv(p) for p in args.venv]}
            validate(doc)
            write_json(args.output, doc)
            return 2 if any(e["status"] != "inventory-only" for e in doc["environments"]) else 0
        doc = validate(json.loads(read_regular(args.inventory)))
        coverage = import_inventory(doc, args.out, args.offline)
        return 2 if any(e["status"] != "scanned" for e in coverage["entries"]) else 0
    except (OSError, ValueError) as exc:
        print("inventory: " + mask_secrets(str(exc)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
