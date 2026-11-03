#!/usr/bin/env python3
"""Structured scan coverage journal. Python stdlib only; never runs target code.

Each component has an atomic journal file, so parallel scanners cannot lose one
another's updates. A successful scanner does not establish discovery completeness.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import load_json, load_tools, mask_secrets, write_json

STATUSES = ("scanned", "inventory-only", "permission-denied", "failed",
            "unsupported", "skipped", "pending")


def now():
    return datetime.now(timezone.utc).isoformat()


def initialize(out):
    raw = os.path.join(out, "raw")
    if os.path.isdir(raw) and any(files for _, _, files in os.walk(raw)):
        raise ValueError("OUT/raw contains prior results; use a fresh output directory")
    if os.path.exists(os.path.join(out, "coverage.json")):
        raise ValueError("OUT already contains a scan run; use a fresh output directory")
    os.makedirs(os.path.join(out, "coverage.d"), exist_ok=True)
    doc = {"schema_version": 1, "run_id": uuid.uuid4().hex,
           "started_at": now(), "finished_at": None, "status": "running",
           "discovery_complete": False, "entries": []}
    write_json(os.path.join(out, "coverage.json"), doc)
    return doc


def record(out, target, name, path, component, status, reason, artifact="",
           scope_complete=False):
    key = json.dumps([target, path, component], ensure_ascii=False)
    entry = {"target": target, "name": name, "path_or_host": path,
             "component": component, "status": status,
             "reason": mask_secrets(reason), "observed_at": now(),
             "scope_complete": bool(scope_complete and status == "scanned"),
             "artifact": artifact or None}
    dest = os.path.join(out, "coverage.d", hashlib.sha256(key.encode()).hexdigest() + ".json")
    write_json(dest, entry)
    return entry


def finalize(out):
    doc = load_json(os.path.join(out, "coverage.json"))
    if not isinstance(doc, dict):
        raise ValueError("coverage was not initialized")
    folder = os.path.join(out, "coverage.d")
    entries = [load_json(os.path.join(folder, f)) for f in sorted(os.listdir(folder))
               if f.endswith(".json")]
    if any(not isinstance(e, dict) for e in entries):
        raise ValueError("invalid coverage journal")
    entries.sort(key=lambda e: (e["target"], e["path_or_host"], e["component"]))
    doc.update(entries=entries, finished_at=now(), status="partial")
    # 'complete' refers only to the explicitly enumerated scan components.
    # discovery_complete deliberately remains false: no filesystem-wide claim.
    if entries and all(e["status"] == "scanned" and e["scope_complete"] for e in entries):
        doc["status"] = "complete"
    doc["counts"] = {s: sum(e["status"] == s for e in entries) for s in STATUSES}
    write_json(os.path.join(out, "coverage.json"), doc)
    tools = load_tools(out)
    manifest = {"schema_version": 1, "run_id": doc["run_id"],
                "started_at": doc["started_at"], "finished_at": doc["finished_at"],
                "python_version": platform.python_version(),
                "tools": [{"name": r["tool"], "version": r["note"]}
                          for r in tools if r["status"] == "available"],
                "database_snapshot": None,
                "reproducibility": "DB snapshots are not pinned; identical targets may yield different findings",
                "coverage_schema_version": 1}
    write_json(os.path.join(out, "manifest.json"), manifest)
    return doc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("init", "record", "finalize"))
    parser.add_argument("out")
    parser.add_argument("--target", choices=("project", "server", "image"))
    parser.add_argument("--name", default="")
    parser.add_argument("--path", default="")
    parser.add_argument("--component", default="")
    parser.add_argument("--status", choices=STATUSES)
    parser.add_argument("--reason", default="")
    parser.add_argument("--artifact", default="")
    parser.add_argument("--scope-complete", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.operation == "init":
            initialize(args.out)
        elif args.operation == "finalize":
            finalize(args.out)
        else:
            if not args.target or not args.path or not args.component or not args.status:
                parser.error("record requires --target, --path, --component, and --status")
            record(args.out, args.target, args.name, args.path, args.component,
                   args.status, args.reason, args.artifact, args.scope_complete)
    except (OSError, ValueError) as exc:
        print("[coverage] " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
