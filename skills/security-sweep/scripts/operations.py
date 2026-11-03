#!/usr/bin/env python3
"""Machine-readable summaries and conservative comparisons (stdlib only).

report.py calls export(); CLI: operations.py OUT [--previous PREVIOUS_OUT].
Missing findings never constitute proof of a fix. Raw scanner findings are
immutable; optional triage.json overrides are bound to an exact evidence hash.
"""
import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

from _common import as_dict, as_list, load_json, mask_secrets, norm_pkg, write_json

SCHEMA_VERSION = 1
POLICY_VERSION = "2026-11-evidence-v1"
PRIORITIES = ("P0", "P1", "P2", "P3")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def target_key(f):
    return (str(f.get("target", "")), str(f.get("path_or_host") or f.get("name", "")))


def identity(f):
    # Version deliberately excluded: upgrading to another affected version is
    # the same outstanding issue. Environment/location separates server venvs.
    return (*target_key(f), str(f.get("kind", "")), str(f.get("ecosystem", "")),
            norm_pkg(f.get("ecosystem", ""), f.get("package", "")),
            str(f.get("location", "")) if f.get("target") == "server" or f.get("kind") != "vuln" else "")


def ids(f):
    return {str(x) for x in [f.get("id")] + as_list(f.get("aliases")) if x}


def evidence_hash(f):
    return digest(f)


def finding_ref(f):
    return {"fingerprint": digest([identity(f), sorted(ids(f))]),
            "evidence_hash": evidence_hash(f), "target": f.get("target"),
            "name": mask_secrets(f.get("name")), "id": f.get("id"),
            "package": f.get("package"), "version": f.get("version"),
            "priority": f.get("priority")}


def coverage_summary(out):
    entries, problems = [], []
    documents = []
    for filename in ("coverage.json", "inventory.coverage.json"):
        path = os.path.join(out, filename)
        if not os.path.exists(path):
            continue
        doc = load_json(path)
        if not isinstance(doc, dict) or doc.get("schema_version") != 1 or not isinstance(doc.get("entries"), list):
            problems.append("invalid " + filename)
            continue
        documents.append(doc)
        for entry in doc["entries"]:
            if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in ("target", "component", "status")):
                problems.append("invalid entry in " + filename)
                continue
            entries.append(entry)
        if doc.get("status") in ("running", "failed"):
            problems.append(filename + ": " + doc["status"])
    counts = dict(Counter(e["status"] for e in entries))
    complete = bool(entries) and not problems and all(
        e["status"] == "scanned" and e.get("scope_complete") is True for e in entries)
    return {"status": "complete" if complete else "partial" if entries else "unknown",
            "scope": "declared-components-only", "discovery_complete": False,
            "statuses": counts, "entry_count": len(entries), "entries": entries,
            "problems": problems,
            "observed_at": sorted({e["observed_at"] for e in entries if isinstance(e.get("observed_at"), str)})}


def compare(current, previous, coverage):
    """Alias-aware one-to-one matching. Ambiguous or lost coverage stays open."""
    matched = set()
    changes = {k: [] for k in ("new", "persistent", "changed", "no_longer_detected", "not_observed", "resolved")}
    for f in current:
        candidates = [i for i, old in enumerate(previous) if i not in matched
                      and identity(f) == identity(old) and ids(f) & ids(old)]
        if len(candidates) != 1:
            changes["new"].append(finding_ref(f))
            continue
        i = candidates[0]
        matched.add(i)
        old = previous[i]
        fields = [k for k in ("version", "priority", "severity", "verified", "verification_status",
                              "reach", "reach_method", "kev", "epss", "fixed") if old.get(k) != f.get(k)]
        ref = finding_ref(f)
        if fields:
            ref["changed_fields"] = fields
            ref["before"] = {k: old.get(k) for k in fields}
        changes["changed" if fields else "persistent"].append(ref)
    for i, old in enumerate(previous):
        if i in matched:
            continue
        relevant = [e for e in coverage["entries"] if target_key(e) == target_key(old)]
        # This remains conservative across components and DB changes. A clean
        # rerun shows absence, not remediation. No automatic resolved state.
        observed = bool(relevant) and not coverage["problems"] and all(
            e.get("status") == "scanned" and e.get("scope_complete") is True for e in relevant)
        ref = finding_ref(old)
        ref["reason"] = "absent from current detections; fix not proven" if observed else "equivalent successful coverage not established"
        changes["no_longer_detected" if observed else "not_observed"].append(ref)
    return {"schema_version": 1, "counts": {k: len(v) for k, v in changes.items()},
            "changes": changes, "resolution_policy": "absence-is-not-proof-of-fix",
            "recurrence": "requires multi-run history; not inferred from two snapshots"}


def apply_triage(findings, document):
    reviewed = [dict(f) for f in findings]
    accepted, rejected = [], []
    if document is None:
        return reviewed, {"accepted": accepted, "rejected": rejected}
    if not isinstance(document, dict) or document.get("schema_version") != 1 or not isinstance(document.get("overrides"), list):
        return reviewed, {"accepted": [], "rejected": [{"reason": "invalid triage schema"}]}
    by_hash = {}
    for i, f in enumerate(findings):
        by_hash.setdefault(evidence_hash(f), []).append(i)
    seen = set()
    for item in document["overrides"]:
        item = as_dict(item)
        key = item.get("evidence_hash")
        reason = None
        if not isinstance(key, str) or len(by_hash.get(key, [])) != 1:
            reason = "stale or unknown evidence"
        elif key in seen:
            reason = "duplicate override"
        elif item.get("priority") not in PRIORITIES:
            reason = "invalid priority"
        elif not all(isinstance(item.get(k), str) and item[k].strip() for k in ("reason", "evidence", "reviewer", "reviewed_at")):
            reason = "reason, evidence, reviewer and reviewed_at are required"
        elif findings[by_hash[key][0]].get("kev") and item["priority"] != "P0":
            reason = "KEV cannot be downgraded"
        if reason:
            rejected.append({"evidence_hash": key if isinstance(key, str) else None, "reason": reason})
            continue
        seen.add(key)
        i = by_hash[key][0]
        reviewed[i]["priority"] = item["priority"]
        accepted.append({k: mask_secrets(item[k]) for k in
                         ("evidence_hash", "priority", "reason", "evidence", "reviewer", "reviewed_at")})
    return reviewed, {"accepted": accepted, "rejected": rejected}


def counts(findings):
    return {p: sum(f.get("priority") == p for f in findings) for p in PRIORITIES}


def export(out, findings, previous=None):
    cov = coverage_summary(out)
    triage_path = os.path.join(out, "triage.json")
    triage = load_json(triage_path) if os.path.exists(triage_path) else None
    if os.path.exists(triage_path) and triage is None:
        triage = {}  # malformed is a rejected review, not an absent review
    reviewed, review_status = apply_triage(findings, triage)
    summary = {"schema_version": SCHEMA_VERSION, "policy_version": POLICY_VERSION,
               "generated_at": datetime.now(timezone.utc).isoformat(),
               "counts": counts(findings), "reviewed_counts": counts(reviewed),
               "finding_count": len(findings),
               "verification": dict(Counter(str(f.get("verification_status", "legacy-unknown"))
                                            for f in findings if f.get("kind") == "vuln")),
               "coverage": cov, "triage": review_status,
               "findings": [finding_ref(f) for f in findings],
               "provenance": {"manifest": load_json(os.path.join(out, "manifest.json"), {}),
                              "verification": load_json(os.path.join(out, "verified.meta.json"), {})},
               "comparison": None,
               "sharing": "Contains internal asset metadata; redact before external publication."}
    if previous is not None:
        old = load_json(os.path.join(previous, "findings.json"))
        if not isinstance(old, list) or not all(isinstance(f, dict) for f in old):
            raise ValueError("previous findings.json is missing or invalid")
        delta = compare(findings, old, cov)
        write_json(os.path.join(out, "diff.json"), delta)
        summary["comparison"] = delta["counts"]
    write_json(os.path.join(out, "summary.json"), summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out")
    parser.add_argument("--previous")
    args = parser.parse_args(argv)
    findings = load_json(os.path.join(args.out, "findings.json"))
    if not isinstance(findings, list) or not all(isinstance(f, dict) for f in findings):
        parser.error("findings.json is missing or invalid; run report.py first")
    try:
        result = export(args.out, findings, args.previous)
    except ValueError as exc:
        parser.error(str(exc))
    print("summary: %s; coverage=%s" % (result["counts"], result["coverage"]["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
