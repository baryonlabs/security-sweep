#!/usr/bin/env python3
"""Verify every vulnerability ID found under OUT/raw against OSV.

usage: verify_cves.py OUT [--offline] [--cache DIR] [--workers N]

Writes OUT/verified.json ({id: {...}}) and OUT/verified.meta.json.
An ID is judged only by what OSV returns for it — never by its shape.
  exists true   OSV returned the record (or osv-scanner/govulncheck embedded it)
  exists false  OSV returned 404
  exists null   network failure / offline with no OSV-sourced record
KEV (CISA) and EPSS (FIRST) enrich CVE aliases; failures there never abort.
"""

import argparse
import concurrent.futures
import json
import math
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (ID_RE, as_dict, as_list, load_json, load_raw, norm_sev,  # noqa: E402
                     record_fixed, score_to_sev, vuln_ids, warn, write_json)

OSV_URL = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
UA = "security-sweep/0.1 (+https://github.com/hongsw/security-sweep)"
TIMEOUT = 15
RETRIES = 2
TTL_FOUND = 7 * 86400
TTL_MISSING = 86400
TTL_FEED = 86400


# ---------------------------------------------------------------------------
# CVSS v3.x base score
# ---------------------------------------------------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x):
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector):
    """Base score for a CVSS:3.0/3.1 vector string, or None if unparsable."""
    try:
        parts = str(vector).strip().split("/")
        if not parts[0].startswith("CVSS:3"):
            return None
        m = dict(p.split(":", 1) for p in parts[1:] if ":" in p)
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
              "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        c, i, a = (_W["CIA"][m[k]] for k in ("C", "I", "A"))
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _roundup(min(1.08 * (impact + expl), 10))
        return _roundup(min(impact + expl, 10))
    except (KeyError, ValueError, IndexError):
        return None


def record_severity(rec):
    """(bucket, cvss string) from an OSV record."""
    rec = as_dict(rec)
    vectors = [as_dict(s) for s in as_list(rec.get("severity"))]
    for aff in as_list(rec.get("affected")):
        vectors += [as_dict(s) for s in as_list(as_dict(aff).get("severity"))]
    best = None
    for s in vectors:
        if str(s.get("type", "")).upper().startswith("CVSS_V3"):
            score = cvss3_base_score(s.get("score"))
            if score is not None and (best is None or score > best[0]):
                best = (score, str(s.get("score")))
    if best:
        return score_to_sev(best[0]), "%.1f %s" % best
    sev = norm_sev(as_dict(rec.get("database_specific")).get("severity"))
    cvss = next((str(s.get("score")) for s in vectors if s.get("score")), "")
    if sev == "unknown":
        for aff in as_list(rec.get("affected")):
            sev = norm_sev(as_dict(as_dict(aff).get("database_specific")).get("severity"))
            if sev != "unknown":
                break
    return sev, cvss


def record_functions(rec):
    """(display strings, structured symbols) from ecosystem/database specific."""
    funcs, symbols = [], []
    for aff in as_list(as_dict(rec).get("affected")):
        aff = as_dict(aff)
        es, ds = as_dict(aff.get("ecosystem_specific")), as_dict(aff.get("database_specific"))
        for imp in as_list(es.get("imports")):
            imp = as_dict(imp)
            path = str(imp.get("path") or "")
            syms = [str(x) for x in as_list(imp.get("symbols")) if x]
            if syms:
                symbols.append({"path": path, "symbols": syms})
                funcs += ["%s.%s" % (path, s) if path else s for s in syms]
        for src in (es, ds):
            for key in ("affected_functions", "functions", "vulnerable_functions"):
                vals = [str(x) for x in as_list(src.get(key)) if x]
                if vals:
                    symbols.append({"path": "", "symbols": vals})
                    funcs += vals
    return list(dict.fromkeys(funcs)), symbols


def summarize(vid, rec, source):
    rec = as_dict(rec)
    sev, cvss = record_severity(rec)
    funcs, symbols = record_functions(rec)
    affected = []
    for aff in as_list(rec.get("affected")):
        pk = as_dict(as_dict(aff).get("package"))
        eco, name = str(pk.get("ecosystem", "")), str(pk.get("name", ""))
        ranges = [{"type": as_dict(r).get("type"), "events": as_list(as_dict(r).get("events"))}
                  for r in as_list(as_dict(aff).get("ranges"))
                  if str(as_dict(r).get("type", "")).upper() != "GIT"]
        affected.append({"ecosystem": eco, "name": name, "ranges": ranges,
                         "fixed": record_fixed({"affected": [aff]}, "", "")})
    aliases = [str(a) for a in as_list(rec.get("aliases")) + as_list(rec.get("upstream")) if a]
    osv_id = str(rec.get("id") or vid)
    if osv_id != vid and osv_id not in aliases:
        aliases.append(osv_id)
    return {"exists": True, "osv_id": osv_id,
            "aliases": [a for a in dict.fromkeys(aliases) if a != vid],
            "summary": str(rec.get("summary") or str(rec.get("details", ""))[:200]),
            "published": str(rec.get("published") or ""),
            "severity": sev, "cvss": cvss, "affected": affected,
            "functions": funcs, "symbols": symbols,
            "kev": False, "epss": None, "source": source}


def unknown_entry(vid, source, error=""):
    return {"exists": None, "osv_id": "", "aliases": [], "summary": "", "published": "",
            "severity": "unknown", "cvss": "", "affected": [], "functions": [], "symbols": [],
            "kev": False, "epss": None, "source": source, "error": error}


# ---------------------------------------------------------------------------
# HTTP + cache
# ---------------------------------------------------------------------------

def http_get(url):
    """(status, bytes|None). status 0 = network failure after retries."""
    last_err = ""
    for attempt in range(RETRIES + 1):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 404, None
            last_err = "HTTP %d" % e.code
            if e.code not in (429, 500, 502, 503, 504):
                return e.code, None
        except (urllib.error.URLError, OSError, ValueError) as e:
            last_err = str(getattr(e, "reason", e))
        if attempt < RETRIES:
            time.sleep(1.5 * (attempt + 1))
    return 0, last_err.encode()


def cache_path(cache, vid):
    return os.path.join(cache, vid.replace(":", "_").replace("/", "_") + ".json")


def cache_read(cache, vid, offline):
    c = as_dict(load_json(cache_path(cache, vid), {}))
    if not c:
        return None
    age = time.time() - float(c.get("fetched_at", 0) or 0)
    ttl = TTL_FOUND if c.get("status") == 200 else TTL_MISSING
    if offline or age < ttl:
        return c
    return None


def cache_write(cache, vid, status, record):
    try:
        write_json(cache_path(cache, vid), {"status": status, "fetched_at": time.time(), "record": record})
    except OSError as e:
        warn("cache write failed for %s: %s" % (vid, e))


def fetch_osv(vid, cache, offline):
    """(status, record|None, source). status 200/404, or 0 for unknown."""
    c = cache_read(cache, vid, offline)
    if c and c.get("status") in (200, 404):
        return c["status"], c.get("record"), "cache"
    if offline:
        return 0, None, "offline"
    status, body = http_get(OSV_URL + urllib.parse.quote(vid, safe=""))
    if status == 200:
        try:
            rec = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return 0, None, "osv-api: invalid JSON"
        cache_write(cache, vid, 200, rec)
        return 200, rec, "osv-api"
    if status == 404:
        cache_write(cache, vid, 404, None)
        return 404, None, "osv-api"
    return 0, None, "osv-api: " + (body.decode("utf-8", "replace") if isinstance(body, bytes) else str(status))


# ---------------------------------------------------------------------------
# KEV / EPSS
# ---------------------------------------------------------------------------

def load_kev(feeds, offline):
    path = os.path.join(feeds, "kev.json")
    c = as_dict(load_json(path, {}))
    fresh = c and (time.time() - float(c.get("fetched_at", 0) or 0) < TTL_FEED)
    if c and (fresh or offline):
        return set(as_list(c.get("cves"))), "cache"
    if offline:
        return None, "offline (캐시 없음)"
    status, body = http_get(KEV_URL)
    if status == 200:
        try:
            data = json.loads(body.decode("utf-8", "replace"))
            cves = sorted({str(as_dict(v).get("cveID")) for v in as_list(data.get("vulnerabilities"))
                           if as_dict(v).get("cveID")})
            write_json(path, {"fetched_at": time.time(), "cves": cves})
            return set(cves), "cisa"
        except (ValueError, OSError) as e:
            warn("KEV parse failed: %s" % e)
    if c:
        return set(as_list(c.get("cves"))), "cache (stale)"
    return None, "실패 (HTTP %s)" % status


def load_epss(feeds, cves, offline):
    path = os.path.join(feeds, "epss.json")
    c = as_dict(load_json(path, {}))
    scores = as_dict(c.get("scores"))
    now = time.time()
    result, todo = {}, []
    for cve in cves:
        e = as_dict(scores.get(cve))
        if e and (offline or now - float(e.get("fetched_at", 0) or 0) < TTL_FEED):
            result[cve] = e.get("epss")
        else:
            todo.append(cve)
    status_note = "cache" if not todo else ("offline" if offline else "first.org")
    if todo and not offline:
        failed = 0
        for i in range(0, len(todo), 100):
            chunk = todo[i:i + 100]
            st, body = http_get(EPSS_URL + "?cve=" + ",".join(urllib.parse.quote(x) for x in chunk))
            if st != 200:
                failed += 1
                continue
            try:
                data = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                failed += 1
                continue
            got = {}
            for row in as_list(data.get("data")):
                row = as_dict(row)
                try:
                    got[str(row.get("cve"))] = float(row.get("epss"))
                except (TypeError, ValueError):
                    pass
            for cve in chunk:
                # Absent from EPSS = no score (recorded so we do not refetch for a day).
                result[cve] = got.get(cve)
                scores[cve] = {"epss": got.get(cve), "fetched_at": now}
        if failed:
            status_note = "부분 실패 (%d개 배치)" % failed
        try:
            write_json(path, {"scores": scores})
        except OSError as e:
            warn("EPSS cache write failed: %s" % e)
    return result, status_note


# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("out")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "security-sweep", "osv"))
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args(argv)

    out = os.path.abspath(args.out)
    if not os.path.isdir(out):
        warn("OUT not found: %s" % out)
        return 1
    cache = os.path.abspath(os.path.expanduser(args.cache))
    feeds = os.path.join(cache, "_feeds")
    for d in (cache, feeds):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            warn("cannot create cache dir %s: %s" % (d, e))

    records, _ = load_raw(out)
    ids = vuln_ids(records)

    # Records osv-scanner / govulncheck already embedded (they come from OSV).
    embedded, alias_index = {}, {}
    for r in records:
        rec = r.get("record")
        if r["source"] in ("osv-scanner", "govulncheck") and isinstance(rec, dict) and rec.get("id"):
            embedded.setdefault(r["id"], rec)
            for a in as_list(rec.get("aliases")):
                alias_index.setdefault(str(a), rec)

    def alias_severity(entry):
        # GO-* / PYSEC-* records often carry no severity; borrow it from a GHSA/CVE alias.
        cands = sorted((a for a in entry["aliases"] if a.startswith(("GHSA-", "CVE-")) and ID_RE.match(a)),
                       key=lambda a: (not a.startswith("GHSA-"), a))[:2]
        for a in cands:
            st, rec, _ = fetch_osv(a, cache, args.offline)
            if st == 200 and isinstance(rec, dict):
                sev, cvss = record_severity(rec)
                if sev != "unknown":
                    entry["severity"], entry["cvss"] = sev, cvss
                    entry["severity_from"] = a
                    return entry
        return entry

    def work(vid):
        status, rec, source = fetch_osv(vid, cache, args.offline)
        if status == 200 and isinstance(rec, dict):
            e = summarize(vid, rec, source)
            return vid, alias_severity(e) if e["severity"] == "unknown" else e
        if status == 404:
            e = unknown_entry(vid, source)
            e["exists"] = False
            return vid, e
        if vid in embedded:
            e = summarize(vid, embedded[vid], "embedded (%s)" % source)
            return vid, alias_severity(e) if e["severity"] == "unknown" else e
        if vid in alias_index:
            e = summarize(vid, alias_index[vid], "embedded-alias (%s)" % source)
            return vid, e
        return vid, unknown_entry(vid, source, "" if args.offline else source)

    verified = {}
    workers = max(1, min(8, args.workers))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for vid, entry in ex.map(work, ids):
            verified[vid] = entry

    cves = sorted({x for vid, e in verified.items() for x in [vid] + e["aliases"]
                   if x.startswith("CVE-") and ID_RE.match(x)})
    kev, kev_note = load_kev(feeds, args.offline)
    epss, epss_note = load_epss(feeds, cves, args.offline) if cves else ({}, "해당 없음")
    for vid, e in verified.items():
        names = [vid] + e["aliases"]
        if kev is not None:
            e["kev"] = any(n in kev for n in names)
        vals = [epss[n] for n in names if epss.get(n) is not None]
        e["epss"] = max(vals) if vals else None

    write_json(os.path.join(out, "verified.json"), verified)
    counts = {"total": len(verified),
              "exists_true": sum(1 for e in verified.values() if e["exists"] is True),
              "exists_false": sum(1 for e in verified.values() if e["exists"] is False),
              "exists_null": sum(1 for e in verified.values() if e["exists"] is None),
              "kev": sum(1 for e in verified.values() if e["kev"])}
    meta = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "offline": args.offline,
            "cache": cache, "kev": kev_note, "kev_loaded": kev is not None,
            "epss": epss_note, "counts": counts}
    write_json(os.path.join(out, "verified.meta.json"), meta)
    print("verified: %(total)d ids (exists %(exists_true)d, 404 %(exists_false)d, "
          "unknown %(exists_null)d, KEV %(kev)d)" % counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
