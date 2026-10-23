#!/usr/bin/env python3
"""Merge raw results, OSV verification and reachability into one report.

usage: report.py OUT

Writes OUT/findings.json, OUT/REPORT.md, OUT/REPORT.html.
Priority (references/prioritize.md):
  P0  KEV, or critical|high with reach=called
  P1  critical|high with reach in {imported, unknown, n/a}, or EPSS >= 0.1, or a secret
  P2  medium, or critical|high with reach=not-imported
  P3  low / unknown
verified=false (OSV 404) vulns get priority null and go to the "검증 실패" section.
"""

import html
import os
import shlex
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (SEV_RANK, as_dict, as_list, load_json, load_raw, load_targets,  # noqa: E402
                     load_tools, mask_secrets, norm_pkg, norm_sev, norm_version,
                     pick_fixed, record_fixed, version_key, warn, write_json)

PRIORITIES = ("P0", "P1", "P2", "P3")
REACH_RANK = {"called": 0, "imported": 1, "unknown": 2, "not-imported": 3, "n/a": 4}
SOURCE_PREF = {"osv-scanner": 0, "govulncheck": 1, "mix_audit": 2, "trivy": 3}
TARGET_LABEL = {"project": "프로젝트", "server": "서버", "image": "이미지"}
KIND_LABEL = {"vuln": "취약 의존성", "secret": "비밀값", "misconfig": "설정 오류", "code": "코드 패턴"}
EPSS_THRESHOLD = 0.1


def priority(f):
    sev, reach = f["severity"], f["reach"]
    hi = sev in ("critical", "high")
    if f["kind"] == "vuln" and f["verified"] is False:
        return None
    if f["kev"] or (hi and reach == "called"):
        return "P0"
    if (hi and reach in ("imported", "unknown", "n/a")) or (f["epss"] or 0) >= EPSS_THRESHOLD \
            or f["kind"] == "secret":
        return "P1"
    if sev == "medium" or (hi and reach == "not-imported"):
        return "P2"
    return "P3"


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def id_set(rec, verified):
    ids = {rec["id"]} | set(rec.get("aliases") or [])
    for vid in list(ids):
        v = as_dict(verified.get(vid))
        ids |= set(as_list(v.get("aliases")))
        if v.get("osv_id"):
            ids.add(v["osv_id"])
    return {i for i in ids if i}


def merge_vulns(records, verified):
    """Group same vuln for the same target/package across scanners."""
    groups = {}
    for r in records:
        key = (r["target"], r["name"], r["ecosystem"], norm_pkg(r["ecosystem"], r["package"]),
               norm_version(r["version"]))
        groups.setdefault(key, []).append(r)
    merged = []
    for recs in groups.values():
        sets = [id_set(r, verified) for r in recs]
        parent = list(range(len(recs)))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        for i in range(len(recs)):
            for j in range(i + 1, len(recs)):
                if sets[i] & sets[j]:
                    parent[find(i)] = find(j)
        clusters = {}
        for i in range(len(recs)):
            clusters.setdefault(find(i), []).append(i)
        for idxs in clusters.values():
            members = sorted((recs[i] for i in idxs), key=lambda r: SOURCE_PREF.get(r["source"], 9))
            ids = set()
            for i in idxs:
                ids |= sets[i]
            merged.append((members, ids))
    return merged


def verify_state(ids, verified):
    states = [as_dict(verified.get(i)).get("exists") for i in ids if i in verified]
    if any(s is True for s in states):
        return True
    if states and all(s is False for s in states):
        return False
    return None


def reach_state(target, name, eco, pkg, ids, reach):
    if target != "project" or eco.startswith("os:"):
        return "n/a", [], ""
    slot = as_dict(as_dict(reach.get(name)).get(norm_pkg(eco, pkg)))
    cands = [as_dict(slot[i]) for i in ids if i in slot]
    if not cands:
        return "unknown", [], ""
    gv = [c for c in cands if c.get("method") == "govulncheck"]
    best = min(gv or cands, key=lambda c: REACH_RANK.get(c.get("status"), 9))
    return (str(best.get("status") or "unknown"),
            [mask_secrets(e) for e in as_list(best.get("evidence"))[:5]],
            str(best.get("note") or ""))


def build_findings(out):
    records, notes = load_raw(out)
    verified = as_dict(load_json(os.path.join(out, "verified.json"), {}))
    reach = as_dict(load_json(os.path.join(out, "reach.json"), {}))
    findings = []

    vulns = [r for r in records if r["kind"] == "vuln"]
    for members, ids in merge_vulns(vulns, verified):
        top = members[0]
        primary = top["id"]
        if top["source"] == "trivy":
            osv_ids = [as_dict(verified.get(m["id"])).get("osv_id") for m in members]
            primary = next((x for x in osv_ids if x), primary)
        aliases = sorted(ids - {primary})
        sev = "unknown"
        for i in [primary] + aliases:
            s = norm_sev(as_dict(verified.get(i)).get("severity"))
            if s != "unknown":
                sev = s
                break
        if sev == "unknown":
            raw = sorted((m["severity"] for m in members), key=lambda s: SEV_RANK.get(s, 9))
            sev = raw[0] if raw else "unknown"
        fixed_c = []
        for m in members:
            fixed_c += m["fixed_candidates"]
        if not fixed_c:
            for i in ids:
                for a in as_list(as_dict(verified.get(i)).get("affected")):
                    a = as_dict(a)
                    if norm_pkg(top["ecosystem"], a.get("name")) == norm_pkg(top["ecosystem"], top["package"]):
                        fixed_c += as_list(a.get("fixed"))
        if not fixed_c and isinstance(top.get("record"), dict):
            fixed_c = record_fixed(top["record"], top["ecosystem"], top["package"])
        kev = any(as_dict(verified.get(i)).get("kev") for i in ids)
        epss_vals = [as_dict(verified.get(i)).get("epss") for i in ids]
        epss_vals = [e for e in epss_vals if isinstance(e, (int, float))]
        rstat, rev, rnote = reach_state(top["target"], top["name"], top["ecosystem"],
                                        top["package"], ids, reach)
        summary = next((as_dict(verified.get(i)).get("summary") for i in [primary] + aliases
                        if as_dict(verified.get(i)).get("summary")), "") or top["message"]
        f = {"target": top["target"], "name": top["name"], "path_or_host": top["path_or_host"],
             "kind": "vuln", "id": primary, "aliases": aliases, "package": top["package"],
             "version": top["version"], "ecosystem": top["ecosystem"],
             "fixed": pick_fixed(top["version"], fixed_c), "severity": sev,
             "verified": verify_state(ids, verified), "kev": bool(kev),
             "epss": max(epss_vals) if epss_vals else None, "reach": rstat,
             "reach_evidence": rev, "reach_note": rnote,
             "source": ", ".join(dict.fromkeys(m["source"] for m in members)),
             "location": ", ".join(dict.fromkeys(m["location"] for m in members if m["location"])),
             "message": mask_secrets(str(summary))[:300]}
        f["priority"] = priority(f)
        findings.append(f)

    for r in records:
        if r["kind"] == "vuln":
            continue
        f = {"target": r["target"], "name": r["name"], "path_or_host": r["path_or_host"],
             "kind": r["kind"], "id": r["id"], "aliases": [], "package": "", "version": "",
             "ecosystem": "", "fixed": "", "severity": r["severity"], "verified": None,
             "kev": False, "epss": None, "reach": "n/a", "reach_evidence": [], "reach_note": "",
             "source": r["source"], "location": r["location"], "message": mask_secrets(r["message"])}
        f["priority"] = priority(f)
        findings.append(f)

    order = {p: i for i, p in enumerate(PRIORITIES)}
    findings.sort(key=lambda f: (order.get(f["priority"], 9), SEV_RANK.get(f["severity"], 9),
                                 f["target"], f["name"], f["package"], f["id"]))
    return findings, notes


# ---------------------------------------------------------------------------
# Next actions
# ---------------------------------------------------------------------------

def os_upgrade_cmd(eco, pkgs):
    typ = eco.split(":", 1)[1] if ":" in eco else ""
    names = " ".join(shlex.quote(p) for p in pkgs)
    if typ in ("debian", "ubuntu"):
        return "sudo apt-get update && sudo apt-get install --only-upgrade " + names
    if typ == "alpine":
        return "apk upgrade " + names
    if typ in ("redhat", "centos", "rocky", "alma", "amazon", "fedora", "oracle", "cbl-mariner", "azurelinux"):
        return "sudo dnf upgrade " + names
    if typ in ("suse", "opensuse", "opensuse.leap", "sles"):
        return "sudo zypper update " + names
    return "패키지 관리자로 업그레이드: " + names


def lang_cmds(eco, pkgs):
    """pkgs: list of (package, fixed)."""
    q = shlex.quote
    if eco == "npm":
        return ["npm audit fix"] + ["# %s → %s 이상" % (p, fx or "최신") for p, fx in pkgs]
    if eco == "pypi":
        return ["pip install -U %s" % q("%s==%s" % (p, fx) if fx else p) for p, fx in pkgs]
    if eco == "hex":
        return ["mix deps.update " + " ".join(q(p) for p, _ in pkgs)]
    if eco == "cargo":
        return ["cargo update -p %s%s" % (q(p), " --precise %s" % q(fx) if fx else "") for p, fx in pkgs]
    if eco == "go":
        return ["go get %s@%s" % (q(p), q("v" + fx.lstrip("v")) if fx else "latest") for p, fx in pkgs] \
            + ["go mod tidy"]
    if eco == "packagist":
        return ["composer update " + " ".join(q(p) for p, _ in pkgs)]
    if eco == "rubygems":
        return ["bundle update " + " ".join(q(p) for p, _ in pkgs)]
    if eco == "maven":
        return ["# pom.xml / build.gradle 에서 %s 를 %s 이상으로 상향" % (p, fx or "패치 버전") for p, fx in pkgs]
    return ["# %s: %s → %s" % (eco or "?", p, fx or "?") for p, fx in pkgs]


def next_actions(findings):
    plan = {}
    for f in findings:
        if f["kind"] != "vuln" or f["priority"] is None:
            continue
        key = (f["target"], f["name"], f["path_or_host"])
        eco_map = plan.setdefault(key, {})
        pk = eco_map.setdefault(f["ecosystem"], {})
        cur = pk.get(f["package"], "")
        cand = [x for x in (cur, f["fixed"]) if x]
        pk[f["package"]] = max(cand, key=version_key) if cand else ""
    out = []
    for (target, name, where), eco_map in sorted(plan.items()):
        cmds = []
        for eco, pk in sorted(eco_map.items()):
            pkgs = sorted(pk.items())
            if eco.startswith("os:"):
                if target == "image":
                    cmds.append("# 베이스 이미지를 최신 패치로 올려 다시 빌드 (docker build --pull ...)")
                cmds.append(os_upgrade_cmd(eco, [p for p, _ in pkgs]))
            else:
                cmds += lang_cmds(eco, pkgs)
        prefix = "cd %s" % shlex.quote(where) if target == "project" and where else ""
        if target == "server":
            prefix = "ssh %s  # 승인 후 수동 실행" % shlex.quote(where or name)
        out.append({"target": target, "name": name, "where": where, "prefix": prefix, "commands": cmds})
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def md(s):
    s = str("" if s is None else s).replace("\r", " ").replace("\n", " ")
    return s.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")


def fmt_verified(v):
    return {True: "확인", False: "404", None: "미확인"}[v]


def fmt_epss(e):
    return "" if e is None else "%.3f" % e


def reason(f):
    bits = []
    if f["kev"]:
        bits.append("KEV")
    if f["epss"] is not None and f["epss"] >= EPSS_THRESHOLD:
        bits.append("EPSS %.2f" % f["epss"])
    if f["kind"] == "vuln":
        bits.append("도달성 %s" % f["reach"])
    if f["kind"] == "secret":
        bits.append("비밀값 노출")
    return ", ".join(bits)


def id_cell(f):
    cves = [a for a in f["aliases"] if a.startswith("CVE-")]
    return f["id"] + (" (%s)" % ", ".join(cves[:2]) if cves and not f["id"].startswith("CVE-") else "")


def pkg_cell(f):
    if f["kind"] != "vuln":
        return KIND_LABEL.get(f["kind"], f["kind"])
    return "%s@%s" % (f["package"], f["version"]) if f["version"] else f["package"]


def summary_data(out, findings, notes, tools, targets_doc, meta):
    counts = {p: 0 for p in PRIORITIES}
    for f in findings:
        if f["priority"]:
            counts[f["priority"]] += 1
    names = {"project": set(), "server": set(), "image": set()}
    for p in as_list(targets_doc.get("projects")):
        names["project"].add(str(as_dict(p).get("name", "")))
    for f in findings:
        names.setdefault(f["target"], set()).add(f["name"])
    for n in notes:
        names.setdefault(n["target"], set()).add(n["name"])
    failed = [f for f in findings if f["kind"] == "vuln" and f["verified"] is False]
    unverified = sum(1 for f in findings if f["kind"] == "vuln" and f["verified"] is None)
    return {"counts": counts, "targets": {k: len(v - {""}) for k, v in names.items()},
            "failed": failed, "unverified": unverified, "tools": tools, "notes": notes,
            "meta": meta, "out": out}


def render_md(findings, s, actions):
    L = []
    L.append("# 보안 스윕 보고서")
    L.append("")
    L.append("- 생성: %s" % time.strftime("%Y-%m-%d %H:%M"))
    L.append("- 출력 디렉터리: `%s`" % s["out"])
    t = s["targets"]
    L.append("- 대상: 프로젝트 %d, 서버 %d, 이미지 %d" % (t.get("project", 0), t.get("server", 0), t.get("image", 0)))
    meta = s["meta"]
    if meta:
        L.append("- OSV 검증: %s%s, KEV: %s, EPSS: %s" % (
            "오프라인(캐시·내장 레코드만) " if meta.get("offline") else "",
            "확인 %(exists_true)d / 404 %(exists_false)d / 미확인 %(exists_null)d" % as_dict(meta.get("counts")),
            meta.get("kev", "?"), meta.get("epss", "?")))
    else:
        L.append("- OSV 검증: verify_cves.py 결과 없음 — 모든 취약점이 미검증 상태")
    L.append("")
    L.append("## 요약")
    L.append("")
    L.append("| 우선순위 | 건수 | 기준 |")
    L.append("|---|---:|---|")
    crit = {"P0": "KEV 등재 또는 critical/high + 실제 호출",
            "P1": "critical/high + import·불명, EPSS ≥ 0.1, 비밀값",
            "P2": "medium, 또는 high 인데 직접 import 없음",
            "P3": "low / unknown"}
    for p in PRIORITIES:
        L.append("| %s | %d | %s |" % (p, s["counts"][p], crit[p]))
    L.append("| 검증 실패(OSV 404) | %d | 우선순위 산정 제외 |" % len(s["failed"]))
    L.append("")
    if s["unverified"]:
        L.append("> 미확인 %d건: OSV 조회 실패/오프라인. 우선순위는 매겼지만 실재 여부는 확인되지 않음." % s["unverified"])
        L.append("")
    L.append("> 도달성 `not-imported` 는 직접 import 를 못 찾았다는 뜻일 뿐이다. 전이 의존성으로 쓰일 수 있으므로 안전을 의미하지 않는다.")
    L.append("")

    L.append("## 도구 상태")
    L.append("")
    if s["tools"]:
        L.append("| 도구 | 상태 | 비고 |")
        L.append("|---|---|---|")
        for row in s["tools"]:
            L.append("| %s | %s | %s |" % (md(row["tool"]), md(row["status"]), md(row["note"])))
    else:
        L.append("tools.txt 없음.")
    for n in s["notes"]:
        L.append("")
        L.append("- %s `%s`: %s" % (TARGET_LABEL.get(n["target"], n["target"]), md(n["name"]), md(n["message"])))
    L.append("")

    L.append("## P0 / P1")
    L.append("")
    top = [f for f in findings if f["priority"] in ("P0", "P1")]
    if top:
        L.append("| 우선순위 | 대상 | 패키지/종류 | ID | 심각도 | 근거 | 수정 버전 | 위치 |")
        L.append("|---|---|---|---|---|---|---|---|")
        for f in top:
            L.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
                f["priority"], md(f["name"]), md(pkg_cell(f)), md(id_cell(f)), f["severity"],
                md(reason(f)), md(f["fixed"]), md(f["location"])))
        L.append("")
        ev = [f for f in top if f["reach_evidence"]]
        if ev:
            L.append("<details><summary>도달성 근거</summary>")
            L.append("")
            for f in ev:
                L.append("- **%s** %s (%s)" % (md(f["id"]), md(f["package"]), md(f["name"])))
                for e in f["reach_evidence"]:
                    L.append("  - `%s`" % md(e))
            L.append("")
            L.append("</details>")
            L.append("")
    else:
        L.append("P0/P1 항목 없음.")
        L.append("")

    L.append("## 대상별 결과")
    L.append("")
    by_target = {}
    for f in findings:
        if f["priority"] is None:
            continue
        by_target.setdefault((f["target"], f["name"]), []).append(f)
    if not by_target:
        L.append("발견 항목 없음.")
        L.append("")
    for (target, name), fs in sorted(by_target.items()):
        L.append("### %s: %s" % (TARGET_LABEL.get(target, target), md(name)))
        L.append("")
        if fs[0]["path_or_host"]:
            L.append("`%s`" % md(fs[0]["path_or_host"]))
            L.append("")
        L.append("| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |")
        L.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for f in fs[:300]:
            L.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
                f["priority"], KIND_LABEL.get(f["kind"], f["kind"]), md(pkg_cell(f)), md(id_cell(f)),
                f["severity"], fmt_verified(f["verified"]) if f["kind"] == "vuln" else "-",
                f["reach"], "예" if f["kev"] else "", fmt_epss(f["epss"]), md(f["fixed"]),
                md(f["source"]), md(f["location"]), md(f["message"][:120])))
        if len(fs) > 300:
            L.append("")
            L.append("… 외 %d건은 findings.json 참고" % (len(fs) - 300))
        L.append("")

    L.append("## 검증 실패 (OSV 404)")
    L.append("")
    if s["failed"]:
        L.append("OSV 가 404 를 돌려준 ID 다. OSV 가 수록하지 않는 DB 의 ID(예: NSWG-*), 철회·오기된 ID, 또는 아직 공개되지 않은 ID 일 수 있다. 실재가 확인되지 않아 우선순위를 매기지 않았다 — 필요하면 원 출처에서 직접 확인한다.")
        L.append("")
        L.append("| 대상 | 패키지 | ID | 스캐너 심각도 | 출처 | 위치 | 스캐너 설명 |")
        L.append("|---|---|---|---|---|---|---|")
        for f in s["failed"]:
            L.append("| %s | %s | %s | %s | %s | %s | %s |" % (
                md(f["name"]), md(pkg_cell(f)), md(f["id"]), f["severity"], md(f["source"]),
                md(f["location"]), md(f["message"][:120])))
    else:
        L.append("없음.")
    L.append("")

    L.append("## 다음 행동")
    L.append("")
    L.append("스윕은 아무것도 수정하지 않았다. 아래 명령은 검토 후 직접 실행한다 (프로젝트별로 브랜치를 만들고 테스트를 돌릴 것).")
    L.append("")
    if not actions:
        L.append("수정할 취약 의존성 없음.")
    for a in actions:
        L.append("**%s `%s`**" % (TARGET_LABEL.get(a["target"], a["target"]), md(a["name"])))
        L.append("")
        L.append("```sh")
        if a["prefix"]:
            L.append(a["prefix"])
        for c in a["commands"]:
            L.append(c)
        L.append("```")
        L.append("")
    secrets = [f for f in findings if f["kind"] == "secret"]
    if secrets:
        L.append("**비밀값**: 위치만 표시했다(값은 보고서에 없음). 해당 키를 즉시 폐기·재발급하고 git 히스토리에서도 제거한다.")
        L.append("")
    return "\n".join(L) + "\n"


CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1b;--muted:#6b6b66;--card:#fff;--line:#e3e2dd;--code:#f0efea;
--p0:#b42318;--p1:#c4570d;--p2:#a77b00;--p3:#5a6b7a;--ok:#2f7d4f;--bad:#b42318;--chip-fg:#fff}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#141413;--fg:#ecebe6;--muted:#a3a29c;
--card:#1e1e1c;--line:#34332f;--code:#2a2a27;--p0:#f04438;--p1:#f38744;--p2:#e0b100;--p3:#8fa3b5;--ok:#5cc489;--bad:#f04438;--chip-fg:#141413}}
:root[data-theme="dark"]{--bg:#141413;--fg:#ecebe6;--muted:#a3a29c;--card:#1e1e1c;--line:#34332f;--code:#2a2a27;
--p0:#f04438;--p1:#f38744;--p2:#e0b100;--p3:#8fa3b5;--ok:#5cc489;--bad:#f04438;--chip-fg:#141413}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Noto Sans KR","Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:22px 0 6px}
.meta{color:var(--muted);font-size:13px}.meta code{word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.card span{color:var(--muted);font-size:13px}
.card.p0 b{color:var(--p0)}.card.p1 b{color:var(--p1)}.card.p2 b{color:var(--p2)}.card.p3 b{color:var(--p3)}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}tr:last-child td{border-bottom:0}
td.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
code{background:var(--code);padding:1px 4px;border-radius:4px}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;color:var(--chip-fg)}
.P0{background:var(--p0)}.P1{background:var(--p1)}.P2{background:var(--p2)}.P3{background:var(--p3)}
.sev{background:transparent;border:1px solid currentColor}.sev.critical{color:var(--p0)}.sev.high{color:var(--p1)}
.sev.medium{color:var(--p2)}.sev.low,.sev.unknown{color:var(--p3)}
.v-ok{color:var(--ok)}.v-bad{color:var(--bad)}.v-unk{color:var(--muted)}
.note{color:var(--muted);font-size:13px;margin:8px 0}
pre{background:var(--code);padding:12px;border-radius:8px;overflow-x:auto;font-size:12.5px}
details{margin:8px 0}summary{cursor:pointer;color:var(--muted)}
ul.ev{margin:4px 0 4px 18px;padding:0}
"""


def h(s):
    return html.escape(str("" if s is None else s), quote=True)


def render_html(findings, s, actions):
    E = []
    t = s["targets"]
    E.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
             "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             "<title>보안 스윕 보고서</title><style>%s</style></head><body><main>" % CSS)
    E.append("<h1>보안 스윕 보고서</h1>")
    E.append("<p class=\"meta\">생성 %s · 프로젝트 %d · 서버 %d · 이미지 %d · <code>%s</code></p>" % (
        h(time.strftime("%Y-%m-%d %H:%M")), t.get("project", 0), t.get("server", 0), t.get("image", 0), h(s["out"])))
    meta = s["meta"]
    if meta:
        c = as_dict(meta.get("counts"))
        E.append("<p class=\"meta\">OSV 검증%s: 확인 %d · 404 %d · 미확인 %d · KEV %s · EPSS %s</p>" % (
            " (오프라인)" if meta.get("offline") else "", c.get("exists_true", 0), c.get("exists_false", 0),
            c.get("exists_null", 0), h(meta.get("kev", "?")), h(meta.get("epss", "?"))))
    E.append("<div class=\"cards\">")
    for p in PRIORITIES:
        E.append("<div class=\"card %s\"><b>%d</b><span>%s</span></div>" % (p.lower(), s["counts"][p], p))
    E.append("<div class=\"card\"><b>%d</b><span>검증 실패 (OSV 404)</span></div></div>" % len(s["failed"]))
    if s["unverified"]:
        E.append("<p class=\"note\">미확인 %d건: OSV 조회 실패/오프라인. 실재 여부는 확인되지 않았다.</p>" % s["unverified"])
    E.append("<p class=\"note\">도달성 <code>not-imported</code> 는 직접 import 를 찾지 못했다는 뜻일 뿐, 전이 의존성일 수 있어 안전을 의미하지 않는다.</p>")

    def table(headers, rows):
        E.append("<div class=\"wrap\"><table><thead><tr>%s</tr></thead><tbody>" % "".join("<th>%s</th>" % h(x) for x in headers))
        for r in rows:
            E.append("<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in r))
        E.append("</tbody></table></div>")

    def chip(p):
        return "<span class=\"chip %s\">%s</span>" % (h(p), h(p)) if p else ""

    def sev(x):
        return "<span class=\"chip sev %s\">%s</span>" % (h(x), h(x))

    def ver(v):
        cls = {True: "v-ok", False: "v-bad", None: "v-unk"}[v]
        return "<span class=\"%s\">%s</span>" % (cls, h(fmt_verified(v)))

    E.append("<h2>도구 상태</h2>")
    if s["tools"]:
        table(["도구", "상태", "비고"], [[h(r["tool"]), h(r["status"]), h(r["note"])] for r in s["tools"]])
    else:
        E.append("<p class=\"note\">tools.txt 없음.</p>")
    for n in s["notes"]:
        E.append("<p class=\"note\">%s <code>%s</code>: %s</p>" % (h(TARGET_LABEL.get(n["target"], n["target"])),
                                                                 h(n["name"]), h(n["message"])))

    E.append("<h2>P0 / P1</h2>")
    top = [f for f in findings if f["priority"] in ("P0", "P1")]
    if top:
        rows = []
        for f in top:
            ev = ""
            if f["reach_evidence"]:
                ev = "<details><summary>근거 %d</summary><ul class=\"ev\">%s</ul></details>" % (
                    len(f["reach_evidence"]), "".join("<li><code>%s</code></li>" % h(e) for e in f["reach_evidence"]))
            rows.append([chip(f["priority"]), h(f["name"]), h(pkg_cell(f)), "<span class=\"mono\">%s</span>" % h(id_cell(f)),
                         sev(f["severity"]), h(reason(f)) + ev, h(f["fixed"]), "<span class=\"mono\">%s</span>" % h(f["location"])])
        table(["우선순위", "대상", "패키지/종류", "ID", "심각도", "근거", "수정 버전", "위치"], rows)
    else:
        E.append("<p class=\"note\">P0/P1 항목 없음.</p>")

    E.append("<h2>대상별 결과</h2>")
    by_target = {}
    for f in findings:
        if f["priority"] is not None:
            by_target.setdefault((f["target"], f["name"]), []).append(f)
    if not by_target:
        E.append("<p class=\"note\">발견 항목 없음.</p>")
    for (target, name), fs in sorted(by_target.items()):
        E.append("<h3>%s: %s</h3>" % (h(TARGET_LABEL.get(target, target)), h(name)))
        if fs[0]["path_or_host"]:
            E.append("<p class=\"meta\"><code>%s</code></p>" % h(fs[0]["path_or_host"]))
        rows = []
        for f in fs[:500]:
            rows.append([chip(f["priority"]), h(KIND_LABEL.get(f["kind"], f["kind"])), h(pkg_cell(f)),
                         "<span class=\"mono\">%s</span>" % h(id_cell(f)), sev(f["severity"]),
                         ver(f["verified"]) if f["kind"] == "vuln" else "-", h(f["reach"]),
                         "KEV" if f["kev"] else "", h(fmt_epss(f["epss"])), h(f["fixed"]), h(f["source"]),
                         "<span class=\"mono\">%s</span>" % h(f["location"]), h(f["message"][:160])])
        table(["우선순위", "종류", "패키지", "ID", "심각도", "검증", "도달성", "KEV", "EPSS", "수정 버전", "출처", "위치", "설명"], rows)
        if len(fs) > 500:
            E.append("<p class=\"note\">… 외 %d건은 findings.json 참고</p>" % (len(fs) - 500))

    E.append("<h2>검증 실패 (OSV 404)</h2>")
    if s["failed"]:
        E.append("<p class=\"note\">OSV 가 404 를 돌려준 ID 다. OSV 가 수록하지 않는 DB 의 ID(예: NSWG-*), 철회·오기된 ID, 또는 아직 공개되지 않은 ID 일 수 있다. 실재가 확인되지 않아 우선순위를 매기지 않았다 — 필요하면 원 출처에서 직접 확인한다.</p>")
        table(["대상", "패키지", "ID", "스캐너 심각도", "출처", "위치", "스캐너 설명"],
              [[h(f["name"]), h(pkg_cell(f)), "<span class=\"mono\">%s</span>" % h(f["id"]), sev(f["severity"]),
                h(f["source"]), h(f["location"]), h(f["message"][:160])] for f in s["failed"]])
    else:
        E.append("<p class=\"note\">없음.</p>")

    E.append("<h2>다음 행동</h2>")
    E.append("<p class=\"note\">스윕은 아무것도 수정하지 않았다. 검토 후 프로젝트별 브랜치에서 실행하고 테스트한다.</p>")
    if not actions:
        E.append("<p class=\"note\">수정할 취약 의존성 없음.</p>")
    for a in actions:
        E.append("<h3>%s: %s</h3>" % (h(TARGET_LABEL.get(a["target"], a["target"])), h(a["name"])))
        lines = ([a["prefix"]] if a["prefix"] else []) + a["commands"]
        E.append("<pre><code>%s</code></pre>" % h("\n".join(lines)))
    if any(f["kind"] == "secret" for f in findings):
        E.append("<p class=\"note\"><b>비밀값</b>: 위치만 표시했다(값은 보고서에 없음). 해당 키를 폐기·재발급하고 git 히스토리에서도 제거한다.</p>")
    E.append("</main></body></html>")
    return "\n".join(E) + "\n"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0].startswith("-"):
        print("usage: report.py OUT", file=sys.stderr)
        return 1
    out = os.path.abspath(argv[0])
    if not os.path.isdir(out):
        warn("OUT not found: %s" % out)
        return 1
    targets_doc, _ = load_targets(out)
    tools = load_tools(out)
    meta = as_dict(load_json(os.path.join(out, "verified.meta.json"), {}))
    findings, notes = build_findings(out)
    s = summary_data(out, findings, notes, tools, targets_doc, meta)
    actions = next_actions(findings)

    write_json(os.path.join(out, "findings.json"), findings)
    with open(os.path.join(out, "REPORT.md"), "w", encoding="utf-8") as fh:
        fh.write(render_md(findings, s, actions))
    with open(os.path.join(out, "REPORT.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(findings, s, actions))
    c = s["counts"]
    print("report: P0 %d, P1 %d, P2 %d, P3 %d, 검증 실패 %d → %s" % (
        c["P0"], c["P1"], c["P2"], c["P3"], len(s["failed"]), os.path.join(out, "REPORT.md")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
