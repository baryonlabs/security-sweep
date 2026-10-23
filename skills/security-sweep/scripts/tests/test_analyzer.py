"""Self-tests for verify_cves.py / reachability.py / report.py (stdlib unittest, no network).

run: python3 -I skills/security-sweep/scripts/tests/test_analyzer.py
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
sys.path.insert(0, SCRIPTS)

import _common  # noqa: E402
import reachability  # noqa: E402
import report  # noqa: E402
import verify_cves  # noqa: E402

FIXTURE = os.path.join(HERE, "fixtures", "sample")
SECRET_VALUES = ("TESTSECRET-DO-NOT-LEAK-7f3a91", "ELIXIRSNIPPETSECRET0123456789")


def finding(**kw):
    f = {"kind": "vuln", "severity": "high", "reach": "unknown", "kev": False, "epss": None,
         "verified": True}
    f.update(kw)
    return f


class CvssTest(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(verify_cves.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(verify_cves.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), 7.5)
        self.assertEqual(verify_cves.cvss3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(verify_cves.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"), 7.2)

    def test_unparsable_and_v4(self):
        self.assertIsNone(verify_cves.cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        self.assertIsNone(verify_cves.cvss3_base_score("garbage"))
        sev, _ = verify_cves.record_severity({
            "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
            "database_specific": {"severity": "MODERATE"}})
        self.assertEqual(sev, "medium")

    def test_functions(self):
        funcs, syms = verify_cves.record_functions({"affected": [{"ecosystem_specific": {
            "imports": [{"path": "golang.org/x/text/language", "symbols": ["Parse"]}]}}]})
        self.assertEqual(funcs, ["golang.org/x/text/language.Parse"])
        self.assertEqual(syms[0]["symbols"], ["Parse"])


class PriorityTest(unittest.TestCase):
    def test_rules(self):
        p = report.priority
        self.assertEqual(p(finding(severity="low", kev=True)), "P0")
        self.assertEqual(p(finding(severity="critical", reach="called")), "P0")
        self.assertEqual(p(finding(severity="high", reach="imported")), "P1")
        self.assertEqual(p(finding(severity="high", reach="unknown")), "P1")
        self.assertEqual(p(finding(severity="low", epss=0.1)), "P1")
        self.assertEqual(p(finding(kind="secret", severity="low", reach="n/a", verified=None)), "P1")
        self.assertEqual(p(finding(severity="medium", reach="called")), "P2")
        self.assertEqual(p(finding(severity="high", reach="not-imported")), "P2")
        self.assertEqual(p(finding(severity="low", reach="imported")), "P3")
        self.assertEqual(p(finding(severity="unknown")), "P3")
        self.assertEqual(p(finding(kind="misconfig", severity="low", reach="n/a", verified=None)), "P3")
        self.assertIsNone(p(finding(severity="critical", kev=True, verified=False)))


class DedupTest(unittest.TestCase):
    def rec(self, **kw):
        base = dict(target="project", name="p", path_or_host="/p", kind="vuln", ecosystem="pypi",
                    package="PyYAML", version="5.1", aliases=[], source="osv-scanner")
        base.update(kw)
        return _common._rec(**base)

    def test_alias_and_version_normalization(self):
        recs = [self.rec(id="PYSEC-2020-176", aliases=["CVE-2019-20477"]),
                self.rec(id="GHSA-3pqx-4fqf-j49f", package="pyyaml", version="5.1.0", aliases=["PYSEC-2020-176"]),
                self.rec(id="CVE-2019-20477", source="trivy"),
                self.rec(id="CVE-2020-1747", source="trivy")]
        merged = report.merge_vulns(recs, {})
        self.assertEqual(sorted(len(m) for m, _ in merged), [1, 3])
        big = [m for m, _ in merged if len(m) == 3][0]
        self.assertEqual(big[0]["source"], "osv-scanner")

    def test_verified_aliases_join(self):
        recs = [self.rec(id="GHSA-aaaa-bbbb-cccc"), self.rec(id="CVE-2000-0001", source="trivy")]
        merged = report.merge_vulns(recs, {"GHSA-aaaa-bbbb-cccc": {"aliases": ["CVE-2000-0001"]}})
        self.assertEqual(len(merged), 1)


class ReachTest(unittest.TestCase):
    def test_import_names(self):
        self.assertIn("yaml", reachability.py_import_names("PyYAML"))
        self.assertIn("bs4", reachability.py_import_names("beautifulsoup4"))
        rx = reachability.import_regex("hex", "plug_crypto")
        self.assertTrue(rx.search("alias Plug.Crypto.MessageVerifier"))
        self.assertFalse(rx.search('{:plug_crypto, "~> 1.0"}'))
        rx = reachability.import_regex("npm", "@scope/pkg")
        self.assertTrue(rx.search("import x from '@scope/pkg/sub'"))
        self.assertFalse(rx.search("import x from '@scope/pkg2'"))
        rx = reachability.import_regex("cargo", "serde-json")
        self.assertTrue(rx.search("use serde_json::Value;"))


class PipelineTest(unittest.TestCase):
    """Offline end-to-end on the fixture: verify -> reach -> report."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sweep-test-")
        out = cls.out = os.path.join(cls.tmp, "out")
        shutil.copytree(os.path.join(FIXTURE, "raw"), os.path.join(out, "raw"))
        shutil.copy(os.path.join(FIXTURE, "tools.txt"), out)
        proj = os.path.join(cls.tmp, "proj")
        shutil.copytree(os.path.join(FIXTURE, "proj"), proj)
        cache = os.path.join(cls.tmp, "cache")
        shutil.copytree(os.path.join(FIXTURE, "cache"), cache)
        for d, _, files in os.walk(os.path.join(out, "raw")):
            for f in files:
                p = os.path.join(d, f)
                with open(p, encoding="utf-8") as fh:
                    txt = fh.read()
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(txt.replace("__PROJ__", proj))
        targets = {"generated_at": "2026-10-23T00:00:00Z", "roots": [proj], "projects": [
            {"path": os.path.join(proj, n), "name": n, "ecosystems": [e], "lockfiles": [], "git": False}
            for n, e in (("webapp", "npm"), ("goapp", "go"), ("exapp", "hex"))]}
        with open(os.path.join(out, "targets.json"), "w", encoding="utf-8") as fh:
            json.dump(targets, fh)
        with contextlib.redirect_stdout(io.StringIO()):
            assert verify_cves.main([out, "--offline", "--cache", cache]) == 0
            assert reachability.main([out]) == 0
            assert report.main([out]) == 0
        with open(os.path.join(out, "verified.json"), encoding="utf-8") as fh:
            cls.verified = json.load(fh)
        with open(os.path.join(out, "reach.json"), encoding="utf-8") as fh:
            cls.reach = json.load(fh)
        with open(os.path.join(out, "findings.json"), encoding="utf-8") as fh:
            cls.findings = json.load(fh)
        with open(os.path.join(out, "REPORT.md"), encoding="utf-8") as fh:
            cls.md = fh.read()
        with open(os.path.join(out, "REPORT.html"), encoding="utf-8") as fh:
            cls.html = fh.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def find(self, **kw):
        hits = [f for f in self.findings if all(f.get(k) == v for k, v in kw.items())]
        self.assertEqual(len(hits), 1, "expected one finding for %r, got %d" % (kw, len(hits)))
        return hits[0]

    def test_offline_verification(self):
        v = self.verified
        self.assertIs(v["GHSA-35jh-r3h4-6jhm"]["exists"], True)          # embedded by osv-scanner
        self.assertIs(v["CVE-2021-23337"]["exists"], True)               # trivy id, alias of embedded record
        self.assertIs(v["CVE-2099-00001"]["exists"], False)              # cached 404
        self.assertIs(v["CVE-2026-97853"]["exists"], True)               # cached 200
        self.assertIsNone(v["CVE-2023-4911"]["exists"])                  # trivy-only, offline
        self.assertEqual(v["GO-2021-0113"]["severity"], "high")          # borrowed from GHSA alias
        self.assertEqual(v["CVE-2026-97853"]["functions"], ["Decimal.round/3"])
        self.assertTrue(v["GHSA-35jh-r3h4-6jhm"]["kev"])

    def test_dedup_and_kev(self):
        f = self.find(name="webapp", package="lodash", kind="vuln", id="GHSA-35jh-r3h4-6jhm")
        self.assertIn("CVE-2021-23337", f["aliases"])
        self.assertIn("osv-scanner", f["source"])
        self.assertIn("trivy", f["source"])
        self.assertEqual(f["priority"], "P0")
        self.assertEqual(f["reach"], "imported")
        self.assertEqual(f["fixed"], "4.17.21")

    def test_not_imported(self):
        f = self.find(name="webapp", package="minimist")
        self.assertEqual((f["severity"], f["reach"], f["priority"]), ("critical", "not-imported", "P2"))

    def test_govulncheck_called(self):
        f = self.find(name="goapp", id="GO-2021-0113")
        self.assertEqual((f["reach"], f["priority"], f["fixed"]), ("called", "P0", "0.3.7"))
        self.assertTrue(any("main.go:10" in e for e in f["reach_evidence"]))

    def test_elixir_symbol_grep(self):
        f = self.find(name="exapp", id="CVE-2026-97853")
        self.assertEqual((f["reach"], f["priority"]), ("called", "P0"))
        self.assertEqual(self.reach["exapp"]["decimal"]["CVE-2026-97853"]["method"], "symbol-grep")
        code = self.find(name="exapp", id="EXS-CFG-001")
        self.assertEqual(code["kind"], "code")

    def test_failed_verification_section(self):
        f = self.find(id="CVE-2099-00001")
        self.assertIsNone(f["priority"])
        self.assertIs(f["verified"], False)
        failed = self.md.split("## 검증 실패")[1].split("## 다음 행동")[0]
        self.assertIn("CVE-2099-00001", failed)
        self.assertNotIn("CVE-2099-00001", self.md.split("## 검증 실패")[0])

    def test_image_and_server(self):
        f = self.find(target="image", id="CVE-2023-4911")
        self.assertEqual((f["reach"], f["priority"], f["name"]), ("n/a", "P1", "myapp:prod"))
        self.assertIsNone(f["verified"])
        self.assertIn("패키지 목록만 수집됨 (trivy 미설치) — 2개 패키지", self.md)
        self.assertIn("apt-get install --only-upgrade libc6", self.md)

    def test_secret_masking(self):
        f = self.find(kind="secret")
        self.assertEqual((f["priority"], f["location"]), ("P1", "src/cfg.js:1"))
        for path in ("findings.json", "REPORT.md", "REPORT.html", "verified.json", "reach.json"):
            with open(os.path.join(self.out, path), encoding="utf-8") as fh:
                txt = fh.read()
            for secret in SECRET_VALUES:
                self.assertNotIn(secret, txt, "%s leaked into %s" % (secret, path))
        self.assertEqual(_common.mask_secrets("key AKIAABCDEFGHIJKLMNOP end"), "key **** end")

    def test_misconfig_pass_skipped(self):
        self.assertFalse([f for f in self.findings if f["id"] == "DS-0005"])
        self.assertEqual(self.find(id="DS-0026")["priority"], "P3")

    def test_html_escaped_and_self_contained(self):
        self.assertNotIn("<img", self.html)
        self.assertIn("&lt;img", self.html)
        self.assertNotIn("<script", self.html)
        self.assertNotIn("<link", self.html)
        self.assertIn("prefers-color-scheme:dark", self.html)

    def test_next_actions(self):
        actions = self.md.split("## 다음 행동")[1]
        self.assertIn("npm audit fix", actions)
        self.assertIn("go get golang.org/x/text@v0.3.7", actions)
        self.assertIn("mix deps.update decimal", actions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
