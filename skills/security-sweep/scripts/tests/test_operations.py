import copy
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations as ops
from _common import write_json


def finding(**kw):
    f = dict(target="project", name="app", path_or_host="/app", kind="vuln",
             ecosystem="pypi", package="pkg", version="1", id="CVE-2026-12345",
             aliases=["GHSA-xxxx-yyyy-zzzz"], priority="P1", severity="high")
    f.update(kw)
    return f


class OperationsTest(unittest.TestCase):
    def test_alias_and_version_change_not_new_or_fixed(self):
        old = finding()
        new = finding(id="GHSA-xxxx-yyyy-zzzz", aliases=[], version="2")
        result = ops.compare([new], [old], {"entries": [], "problems": []})
        self.assertEqual(result["counts"]["changed"], 1)
        self.assertEqual(result["counts"]["new"], 0)
        self.assertEqual(result["counts"]["resolved"], 0)

    def test_missing_coverage_does_not_resolve(self):
        result = ops.compare([], [finding()], {"entries": [], "problems": []})
        self.assertEqual(result["counts"]["not_observed"], 1)
        self.assertEqual(result["counts"]["resolved"], 0)

    def test_clean_scan_is_absence_not_fix_proof(self):
        coverage = {"entries": [dict(target="project", path_or_host="/app",
                                     status="scanned", scope_complete=True)], "problems": []}
        result = ops.compare([], [finding()], coverage)
        self.assertEqual(result["counts"]["no_longer_detected"], 1)
        self.assertEqual(result["counts"]["resolved"], 0)
        coverage["entries"][0]["status"] = "failed"
        self.assertEqual(ops.compare([], [finding()], coverage)["counts"]["not_observed"], 1)

    def test_different_venv_not_matched(self):
        a = finding(target="server", path_or_host="host", location="/venv-a")
        b = finding(target="server", path_or_host="host", location="/venv-b")
        result = ops.compare([b], [a], {"entries": [], "problems": []})
        self.assertEqual(result["counts"]["new"], 1)
        self.assertEqual(result["counts"]["not_observed"], 1)

    def test_review_is_bound_to_evidence_and_preserves_original(self):
        f = finding()
        override = dict(evidence_hash=ops.evidence_hash(f), priority="P2", reason="not deployed",
                        evidence="build manifest abc", reviewer="human", reviewed_at="2026-11-04T00:00:00Z")
        doc = dict(schema_version=1, overrides=[override])
        reviewed, status = ops.apply_triage([f], doc)
        self.assertEqual(reviewed[0]["priority"], "P2")
        self.assertEqual(f["priority"], "P1")
        self.assertEqual(len(status["accepted"]), 1)
        changed = dict(f, version="2")
        self.assertEqual(len(ops.apply_triage([changed], doc)[1]["rejected"]), 1)
        kev = dict(f, kev=True)
        override["evidence_hash"] = ops.evidence_hash(kev)
        self.assertEqual(len(ops.apply_triage([kev], doc)[1]["rejected"]), 1)

    def test_unknown_coverage_and_invalid_review_visible(self):
        with tempfile.TemporaryDirectory() as out:
            write_json(os.path.join(out, "triage.json"), {})
            result = ops.export(out, [])
            self.assertEqual(result["coverage"]["status"], "unknown")
            self.assertTrue(result["triage"]["rejected"])
            self.assertEqual(result["counts"]["P0"], 0)

    def test_inventory_only_never_clean(self):
        with tempfile.TemporaryDirectory() as out:
            write_json(os.path.join(out, "coverage.json"), dict(schema_version=1, entries=[
                dict(target="server", name="host", component="packages", status="inventory-only", scope_complete=False)]))
            self.assertEqual(ops.coverage_summary(out)["status"], "partial")


if __name__ == "__main__":
    unittest.main()
