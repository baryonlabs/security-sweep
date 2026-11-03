import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import coverage as cov
import inventory as inv
from _common import write_json, load_json

class CoverageTest(unittest.TestCase):
    def test_journal_and_finalize(self):
        with tempfile.TemporaryDirectory() as out:
            cov.initialize(out)
            cov.record(out, "project", "webapp", "/path/webapp", "osv-scanner", "scanned", "scan ok", scope_complete=True)
            doc = cov.finalize(out)
            self.assertEqual(doc["status"], "complete")
            self.assertEqual(doc["counts"]["scanned"], 1)
            manifest = load_json(os.path.join(out, "manifest.json"))
            self.assertEqual(manifest["schema_version"], 1)

    def test_partial_status_on_failure(self):
        with tempfile.TemporaryDirectory() as out:
            cov.initialize(out)
            cov.record(out, "server", "host1", "host1", "rootfs", "failed", "timeout", scope_complete=False)
            doc = cov.finalize(out)
            self.assertEqual(doc["status"], "partial")
            self.assertEqual(doc["counts"]["failed"], 1)

class InventoryTest(unittest.TestCase):
    def test_collect_mock_venv(self):
        with tempfile.TemporaryDirectory() as venv_dir:
            sp = os.path.join(venv_dir, "lib", "python3.10", "site-packages")
            dist = os.path.join(sp, "requests-2.28.1.dist-info")
            os.makedirs(dist)
            with open(os.path.join(dist, "METADATA"), "w") as f:
                f.write("Metadata-Version: 2.1\nName: requests\nVersion: 2.28.1\n")
            res = inv.collect_venv(venv_dir)
            self.assertEqual(res["status"], "inventory-only")
            self.assertEqual(len(res["packages"]), 1)
            self.assertEqual(res["packages"][0]["name"], "requests")
            self.assertEqual(res["packages"][0]["version"], "2.28.1")

    def test_import_inventory_offline(self):
        with tempfile.TemporaryDirectory() as out:
            doc = {
                "schema_version": 1,
                "host": "gpu-server",
                "collected_at": "2026-11-04T00:00:00Z",
                "environments": [{
                    "path": "/opt/venv",
                    "status": "inventory-only",
                    "ecosystem": "PyPI",
                    "packages": [{"name": "requests", "version": "2.28.1"}],
                    "errors": []
                }]
            }
            res = inv.import_inventory(doc, out, offline=True)
            self.assertEqual(res["entries"][0]["status"], "inventory-only")
            cov_doc = load_json(os.path.join(out, "inventory.coverage.json"))
            self.assertIn("entries", cov_doc)

if __name__ == "__main__":
    unittest.main()
