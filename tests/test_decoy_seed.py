import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "decoy" / "seed_decoy_filesystem.py"
spec = importlib.util.spec_from_file_location("seed_decoy_filesystem", SCRIPT)
seed_module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(seed_module)


class DecoySeedTests(unittest.TestCase):
    def test_seed_creates_expected_web_server_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dirs, files = seed_module.seed(root)
            self.assertGreater(dirs, 0)
            self.assertGreater(files, 0)
            self.assertTrue((root / "var/www/html/index.php").is_file())
            self.assertTrue((root / "etc/webapp/webapp.conf").is_file())
            self.assertTrue((root / "var/log/webapp/access.log").is_file())

    def test_rerun_does_not_overwrite_attacker_modified_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            seed_module.seed(root)
            target = root / "home/deploy/notes.txt"
            target.write_text("attacker-created change\n", encoding="utf-8")
            _, second_files = seed_module.seed(root)
            self.assertEqual(second_files, 0)
            self.assertEqual(target.read_text(encoding="utf-8"), "attacker-created change\n")

    def test_seed_contains_only_synthetic_placeholder_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            seed_module.seed(root)
            config = (root / "etc/webapp/webapp.conf").read_text(encoding="utf-8")
            self.assertIn("DECOY_ONLY_NOT_A_REAL_SECRET", config)
            self.assertNotIn("password123", config)


if __name__ == "__main__":
    unittest.main()
