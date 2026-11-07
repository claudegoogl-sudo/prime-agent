"""PLATFORM-PATCH 8/9 tests: snapshot drops secret variables; snapshot files are owner-only."""
import os
import stat
import tempfile
import unittest
from unittest import mock

from rlm import repl


class PlatformSnapshotTests(unittest.TestCase):
    def snap(self, ns):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        path = os.path.join(tmp, "kernel-state.dill")
        manifest = os.path.join(tmp, "kernel-state.json")
        result = repl._snapshot_state(ns, path, manifest, 1 << 20, 1 << 20, False)
        self.assertNotIn("error", result)
        return result, path, manifest

    def test_name_rule_is_narrow(self):
        for n in ["api_key", "MY_TOKEN", "password", "db_passwd", "API_KEY", "client_secret"]:
            self.assertTrue(repl._platform_secret_name(n), n)
        for n in ["key", "author", "keyboard", "tokens", "monkey", "keys", "x"]:
            self.assertFalse(repl._platform_secret_name(n), n)

    def test_secret_vars_are_dropped_and_others_kept(self):
        with mock.patch.dict(os.environ, {"PLAT_TEST_TOKEN": "s3cr3t-value-123"}):
            ns = {"api_key": "abc", "author": "me", "key": "k", "leaked": "x-s3cr3t-value-123-y", "n": 5}
            result, path, manifest = self.snap(ns)
        with open(path, "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"s3cr3t-value-123", blob)
        self.assertNotIn(b"abc", blob.replace(b"abcdefg", b""))
        with open(manifest) as mf:
            text = mf.read()
        for kept in ("author", '"key"', '"n"'):
            self.assertIn(kept, text)

        self.assertIn("secret variable", text)

    def test_snapshot_files_are_owner_only(self):
        _, path, manifest = self.snap({"n": 1})
        for p in (path, manifest):
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600, p)


if __name__ == "__main__":
    unittest.main()
