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

    def _needles(self, entries):
        import json
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        f = os.path.join(d, "n.json")
        with open(f, "w") as fh:
            json.dump({"needles": entries}, fh)
        return f

    def test_needles_file_drops_data_borne_secrets(self):
        import base64
        sec = "bt-Syn7h3tic-value-42"
        f = self._needles([{"name": "BURST_TEST_SECRET", "secret": sec},
                           {"name": "B64", "secret_b64": base64.b64encode(b"other-secret-9999").decode()},
                           {"name": "SHORT", "secret": "abc"}])
        ns = {"plain": {"a": sec}, "nested": {"x": [{"y": ("p", sec)}]},
              "enc": {"e": base64.b64encode(sec.encode()).decode()},
              "viaB64": ["other-secret-9999"], "ok": {"k": "harmless abc"}, "n": 3}
        with mock.patch.dict(os.environ, {"PRIME_AGENT_PLATFORM_NEEDLES_FILE": f}):
            _, path, manifest = self.snap(ns)
        blob = open(path, "rb").read()
        self.assertNotIn(sec.encode(), blob)
        self.assertNotIn(base64.b64encode(sec.encode()), blob)
        self.assertNotIn(b"other-secret-9999", blob)
        text = open(manifest).read()
        for kept in ('"ok"', '"n"'):
            self.assertIn(kept, text)
        for gone in ('"plain"', '"nested"', '"enc"', '"viaB64"'):
            self.assertIn(gone, text)  # listed under skipped only
        import json
        self.assertEqual(json.loads(text)["savedNames"], ["n", "ok"])

    def test_unreadable_needles_file_fails_closed(self):
        import json
        with mock.patch.dict(os.environ, {"PRIME_AGENT_PLATFORM_NEEDLES_FILE": "/nonexistent/needles.json"}):
            _, _, manifest = self.snap({"d": {"a": 1}, "n": 3})
        self.assertEqual(json.load(open(manifest))["savedNames"], ["n"])

    def test_snapshot_files_are_owner_only(self):
        _, path, manifest = self.snap({"n": 1})
        for p in (path, manifest):
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600, p)


if __name__ == "__main__":
    unittest.main()
