"""PLATFORM-PATCH 13/14 tests: paperclip_api re-reads auth from os.environ on every call."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import paperclip_api  # noqa: E402


class HeadersTests(unittest.TestCase):
    def test_headers_follow_env_changes(self):
        with mock.patch.dict(os.environ, {"PAPERCLIP_API_KEY": "k1-test-value", "PAPERCLIP_RUN_ID": "run-1"}):
            h1 = paperclip_api.headers()
        with mock.patch.dict(os.environ, {"PAPERCLIP_API_KEY": "k2-test-value", "PAPERCLIP_RUN_ID": "run-2"}):
            h2 = paperclip_api.headers()
        self.assertNotEqual(h1, h2)
        self.assertIn("run-2", "".join(h2.values()))
        self.assertNotIn("run-1", "".join(h2.values()))

    def test_no_key_means_no_authorization(self):
        env = {k: v for k, v in os.environ.items() if k not in ("PAPERCLIP_API_KEY", "PAPERCLIP_RUN_ID")}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertNotIn("Authorization", paperclip_api.headers())


if __name__ == "__main__":
    unittest.main()
