"""Paperclip API client; auth is re-read from os.environ on every call."""
from __future__ import annotations
import json, os, urllib.request, urllib.error


def headers() -> dict:
    h = {"Content-Type": "application/json"}
    key = os.environ.get("PAPERCLIP_API_KEY", "")
    if key:
        h["Authorization"] = f"Bearer {key}"
    run = os.environ.get("PAPERCLIP_RUN_ID", "")
    if run:
        h["X-Paperclip-Run-Id"] = run
    return h


def call(method: str, path: str, json_body=None, timeout: float = 30):
    base = os.environ.get("PAPERCLIP_API_URL", "http://127.0.0.1:3100/api").rstrip("/")
    if not base.endswith("/api"):
        base += "/api"
    data = None if json_body is None else json.dumps(json_body).encode()
    req = urllib.request.Request(base + "/" + path.lstrip("/"), data=data, method=method.upper(), headers=headers())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read().decode()
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw


async def run(method: str, path: str, json: object = None):
    return call(method, path, json)
