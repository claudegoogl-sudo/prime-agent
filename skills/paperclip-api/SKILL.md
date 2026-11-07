---
name: paperclip-api
description: Call the Paperclip API with auth read fresh from os.environ on every call. Use for all Paperclip comments and status changes so a resumed session never sends a stale API key or run id (agent_jwt_run_id_mismatch).
---

# paperclip_api

    status, body = paperclip_api.call("POST", f"/issues/{id}/comments", {"body": "..."})

Reads PAPERCLIP_API_URL, PAPERCLIP_API_KEY, PAPERCLIP_RUN_ID from `os.environ`
on EVERY call. Adds Authorization and X-Paperclip-Run-Id. Never cache headers
in kernel variables: the kernel survives across runs, the run id does not.
Returns (http_status, parsed_json_or_text). Never prints secrets.
