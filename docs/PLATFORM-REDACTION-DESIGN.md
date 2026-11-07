# Platform patch 7: value-based secret redaction (DESIGN, for review)

Goal: no secret VALUE (plain, base64, URL-encoded) reaches a persisted or emitted byte: session transcript, logs, stdout JSONL.
Status: design only. No code yet.

## Needles
- Source: env vars whose NAME matches the shared filter (`platform_env_blocked`, plus the allowlisted keys that workers hold such as PAPERCLIP_API_KEY) and the optional needles file (one value per line, owner-only 0600, path from `PRIME_AGENT_PLATFORM_NEEDLES_FILE`).
- Minimum needle length: 8 bytes. Shorter values are ignored (too many false hits); this is logged once by name only.
- Encodings per needle: plain, standard base64, urlsafe base64 (each of the 3 byte alignments, unpadded prefix/suffix trimmed to the stable middle), percent-encoded, JSON-escaped.
- Never print or log a needle or any substring. Logs say `needles=<count>` only.

## Matching
- Aho-Corasick (one automaton, built once, rebuilt when the env/needles file changes) over UTF-8 bytes. Replacement: `[REDACTED:<NAME>]`; name only, never length.
- Chunk-split secrets: sinks that receive streamed fragments (stdout JSONL deltas, streamed assistant text) keep a rolling tail buffer of (max needle length - 1) bytes per stream. A fragment is released only after the tail is checked with the next chunk. At stream end the tail is flushed through the same matcher.

## Sinks (every sink goes through ONE function `redact_bytes(sink, bytes)`)
1. Session transcript (`session_store/write.rs` `persist_built_entry` / `append_entry`): redact the serialized JSON line before the append. Redact the string leaves, not the JSON structure, so escapes stay valid.
2. Logs (tracing writer layer): wrap the writer.
3. stdout JSONL in `--mode json` (`pa-cli` print runtime): wrap the stdout writer with the streaming (tail-buffer) variant.
4. Kernel stderr log files and tool-result text before it is stored.
(Provider request bodies are NOT redacted: the model needs them to work.)

## Fail closed
- If the needle source cannot be read or parsed, or the automaton cannot be built: the process refuses to persist transcripts/emit JSONL and exits with a clear error (no secret value in the message). A missing needles file that was never configured is NOT an error; a configured-but-unreadable one is.
- Matcher panics are caught at the sink: on any internal error the sink writes `[REDACTED:ERROR]` for that record instead of the raw bytes.

## Tests (each fails without the patch)
plain / base64 (3 alignments) / url-encoded / JSON-escaped hits; secret split across 2 and 3 chunks; needle length 7 ignored, 8 matched; every sink; unreadable needles file => refuse; matcher error => `[REDACTED:ERROR]`; no needle value in any log line.

## Known limits (stated up front)
- Hex, base32, gzip+base64 and other encodings are not in v1. The SE directive treats them as secrets too: ask whether v1 must include hex/base32 (cheap to add) before code.
- Secrets under 8 bytes are not covered.
- A secret the model transforms (reverses, splits with other text) is not detectable by value.
- The kernel can still read allowlisted env keys by design; redaction limits what is persisted, not what code can read.

## Questions for the reviewer
1. Add hex and base32 in v1? (recommended: yes)
2. Is min length 8 right?
3. Fail-closed = refuse to persist. Is a hard exit acceptable for a long-running daemon, or should it only block new sessions?
