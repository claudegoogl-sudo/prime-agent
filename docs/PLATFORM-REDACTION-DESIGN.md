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

## Reviewer verdict applied (approve with conditions)
- Encodings in v1: plain, percent (upper/lower), JSON-escaped (with and without `\/`, with `\uXXXX`), hex lower+upper, base64 std+urlsafe at 3 explicit alignments (pad 0,1,2), base32 at 5 alignments (pad 0..4; padded/unpadded share the same stable middle). gzip+base64 is a known limit.
- Min length: needles from filter-named env vars and the needles file need length >= 4; a shorter value makes the build FAIL (refuse), never a silent skip. Error names the needle by sanitized name only.
- Fail closed: no hard exit of a running daemon. New sessions and new sink writes are blocked; live sessions write `[REDACTED:ERROR]` per record and stop persisting raw bytes; one name-free error + a health flag. Exit only for bad startup config.
- R1: redact decoded string leaves AND run a second pass over the final serialized line before append.
- R2: alignments explicit and tested (module `pa_types::redact`, tests for std/url base64 and base32).
- R3: rolling tail is per stream AND per sink. Held bytes are never released raw: dropping the stream (error, cancel, panic, signal) discards them; only `finish()` flushes, redacted. Signal handlers drop the streams.
- R4: matcher is immutable; rebuild swaps an `Arc<Redactor>` atomically; on rebuild failure keep the old one and set the fail-closed flag.
- R5: needles file: fstat on the open fd (mode 0600, owner = euid), refuse symlinks (O_NOFOLLOW), cap size (64 KiB) and lines (256).
- R6: marker name = env var name or file line index, charset `[A-Za-z0-9_-]`, max 64 (implemented).
- R7: leftmost-longest (implemented + tested).
- R8: extra sinks: tool-result text, kernel stderr, panic messages and error chains, crash dumps, debug/trace files. An end-to-end test greps every file written in a full run for all needle encodings.
- R9: provider request bodies are not redacted; provider RESPONSES echoed back are sinks and are redacted.
- R10: each sink regression test must fail on unpatched code.

## Status
- Done: `pa_types::redact` (variants, Redactor, StreamRedactor) with unit tests.
- Next: needle loading (env + file, R5), sink wiring (transcript R1, logs, stdout JSONL, tool results, kernel stderr), fail-closed flag, e2e grep test.
