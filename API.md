# Arrowmesh loopback API, v1

The contract is `openapi/arrowmesh-v1.yaml` (OpenAPI 3.1). The running daemon serves the same file
at `GET /v1/openapi.yaml`. A test fails if a served route is missing from the document or the
document names a route that is not served.

## Authenticate

Every request needs both:

1. **Host.** An IP literal, with or without a port, that is loopback or equal to the daemon's bind
   address (`chat_addr`). A name (`localhost` included), a missing Host or a repeated Host is
   `403` with an empty body. This is checked first, so a web page that rebinds a name to
   `127.0.0.1` gets nothing, token or not. Put the IP literal in the URL you connect to.
2. **Bearer token.** `Authorization: Bearer <token>`, where the token is the contents of the
   mode 600 `api-token` file that `arrowmesh install` writes. Missing or wrong is
   `401 {"error":"unauthorized"}`. A repeated Authorization header counts as absent.

The daemon logs no request body, no passphrase and no message text. Bodies over 1 MiB are `413`.

## Errors

JSON `{"error": "<short text>"}` with the status code. Two other shapes:

- Host refusal: `403`, empty body.
- Leak gate refusal: `403 {"blocked": true, "stage": "prompt" | "reply" | "text", "categories": [...]}`.
  Categories are names such as `personal:email`, never the matched text. Nothing was sent to the
  model or the peer (prompt, text) or shown to you (reply).

An empty `403` means Host; a `403` with `"blocked": true` means the gate. A `405` means the path
exists but not for that method.

## Chat and streaming

`POST /v1/chat` is one request, one gated reply, with `"gate": {"prompt": "pass", "reply": "pass"}`
in it: the gate sees the whole reply before any of it is shown. For a long reply send
`"async": true`, receive `202 {"job": n}`, and poll `GET /v1/chat/jobs/{n}` until `state` is
`done`; the job then carries the `status` and `result` the chat would have returned, once.

**Streaming (1.2).** Send `"stream": true` **and** `Accept: text/event-stream` to see the reply
while it is generated. Both are required (a `q=0` on the type, as in `text/event-stream;q=0`, refuses it and does not count): `"stream": true` alone, as an OpenAI style client sends it
by default, is the 1.1 request and gets the one JSON answer above (and `async` still works with it).
`stream` must be a boolean whatever the header says (`400` otherwise), and `stream` with `async` and
the header is `400`. Everything that can be refused before the model
answers (`423` sealed vault, `400`, `403` prompt gate, `413`, `429`, `502`) is still an ordinary
JSON answer with no event. Otherwise the answer is `200`, `Content-Type: text/event-stream`,
chunked, and a browser reads it with `fetch` and a reader (`EventSource` cannot POST). Each event
has an `event:` name, an `id:` counting up from 1 and one `data:` line holding one JSON object, so
reply text (always inside a JSON string) cannot forge an event. Lines starting with a colon are
keepalives.

| event | data | meaning |
|---|---|---|
| `delta` | `{"text": "..."}` | Released reply text, in order. Concatenate. |
| `held` | `{"chars": n}` | Characters held back for now. A count, never content. Show a typing indicator, never a box sized to `n`. |
| `blocked` | `{"blocked": true, "stage": "reply", "categories": [...]}` | Terminal. Discard everything shown. Nothing was stored. |
| `done` | the full ChatReply | Terminal. Its text equals the concatenated deltas. The exchange is now in the vault. |
| `error` | `{"error": "..."}` | Terminal. Discard everything shown. Nothing was stored (the vault was sealed mid stream, the model dropped, or the vault write failed). |

After an `error` event the vault history is the truth for what was stored: the exchange may be stored while the client saw `error`, so read the history before you retry or tell the user it was lost.

Exactly one terminal event ends a stream. A connection that ends with no terminal event is an
`error`: discard what was shown.

What is promised: every delta was, when released, a prefix of text that passed the rules scan, cut
at Unicode whitespace so no whitespace free run (a key, an email, a long number) is ever released
in part, and kept 64 characters behind the newest text so short multi word patterns (a card number
with spaces, a phone number, a key header) are caught before they are released. Once the reply so
far holds anything the gate decodes (an HTML numeric reference `&#`, a percent escape, a backslash
`u` or `x` escape, `xn--`, or a run of 16 or more base64 alphabet characters, which includes a 32
character hex run), nothing more is released until the whole reply has been checked, because
decoding can make the text the gate reads much longer than the text on the wire. Such a reply
shows its text late, all at once, at the end. The vault lock is checked immediately before every
`delta`, so a lock ends the stream with `error` and no further text. The model layer,
when on, runs once on the whole reply before `done`, and the final verdict is the one a
non streaming chat gives the same reply. What is not promised: a pattern that only the whole reply
shows (base64 split by spaces, many short high entropy runs, a personal sentence late in the reply)
can be shown first and withdrawn by `blocked`. That happens on the owner's own screen only. After
16 KiB of reply nothing more is released until the whole reply has been checked. At most two
streams run at once; a third is `429`. A stream that is not read for 30 seconds is dropped, a response write that makes no
progress for 10 seconds ends the response, and closing the connection closes the model's. A
stream's place is given back when its response has ended, not before. While a blocklist line is longer than the hold window,
or the blocklist cannot be read, `GET /v1/status` says `"streaming": false` and a streaming request is
`400`.

A peer never receives a stream. To send a streamed reply on, send the finished text with
`POST /v1/send` after `done`; it is gated again as a whole.

`GET /v1/status` also carries, since 1.2, `messages_received` (peer messages accepted since the
daemon started) and `gate_verdicts` (whole text gate verdicts since the daemon started). Both are
counts held in memory and zero after a restart; no content is stored for them.

`GET /v1/status` also carries, since 1.3, `model_keyed` (boolean, true when a bearer key is being
sent on upstream model calls; the key itself is never shown).

Config `llama_key_required` (default `false`). While `true`, a missing or unreadable `llama_key_file`
in attach mode (no `model_path`) refuses to start the daemon with one line and no unauthenticated
upstream call is ever made. While `false` and no key file exists, the daemon starts with a one line
warning (a standalone user attaching their own server). The tray sets it `true`.

## Peers and sends

`POST /v1/peers` saves a peer; it becomes active at the next daemon restart (`active: false`,
`restart_required: true` until then). `POST /v1/send` returns a `send_id`; `GET /v1/sends/{id}`
gives `delivered`, `failed` or `blocked`. The send log keeps the last 256 attempts in memory, metadata
only, and starts empty after a restart.

## Vault

**Locked start (v1.1).** `arrowmesh run` boots with the vault sealed and reads no passphrase from
the environment, a file or the command line. While locked, `POST /v1/chat` (sync and async),
`GET /v1/chat/jobs/{id}`, `POST /v1/send`, `GET /v1/history`, `GET /v1/vault/conversations` and
`GET /v1/vault/export` answer `423 {"error":"vault locked"}`, `GET /v1/status` reports
`vault_unlocked: false`, and the mesh listener closes incoming connections unanswered (a peer's send
fails until you unlock). Routes that need no key (`/v1/install`, `/v1/peers`, `/v1/gate/check`,
`/v1/sends`, `/v1/openapi.yaml`) keep working.

`POST /v1/vault/unlock {"passphrase": "..."}` unwraps the identity key and opens the vault. It never
echoes the passphrase. Every attempt, right or wrong, is counted in a 30 second window that opens at
the first counted attempt; the sixth attempt inside the window is refused with 429 until the window
ends, locked or not; a right passphrase resets the count. A `503` from this route means the key
unwrapped but this vault was not sealed by it (body `{"error":"key opened but this vault was not sealed by it"}`);
the vault stays sealed. `423` is used for the sealed state only.
When the daemon is already unlocked the route only re-checks the passphrase and changes no access.

`POST /v1/vault/lock` drops the unwrapped key (`200 {"locked": true}`, idempotent) and forgets every
chat job, running or finished. A request already running when the lock lands is discarded: it writes
no record, a sync chat answers `423`, and an async job is gone (`404`) after the next unlock.

`GET /v1/vault/export` is the sealed export: the vault's own ciphertext objects in hex, paged.
No plaintext leaves in it.

The last page of the export (`next` is null) also carries `head`: the sealed head record, hex
(null if the vault has none yet). The head is what lets a restore detect a cut tail.

### Restore from an export

1. Create an empty vault directory with a `r/` folder inside (mode 700 on the directory).
2. For every record on every page, write the decoded bytes of `object` to `r/<n>.obj`, where
   `<n>` is `n` as 16 lowercase hex digits (for example `r/0000000000000001.obj`), mode 600.
3. Decode the last page's `head` and write it to `head` in the vault directory, mode 600.
4. Start the daemon on that directory with the same identity key. A vault missing the head, or
   missing records the head counts, is refused on open; that is the check that the export was
   complete. An export whose last page was never fetched has no `head` and cannot be restored.
`send` answers 503 when the vault refuses a write: with nothing sent if refused before, or with
`"delivered": true` if the peer got the message but the owner's record could not be written.

## Versioning policy

- **/v1 is frozen.** A client written against it keeps working.
- **Only additive changes inside /v1** (1.1 added locked start and `POST /v1/vault/lock`; 1.2 added `stream` on chat, which needs `Accept: text/event-stream` as well so that a 1.1 request carrying `stream: true` is unchanged, and three status fields): new routes, new optional request fields, new response
  fields, new error `categories` and new enum values documented as open. Clients must ignore
  response fields they do not know.
- **Anything that removes or renames a route or field, changes a type, tightens validation of an
  existing field, or changes the meaning of a status code is `/v2`**, served beside `/v1` for at
  least one release.
- The document's `info.version` is the contract version (`1.x.y`); `GET /v1/status` returns
  `"api": "v1"`.
