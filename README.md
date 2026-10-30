# Arrowmesh

One binary, `arrowmesh`, that turns a Linux box into a private assistant host. Version 0.1.

- **Model.** Launches and supervises a local llama.cpp server bound to `127.0.0.1`, or attaches to one already running.
- **Gate.** A loopback chat endpoint. Every outgoing prompt, and every model reply, is scanned by
  [arrowmem-gate](../arrowmem-gate) before it moves on. Fails closed.
- **Vault.** Conversations are stored as sealed objects (arrowmem-core `seal` and `open`), one 1114-byte file per record. The identity key that opens them is wrapped at rest under a passphrase.
- **Mesh.** Sealed messages between two boxes on one LAN, using arrowmem-core's envelope. Peers come from a static list in the config.
- **Install.** `arrowmesh install` writes a systemd user unit, a config skeleton and an identity key.

Licence: Apache-2.0.

## The no-internet claim, exactly as tested

Every socket this program opens or binds goes through one function in `src/net.rs`. That function refuses an address
unless it is an IP literal that is loopback (`127.0.0.0/8`, `::1`) or RFC1918 (`10/8`, `172.16/12`, `192.168/16`).
Hostnames are refused and never resolved, so arrowmesh itself makes no DNS query. The same rule is applied to every address in the config when it is loaded.

What the tests hold:

- `net::tests::allowed_classes` and `refused_classes`: the accepted and refused address classes, including `0.0.0.0`, link-local, CGNAT, IPv6 ULA and link-local, IPv4-mapped IPv6, and hostnames.
- `net::tests::connect_and_listen_recheck`: `connect` and `listen` refuse a public address even if a caller skips the parse step.
- `config::tests::refuses_public_and_hostnames`, `peer_checks`: a config naming such an address does not load.
- `only_net_rs_opens_sockets` (tests/two_boxes.rs): no other file in `src/` contains a direct socket entry point.

What is **not** tested, so not claimed:

- That the arrowmem-gate crate, which arrowmesh links, makes no other connection. Its model layer is loopback-only by its own rules, but its crate also carries an HTTPS client for its separate proxy mode; arrowmesh never calls that mode.
- Kernel-level enforcement. The installed unit sets `IPAddressDeny=any` with an allow list for loopback and RFC1918, as a second layer. **UNVERIFIED:** whether systemd enforces `IPAddressDeny` in a user unit has not been checked here, so nothing in this README relies on it.
- Anything about the llama.cpp binary or the model you run. Run it on a box with no route out if that matters to you.

## What the gate is, and is not

A control, not a guarantee. The rules layer is regex plus checks; the optional model layer (`gate_model = true`) asks the local model for a verdict. Read arrowmem-gate's own README for what it misses
(its rules layer can be bypassed by encoding, and its model layer can be steered by the text it reads). A pass means "nothing this gate knows how to see".

- Both layers fail closed: a scan that errors, panics, or cannot reach its model refuses the text.
- A refusal returns HTTP 403 with category names only, never the matched text.
- A refused prompt is never sent to the model and never stored. A refused reply is never delivered and never stored.
- Messages are rebuilt from `role` and `content` only before forwarding, so no unscanned field travels to the model.
- Outgoing peer messages go through the same gate.

## Install

```
cargo build --release
./target/release/arrowmesh install     # unit, config skeleton, passphrase-wrapped identity key, API token file (both mode 600). Never overwrites.
$EDITOR ~/.config/arrowmesh/config     # set model_path, or leave it out to attach to a running llama.cpp
systemctl --user daemon-reload && systemctl --user enable --now arrowmesh
arrowmesh status
```

`arrowmesh pubkeys` prints this box's signing and sealing keys. To pair two boxes, put each one's line in the other's config:

```
peer = "name 192.168.1.20:8090 <signing key hex> <sealing key hex>"
mesh_listen = 192.168.1.10:8090
```

`arrowmesh status` prints yes/no and counts only: model up, gate up, vault unlocked (record count), peers reachable (count). Exit 0 only if all are up.

### Loopback API (port from `chat_addr`, default 127.0.0.1:8088)

```
POST /v1/chat     {"conv":"name","messages":[{"role":"user","content":"..."}]}
POST /v1/send     {"peer":"name","text":"..."}      (one sealed object: at most 885 bytes)
GET  /v1/history?conv=name
GET  /v1/status
```

**Fixed (M1).** Every request must carry an `Authorization` header with the token from `token_file` (default
`~/.local/share/arrowmesh/api-token`, 32 random bytes as hex, written by `install` with mode 600; the daemon refuses to
start if the file is missing, shorter than 64 characters, or readable by group or others). The comparison is constant
time (`subtle`). The `Host` header must be an IP literal that is loopback or equal to the bind address, otherwise the
reply is 403 with an empty body; a name such as `localhost` or `evil.example` is refused, which is the DNS-rebinding shape.
A missing or wrong token is 401. The Host check runs first. A header sent twice counts as absent.
Tests: `m1_no_credential_and_a_wrong_credential_are_401`, `m1_wrong_host_and_the_dns_rebinding_shape_are_403_with_no_body`,
`m1_daemon_refuses_to_start_with_a_loose_or_missing_token_file`.

Limits of M1: the token is a bearer credential in a file the user can read, so any process running as the same user
can read it and use the API; this stops web pages and other users, not other processes of the same user. The port is not
checked in `Host`. There is no TLS (loopback). The token is not rotated automatically; delete the file and run `install` to mint a new one.

## What the vault stores

Each record is sealed to this box's own sealing key and signed by its own signing key. File names are sequence numbers, so the count and order of records are visible on disk. Content, conversation names and kinds are not.

**Fixed (M3), with limits.** `read` checks the whole vault, not just the conversation asked for. It refuses: a file whose name differs
from the counter sealed inside it (copies, renames, swaps, reordering); a gap in the numbering or numbering that does not start at 1
(a deleted record anywhere but the end); chunks that do not continue one message (same message id, kind, total and conversation, index up by one).
**Head record.** `<vault>/head` is one arrowmem-core sealed object (to and from this box) holding the last record number and a chain value, chain(k) = `content_id`(chain(k-1) || `content_id`(record k)), rewritten after every record. A read or an append refuses a vault with fewer records than the head says (deleted from the end), a chain that differs at the head's number (a record changed, swapped or reordered), or records but no head. A crash between a record and its head leaves records past the head; they are accepted and the next append re-seals the head over them. Not detected: restoring an old head together with the matching old records (whole-vault rollback), wiping the whole vault, and anything an attacker who holds the identity key can forge. A vault written before the head record existed is refused with "head record missing"; v0.1 has not shipped, so there is no migration.
A half-written long message left by a crash is dropped, not fatal. Tests: the `m3_*` tests in `src/vault.rs`.

## What v0.1 does not do

- **Identity key at rest (M2).** Wrapped with Argon2id (RFC 9106 second recommended cost: 64 MiB, 3 passes, 4 lanes; `argon2` crate; a key file whose cost is below that in any of the three is refused at load) and AES-256-GCM (`aes-gcm` crate), with the header authenticated. The daemon (`arrowmesh run`) starts locked and reads no passphrase from the environment, a file or argv: the app sends it to `POST /v1/vault/unlock` over loopback and can seal it again with `POST /v1/vault/lock`. The one-shot commands (`install`, `pubkeys`, `status`) still take it from `ARROWMESH_PASSPHRASE` or a terminal prompt, never a config file. `arrowmesh status` reports the vault locked when no passphrase is offered or it is wrong. Limits: the passphrase is only as strong as you make it; an environment variable is readable by processes of the same user (`/proc/<pid>/environ`); the daemon keeps the passphrase for the unwrap only (it is not stored in the running daemon, it is held for the duration of one unlock request in this process's memory, and `status` does not re-run Argon2id), holds the unwrapped keys in memory while it runs, does not lock the memory, and zeroizes the signing key on drop (checked by type); the sealing key's erasure on drop is not proven by its type; there is no forward secrecy on the mesh (HPKE base mode, static key), so a stolen unwrapped key reads past traffic that was captured. A plain-text key file from the first v0.1 build is refused, not migrated. The daemon no longer needs an unattended passphrase: under systemd it comes up locked and waits for the app, so `Restart=on-failure` does not loop. While locked, the mesh listener closes connections unanswered, so a peer's message sent in that window is lost, not queued. `systemctl --user set-environment` is not recommended: the user manager's environment is readable by every process of that user.

- **Counter and replay files (M4).** Written to a temp file, fsynced, renamed, then the directory fsynced; stale temp files are removed on start. A crash leaves the old file or the new one. A file already torn by an older non-atomic writer is still refused at start (fail closed), as is a missing-but-malformed one. **A deleted send counter restarts at 1 and every peer refuses this box as too old until the number passes; there is no recovery for that beyond restoring the file.** A deleted replay file re-opens that peer's window (the first object sets it again). The vault is written before the replay file, so a crash between the two can store a message twice.
- **No discovery.** Peers are a static list. No mDNS, no BLE, no relay, no carry.
- **No pairing flow.** Keys are exchanged by you, by hand. arrowmem-core's admission, invite and intro machinery is not used.
- **The mesh transport is plain TCP carrying sealed objects.** The envelope hides content; it does not hide who connects to whom from the LAN.
- **A new peer's first object sets its replay window** at that object's counter. Replay state lives in `<vault>/mesh/`; losing it re-opens that window.
- **No TLS** (not needed on loopback; not provided on the LAN), no multi-user.
- **Not tested on a real llama.cpp.** The tests use a stand-in server that answers `/health` and `/v1/chat/completions`.
- **Linux only.** systemd user unit; Unix file modes.

## Mesh receiver limits (M5)

Each inbound mesh connection is served on its own thread under a 3 second total deadline (a peer that drips bytes cannot extend it), at most 8 at once; the ninth is closed without an answer. Tests: the `m5_*` tests in `tests/two_boxes.rs`.

## Tests

```
cargo test
cargo clippy --all-targets -- -D warnings
```

Depends on `../arrowmem-core` and `../arrowmem-gate` by path. `serde_json` is pinned to `=1.0.140`, the same exact pin arrowmem-gate uses, so one copy is built. `argon2`, `aes-gcm`, `subtle` and `rpassword` are pinned with `=`, and `crypto-bigint` is held at 0.7.9 in `Cargo.lock`.
