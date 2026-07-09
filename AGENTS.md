# Review notes: memory footprint & correctness

Findings from reviewing `src/main.rs` (single-file websocketd daemon,
embedded gateway target). Kept here since this is a small crate without a
separate docs directory.

## Severe issues (fixed)

1. **Dead-connection leak** (`ws_sender`): the `Some(msgs) = rep_rx.recv()`
   select arm only fires on `Some`, so a closed `rep_rx` (client disconnected)
   silently disables that branch instead of ending the task. The sender task,
   its TLS stream, and its broadcast subscription lived until the next
   broadcast event failed to send. On a quiet bus, reconnecting clients would
   leak a full connection's worth of state per cycle.

2. **Auth bypass via suffix match**: `check_basic_auth` compared credentials
   with `credentials.ends_with(":{password}")`. Password `1234` matched any
   username containing `x:1234`, e.g. user `foo:x`, password `1234` — no,
   concretely: username `evil:x`, password field `1234` decodes to
   `evil:x:1234`, which `ends_with(":1234")`. Any credential string ending in
   the right password, regardless of the "username" portion, was accepted.
   Fixed to split on the first `:` and compare the password field exactly.

3. **Permanent IPC service death**: `run_req_service` returned from the task
   entirely if `sg_ipc::ReqService::new` failed once, dropping the request
   receiver. Every future WebSocket request routed to that service then got
   silently stuck (sender dropped, oneshot never resolves) until the whole
   daemon was restarted. Changed to reply with an error and keep looping.

## Memory optimizations (fixed)

- **Tungstenite buffer/message limits**: default `WebSocketConfig` reserves
  128 KiB read + 128 KiB write buffers per connection and allows messages up
  to 64 MiB / frames up to 16 MiB. On an embedded gateway this is both wasted
  steady-state memory per connection and an unbounded-allocation DoS surface.
  Configured explicit small buffers and message/frame caps in
  `run_ws_accept_loop`.
- **Broadcast payload**: `pub_tx` broadcast previously carried `Msg` (owned
  `HashMap`s), so N subscribers meant N deep clones of the parsed tree plus N
  redundant re-serializations back to JSON in each `ws_sender`. Switched the
  channel to carry `Arc<str>` of the already-serialized JSON — one parse in
  `run_sub_service`, one clone (Arc bump) per subscriber, no re-serialization.
- **Unnecessary clones**: `Msg::from_json` cloned the first element out of a
  parsed `Vec<Msg>` instead of moving it (`swap_remove(0)`); `to_json`
  allocated a `Vec` just to serialize a single-element array (now a stack
  slice); `run_req_service` cloned the outgoing request JSON solely to embed
  it in a rarely-hit error message (now moved, error message dropped the
  echo).
- **Payload passthrough**: the `payload` field is never inspected by
  websocketd — it's parsed into a `HashMap<String, Value>` tree and
  re-serialized untouched. Changed to `Box<RawValue>` (serde_json
  `raw_value` feature) so payload bytes pass through without being parsed
  into an object graph at all. `metadata` stays a `HashMap` since websocketd
  mutates it (inserts `source`/`error_source`).
- **Release profile**: added `strip = true` to shrink the binary, on top of
  the existing `lto = true`, `opt-level = "z"`, `codegen-units = 1`.
  Deliberately did *not* add `panic = "abort"`: `main()` relies on unwinding
  to catch per-task panics via `JoinSet::join_next` (a panicking task is
  logged and the daemon keeps running) — aborting would turn one bad task
  into a full daemon crash.

## Deferred (not memory-critical, left as-is)

- `run_req_service` opens a fresh `sg_ipc::ReqService` connection per
  request instead of reusing one — churn, not a leak.
- Auth comparison is not constant-time (timing side channel); low risk on a
  LAN-only gateway endpoint, flagged for awareness only.
