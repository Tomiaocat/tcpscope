# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`tcpscope` (了不起的 TCP) is a zero-dependency Go binary that serves a browser teaching lab for TCP/TLS/HTTP/WebSocket. Everything ships in one executable: the whole frontend is a single `awesome_tcp.html` embedded with `//go:embed`. No third-party modules — `go.mod` has no `require` block, and adding one should be treated as a significant design decision.

Module name is `awesome_tcp` (not the repo name), `package main` throughout.

## Commands

```bash
go build -ldflags="-s -w" -o awesome_tcp .   # build (./build.sh and build.bat do this + launch)
go test ./...                                 # full test suite
go test -run TestWSFrameRoundTrip ./...       # single test
go vet ./...
CGO_ENABLED=1 go test -race ./...             # needs gcc; `gcc` is not on PATH on this Windows box
```

On this machine Go is not on `PATH`; a toolchain lives at `~/tools/go/bin/go.exe`
(add it to `PATH` for the session: `$env:PATH = "$env:USERPROFILE\tools\go\bin;" + $env:PATH`).

Run with flags from `config.go`: `-mode stack|legacy`, `-tls`, `-control`, `-demo`, `-data-dir`, `-cert`/`-key`, `-max-sessions`, `-open=false`.

Two entry modes share `main()` in `awesome_tcp.go`:
- `-mode stack` (default) → `NewLab(cfg).Run()` — the real HTTP/WS/TLS lab on ports 19527 (control) and 9527 (demo).
- `-mode legacy` → `runLegacy()` — the original self-contained raw-TCP teaching engine (`AwesomeTCPEngine`), single connection, its own `/api/*` routes on 19527. Nothing else in the repo depends on it; treat it as frozen.

## Architecture

Two HTTP servers with deliberately different security/lifecycle rules:

- **Control plane** (`lab.go` → `controlMux`, handlers in `lab_control.go`). Always plaintext, serves the embedded UI at `/`, exposes `/api/*`. All HTTP methods are strictly checked via `requireMethod`, bodies via `readJSONLimited`, errors via `writeError` with a stable `code` string.
- **Demo plane** (`lab.go` → `demoMux`, routes in `lab_http.go`). Handles the *real* protocol traffic at `/demo/*`. This is the only listener affected by the TLS switch. It sets `TLSNextProto` to an empty map — HTTP/2 disables hijacking, and WebSocket needs HTTP/1.1.

The UI drives everything through the control plane; the control plane then acts as a *client* against its own demo plane (`/api/demo/http`, `/api/demo/ws/open`, `/api/demo/journey`). So every interaction produces **two sessions — a server-side one and a client-side one** — which the UI shows side by side. When adding a demo route, remember the mirrored client path in `lab_http.go`/`lab_ws.go`.

### TLS switch (`Lab.switchTLS` in `lab.go`)

Not cosmetic. It stops the demo listener, flips `TLSManager`, and rebinds on the same address as a `tls.Listener`, rolling back and publishing `tls.switch_failed` if the rebind fails. `switchMu` + `errSwitchBusy` (mapped to HTTP 409) serialize the operation; `tlsMgr.State()` reports `on|off|switching_on|switching_off|error`. Switching always closes demo sessions — that's the honest behavior, and the UI tells the user so.

TLS records are observed on the wire by wrapping accepted/outgoing connections (`tlsRecordingListener` / `recordingConn` in `lab.go`): raw bytes are parsed into 5-byte record headers *before* `crypto/tls` consumes them, and published as `tls.record` events. The server side wraps in `Accept`; the client side wraps in `newLabTransport`'s `DialTLSContext`.

### The reveal gate — central invariant

"Reveal" is the teacher's switch between the **wire view** (nothing decryptable) and the **endpoint view** (plaintext the application already holds). It is enforced on the server, not by CSS:

- `Event.Sanitize(reveal)` (`sessions.go`) nils `Plaintext` whenever `reveal` is false. Every serialization path must call it — `/api/events`, `/api/ws`, `/api/sessions/{id}`, `handleDemoHTTP`.
- `Session.Detail` additionally blanks frame payload/raw hex for TLS-transport sessions when reveal is off.
- `handleDemoHTTP` returns only sizes with `"masked": true` when the request is TLS and `reveal` was not requested.
- Docs/journal traces are gated in `lab_journey.go`.

`reveal` defaults to *off*, and the frontend's `effectiveReveal()` (in `awesome_tcp.html`) treats plaintext transport as always-revealed. Any new field carrying payload bytes needs to go through this gate.

### Sessions and events (`sessions.go`)

- `SessionRegistry` caps live sessions (`-max-sessions`); over the cap it evicts the oldest by `lastAt`. A 30s janitor (`Lab.runJanitor`) closes idle sessions (2 min HTTP / 5 min WS). Each `Session` keeps bounded ring buffers (`maxSessionEvents` / `maxSessionFrames` = 500) and a `closeFn` the owning handler installs so external closes (API, eviction, timeout) actually tear down the socket.
- `EventBus` is the fan-out: a bounded ring (2000) for `Since(seq)` catch-up plus per-subscriber channels (buffer 256). Slow subscribers are dropped, never blocked — the UI recovers with `since=`. Every event carries a monotonically increasing `Seq`; that's the resume cursor for both `/api/events` and `/api/ws?since=`.
- Events come in two views: `View: "wire"` (TLS records, handshakes) and `View: "endpoint"` (HTTP, WS, TCP) — the UI renders them in separate columns. Keep that distinction when publishing.

### TCP frame reconstruction (`FrameRecord`, `buildFrame`)

Frames are **synthesized from real application byte streams**, not captured off the kernel. `buildFrame` calls `BuildRawTCPHeaderAndChecksum` (`awesome_tcp.go`, RFC 9293 big-endian header + pseudo-header checksum) and sets `Reconstructed: true`. Sequence numbers are arbitrary teaching values.

The two ports are taken from the live connection rather than invented:

- HTTP: `newLabTransport` wraps `DialContext`/`DialTLSContext` to record the ephemeral client port in an `atomic.Uint32` (keep-alives are disabled, so one connection per request).
- WS: `handleDemoWS` / `handleDemoWSOpen` call `Session.SetConn`, and `wsFramePorts` reads the client port back via `liveConn()`.

If a port can't be determined it stays `0`, which reads as "unknown" — never substitute a placeholder. `buildFrame`'s signature is `(srcPort, dstPort)`, so frame orientation must follow `direction` (C2S = client→server); getting this backwards is easy and `TestWSFramesUseRealClientPort` guards it.

### WebSocket (`ws.go`)

Hand-rolled RFC 6455, used for both directions: `Upgrade` (hijacks the `http.ResponseWriter`) and `Dial`/`upgradeClient` (also used for HTTP→WS upgrade on an already-open conn, see `lab_journey.go`). Frame codec enforces masking direction (server rejects unmasked client frames and vice versa), control-frame rules, fragmentation, and UTF-8 validity for text. `ReadMessage` handles ping/pong transparently and returns `*WSCloseError` on close. `defaultOriginCheck` allows loopback origins on port 19527 and non-browser clients (no `Origin` header).

`/api/demo/journey` (`lab_journey.go`) is the one place that walks TCP → optional TLS → HTTP → WS upgrade on a single raw connection using `Request.Write`/`http.ReadResponse`/`upgradeClient`, so the UI can replay a genuine layered trace.

### Certificates (`certs.go`)

`TLSManager` owns an ECDSA P-256 self-signed cert (SANs `127.0.0.1`, `::1`, `localhost`), generated on first run into `-data-dir` (default `%AppData%\tcpscope` / `~/.config/tcpscope`), private key `0600`. `ClientConfig()` trusts that cert explicitly, which is how the lab's own HTTP/WS clients verify themselves without touching the system trust store. `InfoFromState` reports the local cert on the server side (there is no peer cert there). Generated PEMs and `.key` files are gitignored — never commit them.

## Conventions worth keeping

- UI text and log messages are Simplified Chinese; code identifiers, comments and this file are English.
- JSON responses use `{"ok": bool, ...}` and errors use `{"ok": false, "error": ..., "code": ...}`; the frontend's `api()` helper throws on either.
- Both muxes are wrapped in `withSecurityHeaders`; JSON responses set `Cache-Control: no-store`.
- `safeHeaders` redacts `Authorization` and `Cookie` — extend it if new credential-bearing headers appear.
- Listeners bind to loopback only. Do not introduce an option to bind externally.

## Testing notes

`lab_test.go` is the whole suite (no build tags, no external test deps). It starts real listeners on `127.0.0.1:0` and uses `t.TempDir()` for certs, so tests are hermetic and parallel-safe. Coverage: cert SANs/persistence, WS frame round-trip over `net.Pipe`, `Event.Sanitize`, registry cap, TLS switch + HTTP round-trip, the reveal gate over the control plane, and the reconstructed-frame ports/orientation for both HTTP and WS. New behavior on the reveal path or the TLS switch should get a test here — those are the two invariants the project exists to demonstrate.
