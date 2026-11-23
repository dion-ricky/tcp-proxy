# Build a bore-style TCP tunnel in Rust (tokio)

## Goal
Expose a local service (e.g. `localhost:3000`) through a public server: `server:PORT` -> client's `localhost:3000`, even when the client is behind NAT.

## Architecture
```
visitor --> server:PUBLIC_PORT        server:CONTROL_PORT <-- client --> localhost:3000
                  |                              ^
                  +---- "new connection, id" ----+   (control channel, signaling only)
```

Flow:
1. Client connects outbound to the server's control port.
2. Client sends `Hello` (the local port it wants to expose).
3. Server binds a public listener and replies with the assigned port.
4. A visitor connects to the public port; server stores the socket under a new ID and sends `Connection(id)` over the control channel.
5. Client opens a NEW connection to the server and sends `Accept(id)`, and also connects to the local service.
6. Server pairs the visitor socket with the client's new socket; bytes are copied both ways.

## Protocol
- Enum: `Hello`, `Connection(Uuid)`, `Accept(Uuid)`, `Heartbeat`, `Error`
- Newline-delimited JSON (`serde_json`), easy to debug with `nc`

## Crates
- `tokio` (net, io-util, time, macros, rt-multi-thread)
- `tokio-util` (codec: `LinesCodec`)
- `serde`, `serde_json`
- `uuid`
- `dashmap`
- `clap`
- `anyhow`, `tracing`

## Milestones

### 1. Dumb TCP forwarder
- [x] Listen on port A, forward each connection to address B
- [x] Use `tokio::spawn` per connection and `copy_bidirectional`
- [x] Test: local echo server + `nc`

> Done 2026-11-19. Verified with a Python echo server on `:8000`: 5 concurrent
> connections echoed correctly, a 2 MiB `urandom` transfer round-tripped
> byte-for-byte, and `SHUT_WR` half-close propagated cleanly.

### 2. Control channel
- [x] Server listens on the control port
- [x] Client connects, sends `Hello`, receives an assigned port
- [x] Server binds the public listener (no proxying yet)

### 3. Full proxy flow
- [x] `DashMap<Uuid, TcpStream>` of pending visitor connections
- [x] Visitor connects: store it, send `Connection(id)`
- [x] Client handles `Connection(id)`: dial server, send `Accept(id)`, dial local service, proxy
- [x] Server on `Accept(id)`: remove the pending stream, proxy

### 4. Hardening
- [x] Timeout on pending connections (`tokio::time::timeout`)
- [x] Heartbeats on the control channel
- [x] Cleanup when the client disconnects (drop the public listener, remove pending entries)
- [x] Shared-secret auth (challenge/response, e.g. HMAC)
- [x] Optional: request a specific public port, port range limits

> Verified 2026-11-23: 90s idle tunnel survives, `SIGSTOP`ed client reaped at
> 45s, parked visitor reaper fires at 30s, auth replay rejected on a fresh
> nonce, wrong secret allocates no port.
>
> Verified 2026-11-24: requested port honoured exactly, out-of-range and busy
> ports refused with a reason, 20 concurrent tunnels get distinct in-range
> ports, an exhausted range fails cleanly, and a client that predates
> `requested_port` still connects.

## Concepts to focus on
- **Framing:** TCP is a byte stream, not messages
- **Half-close / EOF:** what `shutdown()` on the write half means
- **Resource cleanup:** leaked listeners and map entries
- **Backpressure:** write your own copy loop once, then compare with `copy_bidirectional`
- **NAT:** why the client must dial out

## Testing checklist
- [ ] Echo server on the client side, `nc server PUBLIC_PORT` from another machine
- [x] Many concurrent visitors
- [x] Kill the client mid-transfer
- [x] Visitor connects but client never accepts (timeout fires)
- [x] Large transfer (e.g. `dd` into `nc`) to check data integrity

## After you finish
- Read bore's source: `github.com/ekzhang/bore`
- Compare with rathole (config files, multiple services, Noise encryption) and frp
- Next ideas: TLS, multiple tunnels per client, UDP, reconnect logic