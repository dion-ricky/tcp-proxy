//! Shared pieces of the TCP tunnel: the wire protocol, shared-secret auth, and
//! the timing constants both binaries must agree on.

pub mod auth;
pub mod protocol;

use std::time::Duration;

/// How often the client pings the control channel.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// The server gives up on a tunnel after three missed heartbeats.
pub const HEARTBEAT_DEAD_AFTER: Duration = Duration::from_secs(45);

/// Upper bound for each step of the handshake (auth, then `Hello`).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
