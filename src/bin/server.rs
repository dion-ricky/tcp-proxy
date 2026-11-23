use std::{sync::Arc, time::Duration};

use anyhow::{Context, bail};
use clap::Parser;
use dashmap::DashMap;
use tcp_proxy::{
    HANDSHAKE_TIMEOUT, HEARTBEAT_DEAD_AFTER, auth,
    protocol::{HelloKind, Message, MessageStream, recv, send},
};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    time::{Instant, sleep, sleep_until, timeout},
};
use tokio_util::codec::LinesCodec;
use uuid::Uuid;

/// How long a visitor may sit unclaimed before it is dropped.
const PENDING_TIMEOUT: Duration = Duration::from_secs(30);

/// Visitor sockets waiting for a client to claim them with `Accept(id)`.
type Pending = Arc<DashMap<Uuid, TcpStream>>;

/// One event in a tunnel's event loop.
enum Ev {
    /// A control message arrived, or the channel closed (`None`).
    Msg(Option<Message>),
    /// A visitor connected to the tunnel's public port.
    Visitor(TcpStream),
    /// The client missed too many heartbeats.
    Dead,
}

/// Removes this tunnel's still-parked visitors when the tunnel ends, however
/// it ends: `break`, `?`, early return, or panic.
struct PendingGuard {
    pending: Pending,
    ids: Vec<Uuid>,
}

impl PendingGuard {
    fn new(pending: Pending) -> Self {
        Self {
            pending,
            ids: Vec::new(),
        }
    }

    fn track(&mut self, id: Uuid) {
        self.ids.push(id);
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        for id in &self.ids {
            if self.pending.remove(id).is_some() {
                println!("releasing parked visitor {id}");
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PortRange {
    min: u16,
    max: u16,
}

impl std::str::FromStr for PortRange {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (min, max) = s
            .split_once('-')
            .context("expected MIN-MAX, e.g. 20000-30000")?;
        let min: u16 = min.parse().context("invalid minimum port")?;
        let max: u16 = max.parse().context("invalid maximum port")?;
        anyhow::ensure!(min > 0 && min <= max, "invalid port range {min}-{max}");
        Ok(Self { min, max })
    }
}

#[derive(Parser)]
struct Args {
    /// Address the control port listens on
    #[arg(long, default_value = "0.0.0.0:7887")]
    bind: String,

    /// Shared secret clients must authenticate with
    #[arg(long, env = "TCP_PROXY_SECRET")]
    secret: String,

    /// Allowed public port range
    #[arg(long, default_value = "20000-30000")]
    port_range: PortRange,
}

#[derive(Clone)]
struct Ctx {
    pending: Pending,
    secret: Arc<String>,
    port_range: PortRange,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Args {
        bind,
        secret,
        port_range,
    } = Args::parse();
    let ctx = Ctx {
        pending: Pending::default(),
        secret: Arc::new(secret),
        port_range,
    };

    let listener = TcpListener::bind(&bind).await?;
    println!("Listening on {bind}");

    loop {
        let (stream, addr) = listener.accept().await?;
        let ctx = ctx.clone();
        println!("Accepted connection from {addr}");

        tokio::spawn(async move {
            if let Err(err) = handle_control(stream, ctx).await {
                eprintln!("control connection failed: {err:#}");
            }
        });
    }
}

async fn handle_control(stream: TcpStream, ctx: Ctx) -> anyhow::Result<()> {
    let mut control = MessageStream::new(stream, LinesCodec::new());

    if !authenticate(&mut control, ctx.secret.as_str()).await? {
        eprintln!("authentication failed");
        return Ok(());
    }

    let first = match timeout(HANDSHAKE_TIMEOUT, recv(&mut control)).await {
        Err(_) => bail!("handshake timed out after {HANDSHAKE_TIMEOUT:?}"),
        Ok(msg) => msg?,
    };

    match first {
        Some(Message::Hello(HelloKind::Control {
            local_port,
            requested_port,
        })) => run_tunnel(control, local_port, requested_port, ctx).await,
        Some(Message::Accept { id }) => handle_accept(control, id, ctx.pending).await,
        Some(other) => bail!("unexpected first message: {other:?}"),
        None => Ok(()),
    }
}

/// Sends a fresh challenge and checks the client's response against it.
///
/// Returns `false` when the mac does not match; the caller drops the
/// connection without telling the peer why, so a wrong secret is
/// indistinguishable from a malformed handshake.
async fn authenticate(control: &mut MessageStream, secret: &str) -> anyhow::Result<bool> {
    let nonce = Uuid::new_v4().to_string();
    send(
        control,
        &Message::Challenge {
            nonce: nonce.clone(),
        },
    )
    .await?;

    let reply = match timeout(HANDSHAKE_TIMEOUT, recv(control)).await {
        Err(_) => bail!("auth timed out after {HANDSHAKE_TIMEOUT:?}"),
        Ok(msg) => msg?,
    };

    let Some(Message::Authenticate { mac }) = reply else {
        bail!("expected authenticate, got {reply:?}");
    };

    auth::verify(secret, &nonce, &mac)
}

async fn run_tunnel(
    mut control: MessageStream,
    local_port: u16,
    requested_port: Option<u16>,
    ctx: Ctx,
) -> anyhow::Result<()> {
    let mut guard = PendingGuard::new(Arc::clone(&ctx.pending));

    let listener = match bind_public(ctx.port_range, requested_port).await {
        Ok(listener) => listener,
        Err(err) => {
            let message = format!("{err:#}");
            let _ = send(
                &mut control,
                &Message::Error {
                    message: message.clone(),
                },
            )
            .await;
            bail!("{message}");
        }
    };
    let public_port = listener.local_addr()?.port();

    send(
        &mut control,
        &Message::Hello(HelloKind::Response { port: public_port }),
    )
    .await?;
    println!("local port {local_port} is public on {public_port}");

    let mut deadline = next_deadline();

    loop {
        let ev = tokio::select! {
            m = recv(&mut control) => Ev::Msg(m?),
            a = listener.accept() => Ev::Visitor(a?.0),
            _ = sleep_until(deadline) => Ev::Dead,
        };

        match ev {
            Ev::Msg(None) => break,

            Ev::Msg(Some(Message::Heartbeat)) => deadline = next_deadline(),

            Ev::Msg(Some(other)) => {
                deadline = next_deadline();
                println!("ignoring {other:?}");
            }

            Ev::Visitor(visitor) => {
                let id = Uuid::new_v4();
                ctx.pending.insert(id, visitor);
                guard.track(id);

                let reaper = Arc::clone(&ctx.pending);
                tokio::spawn(async move {
                    sleep(PENDING_TIMEOUT).await;
                    if reaper.remove(&id).is_some() {
                        println!("visitor {id} timed out, dropping");
                    }
                });

                send(&mut control, &Message::Connection { id }).await?;
            }

            Ev::Dead => {
                println!("client heartbeat timeout");
                break;
            }
        }
    }

    Ok(())
}

async fn bind_public(range: PortRange, requested: Option<u16>) -> anyhow::Result<TcpListener> {
    if let Some(port) = requested {
        anyhow::ensure!(
            (range.min..=range.max).contains(&port),
            "requested port {port} is outside the allowed range {}-{}",
            range.min,
            range.max
        );
        return TcpListener::bind(("0.0.0.0", port))
            .await
            .with_context(|| format!("public port {port} is unavailable"));
    }

    let span = range.max - range.min + 1;
    let start = Uuid::new_v4().as_u128() as u16 % span;

    for offset in 0..span.min(200) {
        let port = range.min + (start + offset) % span;
        match TcpListener::bind(("0.0.0.0", port)).await {
            Ok(listener) => return Ok(listener),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(err) => return Err(err).with_context(|| format!("binding public port {port}")),
        }
    }

    bail!("no free port in range {}-{}", range.min, range.max)
}

/// Deadline for the next heartbeat, refreshed on every control message.
fn next_deadline() -> Instant {
    Instant::now() + HEARTBEAT_DEAD_AFTER
}

async fn handle_accept(
    mut stream: MessageStream,
    id: Uuid,
    pending: Pending,
) -> anyhow::Result<()> {
    let Some((_, mut visitor)) = pending.remove(&id) else {
        let _ = send(
            &mut stream,
            &Message::Error {
                message: format!("unknown id {id}"),
            },
        )
        .await;
        bail!("no pending visitor for {id}");
    };

    // The client may already have forwarded bytes for this visitor. They are
    // sitting in the codec's read buffer, so flush them before switching to a
    // raw bidirectional copy (which would otherwise drop them).
    let mut parts = stream.into_parts();
    if !parts.read_buf.is_empty() {
        visitor.write_all(&parts.read_buf).await?;
        parts.read_buf.clear();
    }
    let mut client = parts.io;

    let (up, down) = copy_bidirectional(&mut visitor, &mut client).await?;
    println!("tunnel {id}: {up} bytes up, {down} bytes down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_range() {
        let r: PortRange = "20000-30000".parse().unwrap();
        assert_eq!((r.min, r.max), (20000, 30000));
    }

    #[test]
    fn rejects_inverted_range() {
        assert!("30000-20000".parse::<PortRange>().is_err());
    }

    #[test]
    fn rejects_zero_min() {
        assert!("0-100".parse::<PortRange>().is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!("abc".parse::<PortRange>().is_err());
    }
}
