use std::{sync::Arc, time::Duration};

use anyhow::bail;
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

#[derive(Parser)]
struct Args {
    /// Address the control port listens on
    #[arg(long, default_value = "0.0.0.0:7887")]
    bind: String,

    /// Shared secret clients must authenticate with
    #[arg(long, env = "TCP_PROXY_SECRET")]
    secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Args { bind, secret } = Args::parse();
    let secret = Arc::new(secret);
    let pending: Pending = Pending::default();

    let listener = TcpListener::bind(&bind).await?;
    println!("Listening on {bind}");

    loop {
        let (stream, addr) = listener.accept().await?;
        let pending = Arc::clone(&pending);
        let secret = Arc::clone(&secret);
        println!("Accepted connection from {addr}");

        tokio::spawn(async move {
            if let Err(err) = handle_control(stream, pending, secret).await {
                eprintln!("control connection failed: {err:#}");
            }
        });
    }
}

async fn handle_control(
    stream: TcpStream,
    pending: Pending,
    secret: Arc<String>,
) -> anyhow::Result<()> {
    let mut control = MessageStream::new(stream, LinesCodec::new());

    if !authenticate(&mut control, secret.as_str()).await? {
        eprintln!("authentication failed");
        return Ok(());
    }

    let first = match timeout(HANDSHAKE_TIMEOUT, recv(&mut control)).await {
        Err(_) => bail!("handshake timed out after {HANDSHAKE_TIMEOUT:?}"),
        Ok(msg) => msg?,
    };

    match first {
        Some(Message::Hello(HelloKind::Control { local_port })) => {
            run_tunnel(control, local_port, pending).await
        }
        Some(Message::Accept { id }) => handle_accept(control, id, pending).await,
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
    pending: Pending,
) -> anyhow::Result<()> {
    let mut guard = PendingGuard::new(Arc::clone(&pending));
    let listener = TcpListener::bind(("0.0.0.0", 0)).await?;
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
                pending.insert(id, visitor);
                guard.track(id);

                let reaper = Arc::clone(&pending);
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
