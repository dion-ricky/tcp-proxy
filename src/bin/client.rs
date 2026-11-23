use anyhow::{Context, bail};
use clap::Parser;
use tcp_proxy::{
    HANDSHAKE_TIMEOUT, HEARTBEAT_INTERVAL, auth,
    protocol::{HelloKind, Message, MessageStream, recv, send},
};
use tokio::{
    net::TcpStream,
    time::{MissedTickBehavior, interval, timeout},
};
use tokio_util::codec::LinesCodec;
use uuid::Uuid;

#[derive(Parser)]
struct Args {
    /// Address of the server's control port
    #[arg(long, default_value = "127.0.0.1:7887")]
    server: String,

    /// Port of the local service to expose
    #[arg(long, default_value_t = 3000)]
    local_port: u16,

    /// Shared secret; must match the server's
    #[arg(long, env = "TCP_PROXY_SECRET")]
    secret: String,
}

/// One event in the control-channel loop.
enum CEv {
    /// A control message arrived, or the channel closed (`None`).
    Msg(Option<Message>),
    /// Time to send a heartbeat.
    Tick,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut stream = connect_authenticated(&args.server, &args.secret).await?;

    timeout(
        HANDSHAKE_TIMEOUT,
        send(
            &mut stream,
            &Message::Hello(HelloKind::Control {
                local_port: args.local_port,
            }),
        ),
    )
    .await
    .context("timed out sending hello")??;

    match timeout(HANDSHAKE_TIMEOUT, recv(&mut stream))
        .await
        .context("timed out waiting for server reply")??
    {
        Some(Message::Hello(HelloKind::Response { port })) => println!("public port: {port}"),
        Some(other) => bail!("unexpected reply: {other:?}"),
        None => bail!("server closed the connection during handshake"),
    }

    let mut ticker = interval(HEARTBEAT_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        let ev = tokio::select! {
            m = recv(&mut stream) => CEv::Msg(m?),
            _ = ticker.tick() => CEv::Tick,
        };

        match ev {
            CEv::Tick => send(&mut stream, &Message::Heartbeat).await?,

            CEv::Msg(None) => break,

            CEv::Msg(Some(Message::Connection { id })) => {
                let server = args.server.clone();
                let local_port = args.local_port;
                let secret = args.secret.clone();
                tokio::spawn(async move {
                    if let Err(err) = serve_visitor(id, &server, local_port, secret).await {
                        eprintln!("guest connection failed: {err:#}");
                    }
                });
            }

            CEv::Msg(Some(Message::Heartbeat)) => {}
            CEv::Msg(Some(other)) => println!("ignoring {other:?}"),
        }
    }

    Ok(())
}

/// Dials the control server and completes the challenge/response handshake.
///
/// Returns a stream that is authenticated and ready for `Hello` or `Accept`.
async fn connect_authenticated(server: &str, secret: &str) -> anyhow::Result<MessageStream> {
    let stream = TcpStream::connect(server)
        .await
        .with_context(|| format!("connecting to control server at {server}"))?;
    let mut stream = MessageStream::new(stream, LinesCodec::new());

    let nonce = match timeout(HANDSHAKE_TIMEOUT, recv(&mut stream))
        .await
        .context("timed out waiting for challenge")??
    {
        Some(Message::Challenge { nonce }) => nonce,
        Some(other) => bail!("expected challenge, got {other:?}"),
        None => bail!("server closed the connection before authenticating"),
    };

    let mac = auth::mac_hex(secret, &nonce)?;
    timeout(
        HANDSHAKE_TIMEOUT,
        send(&mut stream, &Message::Authenticate { mac }),
    )
    .await
    .context("timed out sending authenticate")??;

    Ok(stream)
}

/// Claims a waiting visitor on a dedicated connection and pipes it to the
/// local service.
async fn serve_visitor(
    id: Uuid,
    server: &str,
    local_port: u16,
    secret: String,
) -> anyhow::Result<()> {
    let mut proxy = connect_authenticated(server, &secret).await?;
    send(&mut proxy, &Message::Accept { id }).await?;

    let mut local = TcpStream::connect(("127.0.0.1", local_port)).await?;
    let mut proxy = proxy.into_inner();
    tokio::io::copy_bidirectional(&mut proxy, &mut local).await?;
    Ok(())
}
