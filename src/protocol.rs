use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LinesCodec};
use uuid::Uuid;

pub type MessageStream = Framed<TcpStream, LinesCodec>;

pub async fn send(stream: &mut MessageStream, msg: &Message) -> anyhow::Result<()> {
    let line = serde_json::to_string(msg).context("serializing message")?;
    stream.send(line).await.context("writing message")?;
    Ok(())
}

pub async fn recv(stream: &mut MessageStream) -> anyhow::Result<Option<Message>> {
    let Some(line) = stream.next().await else {
        return Ok(None);
    };
    let line = line.context("reading message")?;
    let msg = serde_json::from_str(&line).context("parsing message")?;
    Ok(Some(msg))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Challenge { nonce: String },
    Authenticate { mac: String },
    Hello(HelloKind),
    Connection { id: Uuid },
    Accept { id: Uuid },
    Heartbeat,
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HelloKind {
    Control { local_port: u16 },
    Response { port: u16 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrips() {
        for msg in [
            Message::Challenge {
                nonce: "n-1".into(),
            },
            Message::Authenticate {
                mac: "deadbeef".into(),
            },
            Message::Hello(HelloKind::Control { local_port: 3000 }),
            Message::Hello(HelloKind::Response { port: 51234 }),
            Message::Heartbeat,
            Message::Error {
                message: "boom".into(),
            },
        ] {
            let line = serde_json::to_string(&msg).unwrap();
            println!("{line}");
            assert_eq!(serde_json::from_str::<Message>(&line).unwrap(), msg);
        }
    }
}
