use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};

/// Send a length-prefixed bincode message.
/// Format:
///   [u32 big-endian length][that many bytes of bincode(msg)]
pub async fn send_msg<T: serde::Serialize>(s: &mut SendStream, msg: &T) -> Result<()> {
    // serialize
    let payload = bincode::serialize(msg).context("serialize msg")?;

    // length prefix
    let len_u32: u32 = payload
        .len()
        .try_into()
        .context("msg too big for u32 length prefix")?;
    s.write_all(&len_u32.to_be_bytes())
        .await
        .context("write length prefix")?;

    // body
    s.write_all(&payload).await.context("write payload bytes")?;

    // half-close the send side
    s.finish().await.context("finish send stream")?;

    Ok(())
}

/// Receive one length-prefixed bincode message.
pub async fn recv_msg<T: serde::de::DeserializeOwned>(r: &mut RecvStream) -> Result<T> {
    // read length
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .context("read length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // read body
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.context("read message body")?;

    let msg: T = bincode::deserialize(&buf).context("deserialize body")?;
    Ok(msg)
}
