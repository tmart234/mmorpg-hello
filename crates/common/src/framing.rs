use anyhow::Result;
use bincode;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn send_msg<T: serde::Serialize>(mut s: SendStream, msg: &T) -> Result<()> {
    let bytes = bincode::serialize(msg)?;
    let len = (bytes.len() as u32).to_be_bytes();
    s.write_all(&len).await?;
    s.write_all(&bytes).await?;
    s.finish()?; // finish() is NOT async on quinn
    Ok(())
}

pub async fn recv_msg<T: serde::de::DeserializeOwned>(mut s: RecvStream) -> Result<T> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0; n];
    s.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}
