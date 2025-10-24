use anyhow::{anyhow, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn send_msg<T: Serialize>(s: &mut quinn::SendStream, v: &T) -> Result<()> {
    let body = bincode::serialize(v)?;
    s.write_all(&(body.len() as u32).to_be_bytes()).await?;
    s.write_all(&body).await?;
    s.finish().await?;
    Ok(())
}

pub async fn recv_msg<T: DeserializeOwned>(r: &mut quinn::RecvStream) -> Result<T> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes(hdr) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    bincode::deserialize::<T>(&body).map_err(|e| anyhow!("bincode: {e}"))
}
