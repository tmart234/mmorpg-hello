// common/src/tcp_framing.rs
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn tcp_recv_msg<T: serde::de::DeserializeOwned>(sock: &mut TcpStream) -> Result<T> {
    let mut len_bytes = [0u8; 4];
    sock.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf).await?;

    let msg: T = bincode::deserialize(&buf)?;
    Ok(msg)
}

pub async fn tcp_send_msg<T: serde::Serialize>(sock: &mut TcpStream, msg: &T) -> Result<()> {
    let buf = bincode::serialize(msg)?;
    let len = buf.len() as u32;

    sock.write_all(&len.to_le_bytes()).await?;
    sock.write_all(&buf).await?;
    Ok(())
}
