//! Finding Miniservers on the local network (Loxone discovery over UDP).
//!
//! A broadcast to port 7070 is answered from port 7071 with a line such as
//! `LoxLIVE:... 192.168.1.10:8080 ...`. The address in that line is the Miniserver's
//! HTTP address and port.

use std::io;
use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;

/// Port the Miniservers listen on for discovery broadcasts.
pub const DISCOVERY_PORT: u16 = 7070;
/// Port the replies come back to.
pub const REPLY_PORT: u16 = 7071;

/// One Miniserver that answered the discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// Address and port of the Miniserver's HTTP interface.
    pub addr: SocketAddrV4,
    /// The whole reply line (it contains the serial number and firmware).
    pub reply: String,
}

/// Read one reply line. Returns the address if the line is a Miniserver reply.
pub fn parse_reply(text: &str) -> Option<SocketAddrV4> {
    if !text.starts_with("LoxLIVE:") {
        return None;
    }
    text.split_whitespace()
        .find_map(|token| token.parse::<SocketAddrV4>().ok())
}

/// Broadcast for `timeout` and collect every Miniserver that answers, once each.
///
/// Fails if the reply port cannot be opened (another program may be using it).
pub async fn discover(timeout: Duration) -> io::Result<Vec<Found>> {
    let socket = UdpSocket::bind(("0.0.0.0", REPLY_PORT)).await?;
    socket.set_broadcast(true)?;
    for _ in 0..3 {
        socket
            .send_to(&[0u8], ("255.255.255.255", DISCOVERY_PORT))
            .await?;
    }
    let deadline = Instant::now() + timeout;
    let mut found: Vec<Found> = Vec::new();
    let mut buf = [0u8; 1024];
    while let Ok(Ok((n, _))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
        let text = String::from_utf8_lossy(&buf[..n]).trim().to_owned();
        if let Some(addr) = parse_reply(&text)
            && !found.iter().any(|f| f.addr == addr)
        {
            found.push(Found { addr, reply: text });
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_address_from_a_loxlive_reply() {
        let line = "LoxLIVE:12345678 Miniserver 192.168.1.10:8080 12.2.10.6";
        assert_eq!(
            parse_reply(line),
            Some("192.168.1.10:8080".parse().unwrap())
        );
    }

    #[test]
    fn ignores_other_lines() {
        assert_eq!(parse_reply("hello 192.168.1.10:8080"), None);
        assert_eq!(parse_reply("LoxLIVE: no address here"), None);
    }
}
