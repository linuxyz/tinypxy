//#![warn(rust_2018_idioms)]

use tinypxy::*;

use socket2::{Domain, Socket, Type};
use std::net::{SocketAddr, TcpListener};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_splice::zero_copy_bidirectional;

use byteorder::{BigEndian, ByteOrder};
use lazy_static::lazy_static;
use regex::bytes::Regex;

use std::env;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;

//#[derive(Copy)]
#[derive(Debug)]
struct TcpBridge {
    /// in bound stream
    inbound: TcpStream,
    /// remote address
    remote_addr: SocketAddr,
    remote_name: String,
    remote_port: u16,
    msg_buffer: [u8; 1420],
}

impl TcpBridge {
    fn decode_address(&mut self, len: usize) -> Result<(), Box<dyn Error>> {
        let atype = self.msg_buffer[3]; // type of the dist server 1-ipv4 3-domain 4-ipv6
        let buf = &self.msg_buffer;
        match atype {
            1 => {
                if len != 10 {
                    return Err("SOCKS5_PROXY invalid IPv4 address length")?;
                }
                self.remote_addr = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])),
                    BigEndian::read_u16(&buf[8..]),
                );
                Ok(())
            }
            3 => {
                let offset = 4 + 1 + (buf[4] as usize);
                if offset + 2 != len {
                    Err("SOCKS5_PROXY invalid domain name length")?
                }
                self.remote_port = BigEndian::read_u16(&buf[offset..]);
                self.remote_name = std::str::from_utf8(&buf[5..offset]).unwrap().to_string();
                Ok(())
            }
            4 => {
                if len != 22 {
                    Err("SOCKS5_PROXY invalid IPv6 address length")?
                }
                let dst_addr = Ipv6Addr::new(
                    ((buf[4] as u16) << 8) | buf[5] as u16,
                    ((buf[6] as u16) << 8) | buf[7] as u16,
                    ((buf[8] as u16) << 8) | buf[9] as u16,
                    ((buf[10] as u16) << 8) | buf[11] as u16,
                    ((buf[12] as u16) << 8) | buf[13] as u16,
                    ((buf[14] as u16) << 8) | buf[15] as u16,
                    ((buf[16] as u16) << 8) | buf[17] as u16,
                    ((buf[18] as u16) << 8) | buf[19] as u16,
                );
                self.remote_addr =
                    SocketAddr::new(IpAddr::V6(dst_addr), BigEndian::read_u16(&buf[20..]));
                Ok(())
            }
            _ => Err(format!(
                "SOCKS5_PROXY Address type not supported, type={}",
                atype
            ))?,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listen_addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:2080".to_string())
        .parse()
        .unwrap();

    println!("TinyPxy listen at: {}", listen_addr);

    // Start from socket2 for REUSEPORT and backlog
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.reuse_address()?;
    socket.set_nonblocking(true)?;
    socket.bind(&listen_addr.into())?;
    socket.listen(512)?;
    let std_listener: TcpListener = socket.into();

    let listener = TokioTcpListener::from_std(std_listener)?;
    while let Ok((inbound, in_addr)) = listener.accept().await {
        let bridge = TcpBridge {
            inbound,
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 1, 1, 1)), 80),
            remote_name: String::from("#"),
            remote_port: 80,
            msg_buffer: [0; 1420],
        };
        tokio::spawn(async move {
            if let Err(_) = process(bridge, in_addr).await {
                warn!("Exception to process remote request!")
            }
        });
    }
    Ok(())
}

async fn process(mut bridge: TcpBridge, in_addr: SocketAddr) -> Result<TcpBridge, Box<dyn Error>> {
    let pre_len = match bridge.inbound.read(&mut bridge.msg_buffer).await {
        Ok(n) => n,
        Err(_) => 0,
    };

    // Health checking
    if pre_len < 3 {
        bridge.inbound.shutdown().await?;
        warn!("From:{} Error:First message is too short!", in_addr);
        return Ok(bridge);
    }

    // SOCKS5: first handshake begin - x05,x01,x00 || x05,x02,x00,x01
    if bridge.msg_buffer[0] == b'\x05' {
        // SOCKS5 Proxy
        handle_socks(bridge).await
    } else {
        // HTTP Proxy
        handle_http(bridge, pre_len).await
    }
}

async fn handle_socks(mut bridge: TcpBridge) -> Result<TcpBridge, Box<dyn Error>> {
    // Socket Ack
    if let Err(e) = bridge.inbound.write_all(b"\x05\x00").await {
        // version 5, method 0
        Err(e)?
    }

    // socks5: connect request handshake begin
    let len = bridge.inbound.read(&mut bridge.msg_buffer).await?;
    if len <= 4 {
        Err("SOCKS_PROXY first message is too short!")?
    }

    let ver = bridge.msg_buffer[0]; // version
    if ver != b'\x05' {
        bridge
            .inbound
            .write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .await?;
        Err("SOCKS_PROXY Unsupported SOCKS version!")?
    }

    let cmd = bridge.msg_buffer[1]; // command code 1-connect 2-bind 3-udp forward
    if cmd != 1 {
        bridge
            .inbound
            .write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .await?;
        Err("SOCKS_PROXY Unsupported SOCKS5 command!")?
    }

    // Decode the remote address
    if let Err(e) = bridge.decode_address(len) {
        Err(e)?
    }
    // hard-coded remote address if connect remote successfully
    setup_bridge(bridge, 0, b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await
}

async fn handle_http(
    mut bridge: TcpBridge,
    mut pre_len: usize,
) -> Result<TcpBridge, Box<dyn Error>> {
    lazy_static! {
        static ref RE_HOST: Regex = Regex::new(r"(?i)\nHost:\s+(.*)\r\n").unwrap();
        static ref RE_CONN: Regex = Regex::new(r"^CONNECT\s+(.*)\s+(HTTP/.*)\r\n").unwrap();
    }
    const HTTP_CONNECT: &[u8] = "CONNECT ".as_bytes();

    // request validation
    if bridge.msg_buffer.len() < 8 {
        bridge
            .inbound
            .write_all(b"HTTP/1.1 400 Invalid Request\r\n\r\n")
            .await?;
        Err(format!("HTTP_PROXY invalid request length={}", pre_len))?
    }

    let mut is_conn = 1;
    let mut rport: u16 = 443;
    // Try CONNECT method for HTTPS
    let server_name = if bridge.msg_buffer.starts_with(HTTP_CONNECT) {
        let end = bridge.msg_buffer[9..]
            .iter()
            .position(|&c| c == 0x20)
            .unwrap()
            + 9;
        &bridge.msg_buffer[8..end]
    } else {
        // GET method with HTTP
        is_conn = 0;
        rport = 80;
        RE_HOST
            .captures(&bridge.msg_buffer)
            .unwrap()
            .get(1)
            .unwrap()
            .as_bytes()
    };
    let full_name = str::from_utf8(server_name).unwrap();
    //info!("HTTP, request {:?} {:?}", server_name, full_name);
    let pos = full_name.find(':').unwrap_or(full_name.len());
    let (rhost, srport) = full_name.split_at(pos);
    if srport.len() > 0 {
        rport = srport[1..].parse::<u16>().unwrap();
    }
    //info!("HTTP from {:?} to '{}:{}'", bridge.inbound.peer_addr()?, rhost, rport);
    bridge.remote_name = String::from(rhost);
    bridge.remote_port = rport;

    // CONNECT should ignore the HTTP request
    let mut resp: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
    if is_conn > 0 {
        pre_len = 0;
        resp = b"HTTP/1.1 200 OK\r\n\r\n";
    }

    setup_bridge(bridge, pre_len, resp).await
}

async fn setup_bridge(
    mut bridge: TcpBridge,
    pre_len: usize,
    resp: &[u8],
) -> Result<TcpBridge, Box<dyn Error>> {
    let mut stream_s = match if bridge.remote_name.len() > 1 {
        TcpStream::connect((bridge.remote_name.as_str(), bridge.remote_port)).await
    } else {
        TcpStream::connect(bridge.remote_addr).await
    } {
        Ok(stream) => stream,
        Err(e) => {
            bridge.inbound.shutdown().await?;
            Err(format!(
                "Cannot connect to {}:{}|{:?}, Error:{:?}",
                bridge.remote_name, bridge.remote_port, bridge.remote_addr, e
            ))?
        }
    };

    //info!("Connect remote {:?} {:?}", stream_s, bridge);
    // Make sure connected with remote.
    if let Err(e) = stream_s.writable().await {
        bridge.inbound.shutdown().await?;
        stream_s.shutdown().await?;
        Err(format!(
            "Cannot writable (outbound) to {}:{}|{:?}, Error:{:?}",
            bridge.remote_name, bridge.remote_port, bridge.remote_addr, e
        ))?
    }
    // None CONNECT mode, we should forward the request to server directly.
    if pre_len > 0 {
        if let Err(e) = stream_s.write_all(&bridge.msg_buffer[..pre_len]).await {
            bridge.inbound.shutdown().await?;
            stream_s.shutdown().await?;
            Err(format!(
                "Cannot write (outbound) to {}:{}|{:?}, Error:{:?}",
                bridge.remote_name, bridge.remote_port, bridge.remote_addr, e
            ))?
        }
    }
    // Response to client: HTTP Proxy - HTTP/1.1 100; CONNECT - HTTP/1.1 200
    if let Err(e) = bridge.inbound.write_all(&resp).await {
        bridge.inbound.shutdown().await?;
        stream_s.shutdown().await?;
        Err(format!(
            "Cannot write (inbound) to {}:{}|{:?}, Error:{:?}",
            bridge.remote_name, bridge.remote_port, bridge.remote_addr, e
        ))?
    }
    // Connected
    zero_copy_bidirectional(&mut bridge.inbound, &mut stream_s).await?;
    stream_s.shutdown().await?;
    bridge.inbound.shutdown().await?;
    Ok(bridge)
}
