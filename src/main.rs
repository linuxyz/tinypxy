//#![warn(rust_2018_idioms)]

use tinypxy::*;

use socket2::{Domain, Socket, Type};
use std::net::{SocketAddr, TcpListener};

use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};

use byteorder::{BigEndian, ByteOrder};
use lazy_static::lazy_static;
use regex::bytes::Regex;

use std::env;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;

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
    while let Ok((inbound, addr)) = listener.accept().await {
        tokio::spawn(async move {
            if let Err(e) = handshake(inbound).await {
                println!("Failed to transfer with: {:?} error: {:?}", addr, e);
            }
        });
    }
    Ok(())
}

async fn handshake(mut stream_c: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut pre_buffer = [0; 1420];
    let pre_len = stream_c.read(&mut pre_buffer).await?;

    // Health checking
    if pre_len < 3 {
        stream_c.shutdown().await?;
        return Ok(());
    }

    // SOCKS5: first handshake begin - x05,x01,x00 || x05,x02,x00,x01
    if pre_buffer[0] == b'\x05' {
        // SOCKS5 Proxy
        handle_socks(stream_c).await?;
    } else {
        // HTTP Proxy
        handle_http(stream_c, &pre_buffer).await?;
    }
    Ok(())
}

async fn handle_socks(mut stream_c: TcpStream) -> Result<(), Box<dyn Error>> {
    // Socket Ack
    stream_c.write_all(b"\x05\x00").await?; // version 5, method 0

    // socks5: connect request handshake begin
    let mut buf = [0; 1420];
    let len = stream_c.read(&mut buf).await?;
    if len <= 4 {
        warn!("invalid proto: first message is too short");
        return Ok(());
    }

    let ver = buf[0]; // version
    let cmd = buf[1]; // command code 1-connect 2-bind 3-udp forward
    let atype = buf[3]; // type of the dist server 1-ipv4 3-domain 4-ipv6

    if ver != b'\x05' {
        stream_c.write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        stream_c.shutdown().await?;
        return Ok(());
    }

    if cmd != 1 {
        warn!("SOCKS5 command not supported");
        stream_c.write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        stream_c.shutdown().await?;
        return Ok(());
    }

    let soaddr = decode_address(atype, len, &buf).await?;
    debug!("SOCKS5 from {:?} to {:?}", stream_c.peer_addr()?, soaddr);
    let stream_s = TcpStream::connect(soaddr).await?;
    // wait until connected
    stream_s.writable().await?;
    // hard-coded remote address
    stream_c.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await?;
    // Connected
    transfer(stream_c, stream_s).await?;
    Ok(())
}

async fn handle_http(mut stream_c: TcpStream, pre_buffer: &[u8]) -> Result<(), Box<dyn Error>> {
    lazy_static! {
        static ref RE_HOST: Regex = Regex::new(r"(?i)\nHost:\s+(.*)\r\n").unwrap();
        static ref RE_CONN: Regex = Regex::new(r"^CONNECT\s+(.*)\s+(HTTP/.*)\r\n").unwrap();
    }
    const HTTP_CONNECT: &[u8] = "CONNECT ".as_bytes();

    // request validation
    if pre_buffer.len() < 8 {
        stream_c.write_all(b"HTTP/1.1 400 Invalid Request\r\n\r\n").await?;
        stream_c.shutdown().await?;
        return Ok(());
    }

    let mut is_conn = 1;
    let mut resp: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

    let mut rport: u16 = 443;
    // Try CONNECT method for HTTPS
    let server_name = if pre_buffer.starts_with(HTTP_CONNECT) {
        let end = pre_buffer[9..].iter().position(|&c| c == 0x20).unwrap() + 9;
        &pre_buffer[8..end]
    } else {
        // GET method with HTTP
        is_conn = 0;
        rport = 80;
        resp = b"HTTP/1.1 100 Continue\r\n\r\n";
        RE_HOST.captures(pre_buffer).unwrap().get(1).unwrap().as_bytes()
    };
    let full_name = str::from_utf8(server_name).unwrap();
    //info!("HTTP, request {:?} {:?}", server_name, full_name);
    let pos = full_name.find(':').unwrap_or(full_name.len());
    let (rhost, srport) = full_name.split_at(pos);
    if srport.len() > 0 {
        rport = srport[1..].parse::<u16>().unwrap();
    }
    //info!("HTTP, request upstream: {}:{}", server_name, port);
    debug!("HTTP from {:?} to {:?}:{:?}", stream_c.peer_addr()?, rhost, rport);
    let mut stream_s = TcpStream::connect((rhost, rport)).await?;
    // Make sure connected with remote.
    stream_s.writable().await?;
    // None CONNECT mode, we should forward the request to server directly.
    if 0 == is_conn {
        stream_s.write_all(pre_buffer).await?;
    }
    // Response to client: HTTP Proxy - HTTP/1.1 100; CONNECT - HTTP/1.1 200
    stream_c.write_all(&resp).await?;
    // Connected
    transfer(stream_c, stream_s).await?;
    Ok(())
}

async fn decode_address(atype: u8, len: usize, buf: &[u8]) -> Result<SocketAddr, Box<dyn Error>> {
    match atype {
        1 => {
            if len != 10 {
                return Err("invalid IPv4 address length")?;
            }
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])),
                BigEndian::read_u16(&buf[8..]),
            ))
        }
        3 => {
            let offset = 4 + 1 + (buf[4] as usize);
            if offset + 2 != len {
                Err("invalid domain name length")?
            }
            let port = BigEndian::read_u16(&buf[offset..]);
            let rhost = std::str::from_utf8(&buf[5..offset]).unwrap();
            match std::net::ToSocketAddrs::to_socket_addrs(&(rhost, port)) {
                Err(_) => Err(format!("Unresolved remote host: {}", rhost))?,
                Ok(mut iter) => Ok(iter.next().unwrap())
            }
        }
        4 => {
            if len != 22 {
                return Err("invalid IPv6 address length")?;
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
            Ok(SocketAddr::new(
                IpAddr::V6(dst_addr),
                BigEndian::read_u16(&buf[20..]),
            ))
        }
        _ => {
            Err(format!("Address type not supported, type={}", atype))?
        }
    }
}

async fn transfer(mut inbound: TcpStream, mut outbound: TcpStream) -> Result<(), Box<dyn Error>> {
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        io::copy(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };
    let server_to_client = async {
        io::copy(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    inbound.shutdown().await?;
    outbound.shutdown().await?;
    Ok(())
}
