//#![warn(rust_2018_idioms)]

use tinypxy::*;

use std::net::{SocketAddr, TcpListener};
use socket2::{Socket, Domain, Type};

use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};

use byteorder::{BigEndian, ByteOrder};
use futures::FutureExt;
use lazy_static::lazy_static;
use regex::bytes::Regex;

use std::env;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listen_addr : SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:2080".to_string())
        .parse().unwrap();

    println!("TinyPxy listen at: {}", listen_addr);

    // Start from socket2 for REUSEPORT and backlog
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(false)?;
    socket.reuse_address()?;
    socket.set_nonblocking(true)?;
    socket.bind(&listen_addr.into())?;
    socket.listen(512)?;
    let std_listener : TcpListener = socket.into();

    let listener = TokioTcpListener::from_std(std_listener)?;
    while let Ok((inbound, addr)) = listener.accept().await {
        let transfer = handshake(inbound)
            .map(move |r| {
                if let Err(e) = r {
                    println!("Failed to transfer with: {:?} error: {:?}", addr, e);
                }});
        tokio::spawn(transfer);
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
    let atyp = buf[3]; // type of the dist server 1-ipv4 3-domain 4-ipv6

    if ver != b'\x05' {
        stream_c.write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        stream_c.shutdown().await?;
        return Ok(());
    }

    if cmd != 1 {
        warn!("Command not supported");
        stream_c.write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        stream_c.shutdown().await?;
        return Ok(());
    }

    let (server_name, port) = decode_address(atyp, len, &buf).unwrap();
    let stream_s = TcpStream::connect(format!("{}:{}", server_name, port)).await?;
    // hard-coded remote address
    stream_c.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await?;
    // Connected
    transfer(stream_c, stream_s).await?;
    Ok(())
}

async fn handle_http(mut stream_c: TcpStream, pre_buffer: &[u8]) -> Result<(), Box<dyn Error>> {
    lazy_static! {
        static ref RE_HOST: Regex = Regex::new(r"\nHost: (.*)\r\n").unwrap();
        static ref RE_CONN: Regex = Regex::new(r"^CONNECT (.*) (HTTP/\d*\.\d*)\r\n").unwrap();
    }

    // request validation
    if pre_buffer.len() < 8 {
        stream_c.write_all(b"HTTP/1.1 400 Invalid Request\r\n\r\n").await?;
        stream_c.shutdown().await?;
        return Ok(());
    }

    let mut is_conn = 1;
    let mut resp: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

    // Try CONNECT method for HTTPS
    let server_name = match RE_CONN.captures(pre_buffer) {
        Some(caps) => {
            caps[1].to_vec()
        }
        None => {
           // GET method with HTTP
            is_conn = 0;
            resp = b"HTTP/1.1 100 Continue\r\n\r\n";
            RE_HOST.captures(pre_buffer).unwrap()[1].to_vec()
        }
    };

    let mut full_name = String::from_utf8(server_name).unwrap();
    //info!("HTTP, request {} {} {:?}", server, port, v)
    if full_name.find(':').is_none()  {
        // If no port specified, use default HTTP:8
        full_name.push_str(":80");
    }
    //info!("HTTP, request upstream: {}:{}", server_name, port);
    let mut stream_s = TcpStream::connect(full_name).await?;
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

fn decode_address(atyp: u8, len: usize, buf: &[u8]) -> Result<(String, u16), Box<dyn Error>> {
    let addr;
    let port: u16;
    let error_ret = (String::from("NULL"), 0);
    match atyp {
        1 => {
            if len != 10 {
                warn!("invalid IPv4 address length");
                return Ok(error_ret);
            }
            let dst_addr = IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]));
            let dst_port = BigEndian::read_u16(&buf[8..]);
            addr = dst_addr.to_string();
            port = dst_port;
        }
        3 => {
            let offset = 4 + 1 + (buf[4] as usize);
            if offset + 2 != len {
                warn!("invalid domain name length");
                return Ok(error_ret);
            }
            let dst_port = BigEndian::read_u16(&buf[offset..]);
            let dst_addr = std::str::from_utf8(&buf[5..offset]).unwrap().to_string();
            addr = dst_addr;
            port = dst_port;
        }
        4 => {
            if len != 22 {
                warn!("invalid IPv6 address length");
                return Ok(error_ret);
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
            let dst_port = BigEndian::read_u16(&buf[20..]);
            addr = dst_addr.to_string();
            port = dst_port;
        }
        _ => {
            warn!("Address type not supported, type={}", atyp);
            return Ok(error_ret);
        }
    }
    //info!("incoming socket, request upstream: {}:{}", addr, port);
    Ok((addr, port))
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
    Ok(())
}
