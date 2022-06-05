//#![warn(rust_2018_idioms)]

use tinypxy::*;

use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use byteorder::{BigEndian, ByteOrder};
use futures::FutureExt;
use lazy_static::lazy_static;
use regex::Regex;

use std::env;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:8081".to_string());

    println!("TinyPxy listen at: {}", listen_addr);

    let listener = TcpListener::bind(listen_addr).await?;

    while let Ok((inbound, _)) = listener.accept().await {
        let transfer = handle_socket(inbound).map(|r| {
            if let Err(e) = r {
                println!("Failed to transfer; error={}", e);
            }
        });

        tokio::spawn(transfer);
    }

    Ok(())
}

async fn handle_socket(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut pre_buffer = [0; 1420];
    let pre_len = stream.read(&mut pre_buffer).await?;

    // Health checking
    if pre_len < 4 {
        stream.shutdown().await?;
        return Ok(());
    }

    // socks5: first handshake begin - x05,x01,x00
    if 1 + 1 + (pre_buffer[1] as usize) != pre_len || pre_buffer[0] != b'\x05' {
        handle_http(stream, &pre_buffer).await?;
        return Ok(());
    }

    // Socket Ack
    stream.write_all(b"\x05\x00").await?; // version 5, method 0

    // socks5: first handshake begin
    let mut buf = [0; 1420];
    let len = stream.read(&mut buf).await?;
    if len <= 4 {
        warn!("invalid proto");
        return Ok(());
    }

    let ver = buf[0]; // version
    let cmd = buf[1]; // command code 1-connect 2-bind 3-udp forward
    let atyp = buf[3]; // type of the dist server 1-ipv4 3-domain 4-ipv6

    if ver != b'\x05' {
        stream.write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        stream.shutdown().await?;
        return Ok(());
    }

    if cmd != 1 {
        warn!("Command not supported");
        stream.write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        stream.shutdown().await?;
        return Ok(());
    }

    let (server_addr, _, _) = decode_atyp(atyp, len, &buf).unwrap();
    buf[1] = 0; buf[3] = 1;
    let resp = buf[0..len].to_vec();
    let transfer = transfer(stream, server_addr, resp).map(|r| {
        if let Err(e) = r {
            println!("Failed to transfer; error={}", e);
        }
    });
    tokio::spawn(transfer);
    Ok(())
}

async fn handle_http(stream_c: TcpStream, pre_buffer: &[u8]) -> Result<(), Box<dyn Error>> {
    lazy_static! {
        static ref RE_HOST: Regex = Regex::new(r"Host: (.*)(:\d+)\r\n").unwrap();
        static ref RE_CONN: Regex = Regex::new(r"CONNECT (.*) (HTTP/\d+\.\d+)\r\n").unwrap();
    }
    
    let req = std::str::from_utf8(pre_buffer).unwrap();
    let caps = RE_CONN.captures(req).unwrap();
    let server_addr = caps[1].to_string();
    let http_ver = caps[2].to_string();
    let resp = [http_ver.as_bytes(), " 200 Connection Established\r\n\r\n".as_bytes()].concat();
    let transfer = transfer(stream_c, server_addr, resp).map(|r| {
        if let Err(e) = r {
            println!("Failed to transfer; error={}", e);
        }
    });
    tokio::spawn(transfer);
    Ok(())
}

fn decode_atyp(atyp: u8, len: usize, buf: &[u8]) -> Result<(String, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let addr;
    let ipbuf;
    let portbuf;
    let error_ret = (String::from("NULL"), vec![0], vec![0]);
    match atyp {
        1 => {
            if len != 10 {
                warn!("invalid proto");
                return Ok(error_ret);
            }
            ipbuf = Vec::from([buf[4], buf[5], buf[6], buf[7]]);
            portbuf = Vec::from(&buf[8..10]);

            let dst_addr = IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]));
            let dst_port = BigEndian::read_u16(&buf[8..]);
            addr = SocketAddr::new(dst_addr, dst_port).to_string();
        }
        3 => {
            let offset = 4 + 1 + (buf[4] as usize);
            if offset + 2 != len {
                warn!("invalid proto");
                return Ok(error_ret);
            }
            ipbuf = Vec::from(&buf[5..offset]);
            portbuf = Vec::from(&buf[offset..offset + 2]);
            let dst_port = BigEndian::read_u16(&buf[offset..]);
            let mut dst_addr = std::str::from_utf8(&buf[5..offset]).unwrap().to_string();
            dst_addr.push_str(":");
            dst_addr.push_str(&dst_port.to_string());
            addr = dst_addr;
        }
        4 => {
            if len != 22 {
                warn!("invalid proto");
                return Ok(error_ret);
            }
            ipbuf = Vec::from(&buf[4..20]);
            portbuf = Vec::from(&buf[20..22]);
            let dst_addr = IpAddr::V6(Ipv6Addr::new(
                ((buf[4] as u16) << 8) | buf[5] as u16,
                ((buf[6] as u16) << 8) | buf[7] as u16,
                ((buf[8] as u16) << 8) | buf[9] as u16,
                ((buf[10] as u16) << 8) | buf[11] as u16,
                ((buf[12] as u16) << 8) | buf[13] as u16,
                ((buf[14] as u16) << 8) | buf[15] as u16,
                ((buf[16] as u16) << 8) | buf[17] as u16,
                ((buf[18] as u16) << 8) | buf[19] as u16,
            ));

            let dst_port = BigEndian::read_u16(&buf[20..]);
            addr = SocketAddr::new(dst_addr, dst_port).to_string();
        }
        _ => {
            warn!("Address type not supported, type={}", atyp);
            return Ok(error_ret);
        }
    }
    info!("incoming socket, request upstream: {:?}", addr);
    Ok((addr, ipbuf, portbuf))
}


async fn transfer(mut inbound: TcpStream, remote_addr: String, ack_resp: Vec<u8>) -> Result<(), Box<dyn Error>> {
    let mut outbound = TcpStream::connect(remote_addr).await?;

    inbound.write(&ack_resp).await?;

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
