//#![warn(rust_2018_idioms)]

use tinypxy::*;

use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener};
use tokio::net::TcpStream;

use byteorder::{BigEndian, ByteOrder};
use futures::FutureExt;
use lazy_static::lazy_static;
use regex::Regex;

use std::env;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

async fn handle_socket(mut stream_c: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut pre_buffer = [0; 1420];
    let pre_len = stream_c.read(&mut pre_buffer).await?;

    // Health checking
    if pre_len < 3 {
        stream_c.shutdown().await?;
        return Ok(());
    }

    // socks5: first handshake begin - x05,x01,x00
    if 1 + 1 + (pre_buffer[1] as usize) != pre_len || pre_buffer[0] != b'\x05' {
        handle_http(stream_c, &pre_buffer).await?;
        return Ok(());
    }

    // Socket Ack
    stream_c.write_all(b"\x05\x00").await?; // version 5, method 0

    // socks5: first handshake begin
    let mut buf = [0; 1420];
    let len = stream_c.read(&mut buf).await?;
    if len <= 4 {
        warn!("invalid proto");
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

    let (server_name, port) = decode_atyp(atyp, len, &buf).unwrap();
    let stream_s = TcpStream::connect(format!("{}:{}", server_name, port)).await?;
    // hard-coded remote address
    buf[0] = 5; buf[1] = 0; buf[3] = 1; buf[4] = 0; buf[5] = 0; buf[6] = 0; buf[7] = 0; buf[8] = 0; buf[9] = 0;
    stream_c.write_all(&buf[0..10]).await?;
    let transfer = transfer(stream_c, stream_s).map(|r| {
        if let Err(e) = r {
            println!("Failed to transfer; error={}", e);
        }
    });
    tokio::spawn(transfer);
    Ok(())
}

async fn handle_http(mut stream_c: TcpStream, pre_buffer: &[u8]) -> Result<(), Box<dyn Error>> {
    lazy_static! {
        static ref RE_HOST: Regex = Regex::new(r"Host: (.*)\r\n").unwrap();
        static ref RE_CONN: Regex = Regex::new(r"CONNECT (.*) (HTTP/\d*\.\d*)\r\n").unwrap();
    }
    
    let server_name: String;
    let mut port: u16 = 80;
    let mut is_conn = 1;
    let mut resp: Vec<u8> = "HTTP/1.1 200 Connection Established\r\n\r\n".into();

    let req = std::str::from_utf8(pre_buffer).unwrap();
    let server = match RE_CONN.captures(req) {
        Some(caps) => {
            caps[1].to_string()
        }
        None => {
            is_conn = 0;
            resp = "HTTP/1.1 100 Continue\r\n\r\n".into();
            RE_HOST.captures(req).unwrap()[1].to_string()
        }
    };
    let v: Vec<&str> = server.split(':').collect();
    //info!("HTTP, request {} {} {:?}", server, port, v);
    if v.len() > 1 {
        server_name = v[0].to_string();
        port = v[1].parse().unwrap();
    } else {
        server_name = server;
    }
    //info!("HTTP, request upstream: {}:{}", server_name, port);
    let mut stream_s = TcpStream::connect(format!("{}:{}", server_name, port)).await?;
    if 0 == is_conn {
        stream_s.write_all(pre_buffer).await?;
    }
    stream_c.write_all(&resp).await?;
    let transfer = transfer(stream_c, stream_s).map(|r| {
        if let Err(e) = r {
            println!("Failed to transfer; error={}", e);
        }
    });
    tokio::spawn(transfer);
    Ok(())
}

fn decode_atyp(atyp: u8, len: usize, buf: &[u8]) -> Result<(String, u16), Box<dyn Error>> {
    let addr;
    let port: u16;
    let error_ret = (String::from("NULL"), 0);
    match atyp {
        1 => {
            if len != 10 {
                warn!("invalid proto");
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
                warn!("invalid proto");
                return Ok(error_ret);
            }
            let dst_port = BigEndian::read_u16(&buf[offset..]);
            let dst_addr = std::str::from_utf8(&buf[5..offset]).unwrap().to_string();
            addr = dst_addr;
            port = dst_port;
        }
        4 => {
            if len != 22 {
                warn!("invalid proto");
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
    info!("incoming socket, request upstream: {}:{}", addr, port);
    Ok((addr, port))
}


async fn transfer(mut inbound: TcpStream, mut outbound: TcpStream) -> Result<(), Box<dyn Error>> {
    //debug!("transfer({}:{})", remote_name, port);
    //let mut outbound = TcpStream::connect(format!("{}:{}", remote_name, port)).await?;
    //if ack_resp.len() > 0 {
    //    inbound.write_all(&ack_resp).await?;
    //}

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
