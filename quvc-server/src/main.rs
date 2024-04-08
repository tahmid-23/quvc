use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use bytes::Bytes;
use clap::Parser;
use quinn::{Connecting, Connection, Endpoint};
use rustls::{Certificate, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use quvc_common::tun_device::{TunReader, TunWriter};

#[derive(Parser)]
struct Cli {
    #[arg(short, long, value_name = "FILE", default_value = "cert.der")]
    cert_path: PathBuf,
    #[arg(short, long, value_name = "FILE", default_value = "key.der")]
    key_path: PathBuf,
    #[arg(short, long, default_value = "8000")]
    port: u16,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let (cert, key) = tokio::join!(async {
        let cert = tokio::fs::read(&cli.cert_path).await.unwrap_or_else(|e| panic!("Failed to read certificate from {:?}: {}", cli.cert_path, e));
        Certificate(cert)
    }, async {
        let key = tokio::fs::read(&cli.key_path).await.unwrap_or_else(|e| panic!("Failed to read key from {:?}: {}", cli.key_path, e));
        PrivateKey(key)
    });

    let crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let quic_endpoint = Endpoint::server(config, SocketAddr::from((Ipv4Addr::from(0), cli.port)))
        .expect("Failed to create QUIC server");

    let (tun_reader, tun_writer) = quvc_common::tun_device::new_tun("quvc").expect("Failed to create TUN device");

    if let Some(quic_connecting) = quic_endpoint.accept().await {
        handle_connecting(tun_reader, tun_writer, quic_connecting).await;
    }
}

async fn handle_connecting(tun_reader: TunReader, tun_writer: TunWriter, quic_connecting: Connecting) {
    match quic_connecting.await {
        Ok(quic_connection) => {
            handle_connection(tun_reader, tun_writer, quic_connection).await;
        }
        Err(e) => {
            eprintln!("Failed to accept QUIC connection: {}", e);
        }
    }
}

async fn tun_to_quic(mut tun_reader: TunReader, quic_connection: &Connection) {
    let mut buf = [0; 1500];

    loop {
        let bytes_read = tun_reader.read(&mut buf).await.unwrap();
        let bytes = Bytes::copy_from_slice(&buf[..bytes_read]);

        quic_connection.send_datagram(bytes).unwrap();
    }
}

async fn quic_to_tun(quic_connection: &Connection, tun_writer: TunWriter) {
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    loop {
        let datagram = quic_connection.read_datagram().await.unwrap();

        let tun_writer = tun_writer.clone();
        tokio::spawn(async move {
            tun_writer.lock().await.write_all(&datagram).await.unwrap();
        });
    }
}

async fn handle_connection(tun_reader: TunReader, tun_writer: TunWriter, quic_connection: Connection) {
    let tun_to_quic_task = {
        let quic_connection = quic_connection.clone();
        tokio::spawn(async move {
            tun_to_quic(tun_reader, &quic_connection).await
        })
    };
    let quic_to_tun_task = tokio::spawn(async move {
        quic_to_tun(&quic_connection, tun_writer).await
    });

    let _ = tokio::join!(tun_to_quic_task, quic_to_tun_task);
}

