use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use clap::Parser;
use quinn::{Connecting, Connection, Endpoint};
use rustls::{Certificate, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use quvc_common::tun_device::{TunReader, TunWriter};

#[derive(Parser)]
struct Cli {
    #[arg(short, long, value_name = "FILE", default_value = "cert.der")]
    cert_path: PathBuf,
    #[arg(short, long, value_name = "FILE", default_value = "key.der")]
    key_path: PathBuf,
    #[arg(short, long, default_value = "8000")]
    port: u16
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

async fn handle_connection(mut tun_reader: TunReader, mut tun_writer: TunWriter, quic_connection: Connection) {
    let mut tasks = JoinSet::new();

    {
        let quic_connection = quic_connection.clone();
        tasks.spawn(async move {
            loop {
                let mut buf = [0; 1500];
                tun_reader.read(&mut buf).await.unwrap();

                let mut stream = quic_connection.open_uni().await.unwrap();
                stream.write_all(&buf).await.unwrap();
                stream.finish().await.unwrap();
            }
        });
    }

    tasks.spawn(async move {
        loop {
            let mut stream = quic_connection.accept_uni().await.unwrap();
            let buf = stream.read_to_end(1500).await.unwrap();

            tun_writer.write_all(&buf).await.unwrap();
        }
    });

    while let Some(_) = tasks.join_next().await {

    }
}

