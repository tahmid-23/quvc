use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use clap::Parser;
use quinn::{Endpoint, TransportConfig, VarInt};
use rustls::{Certificate, PrivateKey};
use tokio::sync::Mutex;

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
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport_config = TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
    transport_config.max_concurrent_uni_streams(VarInt::from_u32(8192));
    config.transport_config(Arc::new(transport_config));
    let quic_endpoint = Endpoint::server(config, SocketAddr::from((Ipv4Addr::from(0), cli.port)))
        .expect("Failed to create QUIC server");

    let (tun_reader, tun_writer) = quvc_common::tun_device::new_tun("quvc").expect("Failed to create TUN device");
    let tun_reader = Arc::new(Mutex::new(tun_reader));
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    while let Some(quic_connecting) = quic_endpoint.accept().await {
        let quic_connection = quic_connecting.await.unwrap();
        quvc_common::tunneling::handle_connection(tun_reader.clone(), tun_writer.clone(), &quic_connection).await;
    }
}


