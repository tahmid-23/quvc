use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use clap::Parser;
use quinn::{Endpoint, TransportConfig};
use rustls::{Certificate, RootCertStore};
use tokio::sync::Mutex;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, value_name = "FILE", default_value = "cert.der")]
    cert_path: PathBuf,
    #[arg(short, long, default_value = "quvc")]
    server_name: String,
    #[arg(short, long, default_value = "8000")]
    port: u16,
    #[arg(short, long)]
    address: SocketAddr,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let mut root_store = RootCertStore::empty();
    let cert = std::fs::read(&cli.cert_path)
        .unwrap_or_else(|e| panic!("Failed to read certificate from {:?}: {}", cli.cert_path, e));

    root_store.add(&Certificate(cert)).expect("Failed to add certificate");

    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport_config = TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
    config.transport_config(Arc::new(transport_config));

    let mut quic_endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::from(0), 0)))
        .expect("Failed to create QUIC client");
    quic_endpoint.set_default_client_config(config);
    let quic_connection = quic_endpoint.connect(cli.address, &cli.server_name)
        .expect("Failed to establish QUIC connection")
        .await
        .expect("Failed to connect to QUIC server");
    let quic_connection = Arc::new(quic_connection);

    let (tun_reader, tun_writer) = quvc_common::tun_device::new_tun("quvc").expect("Failed to create TUN device");
    let tun_reader = Arc::new(Mutex::new(tun_reader));
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    quvc_common::tunneling::handle_connection(tun_reader, tun_writer, &quic_connection).await;
}
