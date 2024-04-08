use std::sync::Arc;
use bytes::Bytes;
use quinn::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Mutex;
use crate::tun_device::{TunReader, TunWriter};

async fn tun_to_quic_transfer(tun_reader: &mut TunReader, quic_connection: &Connection, buf: &mut [u8]) -> Result<(), anyhow::Error> {
    let bytes_read = tun_reader.read(buf).await?;
    let bytes = Bytes::copy_from_slice(&buf[..bytes_read]);
    Ok(quic_connection.send_datagram(bytes)?)
}

async fn tun_to_quic(tun_reader: &mut TunReader, quic_connection: &Connection) -> Result<(), anyhow::Error> {
    let closure_task = quic_connection.closed();
    tokio::pin!(closure_task);

    let mut buf = [0; 1500];

    loop {
        tokio::select! {
            _ = &mut closure_task => {
                return Ok(());
            }
            transfer_result = tun_to_quic_transfer(tun_reader, &quic_connection, &mut buf) => {
                if let Err(e) = transfer_result {
                    quic_connection.close(0u32.into(), &[]);
                    return Err(e.into());
                }
            }
        }
    }
}

async fn quic_to_tun_transfer(quic_connection: &Connection, tx: &UnboundedSender<Bytes>) -> Result<(), anyhow::Error> {
    let datagram = quic_connection.read_datagram().await?;
    tx.send(datagram).unwrap();
    Ok(())
}

async fn quic_to_tun(quic_connection: &Connection, tx: &UnboundedSender<Bytes>) -> Result<(), anyhow::Error> {
    let closure_task = quic_connection.closed();
    tokio::pin!(closure_task);

    loop {
        tokio::select! {
            _ = &mut closure_task => {
                return Ok(());
            }
            transfer_result = quic_to_tun_transfer(&quic_connection, &tx) => {
                if let Err(e) = transfer_result {
                    return Err(e.into());
                }
            }
        }
    }
}

// It must be guaranteed that `handle_connection` has "ownership" of `tun_reader` and `tun_writer`
// but async makes stuff messy
pub async fn handle_connection(tun_reader: Arc<Mutex<TunReader>>, tun_writer: Arc<Mutex<TunWriter>>, quic_connection: &Connection) {
    let tun_to_quic_task = {
        let quic_connection = quic_connection.clone();
        tokio::spawn(async move {
            let mut tun_reader = tun_reader.try_lock().unwrap();
            tun_to_quic(&mut tun_reader, &quic_connection).await
        })
    };

    let quic_to_tun_task = {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        tokio::spawn(async move {
            let mut tun_writer = tun_writer.try_lock().unwrap();

            while let Some(datagram) = rx.recv().await {
                tun_writer.write_all(&datagram).await.unwrap();
            }
        });

        let quic_connection = quic_connection.clone();
        tokio::spawn(async move {
            quic_to_tun(&quic_connection, &tx).await
        })
    };

    let _ = tokio::join!(tun_to_quic_task, quic_to_tun_task);
}