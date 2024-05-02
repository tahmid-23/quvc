use std::collections::HashMap;
use std::sync::Arc;
use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedSender;
use crate::tun_device::{TunReader, TunWriter};

#[derive(Eq, Hash, PartialEq)]
struct TCPKey {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

async fn tun_to_quic_transfer(tun_reader: &mut TunReader, quic_connection: &Connection, buf: &mut [u8], streams: &mut HashMap<TCPKey, Option<SendStream>>) -> Result<(), anyhow::Error> {
    let bytes_read = tun_reader.read(buf).await?;

    if bytes_read >= 10 && (buf[0] >> 4) == 4 && buf[9] == 6 {
        let ihl = 4 * (buf[0] & 0xF);
        if bytes_read >= (ihl as usize) + 4 {
            let src_ip = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
            let dst_ip = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
            let src_port = u16::from_be_bytes([buf[ihl as usize], buf[ihl as usize + 1]]);
            let dst_port = u16::from_be_bytes([buf[ihl as usize + 2], buf[ihl as usize + 3]]);
            let key = TCPKey {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            };

            let stream_opt = streams.entry(key).or_insert(None);
            if stream_opt.is_none() {
                match quic_connection.open_uni().await {
                    Ok(new_stream) => {
                        *stream_opt = Some(new_stream);
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }

            let stream = stream_opt.as_mut().unwrap();
            return match stream.write_all(&buf[..bytes_read]).await {
                Ok(_) => {
                    Ok(())
                }
                Err(e) => {
                    *stream_opt = None;
                    Err(e.into())
                }
            };
        }
    }

    let bytes = Bytes::copy_from_slice(&buf[..bytes_read]);
    quic_connection.send_datagram(bytes)?;
    Ok(())
}

async fn tun_to_quic(tun_reader: &mut TunReader, quic_connection: &Connection) -> Result<(), anyhow::Error> {
    let mut streams = HashMap::new();

    let closure_task = quic_connection.closed();
    tokio::pin!(closure_task);

    let mut buf = [0; 1500];

    loop {
        tokio::select! {
            _ = &mut closure_task => {
                return Ok(());
            }
            transfer_result = tun_to_quic_transfer(tun_reader, &quic_connection, &mut buf, &mut streams) => {
                if let Err(e) = transfer_result {
                    quic_connection.close(0u32.into(), &[]);
                    return Err(e.into());
                }
            }
        }
    }
}

async fn quic_uni_to_tun_transfer(quic_connection: Connection, mut stream: RecvStream, tx: &UnboundedSender<Bytes>) {
    let closure_task = quic_connection.closed();
    tokio::pin!(closure_task);

    let mut buf = [0; 1500];
    loop {
        tokio::select! {
            _ = &mut closure_task => {
                break;
            }
            _ = stream.read_exact(&mut buf[0..20]) => {
                let total_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                match stream.read_exact(&mut buf[20..total_length]).await {
                    Ok(_) => {
                        tx.send(Bytes::copy_from_slice(&buf[0..total_length])).unwrap();
                    }
                    Err(_) => {
                        break;
                    }
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
    {
        let quic_connection = quic_connection.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let closure_task = quic_connection.closed();
            tokio::pin!(closure_task);

            loop {
                tokio::select! {
                    _ = &mut closure_task => {
                        break;
                    }
                    stream = quic_connection.accept_uni() => {
                        match stream {
                            Ok(stream) => {
                                let quic_connection = quic_connection.clone();
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    quic_uni_to_tun_transfer(quic_connection, stream, &tx).await
                                });
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

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
pub async fn handle_connection(tun_reader: Arc<tokio::sync::Mutex<TunReader>>, tun_writer: Arc<tokio::sync::Mutex<TunWriter>>, quic_connection: &Connection) {
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