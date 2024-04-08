use std::ffi::CString;
use std::io::Error;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use std::ptr::addr_of_mut;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use anyhow::anyhow;
use libc::{c_short, ifreq};
use nix::fcntl::OFlag;
use nix::{ioctl_write_int};
use nix::sys::ioctl::ioctl_param_type;
use nix::sys::stat::Mode;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::unix::AsyncFd;

pub struct TunReader {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl AsyncRead for TunReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;

            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| {
                nix::unistd::read(inner.as_raw_fd(), unfilled).map_err(Into::into)
            }) {
                Ok(Ok(len)) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

pub struct TunWriter {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl AsyncWrite for TunWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;

            match guard.try_io(|inner| {
                nix::unistd::write(inner, buf).map_err(Into::into)
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

pub fn new_tun(device_name: &str) -> Result<(TunReader, TunWriter), anyhow::Error> {
    ioctl_write_int!(tunsetiff, b'T', 202);

    if device_name.len() > libc::IFNAMSIZ - 1 {
        return Err(anyhow!("{} is too long of an interface name (max length {})", device_name, libc::IFNAMSIZ));
    }

    let fd = nix::fcntl::open("/dev/net/tun", OFlag::O_RDWR, Mode::empty())?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let ifr_name = CString::new(device_name).unwrap();
    let mut ifr = MaybeUninit::<ifreq>::zeroed();
    let ifr_ptr = ifr.as_mut_ptr();

    unsafe {
        addr_of_mut!((*ifr_ptr).ifr_ifru.ifru_flags).write((libc::IFF_TUN | libc::IFF_NO_PI) as c_short);
        std::ptr::copy_nonoverlapping(ifr_name.as_ptr(), (*ifr_ptr).ifr_name.as_mut_ptr(), ifr_name.as_bytes_with_nul().len());

        tunsetiff(fd.as_raw_fd(), ifr.as_ptr() as ioctl_param_type)?;
    }

    nix::fcntl::fcntl(fd.as_raw_fd(), nix::fcntl::F_SETFL(OFlag::O_NONBLOCK))?;

    let fd = Arc::new(AsyncFd::new(fd)?);

    Ok((TunReader { fd: fd.clone() }, TunWriter { fd }))
}