//! Teleport ALPN ping framing (`*-ping`): u32be length prefix; length 0 is a ping.

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub fn is_ping_alpn(alpn: &[u8]) -> bool {
    alpn.ends_with(b"-ping")
}

pub fn strip_ping_alpn(alpn: &[u8]) -> &[u8] {
    alpn.strip_suffix(b"-ping").unwrap_or(alpn)
}

pub struct PingStream<S> {
    inner: S,
    read_state: ReadState,
    write_state: WriteState,
}

enum ReadState {
    Header { buf: [u8; 4], filled: usize },
    Body { remaining: u32 },
}

enum WriteState {
    Idle,
    Header { hdr: [u8; 4], sent: usize, payload_off: usize },
}

impl<S> PingStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_state: ReadState::Header {
                buf: [0; 4],
                filled: 0,
            },
            write_state: WriteState::Idle,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PingStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.read_state {
                ReadState::Header { buf: hdr, filled } => {
                    let mut tmp = ReadBuf::new(&mut hdr[*filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            *filled += n;
                            if *filled < 4 {
                                return Poll::Pending;
                            }
                            let size = u32::from_be_bytes(*hdr);
                            if size == 0 {
                                *filled = 0;
                                continue;
                            }
                            this.read_state = ReadState::Body { remaining: size };
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ReadState::Body { remaining } => {
                    let want = (*remaining as usize).min(buf.remaining());
                    if want == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let mut tmp = vec![0u8; want];
                    let mut rbuf = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rbuf) {
                        Poll::Ready(Ok(())) => {
                            let n = rbuf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            buf.put_slice(&tmp[..n]);
                            *remaining -= n as u32;
                            if *remaining == 0 {
                                this.read_state = ReadState::Header {
                                    buf: [0; 4],
                                    filled: 0,
                                };
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PingStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        loop {
            match &mut this.write_state {
                WriteState::Idle => {
                    let len = buf.len() as u32;
                    this.write_state = WriteState::Header {
                        hdr: len.to_be_bytes(),
                        sent: 0,
                        payload_off: 0,
                    };
                }
                WriteState::Header {
                    hdr,
                    sent,
                    payload_off,
                } => {
                    if *sent < 4 {
                        match Pin::new(&mut this.inner).poll_write(cx, &hdr[*sent..]) {
                            Poll::Ready(Ok(0)) => return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())),
                            Poll::Ready(Ok(n)) => *sent += n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                        continue;
                    }
                    match Pin::new(&mut this.inner).poll_write(cx, &buf[*payload_off..]) {
                        Poll::Ready(Ok(0)) => return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())),
                        Poll::Ready(Ok(n)) => {
                            *payload_off += n;
                            if *payload_off == buf.len() {
                                this.write_state = WriteState::Idle;
                                return Poll::Ready(Ok(buf.len()));
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
