use byteorder::ReadBytesExt;
use std::io;
use std::io::prelude::*;
use std::net::TcpStream;
#[cfg(feature = "unix_socket")]
use unix_socket::UnixStream;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, RawHandle};

use {SslMode, ConnectError, ConnectParams, ConnectTarget};
use io::{NegotiateSsl, StreamWrapper};
use message::{self, WriteMessage};
use message::FrontendMessage::SslRequest;

const DEFAULT_PORT: u16 = 5432;

/// A connection to the Postgres server.
///
/// It implements `Read`, `Write` and `StreamWrapper`, as well as `AsRawFd` on
/// Unix platforms and `AsRawHandle` on Windows platforms.
pub struct Stream(InternalStream);

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl StreamWrapper for Stream {
    fn get_ref(&self) -> &Stream {
        self
    }

    fn get_mut(&mut self) -> &mut Stream {
        self
    }
}

#[cfg(unix)]
impl AsRawFd for Stream {
    fn as_raw_fd(&self) -> RawFd {
        match self.0 {
            InternalStream::Tcp(ref s) => s.as_raw_fd(),
            #[cfg(feature = "unix_socket")]
            InternalStream::Unix(ref s) => s.as_raw_fd(),
        }
    }
}

#[cfg(windows)]
impl AsRawHandle for Stream {
    fn as_raw_handle(&self) -> RawHandle {
        // Unix sockets aren't supported on windows, so no need to match
        match self.0 {
            InternalStream::Tcp(ref s) => s.as_raw_handle(),
        }
    }
}

enum InternalStream {
    Tcp(TcpStream),
    #[cfg(feature = "unix_socket")]
    Unix(UnixStream),
}

impl Read for InternalStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            InternalStream::Tcp(ref mut s) => s.read(buf),
            #[cfg(feature = "unix_socket")]
            InternalStream::Unix(ref mut s) => s.read(buf),
        }
    }
}

impl Write for InternalStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            InternalStream::Tcp(ref mut s) => s.write(buf),
            #[cfg(feature = "unix_socket")]
            InternalStream::Unix(ref mut s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            InternalStream::Tcp(ref mut s) => s.flush(),
            #[cfg(feature = "unix_socket")]
            InternalStream::Unix(ref mut s) => s.flush(),
        }
    }
}

fn open_socket(params: &ConnectParams) -> Result<InternalStream, ConnectError> {
    let port = params.port.unwrap_or(DEFAULT_PORT);
    match params.target {
        ConnectTarget::Tcp(ref host) => {
            Ok(try!(TcpStream::connect(&(&**host, port)).map(InternalStream::Tcp)))
        }
        #[cfg(feature = "unix_socket")]
        ConnectTarget::Unix(ref path) => {
            let mut path = path.clone();
            path.push(&format!(".s.PGSQL.{}", port));
            Ok(try!(UnixStream::connect(&path).map(InternalStream::Unix)))
        }
    }
}

pub fn initialize_stream<N>(params: &ConnectParams, ssl: &mut SslMode<N>)
                            -> Result<Box<StreamWrapper>, ConnectError>
        where N: NegotiateSsl {
    let mut socket = Stream(try!(open_socket(params)));

    let (ssl_required, negotiator) = match *ssl {
        SslMode::None => return Ok(Box::new(socket)),
        SslMode::Prefer(ref mut negotiator) => (false, negotiator),
        SslMode::Require(ref mut negotiator) => (true, negotiator),
    };

    try!(socket.write_message(&SslRequest { code: message::SSL_CODE }));
    try!(socket.flush());

    if try!(socket.read_u8()) == 'N' as u8 {
        if ssl_required {
            return Err(ConnectError::NoSslSupport);
        } else {
            return Ok(Box::new(socket));
        }
    }

    // Postgres doesn't support SSL over unix sockets
    let host = match params.target {
        ConnectTarget::Tcp(ref host) => host,
        #[cfg(feature = "unix_socket")]
        ConnectTarget::Unix(_) => return Err(ConnectError::BadResponse)
    };

    match negotiator.negotiate_ssl(host, socket) {
        Ok(stream) => Ok(stream),
        Err(err) => Err(ConnectError::SslError(err))
    }
}
