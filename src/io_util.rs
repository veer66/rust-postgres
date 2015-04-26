#[cfg(feature = "openssl")]
use openssl::ssl::{SslStream, SslContext};
use std::io;
use std::io::prelude::*;
use std::net::TcpStream;
#[cfg(feature = "unix_socket")]
use unix_socket::UnixStream;

use {ConnectParams, SslMode, ConnectTarget, ConnectError};
const DEFAULT_PORT: u16 = 5432;

pub enum InternalStream {
    Normal(BaseStream),
    #[cfg(feature = "openssl")]
    Ssl(SslStream<BaseStream>),
}

impl Read for InternalStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            InternalStream::Normal(ref mut s) => s.read(buf),
            #[cfg(feature = "openssl")]
            InternalStream::Ssl(ref mut s) => s.read(buf),
        }
    }
}

impl Write for InternalStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            InternalStream::Normal(ref mut s) => s.write(buf),
            #[cfg(feature = "openssl")]
            InternalStream::Ssl(ref mut s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            InternalStream::Normal(ref mut s) => s.flush(),
            #[cfg(feature = "openssl")]
            InternalStream::Ssl(ref mut s) => s.flush(),
        }
    }
}

enum BaseStream {
    Tcp(TcpStream),
    #[cfg(feature = "unix_socket")]
    Unix(UnixStream),
}

impl Read for BaseStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            BaseStream::Tcp(ref mut s) => s.read(buf),
            #[cfg(feature = "unix_socket")]
            BaseStream::Unix(ref mut s) => s.read(buf),
        }
    }
}

impl Write for BaseStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            BaseStream::Tcp(ref mut s) => s.write(buf),
            #[cfg(feature = "unix_socket")]
            BaseStream::Unix(ref mut s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            BaseStream::Tcp(ref mut s) => s.flush(),
            #[cfg(feature = "unix_socket")]
            BaseStream::Unix(ref mut s) => s.flush(),
        }
    }
}

fn open_socket(params: &ConnectParams) -> Result<BaseStream, ConnectError> {
    let port = params.port.unwrap_or(DEFAULT_PORT);
    match params.target {
        ConnectTarget::Tcp(ref host) => {
            Ok(try!(TcpStream::connect(&(&**host, port)).map(BaseStream::Tcp)))
        }
        #[cfg(feature = "unix_socket")]
        ConnectTarget::Unix(ref path) => {
            let mut path = path.clone();
            path.push(&format!(".s.PGSQL.{}", port));
            Ok(try!(UnixStream::connect(&path).map(BaseStream::Unix)))
        }
    }
}

pub fn initialize_stream(params: &ConnectParams, ssl: &SslMode)
                         -> Result<InternalStream, ConnectError> {
    #[cfg(feature = "openssl")]
    fn handle_ssl(mut socket: BaseStream, ssl_required: bool, ctx: &SslContext)
                  -> Result<InternalStream, ConnectError> {
        use byteorder::ReadBytesExt;
        use message;
        use message::WriteMessage;
        use message::FrontendMessage::SslRequest;

        try!(socket.write_message(&SslRequest { code: message::SSL_CODE }));
        try!(socket.flush());

        if try!(socket.read_u8()) == 'N' as u8 {
            if ssl_required {
                return Err(ConnectError::NoSslSupport);
            } else {
                return Ok(InternalStream::Normal(socket));
            }
        }

        match SslStream::new(ctx, socket) {
            Ok(stream) => Ok(InternalStream::Ssl(stream)),
            Err(err) => Err(ConnectError::SslError(err))
        }
    }

    let socket = try!(open_socket(params));
    match *ssl {
        SslMode::None => Ok(InternalStream::Normal(socket)),
        #[cfg(feature = "openssl")]
        SslMode::Prefer(ref ctx) => handle_ssl(socket, false, ctx),
        #[cfg(feature = "openssl")]
        SslMode::Require(ref ctx) => handle_ssl(socket, true, ctx)
    }

}
