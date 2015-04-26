use std::io;
use std::io::prelude::*;
use std::mem;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use types::Oid;
use util;

use self::BackendMessage::*;
use self::FrontendMessage::*;

pub const PROTOCOL_VERSION: u32 = 0x0003_0000;
pub const CANCEL_CODE: u32 = 80877102;
#[allow(dead_code)] // only used with openssl feature
pub const SSL_CODE: u32 = 80877103;

pub enum BackendMessage {
    AuthenticationCleartextPassword,
    AuthenticationGSS,
    AuthenticationKerberosV5,
    AuthenticationMD5Password {
        salt: [u8; 4]
    },
    AuthenticationOk,
    AuthenticationSCMCredential,
    AuthenticationSSPI,
    BackendKeyData {
        process_id: u32,
        secret_key: u32
    },
    BindComplete,
    CloseComplete,
    CommandComplete {
        tag: String,
    },
    CopyInResponse {
        format: u8,
        column_formats: Vec<u16>,
    },
    DataRow {
        row: Vec<Option<Vec<u8>>>
    },
    EmptyQueryResponse,
    ErrorResponse {
        fields: Vec<(u8, String)>
    },
    NoData,
    NoticeResponse {
        fields: Vec<(u8, String)>
    },
    NotificationResponse {
        pid: u32,
        channel: String,
        payload: String,
    },
    ParameterDescription {
        types: Vec<Oid>
    },
    ParameterStatus {
        parameter: String,
        value: String,
    },
    ParseComplete,
    PortalSuspended,
    ReadyForQuery {
        _state: u8
    },
    RowDescription {
        descriptions: Vec<RowDescriptionEntry>
    }
}

pub struct RowDescriptionEntry {
    pub name: String,
    pub table_oid: Oid,
    pub column_id: i16,
    pub type_oid: Oid,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format: i16
}

pub enum FrontendMessage<'a> {
    Bind {
        portal: &'a str,
        statement: &'a str,
        formats: &'a [i16],
        values: &'a [Option<Vec<u8>>],
        result_formats: &'a [i16]
    },
    CancelRequest {
        code: u32,
        process_id: u32,
        secret_key: u32,
    },
    Close {
        variant: u8,
        name: &'a str
    },
    CopyData {
        data: &'a [u8],
    },
    CopyDone,
    CopyFail {
        message: &'a str
    },
    Describe {
        variant: u8,
        name: &'a str
    },
    Execute {
        portal: &'a str,
        max_rows: i32
    },
    Parse {
        name: &'a str,
        query: &'a str,
        param_types: &'a [Oid]
    },
    PasswordMessage {
        password: &'a str
    },
    Query {
        query: &'a str
    },
    #[allow(dead_code)] // only used with openssl feature
    SslRequest {
        code: u32
    },
    StartupMessage {
        version: u32,
        parameters: &'a [(String, String)]
    },
    Sync,
    Terminate
}

#[doc(hidden)]
trait WriteCStr {
    fn write_cstr(&mut self, s: &str) -> io::Result<()>;
}

impl<W: Write> WriteCStr for W {
    fn write_cstr(&mut self, s: &str) -> io::Result<()> {
        try!(self.write_all(s.as_bytes()));
        Ok(try!(self.write_u8(0)))
    }
}

#[doc(hidden)]
pub trait WriteMessage {
    fn write_message(&mut self, &FrontendMessage) -> io::Result<()> ;
}

impl<W: Write> WriteMessage for W {
    fn write_message(&mut self, message: &FrontendMessage) -> io::Result<()> {
        let mut buf = vec![];
        let mut ident = None;

        match *message {
            Bind { portal, statement, formats, values, result_formats } => {
                ident = Some(b'B');
                try!(buf.write_cstr(portal));
                try!(buf.write_cstr(statement));

                try!(buf.write_u16::<BigEndian>(formats.len() as u16));
                for &format in formats {
                    try!(buf.write_i16::<BigEndian>(format));
                }

                try!(buf.write_u16::<BigEndian>(values.len() as u16));
                for value in values {
                    match *value {
                        None => try!(buf.write_i32::<BigEndian>(-1)),
                        Some(ref value) => {
                            try!(buf.write_i32::<BigEndian>(value.len() as i32));
                            try!(buf.write_all(&**value));
                        }
                    }
                }

                try!(buf.write_u16::<BigEndian>(result_formats.len() as u16));
                for &format in result_formats {
                    try!(buf.write_i16::<BigEndian>(format));
                }
            }
            CancelRequest { code, process_id, secret_key } => {
                try!(buf.write_u32::<BigEndian>(code));
                try!(buf.write_u32::<BigEndian>(process_id));
                try!(buf.write_u32::<BigEndian>(secret_key));
            }
            Close { variant, name } => {
                ident = Some(b'C');
                try!(buf.write_u8(variant));
                try!(buf.write_cstr(name));
            }
            CopyData { data } => {
                ident = Some(b'd');
                try!(buf.write_all(data));
            }
            CopyDone => ident = Some(b'c'),
            CopyFail { message } => {
                ident = Some(b'f');
                try!(buf.write_cstr(message));
            }
            Describe { variant, name } => {
                ident = Some(b'D');
                try!(buf.write_u8(variant));
                try!(buf.write_cstr(name));
            }
            Execute { portal, max_rows } => {
                ident = Some(b'E');
                try!(buf.write_cstr(portal));
                try!(buf.write_i32::<BigEndian>(max_rows));
            }
            Parse { name, query, param_types } => {
                ident = Some(b'P');
                try!(buf.write_cstr(name));
                try!(buf.write_cstr(query));
                try!(buf.write_u16::<BigEndian>(param_types.len() as u16));
                for &ty in param_types {
                    try!(buf.write_u32::<BigEndian>(ty));
                }
            }
            PasswordMessage { password } => {
                ident = Some(b'p');
                try!(buf.write_cstr(password));
            }
            Query { query } => {
                ident = Some(b'Q');
                try!(buf.write_cstr(query));
            }
            StartupMessage { version, parameters } => {
                try!(buf.write_u32::<BigEndian>(version));
                for &(ref k, ref v) in parameters {
                    try!(buf.write_cstr(&**k));
                    try!(buf.write_cstr(&**v));
                }
                try!(buf.write_u8(0));
            }
            SslRequest { code } => try!(buf.write_u32::<BigEndian>(code)),
            Sync => ident = Some(b'S'),
            Terminate => ident = Some(b'X'),
        }

        if let Some(ident) = ident {
            try!(self.write_u8(ident));
        }

        // add size of length value
        try!(self.write_u32::<BigEndian>((buf.len() + mem::size_of::<u32>()) as u32));
        try!(self.write_all(&*buf));

        Ok(())
    }
}

#[doc(hidden)]
trait ReadCStr {
    fn read_cstr(&mut self) -> io::Result<String>;
}

impl<R: BufRead> ReadCStr for R {
    fn read_cstr(&mut self) -> io::Result<String> {
        let mut buf = vec![];
        try!(self.read_until(0, &mut buf));
        buf.pop();
        String::from_utf8(buf).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }
}

#[doc(hidden)]
pub trait ReadMessage {
    fn read_message(&mut self) -> io::Result<BackendMessage>;
}

impl<R: BufRead> ReadMessage for R {
    fn read_message(&mut self) -> io::Result<BackendMessage> {
        let ident = try!(self.read_u8());

        // subtract size of length value
        let len = try!(self.read_u32::<BigEndian>()) - mem::size_of::<u32>() as u32;
        let mut rdr = self.by_ref().take(len as u64);

        let ret = match ident {
            b'1' => ParseComplete,
            b'2' => BindComplete,
            b'3' => CloseComplete,
            b'A' => NotificationResponse {
                pid: try!(rdr.read_u32::<BigEndian>()),
                channel: try!(rdr.read_cstr()),
                payload: try!(rdr.read_cstr())
            },
            b'C' => CommandComplete { tag: try!(rdr.read_cstr()) },
            b'D' => try!(read_data_row(&mut rdr)),
            b'E' => ErrorResponse { fields: try!(read_fields(&mut rdr)) },
            b'G' => {
                let format = try!(rdr.read_u8());
                let mut column_formats = vec![];
                for _ in 0..try!(rdr.read_u16::<BigEndian>()) {
                    column_formats.push(try!(rdr.read_u16::<BigEndian>()));
                }
                CopyInResponse {
                    format: format,
                    column_formats: column_formats,
                }
            }
            b'I' => EmptyQueryResponse,
            b'K' => BackendKeyData {
                process_id: try!(rdr.read_u32::<BigEndian>()),
                secret_key: try!(rdr.read_u32::<BigEndian>())
            },
            b'n' => NoData,
            b'N' => NoticeResponse { fields: try!(read_fields(&mut rdr)) },
            b'R' => try!(read_auth_message(&mut rdr)),
            b's' => PortalSuspended,
            b'S' => ParameterStatus {
                parameter: try!(rdr.read_cstr()),
                value: try!(rdr.read_cstr())
            },
            b't' => try!(read_parameter_description(&mut rdr)),
            b'T' => try!(read_row_description(&mut rdr)),
            b'Z' => ReadyForQuery { _state: try!(rdr.read_u8()) },
            _ => return Err(io::Error::new(io::ErrorKind::Other, "unexpected message tag")),
        };
        if rdr.limit() != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "didn't read entire message"));
        }
        Ok(ret)
    }
}

fn read_fields<R: BufRead>(buf: &mut R) -> io::Result<Vec<(u8, String)>> {
    let mut fields = vec![];
    loop {
        let ty = try!(buf.read_u8());
        if ty == 0 {
            break;
        }

        fields.push((ty, try!(buf.read_cstr())));
    }

    Ok(fields)
}

fn read_data_row<R: BufRead>(buf: &mut R) -> io::Result<BackendMessage> {
    let len = try!(buf.read_u16::<BigEndian>()) as usize;
    let mut values = Vec::with_capacity(len);

    for _ in 0..len {
        let val = match try!(buf.read_i32::<BigEndian>()) {
            -1 => None,
            len => {
                let mut data = Vec::with_capacity(len as usize);
                data.extend((0..len).map(|_| 0));
                try!(util::read_all(buf, &mut data));
                Some(data)
            }
        };
        values.push(val);
    }

    Ok(DataRow { row: values })
}

fn read_auth_message<R: Read>(buf: &mut R) -> io::Result<BackendMessage> {
    Ok(match try!(buf.read_i32::<BigEndian>()) {
        0 => AuthenticationOk,
        2 => AuthenticationKerberosV5,
        3 => AuthenticationCleartextPassword,
        5 => {
            let mut salt = [0; 4];
            try!(util::read_all(buf, &mut salt));
            AuthenticationMD5Password { salt: salt }
        },
        6 => AuthenticationSCMCredential,
        7 => AuthenticationGSS,
        9 => AuthenticationSSPI,
        _ => return Err(io::Error::new(io::ErrorKind::Other, "unexpected authentication tag")),
    })
}

fn read_parameter_description<R: Read>(buf: &mut R) -> io::Result<BackendMessage> {
    let len = try!(buf.read_u16::<BigEndian>()) as usize;
    let mut types = Vec::with_capacity(len);

    for _ in 0..len {
        types.push(try!(buf.read_u32::<BigEndian>()));
    }

    Ok(ParameterDescription { types: types })
}

fn read_row_description<R: BufRead>(buf: &mut R) -> io::Result<BackendMessage> {
    let len = try!(buf.read_u16::<BigEndian>()) as usize;
    let mut types = Vec::with_capacity(len);

    for _ in 0..len {
        types.push(RowDescriptionEntry {
            name: try!(buf.read_cstr()),
            table_oid: try!(buf.read_u32::<BigEndian>()),
            column_id: try!(buf.read_i16::<BigEndian>()),
            type_oid: try!(buf.read_u32::<BigEndian>()),
            type_size: try!(buf.read_i16::<BigEndian>()),
            type_modifier: try!(buf.read_i32::<BigEndian>()),
            format: try!(buf.read_i16::<BigEndian>())
        })
    }

    Ok(RowDescription { descriptions: types })
}
