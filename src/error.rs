use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Not an archive this library reads (no RAR signature, no ZIP directory).
    NotArchive,
    /// A RAR 1.3 / 1.4 archive (`RE~^`): not supported.
    OldFormat,
    /// A feature this build can't read yet (encryption, volumes, …).
    Unsupported(&'static str),
    /// Damaged or malicious data.
    Corrupt(&'static str),
    /// The archive is encrypted and no password was given.
    NeedPassword,
    /// The password is wrong.
    BadPassword,
    /// Data decoded but its checksum doesn't match.
    BadChecksum(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Corrupt("unexpected end of data")
        } else {
            Error::Io(e)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::NotArchive => f.write_str("not a RAR or ZIP archive"),
            Error::OldFormat => f.write_str("RAR 1.3 / 1.4 archives are not supported"),
            Error::Unsupported(what) => write!(f, "not supported yet: {what}"),
            Error::Corrupt(what) => write!(f, "damaged archive: {what}"),
            Error::NeedPassword => f.write_str("a password is needed"),
            Error::BadPassword => f.write_str("wrong password"),
            Error::BadChecksum(name) => write!(f, "checksum mismatch: {name}"),
        }
    }
}

impl std::error::Error for Error {}
