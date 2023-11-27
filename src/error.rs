#[cfg(feature = "hustoj")]
type SqlxError = sqlx::Error;
#[cfg(not(feature = "hustoj"))]
type SqlxError = std::convert::Infallible;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("input/output error: {0}")]
    IOError(std::io::Error),
    #[error("cannot parse TOML: {0}")]
    TOMLParseError(toml::de::Error),
    #[error("cannot parse byte value: {0}")]
    ByteParseError(byte_unit::ParseError),
    #[error("wrong log level: {0}")]
    BadLogLevel(String),
    #[error("non-UTF8 path: {0}")]
    BadPathEncoding(String),
    #[error("systemd error: {0}")]
    SystemdError(systemd_run::Error),
    #[error("unconfigured language: {0}")]
    UnconfiguredLanguage(String),
    #[error("bad solution ID: {0}")]
    BadSolutionID(String),
    #[error("SQL error: {0}")]
    SQLError(SqlxError),
    #[error("bad configuration for program: {0}")]
    BadProblem(i32),
    #[error("message is not UTF-8: {0}")]
    NonUtf8Msg(std::string::FromUtf8Error),
}

pub type Result<T> = std::result::Result<T, Error>;
