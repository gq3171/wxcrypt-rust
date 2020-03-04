use base64::DecodeError;
use std::fmt;
use std::error;
use block_modes;
use quick_xml::de::DeError;

#[derive(Debug)]
pub enum WxError {
    Base64Err(DecodeError),
    BlockModeErr(block_modes::BlockModeError),
    InvalidKeyIvLength(block_modes::InvalidKeyIvLength),
    QuickXmlErr(DeError),
}

pub type Result<T> = std::result::Result<T, WxError>;

impl fmt::Display for WxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            WxError::Base64Err(ref err) => write!(f, "{}", err),
            WxError::BlockModeErr(ref err) => write!(f, "{}", err),
            WxError::InvalidKeyIvLength(ref err) => write!(f, "{}", err),
            WxError::QuickXmlErr(ref err) => write!(f, "{}", err),
        }
    }
}

impl error::Error for WxError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            WxError::Base64Err(ref err) => Some(err),
            WxError::BlockModeErr(ref err) => Some(err),
            WxError::InvalidKeyIvLength(ref err) => Some(err),
            WxError::QuickXmlErr(ref err) => Some(err),
        }
    }
}

impl From<DecodeError> for WxError {
    fn from(err: DecodeError) -> Self {
        WxError::Base64Err(err)
    }
}

impl From<block_modes::BlockModeError> for WxError {
    fn from(err: block_modes::BlockModeError) -> Self {
        WxError::BlockModeErr(err)
    }
}

impl From<block_modes::InvalidKeyIvLength> for WxError {
    fn from(err: block_modes::InvalidKeyIvLength) -> Self {
        WxError::InvalidKeyIvLength(err)
    }
}

impl From<DeError> for WxError {
    fn from(err: DeError) -> Self {
        WxError::QuickXmlErr(err)
    }
}