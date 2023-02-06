use serde::{Deserialize, Serialize};

/// Structure containing the public part of an RSA key
#[derive(Serialize, Deserialize)]
pub struct RsaPublicParts<'d> {
    /// big-endian integer representing the modulus of an RSA key
    pub n: &'d [u8],
    /// big-endian integer representing the public exponent of an RSA key
    pub e: &'d [u8],
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RsaImportFormat<'d> {
    /// big-endian integer representing the modulus of an RSA key
    pub e: &'d [u8],
    /// big-endian integer representing the first prime of a private RSA key
    pub p: &'d [u8],
    /// big-endian integer representing the second prime of a private RSA key
    pub q: &'d [u8],
}
