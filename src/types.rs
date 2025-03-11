// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use heapless_bytes::Bytes;
use serde::{Deserialize, Serialize};
use trussed::types::SerializedKey;

/// Error type
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Error occured during serialization
    SerializeBufferFull,
    /// Serialization failed. This indicates an internal error.
    /// If encountered, please report
    SerializeCustom,
    /// The structure failed to deserialize
    Deseralization,
}

/// Error during serialization.
/// This means that the serialization failed, likely
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Error {
    kind: ErrorKind,
}

/// Structure containing the public part of an RSA key
///
/// Given how Trussed extensions are implemented, this structure cannot be sent as-is to the backend,
/// and is instead sent as a byte array.
/// You can use [`serialize`](RsaPublicParts::serialize) and [`deserialize`](RsaPublicParts::deserialize) functions
/// to convert to and from tha byte array format
#[derive(Serialize, Deserialize)]
pub struct RsaPublicParts<'d> {
    /// big-endian integer representing the modulus of an RSA key
    pub n: &'d [u8],
    /// big-endian integer representing the public exponent of an RSA key
    pub e: &'d [u8],
}

impl<'d> RsaPublicParts<'d> {
    pub fn serialize(&self) -> Result<Bytes<MAX_SERIALIZED_KEY_LENGTH>, Error> {
        use postcard::Error as PError;
        let vec = postcard::to_vec(self).map_err(|err| match err {
            PError::SerializeBufferFull => Error {
                kind: ErrorKind::SerializeBufferFull,
            },
            _ => Error {
                kind: ErrorKind::SerializeCustom,
            },
        })?;
        Ok(Bytes::from(vec))
    }
    pub fn deserialize(data: &'d [u8]) -> Result<Self, Error> {
        postcard::from_bytes(data).map_err(|_err| Error {
            kind: ErrorKind::Deseralization,
        })
    }
}

/// Format for private RSA key import
///
/// Given how Trussed extensions are implemented, this structure cannot be sent as-is to the backend,
/// and is instead sent as a byte array.
/// You can use [`serialize`](RsaImportFormat::serialize) and [`deserialize`](RsaImportFormat::deserialize) functions
/// to convert to and from tha byte array format
#[derive(Debug, Deserialize, Serialize)]
pub struct RsaImportFormat<'d> {
    /// big-endian integer representing the exponent of the public part of the RSA key
    pub e: &'d [u8],
    /// big-endian integer representing the first prime of a private RSA key
    pub p: &'d [u8],
    /// big-endian integer representing the second prime of a private RSA key
    pub q: &'d [u8],
}

impl<'d> RsaImportFormat<'d> {
    pub fn serialize(&self) -> Result<Bytes<MAX_SERIALIZED_KEY_LENGTH>, Error> {
        use postcard::Error as PError;
        let vec = postcard::to_vec(self).map_err(|err| match err {
            PError::SerializeBufferFull => Error {
                kind: ErrorKind::SerializeBufferFull,
            },
            _ => Error {
                kind: ErrorKind::SerializeCustom,
            },
        })?;
        Ok(Bytes::from(vec))
    }
    pub fn deserialize(data: &'d [u8]) -> Result<Self, Error> {
        postcard::from_bytes(data).map_err(|_err| Error {
            kind: ErrorKind::Deseralization,
        })
    }
}
