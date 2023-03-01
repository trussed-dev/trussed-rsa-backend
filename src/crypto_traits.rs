// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use trussed::{
    api::{
        reply,
        request::{DeserializeKey, UnsafeInjectKey},
    },
    client::{ClientError, ClientResult, CryptoClient},
    types::{
        KeyId, KeySerialization, Location, Mechanism, SignatureSerialization, StorageAttributes,
    },
};

use crate::{RsaImportFormat, RsaPublicParts};

impl<C: CryptoClient> Rsa2048Pkcs1v15 for C {}

/// Helper trait to work with RSA 2048 bit keys through a [`Client`](trussed::Client)
///
/// This trait is implemented by all implementors of [`CryptoClient`](trussed::client::CryptoClient)
pub trait Rsa2048Pkcs1v15: CryptoClient {
    fn generate_rsa2048pkcs_private_key(
        &mut self,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.generate_key(
            Mechanism::Rsa2048Pkcs1v15,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn derive_rsa2048pkcs_public_key(
        &mut self,
        shared_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::Rsa2048Pkcs1v15,
            shared_key,
            None,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    /// Serializes an RSA 2048 bit key.
    ///
    /// The resulting [`serialized_key`](trussed::api::reply::SerializeKey::serialized_key) contains a buffer of the parts of the key
    /// as a serialized [`RsaPublicParts`](crate::RsaPublicParts):
    /// ```
    ///# #[cfg(feature = "virt")]
    ///# {
    ///# use trussed_rsa_alloc::*;
    ///# use trussed::{syscall,types::Location::{Volatile,Internal}};
    ///# virt::with_ram_client("rsa tests", |mut client| {
    ///# let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;
    ///# let pk = syscall!(client.derive_rsa2048pkcs_public_key(sk, Volatile)).key;
    /// let serialized_key = syscall!(client.serialize_rsa2048_key(pk)).serialized_key;
    /// let public_key = RsaPublicParts::deserialize(&serialized_key).unwrap();
    ///# })
    ///# }
    ///```
    fn serialize_rsa2048_key(&mut self, key: KeyId) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::Rsa2048Pkcs1v15, key, KeySerialization::RsaParts)
    }

    fn deserialize_rsa2048_public_key<'c>(
        &'c mut self,
        key_parts: RsaPublicParts,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.request(DeserializeKey {
            mechanism: Mechanism::Rsa2048Pkcs1v15,
            serialized_key: key_parts.serialize().map_err(|_err| {
                error!("Failed to serialize key parts: {:?}", _err);
                ClientError::DataTooLarge
            })?,
            format: KeySerialization::RsaParts,
            attributes,
        })
    }

    fn sign_rsa2048pkcs<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(
            Mechanism::Rsa2048Pkcs1v15,
            key,
            message,
            SignatureSerialization::Raw,
        )
    }

    fn verify_rsa2048pkcs<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
    ) -> ClientResult<'c, reply::Verify, Self> {
        self.verify(
            Mechanism::Rsa2048Pkcs1v15,
            key,
            message,
            signature,
            SignatureSerialization::Raw,
        )
    }

    fn unsafe_inject_rsa2048<'c>(
        &'c mut self,
        key_parts: RsaImportFormat,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::UnsafeInjectKey, Self> {
        self.request(UnsafeInjectKey {
            mechanism: Mechanism::Rsa2048Pkcs1v15,
            raw_key: key_parts.serialize().map_err(|_err| {
                error!("Failed to serialize key parts: {:?}", _err);
                ClientError::DataTooLarge
            })?,
            attributes,
            format: KeySerialization::RsaParts,
        })
    }

    fn decrypt_rsa2048pkcs<'c>(
        &'c mut self,
        key: KeyId,
        ciphertext: &[u8],
    ) -> ClientResult<'c, reply::Decrypt, Self> {
        self.decrypt(Mechanism::Rsa2048Pkcs1v15, key, ciphertext, &[], &[], &[])
    }
}

impl<C: CryptoClient> Rsa3072Pkcs1v15 for C {}

/// Helper trait to work with RSA 3072 bit keys through a [`Client`](trussed::Client)
///
/// This trait is implemented by all implementors of [`CryptoClient`](trussed::client::CryptoClient)
pub trait Rsa3072Pkcs1v15: CryptoClient {
    fn generate_rsa3072pkcs_private_key(
        &mut self,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.generate_key(
            Mechanism::Rsa3072Pkcs1v15,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn derive_rsa3072pkcs_public_key(
        &mut self,
        shared_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::Rsa3072Pkcs1v15,
            shared_key,
            None,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    /// Serializes an RSA 3072 bit key.
    ///
    /// The resulting [`serialized_key`](trussed::api::reply::SerializeKey::serialized_key) contains a buffer of the parts of the key
    /// as a serialized [`RsaPublicParts`](crate::RsaPublicParts):
    /// ```
    ///# #[cfg(feature = "virt")]
    ///# {
    ///# use trussed_rsa_alloc::*;
    ///# use trussed::{syscall,types::Location::{Volatile,Internal}};
    ///# virt::with_ram_client("rsa tests", |mut client| {
    ///# let sk = syscall!(client.generate_rsa3072pkcs_private_key(Internal)).key;
    ///# let pk = syscall!(client.derive_rsa3072pkcs_public_key(sk, Volatile)).key;
    /// let serialized_key = syscall!(client.serialize_rsa3072_key(pk)).serialized_key;
    /// let public_key = RsaPublicParts::deserialize(&serialized_key).unwrap();
    ///# })
    ///# }
    ///```
    fn serialize_rsa3072_key(&mut self, key: KeyId) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::Rsa3072Pkcs1v15, key, KeySerialization::RsaParts)
    }

    fn deserialize_rsa3072_public_key<'c>(
        &'c mut self,
        key_parts: RsaPublicParts,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.request(DeserializeKey {
            mechanism: Mechanism::Rsa3072Pkcs1v15,
            serialized_key: key_parts.serialize().map_err(|_err| {
                error!("Failed to serialize key parts: {:?}", _err);
                ClientError::DataTooLarge
            })?,
            format: KeySerialization::RsaParts,
            attributes,
        })
    }

    fn sign_rsa3072pkcs<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(
            Mechanism::Rsa3072Pkcs1v15,
            key,
            message,
            SignatureSerialization::Raw,
        )
    }

    fn verify_rsa3072pkcs<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
    ) -> ClientResult<'c, reply::Verify, Self> {
        self.verify(
            Mechanism::Rsa3072Pkcs1v15,
            key,
            message,
            signature,
            SignatureSerialization::Raw,
        )
    }

    fn unsafe_inject_rsa3072<'c>(
        &'c mut self,
        key_parts: RsaImportFormat,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::UnsafeInjectKey, Self> {
        self.request(UnsafeInjectKey {
            mechanism: Mechanism::Rsa3072Pkcs1v15,
            raw_key: key_parts.serialize().map_err(|_err| {
                error!("Failed to serialize key parts: {:?}", _err);
                ClientError::DataTooLarge
            })?,
            attributes,
            format: KeySerialization::RsaParts,
        })
    }

    fn decrypt_rsa3072pkcs<'c>(
        &'c mut self,
        key: KeyId,
        ciphertext: &[u8],
    ) -> ClientResult<'c, reply::Decrypt, Self> {
        self.decrypt(Mechanism::Rsa3072Pkcs1v15, key, ciphertext, &[], &[], &[])
    }
}

impl<C: CryptoClient> Rsa4096Pkcs1v15 for C {}

/// Helper trait to work with RSA 4096 bit keys through a [`Client`](trussed::Client)
///
/// This trait is implemented by all implementors of [`CryptoClient`](trussed::client::CryptoClient)
pub trait Rsa4096Pkcs1v15: CryptoClient {
    fn generate_rsa4096pkcs_private_key(
        &mut self,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.generate_key(
            Mechanism::Rsa4096Pkcs1v15,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn derive_rsa4096pkcs_public_key(
        &mut self,
        shared_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::Rsa4096Pkcs1v15,
            shared_key,
            None,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    /// Serializes an RSA 4096 bit key.
    ///
    /// The resulting [`serialized_key`](trussed::api::reply::SerializeKey::serialized_key) contains a buffer of the parts of the key
    /// as a serialized [`RsaPublicParts`](crate::RsaPublicParts):
    /// ```
    ///# #[cfg(feature = "virt")]
    ///# {
    ///# use trussed_rsa_alloc::*;
    ///# use trussed::{syscall,types::Location::{Volatile,Internal}};
    ///# virt::with_ram_client("rsa tests", |mut client| {
    ///# let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;
    ///# let pk = syscall!(client.derive_rsa4096pkcs_public_key(sk, Volatile)).key;
    /// let serialized_key = syscall!(client.serialize_rsa4096_key(pk)).serialized_key;
    /// let public_key = RsaPublicParts::deserialize(&serialized_key).unwrap();
    ///# })
    ///# }
    ///```
    fn serialize_rsa4096_key(&mut self, key: KeyId) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::Rsa4096Pkcs1v15, key, KeySerialization::RsaParts)
    }

    fn deserialize_rsa4096_public_key<'c>(
        &'c mut self,
        key_parts: RsaPublicParts,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.request(DeserializeKey {
            mechanism: Mechanism::Rsa4096Pkcs1v15,
            serialized_key: key_parts.serialize().map_err(|_err| {
                error!("Failed to serialize key parts: {:?}", _err);
                ClientError::DataTooLarge
            })?,
            format: KeySerialization::RsaParts,
            attributes,
        })
    }

    fn sign_rsa4096pkcs<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(
            Mechanism::Rsa4096Pkcs1v15,
            key,
            message,
            SignatureSerialization::Raw,
        )
    }

    fn verify_rsa4096pkcs<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
    ) -> ClientResult<'c, reply::Verify, Self> {
        self.verify(
            Mechanism::Rsa4096Pkcs1v15,
            key,
            message,
            signature,
            SignatureSerialization::Raw,
        )
    }

    fn unsafe_inject_rsa4096<'c>(
        &'c mut self,
        key_parts: RsaImportFormat,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::UnsafeInjectKey, Self> {
        self.request(UnsafeInjectKey {
            mechanism: Mechanism::Rsa4096Pkcs1v15,
            raw_key: key_parts.serialize().map_err(|_err| {
                error!("Failed to serialize key parts: {:?}", _err);
                ClientError::DataTooLarge
            })?,
            attributes,
            format: KeySerialization::RsaParts,
        })
    }

    fn decrypt_rsa4096pkcs<'c>(
        &'c mut self,
        key: KeyId,
        ciphertext: &[u8],
    ) -> ClientResult<'c, reply::Decrypt, Self> {
        self.decrypt(Mechanism::Rsa4096Pkcs1v15, key, ciphertext, &[], &[], &[])
    }
}
