use trussed::{
    api::reply,
    client::{ClientResult, CryptoClient},
    types::{
        KeyId, KeySerialization, Location, Mechanism, SignatureSerialization, StorageAttributes,
    },
};

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

    fn serialize_rsa2048pkcs_key(
        &mut self,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::Rsa2048Pkcs1v15, key, format)
    }

    fn deserialize_rsa2048pkcs_key<'c>(
        &'c mut self,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.deserialize_key(
            Mechanism::Rsa2048Pkcs1v15,
            serialized_key,
            format,
            attributes,
        )
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

    fn serialize_rsa3072pkcs_key(
        &mut self,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::Rsa3072Pkcs1v15, key, format)
    }

    fn deserialize_rsa3072pkcs_key<'c>(
        &'c mut self,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.deserialize_key(
            Mechanism::Rsa3072Pkcs1v15,
            serialized_key,
            format,
            attributes,
        )
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

    fn serialize_rsa4096pkcs_key(
        &mut self,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::Rsa4096Pkcs1v15, key, format)
    }

    fn deserialize_rsa4096pkcs_key<'c>(
        &'c mut self,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.deserialize_key(
            Mechanism::Rsa4096Pkcs1v15,
            serialized_key,
            format,
            attributes,
        )
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

    fn decrypt_rsa4096pkcs<'c>(
        &'c mut self,
        key: KeyId,
        ciphertext: &[u8],
    ) -> ClientResult<'c, reply::Decrypt, Self> {
        self.decrypt(Mechanism::Rsa4096Pkcs1v15, key, ciphertext, &[], &[], &[])
    }
}
