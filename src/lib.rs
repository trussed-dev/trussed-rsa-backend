// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg_attr(not(feature = "std"), no_std)]

use heapless_bytes::Bytes;
use num_bigint_dig::traits::ModInverse;
use num_bigint_dig::BigUint;
use rsa::rand_core::{CryptoRng, RngCore};
use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::{
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    signature::hazmat::PrehashSigner,
    signature::SignatureEncoding,
    traits::PublicKeyParts,
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use trussed::{
    api::{reply, request, Reply, Request},
    backend::Backend,
    key,
    platform::Platform,
    service::{Keystore, ServiceResources},
    types::{
        CoreContext, KeyId, KeySerialization, Mechanism, Message, Signature, SignatureSerialization,
    },
    Error,
};

#[cfg(feature = "virt")]
pub mod virt;

#[macro_use]
extern crate delog;
generate_macros!();

#[macro_use]
extern crate alloc;

mod types;
pub use types::{RsaImportFormat, RsaPublicParts};
mod crypto_traits;
pub use crypto_traits::{Rsa2048Pkcs1v15, Rsa3072Pkcs1v15, Rsa4096Pkcs1v15};

pub const MECHANISMS: &[Mechanism] = &[
    Mechanism::Rsa2048Pkcs1v15,
    Mechanism::Rsa3072Pkcs1v15,
    Mechanism::Rsa4096Pkcs1v15,
    #[cfg(feature = "raw")]
    Mechanism::Rsa2048Raw,
    #[cfg(feature = "raw")]
    Mechanism::Rsa3072Raw,
    #[cfg(feature = "raw")]
    Mechanism::Rsa4096Raw,
];

/// Trussed [`Backend`][] implementation adding support for RSA
///
/// This implementation is done in software and requieres an allocator
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub struct SoftwareRsa;

/// The bool returned points at wether the mechanism is raw RSA
fn bits_and_kind_from_mechanism(mechanism: Mechanism) -> Result<(usize, key::Kind, bool), Error> {
    match mechanism {
        Mechanism::Rsa2048Pkcs1v15 => Ok((2048, key::Kind::Rsa2048, false)),
        Mechanism::Rsa3072Pkcs1v15 => Ok((3072, key::Kind::Rsa3072, false)),
        Mechanism::Rsa4096Pkcs1v15 => Ok((4096, key::Kind::Rsa4096, false)),
        Mechanism::Rsa2048Raw => Ok((2048, key::Kind::Rsa2048, true)),
        Mechanism::Rsa3072Raw => Ok((3072, key::Kind::Rsa3072, true)),
        Mechanism::Rsa4096Raw => Ok((4096, key::Kind::Rsa4096, true)),
        _ => Err(Error::RequestNotAvailable),
    }
}
fn derive_key(
    keystore: &mut impl Keystore,
    request: &request::DeriveKey,
    kind: key::Kind,
) -> Result<reply::DeriveKey, Error> {
    // Retrieve private key
    let base_key_id = &request.base_key;
    let priv_key_der = keystore
        .load_key(key::Secrecy::Secret, Some(kind), base_key_id)
        .unwrap_or_else(|_| panic!("Failed to load an RSA private key with the given ID"))
        .material;
    let priv_key = DecodePrivateKey::from_pkcs8_der(&priv_key_der)
        .unwrap_or_else(|_| panic!("Failed to deserialize an RSA private key from PKCS#8 DER"));

    // Derive and store public key
    let pub_key_der = RsaPublicKey::from(&priv_key)
        .to_public_key_der()
        .unwrap_or_else(|_| {
            panic!("Failed to derive an RSA public key or to serialize it to PKCS#8 DER")
        });

    let pub_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        kind,
        pub_key_der.as_ref(),
    )?;

    Ok(reply::DeriveKey { key: pub_key_id })
}

fn deserialize_pkcs_key(
    keystore: &mut impl Keystore,
    request: &request::DeserializeKey,
    bits: usize,
    kind: key::Kind,
) -> Result<reply::DeserializeKey, Error> {
    let pub_key: RsaPublicKey = DecodePublicKey::from_public_key_der(&request.serialized_key)
        .map_err(|_| Error::InvalidSerializedKey)?;

    if pub_key.size() != bits / 8 {
        return Err(Error::WrongKeyKind);
    }

    // We store our keys in PKCS#8 DER format
    let pub_key_der = pub_key
        .to_public_key_der()
        .unwrap_or_else(|_| panic!("Failed to serialize an RSA public key to PKCS#8 DER"));

    let pub_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        kind,
        pub_key_der.as_ref(),
    )?;

    Ok(reply::DeserializeKey { key: pub_key_id })
}

fn deserialize_parts_key(
    keystore: &mut impl Keystore,
    request: &request::DeserializeKey,
    bits: usize,
    kind: key::Kind,
) -> Result<reply::DeserializeKey, Error> {
    let parsed = RsaPublicParts::deserialize(&request.serialized_key).map_err(|_err| {
        error!("Failed to deserialize key parts");
        Error::InvalidSerializedKey
    })?;
    let n = BigUint::from_bytes_be(parsed.n);
    let e = BigUint::from_bytes_be(parsed.e);
    let pub_key = RsaPublicKey::new_unchecked(n, e);

    if pub_key.size() != bits / 8 {
        return Err(Error::WrongKeyKind);
    }

    // We store our keys in PKCS#8 DER format
    let pub_key_der = pub_key
        .to_public_key_der()
        .unwrap_or_else(|_| panic!("Failed to serialize an RSA public key to PKCS#8 DER"));

    let pub_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        kind,
        pub_key_der.as_ref(),
    )?;

    Ok(reply::DeserializeKey { key: pub_key_id })
}

fn deserialize_key(
    keystore: &mut impl Keystore,
    request: &request::DeserializeKey,
    bits: usize,
    kind: key::Kind,
) -> Result<reply::DeserializeKey, Error> {
    // - mechanism: Mechanism
    // - serialized_key: Message
    // - attributes: StorageAttributes

    match request.format {
        KeySerialization::Pkcs8Der => deserialize_pkcs_key(keystore, request, bits, kind),
        KeySerialization::RsaParts => deserialize_parts_key(keystore, request, bits, kind),
        _ => Err(Error::InvalidSerializationFormat),
    }
}

fn serialize_key(
    keystore: &mut impl Keystore,
    request: &request::SerializeKey,
    kind: key::Kind,
) -> Result<reply::SerializeKey, Error> {
    let key_id = request.key;

    // We rely on the fact that we store the keys in the PKCS#8 DER format already
    let pub_key_der = keystore
        .load_key(key::Secrecy::Public, Some(kind), &key_id)
        .unwrap_or_else(|_| panic!("Failed to load an RSA public key with the given ID"))
        .material;

    let serialized_key = match request.format {
        KeySerialization::RsaParts => {
            let key: RsaPublicKey = DecodePublicKey::from_public_key_der(&pub_key_der)
                .unwrap_or_else(|_| panic!("Failed to parse key"));
            let e = &key.e().to_bytes_be();
            let n = &key.n().to_bytes_be();
            RsaPublicParts { e, n }.serialize().map_err(|_err| {
                error!("Failed to serialize public key {_err:?}");
                Error::InternalError
            })?
        }
        KeySerialization::Pkcs8Der => pub_key_der.into(),
        _ => {
            return Err(Error::InvalidSerializationFormat);
        }
    };

    Ok(reply::SerializeKey { serialized_key })
}
fn generate_key(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
    bits: usize,
    kind: key::Kind,
) -> Result<reply::GenerateKey, Error> {
    let priv_key = RsaPrivateKey::new(keystore.rng(), bits)
        .unwrap_or_else(|_| panic!("Failed to generate an RSA 2K private key"));

    let priv_key_der = priv_key
        .to_pkcs8_der()
        .unwrap_or_else(|_| panic!("Failed to serialize an RSA private key to PKCS#8 DER"));

    let priv_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Secret,
        key::Info::from(kind).with_local_flag(),
        priv_key_der.as_bytes(),
    )?;

    Ok(reply::GenerateKey { key: priv_key_id })
}
fn sign(
    keystore: &mut impl Keystore,
    request: &request::Sign,
    kind: key::Kind,
) -> Result<reply::Sign, Error> {
    let key_id = request.key;

    let priv_key_der = keystore
        .load_key(key::Secrecy::Secret, Some(kind), &key_id)
        .unwrap_or_else(|_| panic!("Failed to load an RSA private key with the given ID"))
        .material;

    let priv_key = RsaPrivateKey::from_pkcs8_der(&priv_key_der)
        .unwrap_or_else(|_| panic!("Failed to deserialize an RSA private key from PKCS#8 DER"));

    // RSA lib takes in a hash value to sign, not raw data.
    // We assume we get digest into this function, too.

    let native_signature = match kind {
        key::Kind::Rsa2048 => {
            SigningKey::<Sha256>::new_unprefixed(priv_key).sign_prehash(&request.message)
        }
        key::Kind::Rsa3072 => {
            SigningKey::<Sha384>::new_unprefixed(priv_key).sign_prehash(&request.message)
        }
        key::Kind::Rsa4096 => {
            SigningKey::<Sha512>::new_unprefixed(priv_key).sign_prehash(&request.message)
        }
        _ => unreachable!(),
    }
    .map_err(|_err| {
        error!("Failed to sign message: {:?}", _err);
        Error::InternalError
    })?;
    let our_signature =
        Signature::from_slice(&native_signature.to_bytes()).unwrap_or_else(|_| panic!());

    Ok(reply::Sign {
        signature: our_signature,
    })
}
fn verify(
    keystore: &mut impl Keystore,
    request: &request::Verify,
    bits: usize,
    kind: key::Kind,
) -> Result<reply::Verify, Error> {
    if let SignatureSerialization::Raw = request.format {
    } else {
        return Err(Error::InvalidSerializationFormat);
    }

    if request.signature.len() != bits / 8 {
        return Err(Error::WrongSignatureLength);
    }

    let key_id = request.key;

    let pub_key_der = keystore
        .load_key(key::Secrecy::Public, Some(kind), &key_id)
        .unwrap_or_else(|_| panic!("Failed to load an RSA private key with the given ID"))
        .material;

    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_der)
        .unwrap_or_else(|_| panic!("Failed to deserialize an RSA private key from PKCS#8 DER"));

    let verification_ok = pub_key
        .verify(
            Pkcs1v15Sign::new_unprefixed(),
            &request.message,
            &request.signature,
        )
        .is_ok();

    Ok(reply::Verify {
        valid: verification_ok,
    })
}

fn decrypt(
    keystore: &mut impl Keystore,
    request: &request::Decrypt,
    kind: key::Kind,
) -> Result<reply::Decrypt, Error> {
    use rsa::Pkcs1v15Encrypt;
    let key_id = request.key;

    let priv_key_der = keystore
        .load_key(key::Secrecy::Secret, Some(kind), &key_id)
        .unwrap_or_else(|_| panic!("Failed to load an RSA private key with the given ID"))
        .material;
    let priv_key = RsaPrivateKey::from_pkcs8_der(&priv_key_der)
        .unwrap_or_else(|_| panic!("Failed to deserialize an RSA private key from PKCS#8 DER"));

    let res = priv_key
        .decrypt(Pkcs1v15Encrypt, &request.message)
        .map_err(|_err| {
            warn!("Failed to decrypt: {_err}");
            Error::FunctionFailed
        })?;

    Ok(reply::Decrypt {
        plaintext: Some(Bytes::from_slice(&res).map_err(|_| {
            error!("Failed type conversion");
            Error::InternalError
        })?),
    })
}

#[cfg(feature = "raw")]
fn rsa_raw<R: RngCore + CryptoRng, const N: usize>(
    keystore: &mut impl Keystore,
    key_id: KeyId,
    plaintext: &Message,
    kind: key::Kind,
    bits: usize,
    rng: &mut R,
) -> Result<Bytes<N>, Error> {
    let priv_key_der = keystore
        .load_key(key::Secrecy::Secret, Some(kind), &key_id)
        .unwrap_or_else(|_| panic!("Failed to load an RSA private key with the given ID"))
        .material;
    let priv_key = RsaPrivateKey::from_pkcs8_der(&priv_key_der)
        .unwrap_or_else(|_| panic!("Failed to deserialize an RSA private key from PKCS#8 DER"));

    let c = rsa::BigUint::from_bytes_be(plaintext);
    let res = rsa::hazmat::rsa_decrypt(Some(rng), &priv_key, &c).map_err(|_err| {
        error!("Failed raw decryption: {:?}", _err);
        Error::InternalError
    })?;

    fn to_bytes_with_leading_zeros<const N: usize>(data: &[u8], bits: usize) -> Bytes<N> {
        let expected_len = bits / 8;
        assert!(data.len() <= expected_len);
        let mut bytes = Bytes::new();
        bytes
            .resize(expected_len - data.len(), 0)
            .unwrap_or_else(|_| panic!());
        bytes.extend_from_slice(data).unwrap_or_else(|_| panic!());
        bytes
    }

    Ok(to_bytes_with_leading_zeros(&res.to_bytes_be(), bits))
}

#[cfg(not(feature = "raw"))]
fn rsa_raw<R: RngCore + CryptoRng, const N: usize>(
    _keystore: &mut impl Keystore,
    _key: KeyId,
    _plaintext: &Message,
    _kind: key::Kind,
    _bits: usize,
    _rng: &mut R,
) -> Result<Bytes<N>, Error> {
    warn!("Raw RSA is not enabled. Please enable the `raw` feature");
    Err(Error::FunctionNotSupported)
}

fn unsafe_inject_key(
    keystore: &mut impl Keystore,
    request: &request::UnsafeInjectKey,
    bits: usize,
    kind: key::Kind,
) -> Result<reply::UnsafeInjectKey, Error> {
    let data = RsaImportFormat::deserialize(&request.raw_key).map_err(|_err| {
        error!("Failed to deserialize RSA key: {_err:?}");
        Error::InvalidSerializedKey
    })?;
    let e = BigUint::from_bytes_be(data.e);
    let p = BigUint::from_bytes_be(data.p);
    let q = BigUint::from_bytes_be(data.q);
    let phi = (&p - 1u64) * (&q - 1u64);

    let d = e
        .clone()
        .mod_inverse(&phi)
        .and_then(|int| int.to_biguint())
        .ok_or_else(|| {
            warn!("Failed inverse");
            Error::InvalidSerializedKey
        })?;

    let private_key =
        RsaPrivateKey::from_components(&p * &q, e, d, vec![p, q]).map_err(|_err| {
            warn!("Bad private key: {_err:?}");
            Error::InvalidSerializedKey
        })?;
    private_key.validate().map_err(|_err| {
        warn!("Bad private key: {_err:?}");
        Error::InvalidSerializedKey
    })?;
    if private_key.size() != bits / 8 {
        warn!("Bad key size: {}", private_key.size());
        return Err(Error::InvalidSerializedKey);
    }

    let private_key_der = private_key
        .to_pkcs8_der()
        .unwrap_or_else(|_| panic!("Failed to serialize an RSA 2K private key to PKCS#8 DER"));

    let private_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Secret,
        kind,
        private_key_der.as_bytes(),
    )?;

    Ok(reply::UnsafeInjectKey {
        key: private_key_id,
    })
}

fn exists(
    keystore: &mut impl Keystore,
    request: &request::Exists,
    kind: key::Kind,
) -> Result<reply::Exists, Error> {
    let key_id = request.key;

    let exists = keystore.exists_key(key::Secrecy::Secret, Some(kind), &key_id);
    Ok(reply::Exists { exists })
}

impl Backend for SoftwareRsa {
    type Context = ();
    fn request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        let mut rng = resources.rng()?;
        let mut keystore = resources.keystore(core_ctx.path.clone())?;
        match request {
            Request::DeriveKey(req) => {
                let (_bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
                derive_key(&mut keystore, req, kind).map(Reply::DeriveKey)
            }
            Request::DeserializeKey(req) => {
                let (bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
                deserialize_key(&mut keystore, req, bits, kind).map(Reply::DeserializeKey)
            }
            Request::SerializeKey(req) => {
                let (_bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
                serialize_key(&mut keystore, req, kind).map(Reply::SerializeKey)
            }
            Request::GenerateKey(req) => {
                let (bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
                generate_key(&mut keystore, req, bits, kind).map(Reply::GenerateKey)
            }
            Request::Sign(req) => {
                let (bits, kind, raw) = bits_and_kind_from_mechanism(req.mechanism)?;
                if raw {
                    rsa_raw(&mut keystore, req.key, &req.message, kind, bits, &mut rng)
                        .map(|d| Reply::Sign(reply::Sign { signature: d }))
                } else {
                    sign(&mut keystore, req, kind).map(Reply::Sign)
                }
            }
            Request::Verify(req) => {
                let (bits, kind, raw) = bits_and_kind_from_mechanism(req.mechanism)?;
                if raw {
                    warn!("Attempt at raw verify");
                    return Err(Error::MechanismInvalid);
                }
                verify(&mut keystore, req, bits, kind).map(Reply::Verify)
            }
            Request::Decrypt(req) => {
                let (bits, kind, raw) = bits_and_kind_from_mechanism(req.mechanism)?;
                if raw {
                    rsa_raw(&mut keystore, req.key, &req.message, kind, bits, &mut rng)
                        .map(|r| Reply::Decrypt(reply::Decrypt { plaintext: Some(r) }))
                } else {
                    decrypt(&mut keystore, req, kind).map(Reply::Decrypt)
                }
            }
            Request::UnsafeInjectKey(req) => {
                let (bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
                unsafe_inject_key(&mut keystore, req, bits, kind).map(Reply::UnsafeInjectKey)
            }
            Request::Exists(req) => {
                let (_bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
                exists(&mut keystore, req, kind).map(Reply::Exists)
            }
            _ => Err(Error::RequestNotAvailable),
        }
    }
}
