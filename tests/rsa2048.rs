// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(feature = "virt")]

use rsa::sha2::Sha256;
use rsa::{traits::PublicKeyParts, Pkcs1v15Encrypt, Pkcs1v15Sign};
use trussed::client::CryptoClient;
use trussed::syscall;
use trussed::types::KeyId;
use trussed::types::KeySerialization;
use trussed::types::Location::*;
use trussed::types::Mechanism;
use trussed::types::StorageAttributes;

use trussed_rsa_alloc::*;
use trussed_rsa_types::*;

use hex_literal::hex;
use num_bigint_dig::BigUint;
use rsa::RsaPrivateKey;

// Tests below can be run on a PC using the "virt" feature

#[test_log::test]
fn rsa2048pkcs_generate_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(sk, KeyId::from_special(0));
    })
}

#[test_log::test]
fn rsa2048pkcs_derive_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa2048pkcs_public_key(sk, Volatile)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(pk, KeyId::from_special(0));
    })
}

#[test_log::test]
fn rsa2048pkcs_exists_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;
        let key_exists =
            syscall!(client.exists(trussed::types::Mechanism::Rsa2048Pkcs1v15, sk)).exists;

        assert!(key_exists);
    })
}

#[test_log::test]
fn rsa2048pkcs_serialize_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa2048pkcs_public_key(sk, Volatile)).key;

        let serialized_key = syscall!(client.serialize_rsa2048_key(pk)).serialized_key;

        assert!(!serialized_key.is_empty());
    })
}

#[test_log::test]
fn rsa2048_deserialize_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa2048pkcs_public_key(sk, Volatile)).key;
        let serialized_key = syscall!(client.serialize_rsa2048_key(pk)).serialized_key;
        let public_key = RsaPublicParts::deserialize(&serialized_key).unwrap();
        let location = StorageAttributes::new().set_persistence(Volatile);

        let deserialized_key_id =
            syscall!(client.deserialize_rsa2048_public_key(public_key, location)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(deserialized_key_id, KeyId::from_special(0));
    })
}

#[test_log::test]
fn rsa2048pkcs_encrypt_decrypt() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Volatile)).key;
        let message = [1u8, 2u8, 3u8];
        let pk = syscall!(client.derive_rsa2048pkcs_public_key(sk, Volatile)).key;
        let rs_pks_buffer = syscall!(client.serialize_rsa2048_key(pk)).serialized_key;
        let parsed = RsaPublicParts::deserialize(&rs_pks_buffer).unwrap();
        let pubkey = rsa::RsaPublicKey::new_unchecked(
            BigUint::from_bytes_be(parsed.n),
            BigUint::from_bytes_be(parsed.e),
        );
        assert_eq!(pubkey.size(), 2048 / 8);
        let encrypted = pubkey
            .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &message)
            .unwrap();

        let decrypted = syscall!(client.decrypt_rsa2048pkcs(sk, &encrypted))
            .plaintext
            .unwrap();

        assert_eq!(decrypted, message);
    })
}

#[test_log::test]
fn rsa2048pkcs_sign_verify() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Volatile)).key;
        let hash_prefix = hex!("3031 300d 0609 608648016503040201 0500 0420");
        let message = [1u8, 2u8, 3u8];
        use rsa::sha2::digest::Digest;
        let digest = Sha256::digest(message);
        let digest_to_sign: Vec<u8> = hash_prefix.into_iter().chain(digest).collect();
        let signature = syscall!(client.sign_rsa2048pkcs(sk, &digest_to_sign)).signature;
        let pk = syscall!(client.derive_rsa2048pkcs_public_key(sk, Volatile)).key;

        let verify_ok = syscall!(client.verify_rsa2048pkcs(pk, &digest_to_sign, &signature)).valid;

        assert_eq!(signature.len(), 256);
        assert!(verify_ok);
    })
}
#[test_log::test]
fn rsa2048pkcs_inject() {
    virt::with_ram_client("rsa test", |mut client| {
        let n = hex!("b43f96eee6abf0e71d81244f9adcc049c379f22a40d99e0a921fca08c1a83695f2060eeebc52823e8fa59f61156e42119758c3937c848a69e13a4a3ee23f35bb923a63b7d0cec6092957ff038b58c63339f300fb0d6dfc3d239fb8ef2caafbb40ca98fbd795e6ab5128a6e880b72a0637bfb197ea6697cd045c648d2a55f0f0e181d6bb50e56f297c8da164a3b04fab69e66107a7767e3a2c1df5e655c40db3e76e469e6db71b2d4edd73d48eee894d3c6c8e966bc2153256b014bc63a8f02c59a06b89004903ec4887ac916e2f7c5077b93eef17e914bb07add9dced384946f89d99ba48b28eedcc511ce359d2b2bce8052181f229033b6f2b1a905a55b33bd");
        let e = hex!("010001");
        let d = hex!("0ac47db4b9ccedb030c00536482f05c1a24ec79ba4921b71d036dbefd7f9bf81079b3b0b21eedfdef2dfd6fc8ab63276308f59e79699a85718e04d8d2220da89e0fb61f79a1eb00fde0b66ad848682188f4ea7f15765099b71645a3cd773436407199dff989f7e4a60d82a303056e1a3efc51949ca9124a6a0746ee73e7fc63b5c9df7e15be95b3f83dbb81a3a95284b52ca584fd058e9dbe74285b85b13688225c72cfc4c636950553aa31670de8dac45abac75e8872ee623f6cb0974c1915600bfc8e5c60e38101ae558ab3400d540b1db36b5eb6d9a0674ddbb814b69258ef15a0a3d07d557856a30af72d5c8ebc26d8cb067be783a5aea564afba4e28181");
        let p1 = hex!("ccefc3c11c7a0ed08aa3994c7ebe4ec9fabd1d83ff20c0e203ab1f230ae1ca158b6b6e82661f6ba179acb8ce5eca858abaf1987660748b78f00fc14bfb8fe1569fa7ac71276ce8cc1e1e9679fdfb589e538f6ccdab3b3fe26121a2d0f8d5721daea8104f61569f5f634fcd4c202788e46c1e39295d29b07a410ed4d023577fe1");
        let p2 = hex!("e1290bd8c19fbd77eb271fd081a96af60cc33a9e8b0fffb751b1ed557d8653f39bce97a4733f7725f2b26050317fc816698c3d8ba8b2a3198f167c6708fbb96d45b6c1ff6a1e4b07752f6f316a60d8559904466e3ad04b7d9cf56efda9dfeaaadb74caa0079933c7d063ee80ea4bca73c4e0a20dd7b61a6886666359cec59f5d");

        let raw = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&n),
            BigUint::from_bytes_be(&e),
            BigUint::from_bytes_be(&d),
            vec![BigUint::from_bytes_be(&p1), BigUint::from_bytes_be(&p2)],
        )
        .unwrap();
        let pk = raw.to_public_key();

        let request = RsaImportFormat {
            e: &e,
            p: &p1,
            q: &p2,
        };
        let data = request.serialize().unwrap();
        let sk = syscall!(client.unsafe_inject_key(
            Mechanism::Rsa2048Pkcs1v15,
            &data,
            Volatile,
            KeySerialization::RsaParts
        ))
        .key;

        let hash_prefix = hex!("3031 300d 0609 608648016503040201 0500 0420");
        let message = [1u8, 2u8, 3u8];
        use rsa::sha2::digest::Digest;
        let digest = Sha256::digest(message);
        let digest_to_sign: Vec<u8> = hash_prefix.into_iter().chain(digest).collect();

        let signature = syscall!(client.sign_rsa2048pkcs(sk, &digest_to_sign)).signature;
        assert!(pk
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature,)
            .is_ok());
    });
}
