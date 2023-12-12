// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(feature = "virt")]

use rsa::sha2::Sha384;
use rsa::{traits::PublicKeyParts, Pkcs1v15Encrypt, Pkcs1v15Sign};
use trussed::client::CryptoClient;
use trussed::syscall;
use trussed::types::KeyId;
use trussed::types::KeySerialization;
use trussed::types::Location::*;
use trussed::types::Mechanism;
use trussed::types::StorageAttributes;

use trussed_rsa_alloc::*;

use hex_literal::hex;
use num_bigint_dig::BigUint;
use rsa::RsaPrivateKey;

// Tests below can be run on a PC using the "virt" feature

#[test_log::test]
fn rsa3072pkcs_generate_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa3072pkcs_private_key(Internal)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(sk, KeyId::from_special(0));
    })
}

#[test_log::test]
fn rsa3072pkcs_derive_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa3072pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa3072pkcs_public_key(sk, Volatile)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(pk, KeyId::from_special(0));
    })
}

#[test_log::test]
fn rsa3072pkcs_exists_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa3072pkcs_private_key(Internal)).key;
        let key_exists =
            syscall!(client.exists(trussed::types::Mechanism::Rsa3072Pkcs1v15, sk)).exists;

        assert!(key_exists);
    })
}

#[test_log::test]
fn rsa3072pkcs_serialize_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa3072pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa3072pkcs_public_key(sk, Volatile)).key;

        let serialized_key = syscall!(client.serialize_rsa3072_key(pk)).serialized_key;

        assert!(!serialized_key.is_empty());
    })
}

#[test_log::test]
fn rsa3072_deserialize_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa3072pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa3072pkcs_public_key(sk, Volatile)).key;
        let serialized_key = syscall!(client.serialize_rsa3072_key(pk)).serialized_key;
        let public_key = RsaPublicParts::deserialize(&serialized_key).unwrap();
        let location = StorageAttributes::new().set_persistence(Volatile);

        let deserialized_key_id =
            syscall!(client.deserialize_rsa3072_public_key(public_key, location)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(deserialized_key_id, KeyId::from_special(0));
    })
}

#[test_log::test]
fn rsa3072pkcs_encrypt_decrypt() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa3072pkcs_private_key(Volatile)).key;
        let message = [1u8, 2u8, 3u8];
        let pk = syscall!(client.derive_rsa3072pkcs_public_key(sk, Volatile)).key;
        let rs_pks_buffer = syscall!(client.serialize_rsa3072_key(pk)).serialized_key;
        let parsed = RsaPublicParts::deserialize(&rs_pks_buffer).unwrap();
        let pubkey = rsa::RsaPublicKey::new_unchecked(
            BigUint::from_bytes_be(parsed.n),
            BigUint::from_bytes_be(parsed.e),
        );
        assert_eq!(pubkey.size(), 3072 / 8);
        let encrypted = pubkey
            .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &message)
            .unwrap();

        let decrypted = syscall!(client.decrypt_rsa3072pkcs(sk, &encrypted))
            .plaintext
            .unwrap();

        assert_eq!(decrypted, message);
    })
}

#[test_log::test]
fn rsa3072pkcs_sign_verify() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa3072pkcs_private_key(Volatile)).key;
        let hash_prefix = hex!("3041 300d 0609 608648016503040202 0500 0430");
        let message = [1u8, 2u8, 3u8];
        use rsa::sha2::digest::Digest;
        let digest = Sha384::digest(message);
        let digest_to_sign: Vec<u8> = hash_prefix.into_iter().chain(digest).collect();
        let signature = syscall!(client.sign_rsa3072pkcs(sk, &digest_to_sign)).signature;
        let pk = syscall!(client.derive_rsa3072pkcs_public_key(sk, Volatile)).key;

        let verify_ok = syscall!(client.verify_rsa3072pkcs(pk, &digest_to_sign, &signature)).valid;

        assert_eq!(signature.len(), 384);
        assert!(verify_ok);
    })
}

#[test_log::test]
fn rsa3072pkcs_inject() {
    virt::with_ram_client("rsa test", |mut client| {
        let n  = hex!("c2094ddae7a5de41dbe4b38ad72169027167482983e07b10efb3f549c5d85a1c2d68aba2e2178fc549a51bd18ea2f995bde529f5c6ccfcbef442e8fe6d113fc09a00ccffda8e78e4ecde7aaa30f83fad1d3aa1f923df1ce9fd06f2bb0f73dca779b0645220c5e6da1f4730392af7ea62520c9a80bc49e11c5a53fd6db0be1ba4b6c78fbc6da5d5b86b58b9f512dd580e60cd10a5995c71cabdab4b9afa718bf112da2ed4ab9d419387148116a9cc94b62bafab962f961a3efcd8584b661a1cb5f9b5ddbe2e96f1e7fd1cb3a8ae15d3685eae33c34451d55d8e48a423e910ebde619cba0f6c000c7d85e5d1f9cb03da22764fa67b426f11ba5965491c9ab2697ac050ea1bb6b011a441e707bb2c3380502dc617e3ec3b226350a49c66fa2a6a6e2818fccc9e6c46097d7f658b47665f958a7870fd0ec595b9fe73156d977936b3c952ee24cb71574c68f995260cf59cb1cc5548d512a471708a6aedd32704b8a40ab7fed7de64dca930678e9dae0e02076ab5ff1993547e68b1dfd8e9adf9d9b7");
        let e = hex!("010001");
        let d = hex!("46af20ff779782e9b6f30f3caab5ef0d06c6bb10f48b98094968e31826cc73b7040bb74ab4d6247798265f85ed520d5db1398419967c222e65c8e21b9d1bc57fa21a5c936fc8aaddaa3439b739f3952eb9111ce4275f25a74f9772611675fc91bdd0b61afcf95ae966af862fad2976e6ae410d1f8c77d55b80c44bf3e388bd85395865521d17664db23d3630c2d8833569aa0a406927b6044727d978f176dfa5c85a56e8fe43611a1f01272d5c59bc6ac86b4c347fcd4c6e59a96e30b95715d1c920454006d5dfbf1b1f4c0305dc8a862e131185478b813dfdba873b926f70714c38023698d4b0e933f36c37e32a9dd98d852bf3395dbebb27e2c2ddb378ef56d32614def94e2a44ba3f3ae2d199d1cd57928dec1a3ac1a7ebfd8603ee0948ebc1372e91a8f0ef5e61e069c13d07ba5dc9d6fac172f316812a730b9f80a6ada8508a36c3278ba713809fbfe336369e60983e848ca10607eca3dafa2ecb1cd8d1bfde49830d489f32135e95cb396b589a37fbf81cd4752a2ffd621d70e8a3d0b1");

        let p1 = hex!("c45e0839e403a4e9d925caee3209a53876003266c54129ba8095246b517a4bdc043acddbc40c7d8752f6c3c04ad3e97e159832c4130a1ea04438ebaa4e72e7e7d15656d3249a2b65a9d8b272137086fc59d713c67243e17bd3da288e0bd3a6bec88b53f427ac2dd82ff965d90a0daa4d23014fa1ed65a2ef4561870eec18695fa13571357047715cc553279835a89211ebe2cccd4d6326485c8236466f1ff81bf03fff001a3819768144cad6f022831086a3175433af432d2c50a97fdb67da4d");
        let p2 = hex!("fcf60edc27832acc2406460ec4b6072b55a210749c90f915648d35270ace75f7a27d1c88ce7f5305808a370b29a5c6435cfa2d0c0854b6c94a0f51b5e9c8737c8f67f30739181ce68d8c45dd8a4a1c718406fa01cf3f3facafc0965c17fecdecd07a40d862226bb5d8c36706c5639bf05dce73a3af624ab7ab30d84f39b679a8547030e4fe92ad22889d64cb37da3136d3f428d44e0d30f6db2740bde1444062c7b5625f5c405be2af4cdf4027db4dd622fe825db8271f57260f3ae03efe3e13");

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
            Mechanism::Rsa3072Pkcs1v15,
            &data,
            Volatile,
            KeySerialization::RsaParts
        ))
        .key;
        let hash_prefix = hex!("3041 300d 0609 608648016503040202 0500 0430");
        let message = [1u8, 2u8, 3u8];
        use rsa::sha2::digest::Digest;
        let digest = Sha384::digest(message);
        let digest_to_sign: Vec<u8> = hash_prefix.into_iter().chain(digest).collect();

        let signature = syscall!(client.sign_rsa3072pkcs(sk, &digest_to_sign)).signature;
        assert!(pk
            .verify(Pkcs1v15Sign::new::<Sha384>(), &digest, &signature,)
            .is_ok());
    });
}
