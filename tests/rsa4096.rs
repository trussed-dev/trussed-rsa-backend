// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(feature = "virt")]

use rsa::sha2::Sha512;
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
fn rsa4096pkcs_generate_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(sk, KeyId::from_special(0));
    })
}

#[test_log::test]
fn rsa4096pkcs_derive_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa4096pkcs_public_key(sk, Volatile)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(pk, KeyId::from_special(0));
    })
}

#[test_log::test]
fn rsa4096pkcs_exists_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;
        let key_exists =
            syscall!(client.exists(trussed::types::Mechanism::Rsa4096Pkcs1v15, sk)).exists;

        assert!(key_exists);
    })
}

#[test_log::test]
fn rsa4096pkcs_serialize_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa4096pkcs_public_key(sk, Volatile)).key;

        let serialized_key = syscall!(client.serialize_rsa4096_key(pk)).serialized_key;

        assert!(!serialized_key.is_empty());
    })
}

#[test_log::test]
fn rsa4096_deserialize_key() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa4096pkcs_public_key(sk, Volatile)).key;
        let serialized_key = syscall!(client.serialize_rsa4096_key(pk)).serialized_key;
        let public_key = RsaPublicParts::deserialize(&serialized_key).unwrap();
        let location = StorageAttributes::new().set_persistence(Volatile);

        let deserialized_key_id =
            syscall!(client.deserialize_rsa4096_public_key(public_key, location)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(deserialized_key_id, KeyId::from_special(0));
    })
}

#[test_log::test]
fn rsa4096pkcs_encrypt_decrypt() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Volatile)).key;
        let message = [1u8, 2u8, 3u8];
        let pk = syscall!(client.derive_rsa4096pkcs_public_key(sk, Volatile)).key;
        let rs_pks_buffer = syscall!(client.serialize_rsa4096_key(pk)).serialized_key;
        let parsed = RsaPublicParts::deserialize(&rs_pks_buffer).unwrap();
        let pubkey = rsa::RsaPublicKey::new_unchecked(
            BigUint::from_bytes_be(parsed.n),
            BigUint::from_bytes_be(parsed.e),
        );
        assert_eq!(pubkey.size(), 4096 / 8);
        let encrypted = pubkey
            .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &message)
            .unwrap();

        let decrypted = syscall!(client.decrypt_rsa4096pkcs(sk, &encrypted))
            .plaintext
            .unwrap();

        assert_eq!(decrypted, message);
    })
}

#[test_log::test]
fn rsa4096pkcs_sign_verify() {
    virt::with_ram_client("rsa test", |mut client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Volatile)).key;
        let hash_prefix = hex!("3051 300d 0609 608648016503040203 0500 0440");
        let message = [1u8, 2u8, 3u8];
        use rsa::sha2::digest::Digest;
        let digest = Sha512::digest(message);
        let digest_to_sign: Vec<u8> = hash_prefix.into_iter().chain(digest).collect();
        let signature = syscall!(client.sign_rsa4096pkcs(sk, &digest_to_sign)).signature;
        let pk = syscall!(client.derive_rsa4096pkcs_public_key(sk, Volatile)).key;

        let verify_ok = syscall!(client.verify_rsa4096pkcs(pk, &digest_to_sign, &signature)).valid;

        assert_eq!(signature.len(), 512);
        assert!(verify_ok);
    })
}

#[test_log::test]
fn rsa4096pkcs_inject() {
    virt::with_ram_client("rsa test", |mut client| {
        let n  = hex!("b1cb5aa27a7a8d7b1bb3d0e483be1a04f44c47f0a527814d1681b44fca112cce1a6a62acee4023a27e9208c9afd7bcc5e703cda2e97b5ed32b2b528731ce824e4ad80c6bed565490df84643476f7c8e857682ed0d6c0b4ba3287f26489e9b00469cacbdfd00c90940869762f13d35878ea7aab04b454a2bd3cb2dd3ccc9d51cda24ca199fc6d30005bde0f238cdcd5e21f6709a19275522b39fef15e3a7faa166494abe50ac49fc769a8bcd32d09bba70f6769fa5ecc008a7d5a51a3365f50a13b6e2dee2c961553fd01c5829b012caebf3aa9db46252a0d4f9278302b69bc21ea97ee6dae0fad3a0a82d5b522ef7d9cf308abd79dc462ccfc317d83a4f43541c752c858528adf5e0a7252965782dd6b48941987515641625385c9a1024811d35091fcead599a4b54584cb79e7ce7a336504e79c37540b176eafa2ba57a7e1aea12e8f7aee12ee256570968ae758b2ba5cc684c0d6c798fca822ac8e1cf72b0fba689582de6f0555b6f6b9552ceec2902153f5061a0a4be19401dc097181eec9cf6d8e2c624888c6c8b3f25663f8b5a74512d00aa1b57af70cf93485d033e55f3ce4137ef1158854e7bbcc1adec2c26c2233d4c21fc7cc4d9eb96ff8c6662be9775a75059277b1fe932141ea7325b2877393d21e934ead08e065134edb59d8c3156da6d9a429291adbddcce85ba91977e4d5e93f223c04ecbfcfbabcc6c5463f");
        let e = hex!("010001");
        let d  = hex!("30730ce0c7e58b9667a7299e8bf40add1cc188bd201452dcf1ec2879b1c3da64d3b7f7e9ce06f66efa74cb2642dfd4564dacb0a5db603e27e754a7e9a57df3ee67e0d609b7245669202fd0aaa75cc087e801c0f831fd538285f09bf21fcee9a35a3ce42fba5f222ae4dbf053c5e04af4b058fb2f8e009e54592d18b2cfc3731e4942feaa9aaa1a718e9745a2d768fa73e340cdd414b819cb23c3c07c800e780820228f711bed16e95d7698f62708c6f530726ae3ca5f672a561c7db0af496c0c73c88385aaeabf2723040f9196b1cc3e5668230f58df19c584d09225f63e9b00d70fcdee5f87701a27f11d517e12ab3550d92512ddb03d8844952bf1eaca8d94495c07c3a998ca9ca358aa284d3876d3e0105f0bca15a5f2f798fdf1b30d4140817727d73b5ff42683b37dbba911133770586090f21df022c4685026b1cd21cd55e098dc2b9b30d4bb28b7f36db53e8851d0bedc66bfcceaf4592d634ae1d88d1d21987ba7983bada4c64b57acda4394b58237c10e4c29bb70351732cdc412a621512cddfd1b8025091aa4fb5d4180d1ee5781cdd2ebe0a9426ffc790ad941beb676506026885f2c7a0c827899427ef1fc280e7786b6a88f17d8ec5f7bd99339f03add6113cc8ce3496d209d237efa0878c3f13dfafbaf6bc8909a50522019f87d56daf1900e7eb1b41c1d8ec2487c0040ee07ac6b493632b7846c04bd4762b9");

        let p1 = hex!("ec716ab3b3d9a53a762934e7e3b8c8e2b43e59309bb739f64a92468d3cd0e24a8752e06335caedaa182effe87d4803c073fd8add45955ec14bf2d0ca31840274e8d6b9cd3664422fa1b88e9cb6ebdf83094ff46d9865d0b71fe55702dd9fc67a14c518e9bac7fe9d8ad38dd898058a0ef8dec8366bc0485d5f3cb73858446a2e437c7055114446d78731fc9d0903bd7869d402bc506dfd21d95f1d19b0d59e2b2bf1d64058b0e5241c7bbc05b45eb66b230247ba0d8daa850bae59e62f76e0de632cafcf8ecdccd662ea645597c72b6beb47eb15c3a343be2351c59220d27e81e56f16f1c252a095ef6e7ebdf9fc2a81e387cf17820d78098ec37a2bf8baf523");
        let p2 = hex!("c08013615f1cbba17ad6676b2ccee905fe5d21cbf6c03dd760d630afd8759e6df4ba5aec1ed2a9ef69cc4ad78b1c83245a081be45550613e00bfd282e807fb928a92f08b7737003f805ac4e2c4fa725232c038181ae6b257e410873c254ed438e8450374240a84a65cca22f542d8c983473c260a9bf76af96b978de3e7ee6db6654aa95eef8547636b4fc9b034db914ff781b69fbdcf637f9483966cfa5dda9b072b7359c2afcfd497585ddfdfad90ce6502cfbc693c22884e94da1eaf49c92a4ea342f7edd2bd182869107e6bfd0ba6fee89b731cd9f31c8d90b7d04da342ae23bf6dcc49ca829c4e53e70b7e329ceda62986b41e6ab4910068ac66df44c235");

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
            Mechanism::Rsa4096Pkcs1v15,
            &data,
            Volatile,
            KeySerialization::RsaParts
        ))
        .key;

        let hash_prefix = hex!("3051 300d 0609 608648016503040203 0500 0440");
        let message = [1u8, 2u8, 3u8];
        use rsa::sha2::digest::Digest;
        let digest = Sha512::digest(message);
        let digest_to_sign: Vec<u8> = hash_prefix.into_iter().chain(digest).collect();

        let signature = syscall!(client.sign_rsa4096pkcs(sk, &digest_to_sign)).signature;
        assert!(pk
            .verify(Pkcs1v15Sign::new::<Sha512>(), &digest, &signature,)
            .is_ok());
    });
}
