//! Rotation certificates (`cr1`): what a SERVICE may answer a rotate with, as
//! `r`, its signed statement of which one note the burned note became. An
//! extension, not part of LUD-25. Pure encoding and verification, so no mint
//! is needed. The fixed vector is the one lnurl-mint
//! (`tests/test_rotation_certificate.py`) and lnurl-wallet
//! (`src/lib/rotationCertificate.test.ts`) check themselves against; every
//! other certificate is signed here, from fixed keys.

use lnurlcash_core::recoverable::{
    decode_any_cs1, decode_cr1_with_amount, decode_cs1_with_amount, encode_cp1,
    encode_cr1_with_amount, encode_cs1_with_amount, is_cr1_with_amount, is_cs1_with_amount, Cr1,
};
use lnurlcash_core::{
    note_signature_digest_for_hash, note_signature_message_for_hash, rotation_signature_digest,
    rotation_signature_message, verify_note_signature_hash, verify_rotation_certificate,
};
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Message, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

// pk_0 of LUD-25's test vectors 1 and 2: two real note keys
const SPENT: &str = "aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634";
const NOTE: &str = "01fee34e378bf66de6afa1bfa6e30f5c89551fd92bc1b089dca93c52b7ab61bc";

fn mint_key(fill: u8) -> SecretKey {
    SecretKey::from_secret_bytes([fill; 32]).expect("a valid key")
}

fn pubkey_of(key: &SecretKey) -> String {
    hex::encode(PublicKey::from_secret_key(key).serialize())
}

/// `r || s || recovery id`, RFC6979, as a node's signmessage signs.
fn sign(key: &SecretKey, digest: [u8; 32]) -> [u8; 65] {
    let (recovery, compact) =
        RecoverableSignature::sign_ecdsa_recoverable(Message::from_digest(digest), key)
            .serialize_compact();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&compact);
    signature[64] = u8::from(recovery);
    signature
}

/// A mint's `cr1` for "`spent` became `note`", worth `amount_msat`.
fn certify_rotation(key: &SecretKey, spent: &str, note: &str, amount_msat: u64) -> String {
    encode_cr1_with_amount(
        amount_msat,
        &sign(key, rotation_signature_digest(spent, note, amount_msat)),
    )
}

/// The same signature as some implementations once wrote a note's
/// certificate: `recovery id || r || s`.
fn recovery_id_leading(trailing: [u8; 65]) -> [u8; 65] {
    let mut leading = [0u8; 65];
    leading[0] = trailing[64];
    leading[1..].copy_from_slice(&trailing[..64]);
    leading
}

/// Any payload under any human-readable part, with a valid bech32m
/// checksum: the strings the crate's own encoder never builds.
fn bech32m(hrp: &str, payload: &[u8]) -> String {
    bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse(hrp).expect("a valid hrp"), payload)
        .expect("encodes")
}

// ---- the vector shared with lnurl-mint and lnurl-wallet ----

#[test]
fn the_shared_vector_reproduces_byte_for_byte() {
    let secret: [u8; 32] = Sha256::digest(b"LNURLcash rotation certificate test vector").into();
    assert_eq!(
        hex::encode(secret),
        "e68d48301c476389d71eadbcc6209929339f5326455183f51ee48fb074b2c67b"
    );
    let key = SecretKey::from_secret_bytes(secret).expect("a valid key");
    let mint_pubkey = pubkey_of(&key);
    assert_eq!(
        mint_pubkey,
        "0305299ebc7d5301da5ff64350c558d2daf9933445e611574474024d10d30f826a"
    );

    let cases = [
        (
            1000u64,
            "0d60b3e73e340395bccbd3b87a2210dc6c949df3cd6f0c74d256349b2b989cc1",
            "3ef03201d14594c51de4d5372f57036b29c0fed94f88c804fc6b69198a40155d4d2969bfef7a9226f1fbcb15246a1be0c2f8c3cc2d0983e0c3e67e422c7c807001",
            "cr10n18mcryqw3gk2v280y65mj74crdv5uplkef7yvsp8udd53nzjqz4w562tfhlhh4y3x78auk9fydgd7pshcc0xz6zvrurp7vljz937gquqp09cjwz",
        ),
        (
            21_000_000u64,
            "2ee0ec8c1361fd0e1613d62575dd3e790cd4480ac699af7c852eb9819a29db05",
            "6c329cc404f152e5d59d3b737ea9a347e718b676475679d13db0b9112bdfe4064bae7416c87918ad030423c9dcf4913994e83eb278c6ca9e955292220cc109ac01",
            "cr210u1dsefe3qy79fwt4va8deha2drgln33dnkgat8n5fakzu3z27lusryhtn5zmy8jx9dqvzz8jwu7jgnn98g86e833k2n6249y3zpnqsntqpu0dlaz",
        ),
    ];
    for (amount, digest, signature_hex, cr1) in cases {
        let at = format!("{amount} msat");
        let message = rotation_signature_message(SPENT, NOTE, amount);
        assert_eq!(
            message,
            format!("LNURLcash:rotate:{amount}:{SPENT}:{NOTE}"),
            "{at}"
        );
        // the node signmessage wrapping, spelled out
        let wrapped = Sha256::digest(Sha256::digest(
            [b"Lightning Signed Message:".as_slice(), message.as_bytes()].concat(),
        ));
        assert_eq!(hex::encode(wrapped), digest, "{at}");
        assert_eq!(
            hex::encode(rotation_signature_digest(SPENT, NOTE, amount)),
            digest,
            "{at}"
        );

        // RFC6979: the mint's key over the digest reproduces the signature
        let signature = sign(&key, rotation_signature_digest(SPENT, NOTE, amount));
        assert_eq!(hex::encode(signature), signature_hex, "{at}");
        assert_eq!(encode_cr1_with_amount(amount, &signature), cr1, "{at}");
        assert_eq!(
            decode_cr1_with_amount(cr1),
            Some(Cr1 {
                amount_msat: amount,
                signature
            }),
            "{at}"
        );
        assert!(
            verify_rotation_certificate(SPENT, NOTE, amount, cr1, &mint_pubkey),
            "{at}"
        );

        // the direction and the notes themselves are signed
        assert!(
            !verify_rotation_certificate(NOTE, SPENT, amount, cr1, &mint_pubkey),
            "{at}"
        );
        assert!(
            !verify_rotation_certificate(SPENT, SPENT, amount, cr1, &mint_pubkey),
            "{at}"
        );
        assert!(
            !verify_rotation_certificate(NOTE, NOTE, amount, cr1, &mint_pubkey),
            "{at}"
        );
        // and a rotation certificate is never a note's own, for either of
        // the two notes it names
        for id in [SPENT, NOTE] {
            assert!(
                !verify_note_signature_hash(id, amount, signature_hex, &mint_pubkey),
                "{at}"
            );
        }
    }

    // so is the amount: neither certificate stands in for the other
    let (small, large) = (cases[0].3, cases[1].3);
    assert!(!verify_rotation_certificate(
        SPENT,
        NOTE,
        21_000_000,
        small,
        &mint_pubkey
    ));
    assert!(!verify_rotation_certificate(
        SPENT,
        NOTE,
        1000,
        large,
        &mint_pubkey
    ));
}

// ---- the string ----

#[test]
fn a_cr1_round_trips_with_its_amount_in_the_human_readable_part() {
    let signature = [0xab; 65];
    let cr1 = encode_cr1_with_amount(1000, &signature);
    assert!(cr1.starts_with("cr10n1"), "{cr1}");
    assert_eq!(cr1.len(), encode_cs1_with_amount(1000, &signature).len());
    let decoded = Cr1 {
        amount_msat: 1000,
        signature,
    };
    assert_eq!(decode_cr1_with_amount(&cr1), Some(decoded.clone()));
    assert!(is_cr1_with_amount(&cr1));
    // all uppercase is the same string, and whitespace around it is not part
    // of it
    assert_eq!(
        decode_cr1_with_amount(&format!(" {} ", cr1.to_ascii_uppercase())),
        Some(decoded)
    );
}

#[test]
fn a_cs1_and_a_cr1_never_decode_as_each_other() {
    let signature = [0xab; 65];
    let cs1 = encode_cs1_with_amount(1000, &signature);
    let cr1 = encode_cr1_with_amount(1000, &signature);
    assert_eq!(decode_cr1_with_amount(&cs1), None);
    assert_eq!(decode_cs1_with_amount(&cr1), None);
    assert_eq!(decode_any_cs1(&cr1), None);
    assert!(!is_cr1_with_amount(&cs1));
    assert!(!is_cs1_with_amount(&cr1));
}

#[test]
fn garbage_a_wrong_length_and_a_flipped_character_are_no_cr1() {
    let long = format!("cr10n1{}", "q".repeat(10_000));
    for value in [
        "",
        "1",
        "cr1",
        "cr10n1",
        "cr10n1q",
        "not a certificate",
        "cr10n1\u{e9}\u{e9}\u{e9}",
        "\u{1f4b8}1qqqqqq",
        long.as_str(),
    ] {
        assert_eq!(decode_cr1_with_amount(value), None, "{value:?}");
        assert!(!is_cr1_with_amount(value), "{value:?}");
    }

    let cr1 = encode_cr1_with_amount(1000, &[0x01; 65]);
    let last = cr1.chars().last().expect("non-empty");
    let flipped = format!(
        "{}{}",
        &cr1[..cr1.len() - 1],
        if last == 'q' { 'p' } else { 'q' }
    );
    assert_eq!(decode_cr1_with_amount(&flipped), None);
    assert_eq!(decode_cr1_with_amount(&cr1[..cr1.len() - 1]), None);

    let mut mixed = cr1.clone();
    mixed.replace_range(..2, "CR");
    assert_eq!(decode_cr1_with_amount(&mixed), None, "mixed case");

    // a payload of any other length, under the same human-readable part and
    // a checksum that is valid for it: nothing is wrong with it but its
    // length
    assert_eq!(bech32m("cr10n", &[0x01; 65]), cr1);
    for length in [0, 1, 32, 64, 66, 96, 130] {
        let wrong = bech32m("cr10n", &vec![0x01; length]);
        assert_eq!(decode_cr1_with_amount(&wrong), None, "{length} bytes");
        assert!(!is_cr1_with_amount(&wrong), "{length} bytes");
    }
}

#[test]
fn an_amount_that_is_no_whole_number_of_millisatoshi_is_no_cr1() {
    let signature = [0xab; 65];
    // BOLT-11's smallest unit is a tenth of a millisatoshi, so `10p` is the
    // one millisatoshi and a certificate cannot be for less
    let one_msat = bech32m("cr10p", &signature);
    assert_eq!(one_msat, encode_cr1_with_amount(1, &signature));
    assert_eq!(
        decode_cr1_with_amount(&one_msat),
        Some(Cr1 {
            amount_msat: 1,
            signature
        })
    );
    for hrp in ["cr1p", "cr5p", "cr15p", "cr1001p", "cr210000000001p"] {
        let value = bech32m(hrp, &signature);
        assert_eq!(decode_cr1_with_amount(&value), None, "{hrp}");
        assert!(!is_cr1_with_amount(&value), "{hrp}");
    }

    // nor is anything else that spells no amount: no digits, no such unit, a
    // sign or a fraction, or more millisatoshi than a u64 counts
    let past_u128 = format!("cr{}", "9".repeat(40));
    for hrp in [
        "crp",
        "crn",
        "cr10x",
        "cr1n0",
        "cr-1n",
        "cr+1n",
        "cr1.5n",
        "cr184467440737095516160p",
        "cr18446744073709551616n",
        past_u128.as_str(),
    ] {
        let value = bech32m(hrp, &signature);
        assert_eq!(decode_cr1_with_amount(&value), None, "{hrp}");
    }
}

// ---- verification ----

#[test]
fn a_cr1_verifies_only_against_the_mint_that_signed_it() {
    let key = mint_key(0x42);
    let pubkey = pubkey_of(&key);
    let other = pubkey_of(&mint_key(0x43));
    let cr1 = certify_rotation(&key, SPENT, NOTE, 5000);
    assert!(cr1.starts_with("cr50n1"), "{cr1}");
    assert!(verify_rotation_certificate(
        SPENT, NOTE, 5000, &cr1, &pubkey
    ));
    assert!(!verify_rotation_certificate(
        SPENT, NOTE, 5000, &cr1, &other
    ));
    // case and whitespace of the ids, the certificate and the key don't
    // matter
    assert!(verify_rotation_certificate(
        &format!(" {} ", SPENT.to_ascii_uppercase()),
        &NOTE.to_ascii_uppercase(),
        5000,
        &format!(" {} ", cr1.to_ascii_uppercase()),
        &format!(" {} ", pubkey.to_ascii_uppercase()),
    ));
}

#[test]
fn a_cr1_relabelled_with_another_amount_is_rejected() {
    let key = mint_key(0x42);
    let pubkey = pubkey_of(&key);
    let cr1 = certify_rotation(&key, SPENT, NOTE, 5000);
    // a claim the certificate itself does not make
    assert!(!verify_rotation_certificate(
        SPENT, NOTE, 5001, &cr1, &pubkey
    ));

    // the signed bytes moved under another amount's prefix: the amount it
    // now states is not the one that was signed, and the one that was signed
    // is not the one it states
    let signature = decode_cr1_with_amount(&cr1).expect("a cr1").signature;
    let relabelled = encode_cr1_with_amount(5001, &signature);
    assert!(is_cr1_with_amount(&relabelled));
    assert!(!verify_rotation_certificate(
        SPENT,
        NOTE,
        5000,
        &relabelled,
        &pubkey
    ));
    assert!(!verify_rotation_certificate(
        SPENT,
        NOTE,
        5001,
        &relabelled,
        &pubkey
    ));
}

#[test]
fn a_cr1_names_one_step_in_one_direction() {
    // what a note's lineage carries: one certificate per rotation, each
    // one's credited note the next one's burned note
    let key = mint_key(0x42);
    let pubkey = pubkey_of(&key);
    let chain = [
        SPENT.to_string(),
        NOTE.to_string(),
        "11".repeat(32),
        "22".repeat(32),
    ];
    let certificates: Vec<String> = chain
        .windows(2)
        .map(|step| certify_rotation(&key, &step[0], &step[1], 5000))
        .collect();

    for (index, cr1) in certificates.iter().enumerate() {
        for (from, spent) in chain.iter().enumerate() {
            for (to, note) in chain.iter().enumerate() {
                // never backwards, never the next step, never a shortcut
                // past a note in between, and never a note into itself
                assert_eq!(
                    verify_rotation_certificate(spent, note, 5000, cr1, &pubkey),
                    from == index && to == index + 1,
                    "certificate {index} for {from} -> {to}"
                );
            }
        }
    }
}

#[test]
fn a_cr1_is_never_a_note_certificate_and_a_cs1_is_never_a_cr1() {
    let key = mint_key(0x42);
    let pubkey = pubkey_of(&key);
    assert_ne!(
        rotation_signature_message(SPENT, NOTE, 5000),
        note_signature_message_for_hash(NOTE, 5000)
    );

    // a rotation's signature under a cs1's prefix, or as raw hex, certifies
    // neither note
    let cr1 = certify_rotation(&key, SPENT, NOTE, 5000);
    let rotation = decode_cr1_with_amount(&cr1).expect("a cr1").signature;
    let as_cs1 = encode_cs1_with_amount(5000, &rotation);
    for id in [SPENT, NOTE] {
        for signature in [as_cs1.clone(), hex::encode(rotation), cr1.clone()] {
            assert!(
                !verify_note_signature_hash(id, 5000, &signature, &pubkey),
                "{id}: {signature}"
            );
        }
    }
    // and neither spelling is a rotation certificate: only a cr1 is read
    for not_a_cr1 in [as_cs1, hex::encode(rotation)] {
        assert!(
            !verify_rotation_certificate(SPENT, NOTE, 5000, &not_a_cr1, &pubkey),
            "{not_a_cr1}"
        );
    }

    // a note's real certificate under a cr1's prefix decodes, and certifies
    // no rotation into or out of that note
    let certificate = sign(&key, note_signature_digest_for_hash(NOTE, 5000));
    let cs1 = encode_cs1_with_amount(5000, &certificate);
    assert!(verify_note_signature_hash(NOTE, 5000, &cs1, &pubkey));
    let as_cr1 = encode_cr1_with_amount(5000, &certificate);
    assert!(is_cr1_with_amount(&as_cr1));
    for (spent, note) in [(SPENT, NOTE), (NOTE, SPENT), (NOTE, NOTE)] {
        assert!(
            !verify_rotation_certificate(spent, note, 5000, &as_cr1, &pubkey),
            "{spent} -> {note}"
        );
        assert!(
            !verify_rotation_certificate(spent, note, 5000, &cs1, &pubkey),
            "{spent} -> {note}"
        );
    }
}

#[test]
fn a_cr1_with_its_recovery_id_leading_does_not_verify() {
    // r || s || recovery id is the layout lnurl-mint writes a cr1 in, and
    // the only one lnurl-wallet reads. A note's certificate is still read
    // with the recovery id at either end, for the sake of ones issued that
    // way; a cr1 has no such past, and one that verified here and nowhere
    // else would be worse than one refused everywhere.
    let key = mint_key(0x42);
    let pubkey = pubkey_of(&key);
    let rotation = sign(&key, rotation_signature_digest(SPENT, NOTE, 5000));
    let trailing = encode_cr1_with_amount(5000, &rotation);
    let leading = encode_cr1_with_amount(5000, &recovery_id_leading(rotation));
    assert!(verify_rotation_certificate(
        SPENT, NOTE, 5000, &trailing, &pubkey
    ));
    assert!(is_cr1_with_amount(&leading));
    assert!(!verify_rotation_certificate(
        SPENT, NOTE, 5000, &leading, &pubkey
    ));

    // the same reordering of a note's own certificate still verifies, as a
    // cs1 and as raw hex
    let certificate = sign(&key, note_signature_digest_for_hash(NOTE, 5000));
    for signature in [certificate, recovery_id_leading(certificate)] {
        for spelling in [
            encode_cs1_with_amount(5000, &signature),
            hex::encode(signature),
        ] {
            assert!(
                verify_note_signature_hash(NOTE, 5000, &spelling, &pubkey),
                "{spelling}"
            );
        }
    }
}

#[test]
fn an_id_that_is_not_64_hex_names_no_note_even_when_it_was_signed() {
    // The message is built from whatever ids it is given, so a mint key can
    // be made to sign one over an id that names no note. Verifying with that
    // same id then checks a good signature over the very message it signs:
    // nothing but the check on the id itself is left to refuse it.
    let key = mint_key(0x42);
    let pubkey = pubkey_of(&key);
    for malformed in [
        "",
        "ab",
        &SPENT[..63],
        &format!("{SPENT}0"),
        &"g".repeat(64),
        // 64 bytes, none of them hex
        &"\u{e9}".repeat(32),
        &format!("{}:", &SPENT[..63]),
        &format!("{SPENT}:{NOTE}"),
    ] {
        let as_spent = certify_rotation(&key, malformed, NOTE, 5000);
        assert!(
            !verify_rotation_certificate(malformed, NOTE, 5000, &as_spent, &pubkey),
            "spent {malformed:?}"
        );
        let as_note = certify_rotation(&key, SPENT, malformed, 5000);
        assert!(
            !verify_rotation_certificate(SPENT, malformed, 5000, &as_note, &pubkey),
            "note {malformed:?}"
        );
    }
    // built the same way from two ids that do name notes, it verifies
    let real = certify_rotation(&key, SPENT, NOTE, 5000);
    assert!(verify_rotation_certificate(
        SPENT, NOTE, 5000, &real, &pubkey
    ));
}

#[test]
fn malformed_input_is_rejected_without_panicking() {
    let key = mint_key(0x42);
    let pubkey = pubkey_of(&key);
    let cr1 = certify_rotation(&key, SPENT, NOTE, 5000);
    assert!(verify_rotation_certificate(
        SPENT, NOTE, 5000, &cr1, &pubkey
    ));

    let cp1 = encode_cp1(
        &hex::decode(SPENT)
            .expect("hex")
            .try_into()
            .expect("32 bytes"),
    );
    let long = "a".repeat(10_000);
    for id in [
        "",
        "zz",
        "ab",
        &SPENT[..63],
        &format!("{SPENT}0"),
        &"g".repeat(64),
        // 64 bytes, none of them hex
        &"\u{e9}".repeat(32),
        &format!("{}:", &SPENT[..63]),
        cp1.as_str(),
        pubkey.as_str(),
        long.as_str(),
    ] {
        assert!(
            !verify_rotation_certificate(id, NOTE, 5000, &cr1, &pubkey),
            "spent {id:?}"
        );
        assert!(
            !verify_rotation_certificate(SPENT, id, 5000, &cr1, &pubkey),
            "note {id:?}"
        );
    }

    let last = cr1.chars().last().expect("non-empty");
    let flipped = format!(
        "{}{}",
        &cr1[..cr1.len() - 1],
        if last == 'q' { 'p' } else { 'q' }
    );
    let long_cr1 = format!("cr50n1{}", "q".repeat(10_000));
    let signature = decode_cr1_with_amount(&cr1).expect("a cr1").signature;
    for certificate in [
        "",
        "nope",
        "cr1",
        "cr50n1",
        "cr50n1\u{e9}\u{e9}\u{e9}",
        &cr1[..cr1.len() - 1],
        flipped.as_str(),
        long_cr1.as_str(),
        // the real signature a byte short and a byte long, checksum valid
        &bech32m("cr50n", &signature[..64]),
        &bech32m("cr50n", &[&signature[..], &[0u8][..]].concat()),
        // well-formed, and signed by nobody
        &encode_cr1_with_amount(5000, &[0x07; 65]),
        &encode_cr1_with_amount(5000, &[0xff; 65]),
        &encode_cr1_with_amount(5000, &[0x00; 65]),
    ] {
        assert!(
            !verify_rotation_certificate(SPENT, NOTE, 5000, certificate, &pubkey),
            "{certificate:?}"
        );
    }

    let x_only = &pubkey[2..];
    for mint_pubkey in [
        "",
        "nope",
        x_only,
        &format!("{pubkey}00"),
        &format!("02{}", "00".repeat(32)),
        "\u{1f4b8}",
        long.as_str(),
    ] {
        assert!(
            !verify_rotation_certificate(SPENT, NOTE, 5000, &cr1, mint_pubkey),
            "{mint_pubkey:?}"
        );
    }
}
