//! LUD-25 offline verification, and the address-registration proof.
//!
//! A SERVICE certifies each note it issues with its Lightning node identity
//! key (the same key it signs BOLT-11 invoices with), so a holder can confirm
//! a note's issuer and amount without contacting anyone. Signed via the
//! node's own signmessage RPC (lnd's `/v1/signmessage`, cln's `signmessage`),
//! which wraps the message with this prefix and double-SHA256s it before
//! signing. That is deliberate reuse: any tool that already verifies a
//! Lightning node's signed messages can verify a note.
//!
//! ```text
//! message = "LNURLcash:" || amount_msat (decimal ASCII) || ":" || hex(Q)
//! digest  = sha256(sha256("Lightning Signed Message:" || message))
//! ```
//!
//! `Q` is the note's taproot output key, for every kind of note: a bearer
//! note's `Q` is public too, so a SERVICE can certify one without disclosing
//! what spends it. A SERVICE from before notes were keyed by `Q` certified a
//! bearer note over its hash `h` instead, and those certificates are still
//! read, reported as [`CertifiedOver::LegacyHash`].
//!
//! A certificate proves issuance, not that the spend in hand opens the note:
//! a `ck1` states its `Q` in plain sight, so anyone who has seen a note's
//! `cp1` and `cs1` can pair them with a signature that opens nothing.
//! [`check_note`] makes both checks, which is why it needs the mint's domain.
//!
//! A SERVICE may answer a rotate with a second certificate, a `cr1`: the
//! same kind of signature, by the same key, over the note it burned, the one
//! note it credited in its place, and that note's value. That one is an
//! extension, not part of LUD-25.
//!
//! ```text
//! message = "LNURLcash:rotate:" || amount_msat || ":" || hex(Q_spent) || ":" || hex(Q)
//! ```
//!
//! A `cs1` says a note exists. A `cr1` says which one note it came from. A
//! SERVICE burns a note once, so it signs at most one such statement for any
//! `Q_spent`, and that is what an asset anchored to a note needs each of its
//! transfers to carry. The statement is the signing key's, and no stronger
//! than that SERVICE's own record of what it burned. See
//! [`verify_rotation_certificate`].

use k256::schnorr::SigningKey;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::Message;
use sha2::{Digest, Sha256};

use crate::recoverable::{decode_cr1_with_amount, decode_cs1, decode_cs1_with_amount, note_id_of};
use crate::spend::{check_spend, decode_note, decode_spend, spend_domain_of, SpendVerdict};

const LIGHTNING_SIGNED_MESSAGE_PREFIX: &[u8] = b"Lightning Signed Message:";
const DOMAIN_TAG: &str = "LNURLcash";

// ---- the address-registration proof ----

/// `LNURLcash:<action>:<domain>:<username>`. `domain` is the SERVICE's own
/// hostname: a URL or `host:port` is reduced to it, as for a spend (see
/// [`spend_domain_of`]). Binding it stops a proof one SERVICE has seen being
/// replayed against another. `username` is used exactly as sent.
pub fn address_proof_message(action: &str, domain: &str, username: &str) -> crate::Result<String> {
    if action != "register" && action != "unregister" {
        return Err(crate::Error::Protocol(
            "an address proof action is register or unregister".into(),
        ));
    }
    let domain = spend_domain_of(domain).ok_or_else(|| {
        crate::Error::Protocol("an address proof names the SERVICE's domain".into())
    })?;
    Ok(format!("{DOMAIN_TAG}:{action}:{domain}:{username}"))
}

/// [`address_proof_message`], hashed to the 32-byte digest that is signed:
/// most Schnorr signers only accept 32 bytes.
pub fn address_proof_digest(action: &str, domain: &str, username: &str) -> crate::Result<[u8; 32]> {
    Ok(Sha256::digest(address_proof_message(action, domain, username)?.as_bytes()).into())
}

/// Sign a register or unregister proof as a raw 64-byte BIP-340 signature,
/// with an all-zero auxiliary input so a retried request resends the same
/// proof. The key is the branch's index-0 note key, which the SERVICE checks
/// against `pk_0` derived from the `cx1`.
pub fn sign_address_proof(
    index_zero_secret_key: &[u8; 32],
    action: &str,
    domain: &str,
    username: &str,
) -> crate::Result<[u8; 64]> {
    let key = SigningKey::from_bytes(index_zero_secret_key).map_err(|_| {
        crate::Error::Protocol("an index-zero secret key is a 32-byte scalar in [1, n)".into())
    })?;
    key.sign_raw(&address_proof_digest(action, domain, username)?, &[0u8; 32])
        .map(|signature| signature.to_bytes())
        .map_err(|_| crate::Error::Protocol("could not sign the address proof message".into()))
}

// ---- certificates ----

/// What a Lightning node's signmessage puts its pen to, and so what every
/// recoverable-ECDSA SERVICE signature is made over.
pub(crate) fn lightning_signed_digest(message: &str) -> [u8; 32] {
    let inner = Sha256::digest([LIGHTNING_SIGNED_MESSAGE_PREFIX, message.as_bytes()].concat());
    Sha256::digest(inner).into()
}

/// The message a SERVICE certifies for the note `k1` spends, over `hex(Q)`.
/// `None` for a `k1` that is no spend (see [`note_id_of`]).
pub fn note_signature_message(k1: &str, amount_msat: u64) -> Option<String> {
    Some(note_signature_message_for_hash(
        &note_id_of(k1)?,
        amount_msat,
    ))
}

/// The same message over a note id given directly: `hex(Q)`, or, to build
/// the message a SERVICE predating taproot signed for a bearer note, its
/// hash `h`. Used exactly as given, lowercased.
pub fn note_signature_message_for_hash(id: &str, amount_msat: u64) -> String {
    format!(
        "{DOMAIN_TAG}:{amount_msat}:{}",
        id.trim().to_ascii_lowercase()
    )
}

pub fn note_signature_digest(k1: &str, amount_msat: u64) -> Option<[u8; 32]> {
    Some(note_signature_digest_for_hash(
        &note_id_of(k1)?,
        amount_msat,
    ))
}

pub fn note_signature_digest_for_hash(id: &str, amount_msat: u64) -> [u8; 32] {
    lightning_signed_digest(&note_signature_message_for_hash(id, amount_msat))
}

/// Which message a certificate verified over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedOver {
    /// `hex(Q)`: LUD-25's certificate, for any note.
    OutputKey,
    /// A bearer note's hash `h`, as a SERVICE signed before notes were keyed
    /// by `Q`. It still proves issuance of that note for that amount.
    LegacyHash,
}

/// Check a certificate over exactly the 64-hex `id` given: `hex(Q)`, or a
/// bearer note's `h` for a pre-taproot certificate. The primitive the other
/// checks here are built on; prefer [`check_note`] or
/// [`check_note_certificate`], which work out the id themselves.
///
/// `signature_hex` is 65 bytes of hex, or a `cs1` in either form. An
/// amount-bearing `cs1` must state `amount_msat` in its human-readable part
/// as well as sign it: a payload moved under another amount's prefix would
/// otherwise verify while displaying an amount nobody certified.
///
/// Which end of the raw bytes carries the recovery id varies by
/// implementation: LUD-25 calls for `r || s || recovery_id`, the layout raw
/// BOLT-11 signatures use, while lnurl-mint once forwarded its node's
/// signmessage output unreordered as `recovery_id || r || s`. Trying both
/// costs nothing security-wise - recovering against the wrong one yields an
/// unrelated pubkey that cannot match - and means a note verifies regardless
/// of which convention issued it.
///
/// Never panics. An unverifiable signature is a `false`.
pub fn verify_note_signature_hash(
    id: &str,
    amount_msat: u64,
    signature_hex: &str,
    mint_pubkey_hex: &str,
) -> bool {
    let id = id.trim();
    if !is_note_id(id) {
        return false;
    }
    let trimmed = signature_hex.trim();
    let signature = if let Some(cs1) = decode_cs1_with_amount(trimmed) {
        if cs1.amount_msat != amount_msat {
            return false;
        }
        cs1.signature.to_vec()
    } else if let Some(signature) = decode_cs1(trimmed) {
        signature.to_vec()
    } else {
        match hex::decode(trimmed) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        }
    };
    recovers_to(
        note_signature_digest_for_hash(id, amount_msat),
        &signature,
        mint_pubkey_hex,
        RecoveryIdAt::EitherEnd,
    )
}

/// A note id as a certificate is checked over: 32 bytes of hex.
fn is_note_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Which end of a 65-byte recoverable signature may carry its recovery id.
#[derive(Clone, Copy)]
enum RecoveryIdAt {
    /// `r || s || recovery_id` only: what LUD-25 calls for.
    Trailing,
    /// That, or `recovery_id || r || s`: a note's certificate has been
    /// issued both ways (see [`verify_note_signature_hash`]).
    EitherEnd,
}

/// Whether a 65-byte recoverable signature over `digest` recovers to
/// `mint_pubkey_hex`, reading the recovery id where `recovery_id` allows.
/// What every certificate check here comes down to.
fn recovers_to(
    digest: [u8; 32],
    signature: &[u8],
    mint_pubkey_hex: &str,
    recovery_id: RecoveryIdAt,
) -> bool {
    if signature.len() != 65 {
        return false;
    }
    let message = Message::from_digest(digest);
    let target = mint_pubkey_hex.trim().to_ascii_lowercase();
    // (compact 64 bytes, recovery id) under each candidate ordering
    let trailing = (&signature[..64], signature[64]);
    let leading = (&signature[1..65], signature[0]);
    let layouts = [trailing, leading];
    let layouts = match recovery_id {
        RecoveryIdAt::Trailing => &layouts[..1],
        RecoveryIdAt::EitherEnd => &layouts[..],
    };

    for &(compact, recovery) in layouts {
        let Ok(id) = RecoveryId::try_from(i32::from(recovery)) else {
            continue;
        };
        let Ok(sig) = RecoverableSignature::from_compact(compact, id) else {
            continue;
        };
        if let Ok(recovered) = sig.recover_ecdsa(message) {
            if hex::encode(recovered.serialize()) == target {
                return true;
            }
        }
    }
    false
}

fn certified_over(
    output_key: &[u8; 32],
    bearer_hash: Option<[u8; 32]>,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> Option<CertifiedOver> {
    if verify_note_signature_hash(
        &hex::encode(output_key),
        amount_msat,
        signature,
        mint_pubkey,
    ) {
        return Some(CertifiedOver::OutputKey);
    }
    bearer_hash
        .filter(|h| {
            verify_note_signature_hash(&hex::encode(h), amount_msat, signature, mint_pubkey)
        })
        .map(|_| CertifiedOver::LegacyHash)
}

/// Check a certificate for a note named without its spend: a `cp1`, or a
/// bearer note's 64-hex `h` (the two things that go where a `cp1` goes).
/// Tries `hex(Q)` first and, for a bearer `h`, the pre-taproot message over
/// `h` itself. What a watcher, or a device that discloses only `h`, checks
/// a note by. `None` if neither verifies.
pub fn check_note_certificate(
    reference: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> Option<CertifiedOver> {
    let output_key = decode_note(reference)?;
    let bearer_hash = crate::secrets::is_preimage(reference)
        .then(|| hex::decode(reference.trim()).ok()?.try_into().ok())
        .flatten();
    certified_over(
        &output_key,
        bearer_hash,
        amount_msat,
        signature,
        mint_pubkey,
    )
}

/// What an offline check of a note found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteCheck {
    /// The note, `Q`.
    pub output_key: [u8; 32],
    /// Whether the spend opens `Q` at the note's domain.
    pub spend: SpendVerdict,
    /// Which message the certificate verified over.
    pub certificate: CertifiedOver,
}

impl NoteCheck {
    /// Issued by the key on record for this amount, and opened by the spend
    /// in hand under a scheme mints accept.
    pub fn is_verified(&self) -> bool {
        self.spend.opens()
    }
}

/// LUD-25's offline verification of a certified note: derive `Q` from the
/// spend, check the spend opens `Q` at `domain` (the note URL's own host, as
/// a note URL, a mint URL or a bare host), and check the certificate over
/// `Q` and `amount_msat` recovers to `mint_pubkey`.
///
/// `None` when `k1` is no spend or the certificate does not verify.
/// Otherwise [`NoteCheck::spend`] says what the spend did: a `ck1` signed for
/// another mint, or a `cw1` whose witness does not satisfy its leaf, comes
/// back [`SpendVerdict::Fails`] with its valid certificate, so a caller can
/// tell a forged spend from a forged certificate. Time claims are left to
/// the SERVICE's clock.
///
/// A certificate proves issuance, not that the note is still outstanding:
/// the previous holder still knows the spend. Rotate on receipt.
pub fn check_note(
    k1: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> Option<NoteCheck> {
    let spend = check_spend(k1, domain)?;
    let bearer_hash = decode_spend(k1)?.bearer_hash();
    let certificate = certified_over(
        &spend.output_key,
        bearer_hash,
        amount_msat,
        signature,
        mint_pubkey,
    )?;
    Some(NoteCheck {
        output_key: spend.output_key,
        spend: spend.verdict,
        certificate,
    })
}

/// [`check_note`] as a yes or no: the certificate verifies, over either
/// message, and the spend opens the note, under any scheme a mint accepts.
/// A `cw1` whose script this crate does not evaluate is a no.
///
/// `domain` is required because a `ck1` means nothing without it: the
/// certificate alone is public, and anyone could pair it with a signature
/// that opens nothing.
pub fn verify_note_signature(
    k1: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> bool {
    check_note(k1, domain, amount_msat, signature, mint_pubkey)
        .is_some_and(|check| check.is_verified())
}

// ---- rotation certificates ----

/// The message a SERVICE certifies a rotation with: the note it burned, the
/// one note it credited in its place, and that note's value. Each id is a
/// note's `hex(Q)`, trimmed and lowercased, and not otherwise checked. Told
/// apart from a note's own message by its second field, which there is
/// always a decimal amount.
pub fn rotation_signature_message(spent_id: &str, note_id: &str, amount_msat: u64) -> String {
    format!(
        "{DOMAIN_TAG}:rotate:{amount_msat}:{}:{}",
        spent_id.trim().to_ascii_lowercase(),
        note_id.trim().to_ascii_lowercase()
    )
}

pub fn rotation_signature_digest(spent_id: &str, note_id: &str, amount_msat: u64) -> [u8; 32] {
    lightning_signed_digest(&rotation_signature_message(spent_id, note_id, amount_msat))
}

/// Check a `cr1`: a SERVICE's signed statement that it burned the note
/// `spent_id` and credited exactly the one note `note_id`, worth
/// `amount_msat`, in its place. Both ids are 64-hex `hex(Q)`.
///
/// A SERVICE may answer a rotate with one, as `r`, and never a split or a
/// merge: neither has one note that became one other. It is an extension,
/// not part of LUD-25, and a SERVICE that issues them still omits one it
/// could not sign. A SERVICE burns a note once, so it signs at most one such
/// statement for any `spent_id`, and with one per transfer a holder can
/// check, against that key alone, each step something anchored to a note
/// took from note to note.
///
/// That is all it is: the signing key's statement, as good as that
/// SERVICE's own record of what it burned. Nothing checked offline can show
/// that no second certificate names the same `spent_id`. Nor does it say
/// `note_id` is still outstanding: its holder may have spent it since.
///
/// Only a `cr1` is read, never a `cs1` or raw hex, and it must state
/// `amount_msat` in its human-readable part as well as sign it. Its 65
/// bytes are `r || s || recovery_id` and nothing else, as the TypeScript
/// kit and lnurl-mint read one. A note's certificate is still read with the
/// recovery id at either end (see [`verify_note_signature_hash`]), for the
/// sake of ones issued that way; a `cr1` is new, and reading both here
/// would only make a certificate one wallet takes and another refuses.
///
/// Never panics. A malformed id, certificate or key is a `false`.
pub fn verify_rotation_certificate(
    spent_id: &str,
    note_id: &str,
    amount_msat: u64,
    cr1: &str,
    mint_pubkey_hex: &str,
) -> bool {
    let (spent_id, note_id) = (spent_id.trim(), note_id.trim());
    if !is_note_id(spent_id) || !is_note_id(note_id) {
        return false;
    }
    let Some(cr1) = decode_cr1_with_amount(cr1) else {
        return false;
    };
    if cr1.amount_msat != amount_msat {
        return false;
    }
    recovers_to(
        rotation_signature_digest(spent_id, note_id, amount_msat),
        &cr1.signature,
        mint_pubkey_hex,
        RecoveryIdAt::Trailing,
    )
}
