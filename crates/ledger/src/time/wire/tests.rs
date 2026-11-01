#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use ed25519_dalek::SigningKey;
use ed25519_dalek::ed25519::signature::Signer as _;
use roughenough_protocol::header::{RawHeader, find_value_range};
use roughenough_protocol::tag::Tag;

use super::*;

const CLOUDFLARE_KEY: [u8; 32] = [
    208, 96, 251, 115, 124, 143, 243, 17, 28, 225, 153, 118, 205, 235, 141, 217, 41, 75, 188, 53,
    85, 161, 200, 236, 61, 34, 252, 253, 25, 127, 239, 56,
];
const CLOUDFLARE_RESPONSE: &[u8] = include_bytes!("../testdata/cloudflare-draft-11.response");
const CLOUDFLARE_NONCE: &[u8; 32] = include_bytes!("../testdata/cloudflare-draft-11.nonce");

const LONG_TERM: [u8; 32] = [0x11; 32];
const ONLINE: [u8; 32] = [0x22; 32];
const NONCE: [u8; 32] = [0x5a; 32];
const MIDP: u64 = 1_793_505_043;

fn encode(pairs: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
    let mut pairs: Vec<_> = pairs.to_vec();
    pairs.sort_by_key(|(t, _)| u32::from_le_bytes(**t));
    let mut out = u32::try_from(pairs.len()).unwrap().to_le_bytes().to_vec();
    let mut offset = 0_u32;
    for (i, (_, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        offset += u32::try_from(v.len()).unwrap();
    }
    for (t, _) in &pairs {
        out.extend_from_slice(*t);
    }
    for (_, v) in &pairs {
        out.extend_from_slice(v);
    }
    out
}

fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = b"ROUGHTIM".to_vec();
    out.extend_from_slice(&u32::try_from(msg.len()).unwrap().to_le_bytes());
    out.extend_from_slice(msg);
    out
}

fn h2(a: &[u8], b: &[u8]) -> [u8; 32] {
    h(&[&[0x01], a, b])
}

struct Answer {
    version: Version,
    contexts: Version,
    index: u32,
    path: Vec<[u8; 32]>,
    midp: u64,
    mint: u64,
    maxt: u64,
}

impl Answer {
    fn new(version: Version) -> Self {
        Self {
            version,
            contexts: version,
            index: 0,
            path: Vec::new(),
            midp: MIDP,
            mint: MIDP - 3_600,
            maxt: MIDP + 3_600,
        }
    }

    fn root(&self) -> [u8; 32] {
        let leaf = match self.version {
            Version::Rfc => asked(Version::Rfc, &NONCE),
            Version::Draft11 => NONCE.to_vec(),
        };
        let mut hash = h(&[&[0x00], &leaf]);
        let mut index = self.index;
        for node in &self.path {
            hash = if index & 1 == 0 {
                h2(&hash, node)
            } else {
                h2(node, &hash)
            };
            index >>= 1;
        }
        hash
    }

    fn packet(&self) -> Vec<u8> {
        let long_term = SigningKey::from_bytes(&LONG_TERM);
        let online = SigningKey::from_bytes(&ONLINE);
        let dele = encode(&[
            (b"PUBK", online.verifying_key().to_bytes().to_vec()),
            (b"MINT", self.mint.to_le_bytes().to_vec()),
            (b"MAXT", self.maxt.to_le_bytes().to_vec()),
        ]);
        let mut srep_pairs = vec![
            (b"ROOT", self.root().to_vec()),
            (b"MIDP", self.midp.to_le_bytes().to_vec()),
            (b"RADI", 3_u32.to_le_bytes().to_vec()),
        ];
        if self.version == Version::Rfc {
            srep_pairs.push((b"VER\0", 1_u32.to_le_bytes().to_vec()));
            srep_pairs.push((b"VERS", 1_u32.to_le_bytes().to_vec()));
        }
        let srep = encode(&srep_pairs);
        let dele_sig = long_term.sign(&[self.contexts.dele_context(), &dele[..]].concat());
        let cert = encode(&[(b"DELE", dele), (b"SIG\0", dele_sig.to_bytes().to_vec())]);
        let srep_sig = online.sign(&[self.contexts.srep_context(), &srep[..]].concat());
        let mut top = vec![
            (b"SIG\0", srep_sig.to_bytes().to_vec()),
            (b"PATH", self.path.concat()),
            (b"SREP", srep),
            (b"CERT", cert),
            (b"INDX", self.index.to_le_bytes().to_vec()),
        ];
        match self.version {
            Version::Rfc => {
                top.push((b"NONC", NONCE.to_vec()));
                top.push((b"TYPE", 1_u32.to_le_bytes().to_vec()));
            }
            Version::Draft11 => top.push((b"VER\0", DRAFT_11.to_le_bytes().to_vec())),
        }
        frame(&encode(&top))
    }
}

fn asked(version: Version, challenge: &[u8; 32]) -> Vec<u8> {
    request(version, challenge, &long_term_key()).unwrap()
}

fn long_term_key() -> [u8; 32] {
    SigningKey::from_bytes(&LONG_TERM)
        .verifying_key()
        .to_bytes()
}

// OP-42
#[test]
fn op_42_a_draft_11_answer_from_cloudflare_verifies() {
    let v = verify(
        Version::Draft11,
        &CLOUDFLARE_KEY,
        &request(Version::Draft11, CLOUDFLARE_NONCE, &CLOUDFLARE_KEY).unwrap(),
        CLOUDFLARE_RESPONSE,
    )
    .unwrap();
    assert_eq!(
        v,
        Verified {
            midpoint_s: 1_793_505_043,
            radius_s: 1,
        }
    );
    assert!(matches!(
        verify(
            Version::Rfc,
            &CLOUDFLARE_KEY,
            &request(Version::Rfc, CLOUDFLARE_NONCE, &CLOUDFLARE_KEY).unwrap(),
            CLOUDFLARE_RESPONSE
        ),
        Err(WireError::Parse(_))
    ));
    assert!(matches!(
        verify(
            Version::Draft11,
            &CLOUDFLARE_KEY,
            &request(Version::Draft11, &[0; 32], &CLOUDFLARE_KEY).unwrap(),
            CLOUDFLARE_RESPONSE
        ),
        Err(WireError::Merkle)
    ));
}

// OP-42
#[test]
fn op_42_rfc_and_draft_11_answers_verify_through_the_same_driver() {
    for version in [Version::Rfc, Version::Draft11] {
        let mut answer = Answer::new(version);
        assert_eq!(
            verify(
                version,
                &long_term_key(),
                &asked(version, &NONCE),
                &answer.packet()
            )
            .unwrap(),
            Verified {
                midpoint_s: MIDP,
                radius_s: 3,
            },
            "{version:?}"
        );
        answer.index = 2;
        answer.path = vec![[0x31; 32], [0x32; 32]];
        assert!(
            verify(
                version,
                &long_term_key(),
                &asked(version, &NONCE),
                &answer.packet()
            )
            .is_ok(),
            "{version:?}"
        );
    }
}

// OP-42
#[test]
fn op_42_the_context_strings_of_one_version_do_not_verify_the_other() {
    let rfc = Answer::new(Version::Rfc).packet();
    let draft = Answer::new(Version::Draft11).packet();
    assert!(matches!(
        verify(
            Version::Draft11,
            &long_term_key(),
            &asked(Version::Draft11, &NONCE),
            &rfc
        ),
        Err(WireError::Parse(_))
    ));
    assert!(matches!(
        verify(
            Version::Rfc,
            &long_term_key(),
            &asked(Version::Rfc, &NONCE),
            &draft
        ),
        Err(WireError::Parse(_))
    ));
    for (version, contexts) in [
        (Version::Draft11, Version::Rfc),
        (Version::Rfc, Version::Draft11),
    ] {
        let mut crossed = Answer::new(version);
        crossed.contexts = contexts;
        assert!(matches!(
            verify(
                version,
                &long_term_key(),
                &asked(version, &NONCE),
                &crossed.packet()
            ),
            Err(WireError::Signature("delegation", _))
        ));
    }
    assert_ne!(Version::Rfc.dele_context(), Version::Draft11.dele_context());
    assert_ne!(Version::Rfc.srep_context(), Version::Draft11.srep_context());
}

// OP-42
#[test]
fn op_42_a_changed_answer_another_key_or_another_nonce_is_refused() {
    for version in [Version::Rfc, Version::Draft11] {
        let packet = Answer::new(version).packet();
        assert!(matches!(
            verify(version, &[0x44; 32], &asked(version, &NONCE), &packet),
            Err(WireError::Signature(..))
        ));
        let msg = packet[12..].to_vec();
        let midp = find_value_range(&msg, &[Tag::SREP, Tag::MIDP]).unwrap();
        let mut changed = packet.clone();
        changed[12 + midp.start] ^= 1;
        assert!(matches!(
            verify(version, &long_term_key(), &asked(version, &NONCE), &changed),
            Err(WireError::Signature("response", _))
        ));
        let other = [0x5b; 32];
        assert!(verify(version, &long_term_key(), &asked(version, &other), &packet).is_err());
        let mut late = Answer::new(version);
        late.maxt = MIDP - 1;
        assert!(matches!(
            verify(
                version,
                &long_term_key(),
                &asked(version, &NONCE),
                &late.packet()
            ),
            Err(WireError::Delegation)
        ));
        let mut wrong_index = Answer::new(version);
        wrong_index.path = vec![[0x31; 32]];
        let mut packet = wrong_index.packet();
        let msg = packet[12..].to_vec();
        let indx = find_value_range(&msg, &[Tag::INDX]).unwrap();
        packet[12 + indx.start] = 4;
        assert!(verify(version, &long_term_key(), &asked(version, &NONCE), &packet).is_err());
        assert!(
            verify(
                version,
                &long_term_key(),
                &asked(version, &NONCE),
                &packet[..20]
            )
            .is_err()
        );
    }
}

// OP-42
#[test]
fn op_42_requests_are_1024_bytes_and_carry_the_version_nonce_and_server_key() {
    for version in [Version::Rfc, Version::Draft11] {
        let req = request(version, &NONCE, &long_term_key()).unwrap();
        assert_eq!(req.len(), 1024, "{version:?}");
        assert_eq!(&req[..8], b"ROUGHTIM");
        let msg = &req[12..];
        RawHeader::parse(msg).unwrap();
        let nonc = find_value_range(msg, &[Tag::NONC]).unwrap();
        assert_eq!(&msg[nonc], &NONCE);
        let srv_value = find_value_range(msg, &[Tag::SRV]).unwrap();
        assert_eq!(&msg[srv_value], &srv(&long_term_key()));
        let ver = find_value_range(msg, &[Tag::VER]).unwrap();
        let want = match version {
            Version::Rfc => 1_u32,
            Version::Draft11 => DRAFT_11,
        };
        assert_eq!(&msg[ver], &want.to_le_bytes());
    }
}
