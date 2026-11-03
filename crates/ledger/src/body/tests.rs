#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::PathBuf;
use std::process::Command;

use super::*;

const PIN: &str = "4711";
const AT: u64 = 1_761_000_000_000;

fn module() -> PathBuf {
    std::env::var_os("PKCS11_MODULE").map_or_else(
        || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        PathBuf::from,
    )
}

/// A `SoftHSM` token of the test's own (T-56): no KMS mock.
fn keys(test: &str) -> BodyKeys {
    let label = format!("body-{test}-{}", std::process::id());
    let init = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            &label,
            "--so-pin",
            "12345678",
            "--pin",
            PIN,
        ])
        .output()
        .expect("softhsm2-util runs (T-56)");
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    BodyKeys::open(&module(), &label, &Secret::new(PIN.to_owned()), 1).unwrap()
}

fn ledger(tag: u8) -> LedgerId {
    LedgerId::from_bytes([tag; 32])
}

fn opening(content: &[u8]) -> BodyOpening {
    BodyOpening {
        part: "note".to_owned(),
        media_type: "text/plain".to_owned(),
        content: content.to_vec(),
        salt: [0x5a; 32],
    }
}

fn commit(o: &BodyOpening) -> [u8; 32] {
    commitment(o).unwrap()
}

fn row(keys: &BodyKeys, l: &LedgerId) -> DekRow {
    let (kek_id, wrapped) = keys.new_class_dek(l).unwrap();
    DekRow {
        dek_id: "0190d4a8-0000-7000-8000-000000000001".to_owned(),
        kek_id,
        wrapped: Some(wrapped),
    }
}

fn sealed(keys: &BodyKeys, dek: &DekRow, l: &LedgerId, o: &BodyOpening) -> SealedPart {
    keys.with_class_dek(dek, AT, |class| seal_part(class, l, &commit(o), o))
        .unwrap()
        .unwrap()
}

fn open(
    keys: &BodyKeys,
    dek: &DekRow,
    l: &LedgerId,
    c: &[u8; 32],
    s: &SealedPart,
) -> Result<Option<BodyOpening>, BodyError> {
    keys.with_class_dek(dek, AT, |class| {
        open_part(class, l, "note", c, &s.wrapped_key, &s.sealed)
    })
}

// OP-45 T-56
#[test]
fn op_45_kek_labels_name_the_ledger_and_the_version() {
    let l = ledger(0xab);
    assert_eq!(
        kek_label(&l, 3),
        format!("work.{}.kek.v3", "ab".repeat(32))
    );
    let c = context(&l, &[0x11; 32]);
    assert_eq!(c.get(..13), Some(b"work/body/v1\0".as_slice()));
    assert_eq!(c.len(), 13 + 32 + 32);
    assert_eq!(object_key(&l, &[0x0f; 32]), format!("{}/{}", "ab".repeat(32), "0f".repeat(32)));
}

// OP-45 P-68 OP-15 T-56
#[test]
fn op_45_a_part_round_trips_under_the_ledger_kek_its_class_dek_and_its_own_key() {
    let keys = keys("round-trip");
    let l = ledger(0x01);
    let dek = row(&keys, &l);
    assert_eq!(dek.kek_id, kek_label(&l, 1));
    let o = opening(b"the agreed delivery date is Friday");
    let s = sealed(&keys, &dek, &l, &o);
    assert_eq!(s.wrapped_key.len(), WRAPPED_LEN);
    assert!(
        !s.sealed
            .ciphertext
            .windows(6)
            .any(|w| w == b"Friday".as_slice())
    );
    let back = open(&keys, &dek, &l, &commit(&o), &s).unwrap().unwrap();
    assert_eq!(back, o);
    let again = sealed(&keys, &dek, &l, &o);
    assert_ne!(again.wrapped_key, s.wrapped_key);
    assert_ne!(again.sealed.ciphertext, s.sealed.ciphertext);
}

// OP-45 P-68 P-104
#[test]
fn p_104_a_part_above_64_kib_round_trips_and_commits_by_its_digest() {
    let keys = keys("large");
    let l = ledger(0x02);
    let dek = row(&keys, &l);
    let o = opening(&vec![0x42; LARGE_PART + 1]);
    let s = sealed(&keys, &dek, &l, &o);
    assert_eq!(open(&keys, &dek, &l, &commit(&o), &s).unwrap(), Some(o));
}

// OP-45 P-68
#[test]
fn op_45_another_ledger_another_part_commit_or_another_class_dek_does_not_open() {
    let keys = keys("context");
    let l = ledger(0x03);
    let dek = row(&keys, &l);
    let o = opening(b"payload");
    let s = sealed(&keys, &dek, &l, &o);
    let c = commit(&o);
    assert!(matches!(
        open(&keys, &dek, &ledger(0x04), &c, &s),
        Err(BodyError::Envelope(EnvelopeError::Open))
    ));
    assert!(matches!(
        open(&keys, &dek, &l, &[0x99; 32], &s),
        Err(BodyError::Envelope(EnvelopeError::Open))
    ));
    let other = row(&keys, &l);
    assert!(matches!(
        open(&keys, &other, &l, &c, &s),
        Err(BodyError::Envelope(EnvelopeError::Wrap))
    ));
}

// P-68 OP-45
#[test]
fn p_68_an_opening_that_does_not_give_its_commitment_is_refused() {
    let keys = keys("commitment");
    let l = ledger(0x05);
    let dek = row(&keys, &l);
    let o = opening(b"one");
    let mut changed = o.clone();
    changed.salt = [0x01; 32];
    let refused = keys
        .with_class_dek(&dek, AT, |class| seal_part(class, &l, &commit(&o), &changed))
        .unwrap_err();
    assert!(matches!(refused, BodyError::Commitment(p) if p == "note"));
    let big = opening(&vec![0; MAX_PART + 1]);
    let refused = keys
        .with_class_dek(&dek, AT, |class| seal_part(class, &l, &[0; 32], &big))
        .unwrap_err();
    assert!(matches!(refused, BodyError::TooLarge(_)));
}

// OP-45 OP-12 Access OP-73
#[test]
fn op_45_a_destroyed_class_dek_or_a_retired_kek_opens_nothing() {
    let keys = keys("shred");
    let l = ledger(0x06);
    let dek = row(&keys, &l);
    let o = opening(b"to be forgotten");
    let s = sealed(&keys, &dek, &l, &o);
    let destroyed = DekRow {
        wrapped: None,
        ..dek.clone()
    };
    assert_eq!(open(&keys, &destroyed, &l, &commit(&o), &s).unwrap(), None);
    if let Some(w) = dek.wrapped {
        keys.forget(&w);
    }
    keys.retire_kek(&l, 1).unwrap();
    assert_eq!(open(&keys, &dek, &l, &commit(&o), &s).unwrap(), None);
    assert!(keys.retire_kek(&l, 1).is_err());
}

// OP-45 T-56
#[test]
fn op_45_rotation_rewraps_a_class_dek_under_the_next_kek_version() {
    let keys = keys("rotate");
    let l = ledger(0x07);
    let dek = row(&keys, &l);
    let o = opening(b"kept across rotation");
    let s = sealed(&keys, &dek, &l, &o);
    let (label, rewrapped) = keys
        .rewrap(&l, &dek.kek_id, 2, &dek.wrapped.unwrap())
        .unwrap();
    assert_eq!(label, kek_label(&l, 2));
    let rotated = DekRow {
        kek_id: label,
        wrapped: Some(rewrapped),
        ..dek.clone()
    };
    keys.retire_kek(&l, 1).unwrap();
    assert_eq!(open(&keys, &dek, &l, &commit(&o), &s).unwrap(), None);
    assert_eq!(
        open(&keys, &rotated, &l, &commit(&o), &s).unwrap(),
        Some(o)
    );
}

// OP-45 SEC-13
#[test]
fn op_45_openings_and_sealed_parts_do_not_print_their_content() {
    let o = opening(b"personal detail");
    let shown = format!("{o:?}");
    assert!(!shown.contains("personal"), "{shown}");
    assert!(!shown.contains("text/plain"), "{shown}");
}
