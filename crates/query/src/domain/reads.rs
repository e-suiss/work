//! What the scoped reads answer (P-56, T-13, P-57, T-26, P-20, T-97): a Work's state from its sync-derived item head, the Works changed since a sealed sync cursor, and a record's four kinds of evidence apart; the sync cursor layout, bound by its MAC to the caller's tenant and Party; and the RFC 9162 audit path of a leaf, computed over the leaf hashes of the covering checkpoint's tree.

use work_kernel::id::{Digest, LedgerId, RecordId, WorkId};
use work_kernel::proof::node_hash;
use work_proto::id::{Cursor, PositionToken};
pub use work_store::CosignatureView;
use work_store::NoticeView;

/// The most Works one page of changes carries (PD).
pub const MAX_CHANGES: u32 = 500;

/// The page of changes asked for without a size (PD).
pub const DEFAULT_CHANGES: u32 = 100;

/// The largest tree an inclusion proof is computed over in a request (PD); a larger tree's
/// record is answered with its checkpoint and no path, for the offline export to prove.
pub const MAX_PROOF_LEAVES: u64 = 65_536;

/// The sync cursor layout version.
pub const CURSOR_VERSION: u8 = 0x01;

/// The MAC context of a sync cursor, apart from the read position token's (T-97 item 1).
pub const CURSOR_CONTEXT: &[u8] = b"work/sync-cursor/v1";

/// The kept MAC bytes of a cursor.
pub const CURSOR_TAG: usize = 16;

const CURSOR_BODY: usize = 58;

/// Why a read answers nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReadRefusal {
    /// The object does not exist or the caller cannot see it (P-56): `404 not_found`.
    #[error("not found")]
    NotFound,
    /// A `Work-Min-Position` that does not open: `400 read_position_invalid`.
    #[error("read position invalid")]
    PositionInvalid,
    /// A `Work-Min-Position` past the head: `400 read_position_ahead`.
    #[error("read position ahead")]
    PositionAhead,
    /// A cursor of another caller, ledger or a forged one: `400 invalid_id`.
    #[error("cursor invalid")]
    CursorInvalid,
    /// The database or the key store did not answer: `503 busy`.
    #[error("unavailable")]
    Unavailable,
}

/// A Work as its caller reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkView {
    /// The ledger.
    pub ledger: LedgerId,
    /// The Work.
    pub work: WorkId,
    /// Its version, the `ETag` a change names in `If-Match` (P-29, P-54 item 5).
    pub version: u64,
    /// The position of its first record.
    pub first_pos: u64,
    /// The position of its last record.
    pub last_pos: u64,
    /// Ledger time of its first record, Unix milliseconds.
    pub opened_at_ms: i64,
    /// Ledger time of its last record, Unix milliseconds.
    pub updated_at_ms: i64,
    /// The positions the answer reflects (T-97 item 2).
    pub position: PositionToken,
}

/// One Work that changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The Work.
    pub work: WorkId,
    /// Its version now.
    pub version: u64,
    /// The position that last changed it.
    pub pos: u64,
}

/// One page of changes (P-57, T-26).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Changes {
    /// The Works changed after the cursor, in the order of the position that last changed them.
    pub changes: Vec<Change>,
    /// The cursor to ask with next.
    pub next: Cursor,
    /// True when more changes follow at once.
    pub more: bool,
    /// True when the cursor no longer opens a difference: the client reads every Work again
    /// and nothing is silently missing (MD-19 item 1).
    pub resync: bool,
    /// The positions the answer reflects (T-97 item 2).
    pub position: PositionToken,
}

/// Whether and how a record is in the ledger's transparency log (P-20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inclusion {
    /// No checkpoint covers the record yet.
    Pending,
    /// The audit path to the root of the first checkpoint that covers it.
    Proven {
        /// The checkpoint.
        checkpoint: CheckpointRef,
        /// The RFC 9162 audit path, leaf side first.
        path: Vec<Digest>,
    },
    /// A checkpoint covers it, but its tree is above [`MAX_PROOF_LEAVES`]; the export proves it.
    Covered {
        /// The checkpoint.
        checkpoint: CheckpointRef,
    },
}

/// A checkpoint as the evidence names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointRef {
    /// Its tree size.
    pub size: u64,
    /// Its root hash.
    pub root: Digest,
    /// The C2SP signed note.
    pub signed_note: String,
    /// When it was issued, Unix milliseconds.
    pub issued_at_ms: i64,
}

/// A record's evidence, each kind apart (P-20): what one kind proves is never shown as another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// The ledger.
    pub ledger: LedgerId,
    /// The record.
    pub record: RecordId,
    /// The Party that wrote it.
    pub author: String,
    /// The author's `COSE_Sign1` as received, only when the author signed it.
    pub author_signature: Option<Vec<u8>>,
    /// The Access `auth_context` digest of an unsigned human record; never an author signature.
    pub auth_context: Option<Digest>,
    /// The ledger's acceptance: the position, epoch, ledger time and leaf hash of its entry.
    pub attestation: Attestation,
    /// Its inclusion in the transparency log.
    pub inclusion: Inclusion,
    /// The witness cosignatures and time stamps of the covering checkpoint.
    pub witnesses: Vec<CosignatureView>,
    /// The compromise windows it falls in, derived from the notices of its ledger (SEC-36
    /// item 4, C-4); empty for a record outside every window.
    pub compromise_window: Vec<CompromiseMark>,
    /// The positions the answer reflects (T-97 item 2).
    pub position: PositionToken,
}

/// A compromise window a record falls in, derived from a SEC-36 notice and never canonical
/// (C-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompromiseMark {
    /// The notice record.
    pub notice: RecordId,
    /// The window's start, Unix milliseconds.
    pub window_from_ms: u64,
    /// The window's end, Unix milliseconds.
    pub window_to_ms: u64,
}

/// The windows of `notices` that mark a record recorded at `recorded_at_ms`: one signed with
/// `kid` when the notice names that kid, or an unsigned one when its `author` is the notice's
/// compromised Party (SEC-36 items 3 and 4).
#[must_use]
pub fn compromise_marks(
    recorded_at_ms: i64,
    kid: Option<[u8; 32]>,
    author: &str,
    notices: &[NoticeView],
) -> Vec<CompromiseMark> {
    let Ok(at) = u64::try_from(recorded_at_ms) else {
        return Vec::new();
    };
    notices
        .iter()
        .filter(|n| n.window_from_ms <= at && at <= n.window_to_ms)
        .filter(|n| match kid {
            Some(k) => n.kids.contains(&k),
            None => n.party.as_deref() == Some(author),
        })
        .map(|n| CompromiseMark {
            notice: RecordId(Digest::sha256(n.record)),
            window_from_ms: n.window_from_ms,
            window_to_ms: n.window_to_ms,
        })
        .collect()
}

/// The ledger's acceptance of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// The position.
    pub pos: u64,
    /// The fencing epoch.
    pub epoch: u64,
    /// Ledger time, Unix milliseconds.
    pub recorded_at_ms: i64,
    /// The RFC 9162 leaf hash of the envelope.
    pub leaf_hash: Digest,
}

/// Where a sync cursor stands: a position and the Work last read at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorAt {
    /// The ledger.
    pub ledger: [u8; 32],
    /// The position.
    pub pos: u64,
    /// The Work last read at it; all `0xff` once every Work at it was read.
    pub work: [u8; 16],
}

/// What a sync cursor opens to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
    /// Where to read on from.
    At(CursorAt),
    /// A cursor of a retired key: the difference is no longer known, the client reads again.
    Expired,
}

/// The cursor bytes the MAC covers after the context: version, key id, ledger, position, Work.
#[must_use]
pub fn cursor_body(key_id: u8, at: &CursorAt) -> Vec<u8> {
    let mut body = Vec::with_capacity(CURSOR_BODY);
    body.extend([CURSOR_VERSION, key_id]);
    body.extend(at.ledger);
    body.extend(at.pos.to_be_bytes());
    body.extend(at.work);
    body
}

/// The cursor MAC input: the context, then the tenant and the Party, each followed by a zero
/// byte, then the body; a cursor opens only for the caller it was given to.
#[must_use]
pub fn cursor_mac_input(tenant: &[u8], party: &[u8], body: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend(CURSOR_CONTEXT);
    input.push(0);
    input.extend(tenant);
    input.push(0);
    input.extend(party);
    input.push(0);
    input.extend(body);
    input
}

/// The key id, the place and the kept tag of a cursor's bytes, before its MAC is checked.
///
/// # Errors
/// [`ReadRefusal::CursorInvalid`] for another version or length.
pub fn cursor_layout(bytes: &[u8]) -> Result<(u8, CursorAt, [u8; CURSOR_TAG]), ReadRefusal> {
    let bad = ReadRefusal::CursorInvalid;
    let (body, tag) = bytes.split_at_checked(CURSOR_BODY).ok_or(bad)?;
    let tag = <[u8; CURSOR_TAG]>::try_from(tag).map_err(|_| bad)?;
    let (head, rest) = body.split_at_checked(2).ok_or(bad)?;
    let [version, key_id] = <[u8; 2]>::try_from(head).map_err(|_| bad)?;
    if version != CURSOR_VERSION {
        return Err(bad);
    }
    let (ledger, rest) = rest.split_at_checked(32).ok_or(bad)?;
    let (pos, work) = rest.split_at_checked(8).ok_or(bad)?;
    Ok((
        key_id,
        CursorAt {
            ledger: <[u8; 32]>::try_from(ledger).map_err(|_| bad)?,
            pos: u64::from_be_bytes(<[u8; 8]>::try_from(pos).map_err(|_| bad)?),
            work: <[u8; 16]>::try_from(work).map_err(|_| bad)?,
        },
        tag,
    ))
}

/// True when `mac` starts with `tag`, compared in constant time.
#[must_use]
pub fn tag_matches(mac: &[u8; 32], tag: &[u8; CURSOR_TAG]) -> bool {
    mac.iter()
        .zip(tag.iter())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// The largest power of two below `n`, for `n` of 2 or more (RFC 9162 section 2.1.1).
fn split_point(n: usize) -> Option<usize> {
    let below = n.checked_sub(1)?;
    let shift = usize::BITS
        .checked_sub(1)?
        .checked_sub(below.leading_zeros())?;
    1_usize.checked_shl(shift)
}

/// The RFC 9162 tree hash of `leaves`, leaf hashes already.
fn subtree(leaves: &[Digest]) -> Option<Digest> {
    match leaves {
        [] => None,
        [leaf] => Some(*leaf),
        _ => {
            let (left, right) = leaves.split_at_checked(split_point(leaves.len())?)?;
            Some(node_hash(&subtree(left)?, &subtree(right)?))
        }
    }
}

/// The RFC 9162 audit path of leaf `index` in the tree of `leaves` (section 2.1.3.1), leaf side
/// first; `None` for an index outside the tree.
#[must_use]
pub fn audit_path(index: usize, leaves: &[Digest]) -> Option<Vec<Digest>> {
    if index >= leaves.len() {
        return None;
    }
    if leaves.len() == 1 {
        return Some(Vec::new());
    }
    let k = split_point(leaves.len())?;
    let (left, right) = leaves.split_at_checked(k)?;
    let (mut path, sibling) = if index < k {
        (audit_path(index, left)?, subtree(right)?)
    } else {
        (audit_path(index.checked_sub(k)?, right)?, subtree(left)?)
    };
    path.push(sibling);
    Some(path)
}

#[cfg(test)]
mod tests {
    use work_kernel::proof::{root, verify_inclusion};

    use super::*;

    fn leaf(n: u8) -> Digest {
        Digest::sha256(suiss_crypto::digest::leaf_hash(&[n]))
    }

    // P-20 P-101 OP-4
    #[test]
    fn p_20_the_audit_path_proves_every_leaf_under_the_tree_root() {
        for size in 1_u8..=13 {
            let data: Vec<Vec<u8>> = (0..size).map(|n| vec![n]).collect();
            let slices: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let tree_root = root(&slices);
            let leaves: Vec<Digest> = (0..size).map(leaf).collect();
            assert_eq!(subtree(&leaves), Some(tree_root), "{size}");
            for index in 0..size {
                let path = audit_path(usize::from(index), &leaves).unwrap();
                verify_inclusion(
                    u64::from(index),
                    u64::from(size),
                    &leaf(index),
                    &path,
                    &tree_root,
                )
                .unwrap();
            }
            assert_eq!(audit_path(usize::from(size), &leaves), None);
        }
        assert_eq!(split_point(5), Some(4));
        assert_eq!(split_point(4), Some(2));
        assert_eq!(split_point(2), Some(1));
    }

    // P-57 T-26 P-56
    #[test]
    fn p_57_a_cursor_lays_out_its_place_and_names_its_caller_in_the_mac() {
        let at = CursorAt {
            ledger: [3; 32],
            pos: 0x0102_0304_0506_0708,
            work: [9; 16],
        };
        let body = cursor_body(2, &at);
        let mut bytes = body.clone();
        bytes.extend([7; CURSOR_TAG]);
        assert_eq!(cursor_layout(&bytes), Ok((2, at, [7; CURSOR_TAG])));
        assert_eq!(bytes.len(), 74);
        let mut other = bytes.clone();
        other[0] = 2;
        assert_eq!(cursor_layout(&other), Err(ReadRefusal::CursorInvalid));
        assert_eq!(cursor_layout(&bytes[1..]), Err(ReadRefusal::CursorInvalid));
        let a = cursor_mac_input(b"tnt_a", b"p1", &body);
        let b = cursor_mac_input(b"tnt_a", b"p2", &body);
        let c = cursor_mac_input(b"tnt_ap", b"2", &body);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert!(a.starts_with(CURSOR_CONTEXT));
        let mut mac = [7_u8; 32];
        assert!(tag_matches(&mac, &[7; CURSOR_TAG]));
        mac[3] = 0;
        assert!(!tag_matches(&mac, &[7; CURSOR_TAG]));
    }

    fn notice(kids: Vec<[u8; 32]>, party: Option<&str>) -> NoticeView {
        NoticeView {
            record: [6; 32],
            pos: 9,
            window_from_ms: 1_000,
            window_to_ms: 5_000,
            kids,
            party: party.map(str::to_owned),
        }
    }

    // SEC-36
    #[test]
    fn sec_36_the_evidence_view_marks_a_record_of_a_window() {
        let notices = [notice(vec![[7; 32]], Some("pty-a"))];
        let marked = compromise_marks(1_000, Some([7; 32]), "pty-a", &notices);
        assert_eq!(
            marked,
            vec![CompromiseMark {
                notice: RecordId(Digest::sha256([6; 32])),
                window_from_ms: 1_000,
                window_to_ms: 5_000,
            }]
        );
        assert_eq!(compromise_marks(5_000, None, "pty-a", &notices).len(), 1);
        assert_eq!(
            compromise_marks(5_001, Some([7; 32]), "pty-a", &notices),
            Vec::<CompromiseMark>::new()
        );
        assert_eq!(
            compromise_marks(999, None, "pty-a", &notices),
            Vec::<CompromiseMark>::new()
        );
        assert_eq!(
            compromise_marks(3_000, Some([8; 32]), "pty-a", &notices),
            Vec::<CompromiseMark>::new()
        );
        assert_eq!(
            compromise_marks(3_000, None, "pty-b", &notices),
            Vec::<CompromiseMark>::new()
        );
        assert_eq!(
            compromise_marks(-1, None, "pty-a", &notices),
            Vec::<CompromiseMark>::new()
        );
        assert_eq!(
            compromise_marks(3_000, Some([7; 32]), "pty-a", &[]),
            Vec::<CompromiseMark>::new()
        );
    }
}
