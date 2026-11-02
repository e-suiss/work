//! What the signer answers on its socket (T-7, T-10, P-20, T-88, T-92, OP-46): its log key, and
//! a C2SP note signature line over the canonical body of a Work `tlog-checkpoint`, with exactly
//! its three profile lines, whose origin is the configured prefix followed by a ledger id in 64
//! lowercase hex. Every other request is refused with a stable code, so the log key never signs
//! a record, an author statement or any bytes that are not a checkpoint.

use std::io::{Read, Write};

use suiss_crypto::note::Checkpoint;
use suiss_crypto::pkcs11::HsmSigner;
use suiss_crypto::signer::sign_note;
use work_kernel::proof::Profile;
use work_proto::signer::{self as frames, Kind, Status, refusal};

/// The log key and what it may sign.
pub(crate) struct LogKey {
    /// The key in the token.
    pub(crate) signer: HsmSigner,
    /// Its Ed25519 public key.
    pub(crate) public: [u8; 32],
    /// Its note key name.
    pub(crate) name: String,
    /// The origin prefix of the ledgers it signs for.
    pub(crate) origin_prefix: String,
}

/// The checkpoint body of `payload` when it is the canonical body of a Work checkpoint with its
/// three profile lines whose origin is `prefix` followed by 64 lowercase hex characters.
pub(crate) fn checkpoint_body<'a>(
    payload: &'a [u8],
    prefix: &str,
) -> Result<&'a str, &'static str> {
    let body = std::str::from_utf8(payload).map_err(|_| refusal::NOT_CHECKPOINT)?;
    let checkpoint = Checkpoint::parse(body).map_err(|_| refusal::NOT_CHECKPOINT)?;
    if checkpoint.to_body().ok().as_deref() != Some(body)
        || Profile::from_extensions(&checkpoint.extensions).is_err()
    {
        return Err(refusal::NOT_CHECKPOINT);
    }
    match checkpoint.origin.strip_prefix(prefix) {
        Some(ledger) if is_ledger_hex(ledger) => Ok(body),
        _ => Err(refusal::ORIGIN),
    }
}

fn is_ledger_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl LogKey {
    /// The answer to a request of kind byte `kind`.
    pub(crate) fn answer(&self, kind: u8, payload: &[u8]) -> (Status, Vec<u8>) {
        let refused = |code: &str| (Status::Refused, code.as_bytes().to_vec());
        match Kind::from_byte(kind) {
            Some(Kind::LogKey) if payload.is_empty() => {
                (Status::Signed, frames::log_key(&self.public, &self.name))
            }
            Some(Kind::LogKey) => refused(refusal::PAYLOAD),
            Some(Kind::Checkpoint) => match checkpoint_body(payload, &self.origin_prefix) {
                Ok(body) => match sign_note(&self.signer, &self.name, body) {
                    Ok((_, line)) => (Status::Signed, line.into_bytes()),
                    Err(_) => refused(refusal::SIGN),
                },
                Err(code) => refused(code),
            },
            _ => refused(refusal::KIND),
        }
    }

    /// Answers the requests of one connection until it closes or sends a malformed frame.
    pub(crate) fn serve<S: Read + Write>(&self, stream: &mut S) -> std::io::Result<()> {
        loop {
            let mut head = [0_u8; frames::HEADER];
            match stream.read_exact(&mut head) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            let header = frames::header(head).map_err(std::io::Error::other)?;
            let mut payload = vec![0_u8; header.len];
            stream.read_exact(&mut payload)?;
            let (status, answer) = self.answer(header.code, &payload);
            let frame = frames::frame(status.as_byte(), &answer).map_err(std::io::Error::other)?;
            stream.write_all(&frame)?;
            stream.flush()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    const PROFILE: &str =
        "durability single-node\ntime_sources dependent\nwitness local-dependent\n";
    const LEDGER: &str =
        "work.example/ledger/abababababababababababababababababababababababababababababababab";

    fn body(origin: &str, size: &str) -> String {
        format!("{origin}\n{size}\n{ROOT}\n{PROFILE}")
    }

    // T-7 P-20 T-92 OP-46
    #[test]
    fn t_7_only_the_canonical_body_of_a_configured_ledger_checkpoint_is_signed() {
        let prefix = "work.example/ledger/";
        let ok = body(LEDGER, "3");
        assert_eq!(checkpoint_body(ok.as_bytes(), prefix), Ok(ok.as_str()));
        let record = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02];
        assert_eq!(
            checkpoint_body(&record, prefix),
            Err(refusal::NOT_CHECKPOINT)
        );
        assert_eq!(
            checkpoint_body(body(LEDGER, "03").as_bytes(), prefix),
            Err(refusal::NOT_CHECKPOINT)
        );
        assert_eq!(
            checkpoint_body(format!("{ok}\n").as_bytes(), prefix),
            Err(refusal::NOT_CHECKPOINT)
        );
        assert_eq!(
            checkpoint_body(body("access.example/domain/ab12", "3").as_bytes(), prefix),
            Err(refusal::ORIGIN)
        );
        assert_eq!(
            checkpoint_body(body("work.example/ledger/", "3").as_bytes(), prefix),
            Err(refusal::ORIGIN)
        );
    }

    // T-92 OP-46
    #[test]
    fn t_92_a_body_without_its_profile_lines_or_a_non_ledger_origin_is_refused() {
        let prefix = "work.example/ledger/";
        let bare = format!("{LEDGER}\n3\n{ROOT}\n");
        assert_eq!(
            checkpoint_body(bare.as_bytes(), prefix),
            Err(refusal::NOT_CHECKPOINT)
        );
        for profile in [
            "durability single-node\ntime_sources dependent\n",
            "time_sources dependent\ndurability single-node\nwitness none\n",
            "durability single-node\ntime_sources dependent\nwitness independent 0\n",
            "durability single-node\ntime_sources dependent\nwitness none\nwitness none\n",
        ] {
            let text = format!("{bare}{profile}");
            assert_eq!(
                checkpoint_body(text.as_bytes(), prefix),
                Err(refusal::NOT_CHECKPOINT),
                "{profile}"
            );
        }
        let short =
            "work.example/ledger/abababababababababababababababababababababababababababababababa";
        let upper =
            "work.example/ledger/ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
        let long = format!("{LEDGER}ab");
        let other =
            "work.example/ledger/gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        for origin in [
            short,
            upper,
            long.as_str(),
            other,
            "work.example/ledger/ab12",
        ] {
            assert_eq!(
                checkpoint_body(body(origin, "3").as_bytes(), prefix),
                Err(refusal::ORIGIN),
                "{origin}"
            );
        }
    }
}
