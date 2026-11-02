//! What the signer answers on its socket (T-7, T-10, P-20, T-88): its log key, and a C2SP note
//! signature line over the canonical body of a `tlog-checkpoint` whose origin is one of the
//! configured ledgers. Every other request is refused with a stable code, so the log key never
//! signs a record, an author statement or any bytes that are not a checkpoint.

use std::io::{Read, Write};

use suiss_crypto::note::Checkpoint;
use suiss_crypto::pkcs11::HsmSigner;
use suiss_crypto::signer::sign_note;
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

/// The checkpoint body of `payload` when it is the canonical body of a checkpoint whose origin
/// starts with `prefix` and names something after it.
pub(crate) fn checkpoint_body<'a>(
    payload: &'a [u8],
    prefix: &str,
) -> Result<&'a str, &'static str> {
    let body = std::str::from_utf8(payload).map_err(|_| refusal::NOT_CHECKPOINT)?;
    let checkpoint = Checkpoint::parse(body).map_err(|_| refusal::NOT_CHECKPOINT)?;
    if checkpoint.to_body().ok().as_deref() != Some(body) {
        return Err(refusal::NOT_CHECKPOINT);
    }
    match checkpoint.origin.strip_prefix(prefix) {
        Some(ledger) if !ledger.is_empty() => Ok(body),
        _ => Err(refusal::ORIGIN),
    }
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

    fn body(origin: &str, size: &str) -> String {
        format!("{origin}\n{size}\n{ROOT}\n")
    }

    // T-7 P-20
    #[test]
    fn t_7_only_the_canonical_body_of_a_configured_ledger_checkpoint_is_signed() {
        let prefix = "work.example/ledger/";
        let ok = body("work.example/ledger/ab12", "3");
        assert_eq!(checkpoint_body(ok.as_bytes(), prefix), Ok(ok.as_str()));
        let record = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02];
        assert_eq!(
            checkpoint_body(&record, prefix),
            Err(refusal::NOT_CHECKPOINT)
        );
        assert_eq!(
            checkpoint_body(body("work.example/ledger/ab12", "03").as_bytes(), prefix),
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
}
