//! Use cases (T-32): [`export`] writes a ledger's canonical rows as a `work-export/1` bundle, page by page from the genesis on, and [`verify`] reads one back and verifies it offline, with nothing but the bundle, the trusted keys and the kernel (P-2 items 2 and 3).

use std::io::Write;

use work_store::{LedgerId, StoreError};

use crate::domain::{self, FormatError, Report, Trust, VerifyError};
use crate::ports::Source;

/// Entries read from the store at a time.
pub const PAGE: u32 = 256;

/// Why an export stopped.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// A store read failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The bundle could not be written.
    #[error("write: {0}")]
    Write(#[from] std::io::Error),
    /// The log has no entry at the position.
    #[error("the log has no entry at position {0}")]
    Gap(u64),
}

/// What an export wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exported {
    /// Entry lines, the genesis included.
    pub entries: u64,
    /// Checkpoint lines.
    pub checkpoints: u64,
}

/// Writes the bundle of `ledger` from `source` to `out`: every entry from the genesis on, then
/// every checkpoint whose tree the written entries hold, then the end line.
///
/// # Errors
/// [`ExportError`].
pub async fn export<S: Source, W: Write>(
    source: &S,
    ledger: &LedgerId,
    out: &mut W,
) -> Result<Exported, ExportError> {
    out.write_all(domain::header_line(ledger.as_bytes()).as_bytes())?;
    let mut next = 0_u64;
    loop {
        let page = source.entries(ledger, next, PAGE).await?;
        if page.is_empty() {
            break;
        }
        for e in &page {
            if e.pos != next {
                return Err(ExportError::Gap(next));
            }
            out.write_all(domain::entry_line(e).as_bytes())?;
            next = next.checked_add(1).ok_or(ExportError::Gap(next))?;
        }
    }
    let mut checkpoints = source.checkpoints(ledger).await?;
    checkpoints.retain(|c| c.size <= next);
    for c in &checkpoints {
        out.write_all(domain::checkpoint_line(c).as_bytes())?;
    }
    let written = u64::try_from(checkpoints.len()).unwrap_or(u64::MAX);
    out.write_all(domain::end_line(next, written).as_bytes())?;
    out.flush()?;
    Ok(Exported {
        entries: next,
        checkpoints: written,
    })
}

/// Why a bundle was refused.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// It is not a `work-export/1` bundle.
    #[error(transparent)]
    Format(#[from] FormatError),
    /// It does not verify.
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

/// Parses and verifies the bundle text `bundle` under `trust`.
///
/// # Errors
/// [`CheckError`].
pub fn verify(bundle: &str, trust: &Trust) -> Result<Report, CheckError> {
    let parsed = domain::parse(bundle)?;
    Ok(domain::verify(&parsed, trust)?)
}
