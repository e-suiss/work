//! Body encryption under three key tiers (§18 OP-45, OP-12, OP-15, §15 P-68): the ledger KEK
//! stays in the PKCS#11 token as `work.<ledger hex>.kek.v<n>`; a random class DEK per subject ×
//! retention class is wrapped under it in `work.body_dek`; a random DEK per part encrypts the
//! part's salt, media type and content in one AES-256-GCM message bound to
//! `"work/body/v1\0" ‖ ledger_id ‖ part_commit`, and is wrapped under the class DEK in process
//! with [`DekKek`] into `work.body_part_key`. The write path checks every opening against the
//! commitment its record carries before sealing it; the read path recomputes the commitment
//! after opening. A destroyed class DEK, a shredded part key or a retired KEK leaves the part
//! unreadable while its skeleton stays and still verifies; the destroyed key is forgotten by the
//! DEK cache at once.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use suiss_crypto::digest::sha256;
use suiss_crypto::envelope::{
    self, Dek, DekCache, DekKek, EnvelopeError, Kek as _, Sealed, open_body, seal_body,
};
use suiss_crypto::pkcs11::{HsmError, HsmKek, KeyStore};
use suiss_crypto::secret::Secret;
use tokio::task::spawn_blocking;
use tokio::time::timeout;
use work_kernel::codec::{LARGE_PART, body_commitment};
use work_kernel::record::PartName;
use work_store::{
    BodyCommitmentRow, BodyPartRow, DekRow, ErasurePool, LedgerId, LedgerTx, Pool, RetentionClass,
    SequencerPool, Shred, StoreError, Stored, StoredPart, WRAPPED_LEN,
};

use crate::ports::{Rng, RngError, bytes32};

#[cfg(feature = "s3")]
mod s3;
#[cfg(feature = "s3")]
pub use s3::S3Store;

/// The fixed start of every part's AEAD context (OP-45 item 4).
pub const BODY_CONTEXT: &[u8] = b"work/body/v1\0";

/// Most content bytes of one part: the request bound (P-33, T-65).
pub const MAX_PART: usize = 262_144;

/// Longest media type of a part, the shared single-string bound of a commitment input (P-68).
pub const MAX_MEDIA_TYPE: usize = 255;

/// Default bound of one key store, database or object store call (T-32 rule 7).
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// The retention class of a part whose subtype schema names none yet (OP-14, P-68 item 1).
pub const DEFAULT_CLASS: RetentionClass = RetentionClass::WorkRecord;

/// Why a body operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BodyError {
    /// An opening names a part its record does not commit to.
    #[error("no commitment for part {0}")]
    UnknownPart(String),
    /// Two openings name the same part.
    #[error("part {0} opened twice")]
    DuplicatePart(String),
    /// The opening does not give the commitment its record carries, or a stored part opened
    /// to other bytes than its commitment (P-68).
    #[error("part {0} does not match its commitment")]
    Commitment(String),
    /// A part's content or media type is above its bound.
    #[error("part {0} is too large")]
    TooLarge(String),
    /// The record carries no skeleton, so nothing can bind a body to it.
    #[error("record without a skeleton")]
    NoSkeleton,
    /// The key store refused (T-56).
    #[error("key store: {0}")]
    Key(HsmError),
    /// Wrapping, unwrapping, sealing or opening failed.
    #[error("envelope: {0}")]
    Envelope(EnvelopeError),
    /// The database refused or failed.
    #[error("store: {0}")]
    Store(StoreError),
    /// The object store refused or failed.
    #[error("object store: {0}")]
    Object(String),
    /// A stored row or object does not match what was written.
    #[error("stored body is malformed")]
    Corrupt,
    /// A call ran past its bound.
    #[error("call timed out")]
    Timeout,
}

impl From<StoreError> for BodyError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<EnvelopeError> for BodyError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

impl From<HsmError> for BodyError {
    fn from(e: HsmError) -> Self {
        Self::Key(e)
    }
}

/// One body part as the author committed to it (P-68): its name, media type, content and salt.
/// Content and salt are personal data or protect it; `Debug` shows only the name and lengths.
#[derive(Clone, PartialEq, Eq)]
pub struct BodyOpening {
    /// The part name in the subtype schema.
    pub part: String,
    /// The media type of the content.
    pub media_type: String,
    /// The content bytes.
    pub content: Vec<u8>,
    /// The part's 32-byte salt.
    pub salt: [u8; 32],
}

impl std::fmt::Debug for BodyOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyOpening")
            .field("part", &self.part)
            .field("media_type", &self.media_type.len())
            .field("content", &self.content.len())
            .finish_non_exhaustive()
    }
}

impl BodyOpening {
    /// A part with a fresh 32-byte salt from `rng` (P-68 item 3, T-32 rule 2): each part takes its
    /// own salt and none is reused.
    ///
    /// # Errors
    /// [`RngError`]; no part is committed without its salt.
    pub fn new(
        rng: &(impl Rng + ?Sized),
        part: String,
        media_type: String,
        content: Vec<u8>,
    ) -> Result<Self, RngError> {
        Ok(Self {
            part,
            media_type,
            content,
            salt: bytes32(rng)?,
        })
    }

    /// The commitment the part's record carries (P-68, P-101, P-104).
    ///
    /// # Errors
    /// [`BodyError::UnknownPart`] for a name the schema cannot carry, [`BodyError::TooLarge`].
    pub fn commitment(&self) -> Result<[u8; 32], BodyError> {
        commitment(self)
    }
}

/// A part as read back (OP-13, EV-33): its content, or the fact that its keys are gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartRead {
    /// The part opened and matched its commitment.
    Readable(BodyOpening),
    /// The part key, its class DEK or the ledger KEK is gone: the content cannot be read while
    /// the skeleton stays (OP-12 item 3).
    Unreadable,
}

/// The PKCS#11 label of version `version` of the KEK of `ledger` (OP-45 item 1).
#[must_use]
pub fn kek_label(ledger: &LedgerId, version: u32) -> String {
    format!("work.{}.kek.v{version}", ledger.to_hex())
}

/// The AEAD context of a part (OP-45 item 4): `pos` never enters it.
#[must_use]
pub fn context(ledger: &LedgerId, part_commit: &[u8; 32]) -> Vec<u8> {
    let mut c = BODY_CONTEXT.to_vec();
    c.extend_from_slice(ledger.as_bytes());
    c.extend_from_slice(part_commit);
    c
}

/// The object key of a ciphertext: the ledger and the ciphertext's SHA-256, both in hex (T-20).
#[must_use]
pub fn object_key(ledger: &LedgerId, ciphertext_digest: &[u8; 32]) -> String {
    format!("{}/{}", ledger.to_hex(), hex(ciphertext_digest))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            s.extend(HEX.get(usize::from(nibble)).map(|&c| char::from(c)));
        }
    }
    s
}

fn commitment(o: &BodyOpening) -> Result<[u8; 32], BodyError> {
    let name = PartName::parse(&o.part).ok_or_else(|| BodyError::UnknownPart(o.part.clone()))?;
    body_commitment(&o.salt, &name, &o.media_type, &o.content)
        .map(|d| *d.as_bytes())
        .map_err(|_| BodyError::TooLarge(o.part.clone()))
}

fn plaintext(o: &BodyOpening) -> Result<Vec<u8>, BodyError> {
    let media =
        u8::try_from(o.media_type.len()).map_err(|_| BodyError::TooLarge(o.part.clone()))?;
    let mut p = Vec::with_capacity(
        o.salt
            .len()
            .saturating_add(1)
            .saturating_add(o.media_type.len())
            .saturating_add(o.content.len()),
    );
    p.extend_from_slice(&o.salt);
    p.push(media);
    p.extend_from_slice(o.media_type.as_bytes());
    p.extend_from_slice(&o.content);
    Ok(p)
}

fn opening(part: &str, plain: &[u8]) -> Result<BodyOpening, BodyError> {
    let (salt, rest) = plain.split_first_chunk::<32>().ok_or(BodyError::Corrupt)?;
    let (media, rest) = rest.split_first().ok_or(BodyError::Corrupt)?;
    let (media, content) = rest
        .split_at_checked(usize::from(*media))
        .ok_or(BodyError::Corrupt)?;
    Ok(BodyOpening {
        part: part.to_owned(),
        media_type: String::from_utf8(media.to_vec()).map_err(|_| BodyError::Corrupt)?,
        content: content.to_vec(),
        salt: *salt,
    })
}

/// One part sealed under a fresh part DEK (OP-45 item 3), its key wrapped under the class DEK.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPart {
    /// The AES-GCM nonce and ciphertext.
    pub sealed: Sealed,
    /// The part DEK wrapped under the class DEK.
    pub wrapped_key: [u8; WRAPPED_LEN],
}

impl std::fmt::Debug for SealedPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedPart")
            .field("ciphertext", &self.sealed.ciphertext.len())
            .finish_non_exhaustive()
    }
}

fn wrapped_len(raw: &[u8]) -> Result<[u8; WRAPPED_LEN], BodyError> {
    <[u8; WRAPPED_LEN]>::try_from(raw).map_err(|_| BodyError::Envelope(EnvelopeError::Wrap))
}

/// Seals `o`, whose commitment is `commit`, under a fresh part DEK and wraps that DEK under
/// `class` (OP-45 items 3 and 4); the part DEK encrypts this one message and is consumed.
///
/// # Errors
/// [`BodyError::Commitment`] when `o` does not give `commit`; [`BodyError::TooLarge`];
/// [`BodyError::Envelope`].
pub fn seal_part(
    class: &Dek,
    ledger: &LedgerId,
    commit: &[u8; 32],
    o: &BodyOpening,
) -> Result<SealedPart, BodyError> {
    if o.content.len() > MAX_PART || o.media_type.len() > MAX_MEDIA_TYPE {
        return Err(BodyError::TooLarge(o.part.clone()));
    }
    if commitment(o)? != *commit {
        return Err(BodyError::Commitment(o.part.clone()));
    }
    let part = Dek::generate()?;
    let wrapped_key = wrapped_len(&DekKek::new("class", class).wrap(&part)?)?;
    let sealed = seal_body(part, &context(ledger, commit), &plaintext(o)?)?;
    Ok(SealedPart {
        sealed,
        wrapped_key,
    })
}

/// Opens the part `part` committed as `commit` with its wrapped key under `class` and checks
/// the commitment of what it opens to (OP-45, P-68).
///
/// # Errors
/// [`BodyError::Envelope`] for another key, ledger or commitment;
/// [`BodyError::Commitment`] when the plaintext does not give `commit`.
pub fn open_part(
    class: &Dek,
    ledger: &LedgerId,
    part: &str,
    commit: &[u8; 32],
    wrapped_key: &[u8],
    sealed: &Sealed,
) -> Result<BodyOpening, BodyError> {
    let key = DekKek::new("class", class).unwrap(wrapped_key)?;
    let plain = open_body(&key, &context(ledger, commit), sealed)?;
    let o = opening(part, &plain)?;
    if commitment(&o)? != *commit {
        return Err(BodyError::Commitment(part.to_owned()));
    }
    Ok(o)
}

struct Held {
    keks: BTreeMap<String, HsmKek>,
    cache: DekCache,
}

/// The ledger KEKs in the PKCS#11 token and the cache of unwrapped class DEKs (OP-45 items 1, 2,
/// 5; Access CR-32). Calls into the token block, so the async callers run them on the blocking
/// pool under a timeout.
pub struct BodyKeys {
    store: KeyStore,
    version: u32,
    held: Mutex<Held>,
}

impl std::fmt::Debug for BodyKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyKeys")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl BodyKeys {
    /// The KEKs of `token` in `module`, new class DEKs wrapped under KEK version `version`, with
    /// the DEK cache's default lifetime and size (Access OP-135 item 5).
    ///
    /// # Errors
    /// [`HsmError`] when the token cannot be opened.
    pub fn open(
        module: &Path,
        token: &str,
        pin: &Secret<String>,
        version: u32,
    ) -> Result<Self, HsmError> {
        Ok(Self::new(KeyStore::open(module, token, pin)?, version))
    }

    /// Over an opened key store.
    #[must_use]
    pub fn new(store: KeyStore, version: u32) -> Self {
        Self {
            store,
            version: version.max(1),
            held: Mutex::new(Held {
                keks: BTreeMap::new(),
                cache: DekCache::default(),
            }),
        }
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn kek_into(&self, held: &mut Held, label: &str, create: bool) -> Result<(), HsmError> {
        if held.keks.contains_key(label) {
            return Ok(());
        }
        let kek = match self.store.kek(label) {
            Ok(k) => k,
            Err(HsmError::Key(_)) if create => match self.store.generate_kek(label) {
                Ok(k) => k,
                Err(_) => self.store.kek(label)?,
            },
            Err(e) => return Err(e),
        };
        held.keks.insert(label.to_owned(), kek);
        Ok(())
    }

    /// A fresh class DEK wrapped under the current KEK of `ledger`, created in the token on
    /// first use (OP-45 items 1 and 2): the KEK label and the wrapped key.
    ///
    /// # Errors
    /// [`BodyError::Key`] or [`BodyError::Envelope`].
    pub fn new_class_dek(
        &self,
        ledger: &LedgerId,
    ) -> Result<(String, [u8; WRAPPED_LEN]), BodyError> {
        let label = kek_label(ledger, self.version);
        let mut held = self.held();
        self.kek_into(&mut held, &label, true)?;
        let kek = held.keks.get(&label).ok_or(BodyError::Corrupt)?;
        let dek = Dek::generate()?;
        Ok((label, wrapped_len(&kek.wrap(&dek)?)?))
    }

    /// Runs `f` with the class DEK of `row` unwrapped under its KEK through the cache at time
    /// `now_ms`; `None` when the DEK is destroyed or its KEK is gone (OP-45 item 5).
    ///
    /// # Errors
    /// [`BodyError::Key`], [`BodyError::Envelope`], or what `f` returns.
    pub fn with_class_dek<T>(
        &self,
        row: &DekRow,
        now_ms: u64,
        f: impl FnOnce(&Dek) -> Result<T, BodyError>,
    ) -> Result<Option<T>, BodyError> {
        let Some(wrapped) = row.wrapped else {
            return Ok(None);
        };
        let mut held = self.held();
        match self.kek_into(&mut held, &row.kek_id, false) {
            Ok(()) => {}
            Err(HsmError::Key(_)) => {
                held.cache.forget(&wrapped);
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
        let Held { keks, cache } = &mut *held;
        let kek = keks.get(&row.kek_id).ok_or(BodyError::Corrupt)?;
        let dek = cache.get(kek, &wrapped, now_ms)?;
        f(dek).map(Some)
    }

    /// Drops a destroyed class DEK from the cache at once (OP-45 item 5, `DekCache::forget`).
    pub fn forget(&self, wrapped: &[u8]) {
        self.held().cache.forget(wrapped);
    }

    /// Destroys KEK version `version` of `ledger` inside the token, the tenant closure: every
    /// class DEK it wrapped, and every part under them, becomes unreadable (OP-45 item 5,
    /// Access OP-73, `KeyStore::destroy_kek`).
    ///
    /// # Errors
    /// [`HsmError`].
    pub fn retire_kek(&self, ledger: &LedgerId, version: u32) -> Result<(), HsmError> {
        let label = kek_label(ledger, version);
        let mut held = self.held();
        held.keks.remove(&label);
        held.cache = DekCache::default();
        self.store.destroy_kek(&label)
    }

    /// The class DEK `wrapped` under KEK `from` rewrapped under KEK version `to` of `ledger`,
    /// created on first use (OP-45 item 1, `envelope::rewrap`).
    ///
    /// # Errors
    /// [`BodyError::Key`] or [`BodyError::Envelope`].
    pub fn rewrap(
        &self,
        ledger: &LedgerId,
        from: &str,
        to: u32,
        wrapped: &[u8],
    ) -> Result<(String, [u8; WRAPPED_LEN]), BodyError> {
        let label = kek_label(ledger, to);
        let mut held = self.held();
        self.kek_into(&mut held, from, false)?;
        self.kek_into(&mut held, &label, true)?;
        let old = held.keks.get(from).ok_or(BodyError::Corrupt)?;
        let new = held.keks.get(&label).ok_or(BodyError::Corrupt)?;
        Ok((label, wrapped_len(&envelope::rewrap(old, new, wrapped)?)?))
    }
}

/// Where ciphertexts above [`LARGE_PART`] content bytes go (§17 T-20, OP-2): the S3-compatible
/// store when one is configured, else the database.
pub trait ObjectStore: Send + Sync + 'static {
    /// Stores `bytes` under `key`; storing the same bytes again is harmless, since the key is
    /// their address.
    fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> impl Future<Output = Result<(), BodyError>> + Send;
    /// The bytes stored under `key`.
    fn get(
        &self,
        key: &str,
        now_ms: u64,
    ) -> impl Future<Output = Result<Vec<u8>, BodyError>> + Send;
}

/// No object store: every ciphertext stays in PostgreSQL (§17 T-20).
#[derive(Debug, Clone, Copy, Default)]
pub struct InDatabase;

fn no_object_store<T>() -> std::future::Ready<Result<T, BodyError>> {
    std::future::ready(Err(BodyError::Object(
        "no object store configured".to_owned(),
    )))
}

impl ObjectStore for InDatabase {
    fn put(
        &self,
        _key: &str,
        _bytes: Vec<u8>,
        _now_ms: u64,
    ) -> impl Future<Output = Result<(), BodyError>> + Send {
        no_object_store()
    }

    fn get(
        &self,
        _key: &str,
        _now_ms: u64,
    ) -> impl Future<Output = Result<Vec<u8>, BodyError>> + Send {
        no_object_store()
    }
}

async fn blocking<T: Send + 'static>(
    limit: Duration,
    f: impl FnOnce() -> Result<T, BodyError> + Send + 'static,
) -> Result<T, BodyError> {
    timeout(limit, spawn_blocking(f))
        .await
        .map_err(|_| BodyError::Timeout)?
        .map_err(|_| BodyError::Corrupt)?
}

async fn bounded<T, E: Into<BodyError>>(
    limit: Duration,
    f: impl Future<Output = Result<T, E>>,
) -> Result<T, BodyError> {
    timeout(limit, f)
        .await
        .map_err(|_| BodyError::Timeout)?
        .map_err(Into::into)
}

/// The write side of the body store (OP-45, OP-2): seals a record's openings and returns the
/// rows its append writes.
pub struct BodyWriter<O: ObjectStore = InDatabase> {
    keys: Arc<BodyKeys>,
    pool: SequencerPool,
    objects: Option<O>,
    limit: Duration,
}

impl<O: ObjectStore> std::fmt::Debug for BodyWriter<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyWriter")
            .field("objects", &self.objects.is_some())
            .finish_non_exhaustive()
    }
}

impl BodyWriter<InDatabase> {
    /// A writer keeping every ciphertext in PostgreSQL.
    #[must_use]
    pub const fn in_database(keys: Arc<BodyKeys>, pool: SequencerPool) -> Self {
        Self {
            keys,
            pool,
            objects: None,
            limit: DEFAULT_CALL_TIMEOUT,
        }
    }
}

impl<O: ObjectStore> BodyWriter<O> {
    /// A writer putting ciphertexts of parts above [`LARGE_PART`] content bytes into `objects`.
    #[must_use]
    pub const fn with_objects(keys: Arc<BodyKeys>, pool: SequencerPool, objects: O) -> Self {
        Self {
            keys,
            pool,
            objects: Some(objects),
            limit: DEFAULT_CALL_TIMEOUT,
        }
    }

    /// The rows of `openings` for a record of `ledger` whose skeleton commits to `commitments`
    /// and whose author is `author`, the parts' data subject (OP-45 item 7): each opening must
    /// give its commitment; a class DEK is created on the subject's first part; the ciphertexts
    /// go to the object store or stay inline. `now_ms` is the ledger time the cache and the
    /// object store use.
    ///
    /// # Errors
    /// [`BodyError`]; nothing is written to the database on error, and an object put before
    /// the error is an unreferenced, content-addressed ciphertext.
    pub async fn seal(
        &self,
        ledger: &LedgerId,
        author: &str,
        commitments: &[BodyCommitmentRow],
        openings: &[BodyOpening],
        now_ms: u64,
    ) -> Result<Vec<BodyPartRow>, BodyError> {
        if openings.is_empty() {
            return Ok(Vec::new());
        }
        let mut plan = Vec::with_capacity(openings.len());
        for o in openings {
            if plan
                .iter()
                .any(|(p, _): &(BodyOpening, [u8; 32])| p.part == o.part)
            {
                return Err(BodyError::DuplicatePart(o.part.clone()));
            }
            let commit = commitments
                .iter()
                .find(|c| c.part == o.part)
                .ok_or_else(|| BodyError::UnknownPart(o.part.clone()))?
                .commit;
            plan.push((o.clone(), commit));
        }
        let class = DEFAULT_CLASS;
        let active = bounded(self.limit, self.pool.active_dek(ledger, author, class)).await?;
        let row = if let Some(row) = active {
            row
        } else {
            let keys = Arc::clone(&self.keys);
            let id = *ledger;
            let (kek_id, wrapped) = blocking(self.limit, move || keys.new_class_dek(&id)).await?;
            bounded(
                self.limit,
                self.pool
                    .class_dek(ledger, author, class, &kek_id, &wrapped),
            )
            .await?
        };
        let keys = Arc::clone(&self.keys);
        let id = *ledger;
        let dek = row.clone();
        let sealed = blocking(self.limit, move || {
            keys.with_class_dek(&dek, now_ms, |class| {
                plan.iter()
                    .map(|(o, commit)| {
                        seal_part(class, &id, commit, o)
                            .map(|s| (o.part.clone(), o.content.len(), s))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
        })
        .await?
        .ok_or(BodyError::Key(HsmError::Key(row.kek_id.clone())))?;
        let mut rows = Vec::with_capacity(sealed.len());
        for (part, len, s) in sealed {
            let ciphertext_digest = sha256(&s.sealed.ciphertext);
            let stored = match &self.objects {
                Some(objects) if len > LARGE_PART => {
                    let key = object_key(ledger, &ciphertext_digest);
                    objects.put(&key, s.sealed.ciphertext, now_ms).await?;
                    Stored::Object(key)
                }
                _ => Stored::Inline(s.sealed.ciphertext),
            };
            rows.push(BodyPartRow {
                part,
                dek_id: row.dek_id.clone(),
                class,
                nonce: s.sealed.nonce,
                stored,
                ciphertext_digest,
                wrapped_key: s.wrapped_key,
            });
        }
        Ok(rows)
    }
}

/// The read side of the body store (OP-45, OP-13): opens a record's parts or tells which are
/// unreadable.
pub struct BodyReader<O: ObjectStore = InDatabase> {
    keys: Arc<BodyKeys>,
    pool: Pool,
    objects: Option<O>,
    limit: Duration,
}

impl<O: ObjectStore> std::fmt::Debug for BodyReader<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyReader")
            .field("objects", &self.objects.is_some())
            .finish_non_exhaustive()
    }
}

impl BodyReader<InDatabase> {
    /// A reader of inline ciphertexts on `pool`, a `work_app` login (T-79).
    #[must_use]
    pub const fn in_database(keys: Arc<BodyKeys>, pool: Pool) -> Self {
        Self {
            keys,
            pool,
            objects: None,
            limit: DEFAULT_CALL_TIMEOUT,
        }
    }
}

impl<O: ObjectStore> BodyReader<O> {
    /// A reader that also fetches ciphertexts from `objects`.
    #[must_use]
    pub const fn with_objects(keys: Arc<BodyKeys>, pool: Pool, objects: O) -> Self {
        Self {
            keys,
            pool,
            objects: Some(objects),
            limit: DEFAULT_CALL_TIMEOUT,
        }
    }

    async fn ciphertext(&self, part: &StoredPart, now_ms: u64) -> Result<Vec<u8>, BodyError> {
        let bytes = match &part.stored {
            Stored::Inline(c) => c.clone(),
            Stored::Object(key) => {
                let objects = self
                    .objects
                    .as_ref()
                    .ok_or_else(|| BodyError::Object("no object store configured".to_owned()))?;
                objects.get(key, now_ms).await?
            }
        };
        if sha256(&bytes) != part.ciphertext_digest {
            return Err(BodyError::Corrupt);
        }
        Ok(bytes)
    }

    /// The parts of the record at `pos` of `ledger` in part order, each readable with its
    /// checked content or unreadable once its keys are gone (OP-45 item 5).
    ///
    /// # Errors
    /// [`BodyError::Commitment`] or [`BodyError::Corrupt`] for a stored part that does not
    /// open to its commitment; otherwise [`BodyError`].
    pub async fn read(
        &self,
        ledger: &LedgerId,
        pos: u64,
        now_ms: u64,
    ) -> Result<Vec<(String, PartRead)>, BodyError> {
        let parts = bounded(self.limit, async {
            let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
            let parts = tx.body_parts(pos).await?;
            tx.commit().await?;
            Ok::<_, StoreError>(parts)
        })
        .await?;
        let mut out = Vec::with_capacity(parts.len());
        for p in parts {
            let Some(part_key) = p.part_key else {
                out.push((p.part, PartRead::Unreadable));
                continue;
            };
            if p.dek.wrapped.is_none() {
                out.push((p.part, PartRead::Unreadable));
                continue;
            }
            let ciphertext = self.ciphertext(&p, now_ms).await?;
            let keys = Arc::clone(&self.keys);
            let id = *ledger;
            let name = p.part.clone();
            let sealed = Sealed {
                nonce: p.nonce,
                ciphertext,
            };
            let commit = p.commit;
            let dek = p.dek.clone();
            let read = blocking(self.limit, move || {
                keys.with_class_dek(&dek, now_ms, |class| {
                    open_part(class, &id, &name, &commit, &part_key, &sealed)
                })
            })
            .await?;
            out.push((
                p.part,
                read.map_or(PartRead::Unreadable, PartRead::Readable),
            ));
        }
        Ok(out)
    }
}

/// The erasure side of the body store (OP-12, OP-15, OP-45 item 5): one-way key removal through
/// `work_erasure`, refused under an active retention hold.
pub struct BodyEraser {
    keys: Arc<BodyKeys>,
    pool: ErasurePool,
    limit: Duration,
}

impl std::fmt::Debug for BodyEraser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyEraser").finish_non_exhaustive()
    }
}

impl BodyEraser {
    /// Over `pool` with the keys whose cache it clears.
    #[must_use]
    pub const fn new(keys: Arc<BodyKeys>, pool: ErasurePool) -> Self {
        Self {
            keys,
            pool,
            limit: DEFAULT_CALL_TIMEOUT,
        }
    }

    /// Destroys the class DEK of `subject` and `class` (subject erasure or retention end):
    /// every part under it becomes unreadable and the DEK leaves the cache; `false` when none
    /// is active.
    ///
    /// # Errors
    /// [`BodyError::Store`] with a constraint under an active retention hold.
    pub async fn destroy_class(
        &self,
        ledger: &LedgerId,
        subject: &str,
        class: RetentionClass,
        why: Shred,
    ) -> Result<bool, BodyError> {
        let row = bounded(
            self.limit,
            self.pool.destroy_dek(ledger, subject, class, why),
        )
        .await?;
        if let Some(wrapped) = row.as_ref().and_then(|r| r.wrapped) {
            self.keys.forget(&wrapped);
        }
        Ok(row.is_some())
    }

    /// Shreds the key of the part `part` of the record at `pos`, the redaction of that part
    /// alone (P-25); `false` when it was already shredded.
    ///
    /// # Errors
    /// [`BodyError::Store`] with a constraint under an active retention hold.
    pub async fn redact(&self, ledger: &LedgerId, pos: u64, part: &str) -> Result<bool, BodyError> {
        Ok(bounded(self.limit, self.pool.shred_part(ledger, pos, part))
            .await?
            .is_some())
    }

    /// Rewraps every active class DEK of `ledger` from KEK version `from` to version `to`
    /// (OP-45 item 1); the count rewrapped.
    ///
    /// # Errors
    /// [`BodyError`].
    pub async fn rotate(&self, ledger: &LedgerId, from: u32, to: u32) -> Result<usize, BodyError> {
        let old = kek_label(ledger, from);
        let rows = bounded(self.limit, self.pool.deks_under(ledger, &old)).await?;
        let mut done = 0_usize;
        for row in rows {
            let Some(wrapped) = row.wrapped else { continue };
            let keys = Arc::clone(&self.keys);
            let id = *ledger;
            let from_label = old.clone();
            let (label, rewrapped) = blocking(self.limit, move || {
                keys.rewrap(&id, &from_label, to, &wrapped)
            })
            .await?;
            if bounded(
                self.limit,
                self.pool
                    .rewrap_dek(ledger, &row.dek_id, &old, &label, &rewrapped),
            )
            .await?
            {
                self.keys.forget(&wrapped);
                done = done.saturating_add(1);
            }
        }
        Ok(done)
    }
}

#[cfg(test)]
mod tests;
