//! The reads of the REST family that act for a caller (P-56, T-13, P-57, T-26, P-20, T-97, E-45): every one names its caller from the Access access token and `DPoP` proof the request carries before it reads anything (C-9, E-7, SEC-18), answers `401 unauthenticated` without one and `503 authority_unverifiable` when Access cannot check it (T-28), names the Access action `work:read`, answers what its caller may see and `404 not_found` for anything else, and carries the positions it reflects in `Work-Position` and `position`.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::{IntoParams, ToSchema};
use work_kernel::id::{Digest, LedgerId, RecordId, WorkId};
use work_proto::id::{Cursor, ExternalId as _, PositionToken};
use work_query::domain::caller::{Caller, CallerRefusal, Presented};
use work_query::domain::reads::{
    Changes, DEFAULT_CHANGES, Evidence, Inclusion, ReadRefusal, WorkView,
};
use work_query::ports::{Authenticate, WorkReads};

use crate::conditional::etag;
use crate::json::rfc3339_millis;
use crate::position::{WORK_POSITION, min_position, position_header};
use crate::problem::{Problem, ProblemCode};

/// The `DPoP` proof header (RFC 9449 section 4.1).
pub const DPOP: HeaderName = HeaderName::from_static("dpop");

/// The challenge of a `401` (RFC 9449 section 7.1).
pub const CHALLENGE: &str = "DPoP algs=\"ES256 Ed25519\"";

/// What the reads that act for a caller need: who the caller is, what it may read, and the
/// origin the API is reached at, which every `DPoP` proof names in `htu`.
pub struct ApiServices {
    /// Names the caller of a request.
    pub auth: Arc<dyn Authenticate>,
    /// The scoped reads.
    pub reads: Arc<dyn WorkReads>,
    /// `https://<host>[:<port>]`, without a trailing slash.
    pub origin: String,
}

impl std::fmt::Debug for ApiServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiServices")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// The problem of a request that names no caller (T-98 item 6, T-28).
#[must_use]
pub fn caller_problem(refusal: CallerRefusal) -> Response {
    match refusal {
        CallerRefusal::Unauthenticated(_) => {
            let mut response = Problem::new(ProblemCode::Unauthenticated).into_response();
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(CHALLENGE),
            );
            response
        }
        CallerRefusal::Unverifiable(_) => {
            Problem::new(ProblemCode::AuthorityUnverifiable).into_response()
        }
    }
}

/// The problem of a read that answers nothing (P-56, T-97 item 4).
#[must_use]
pub fn read_problem(refusal: ReadRefusal) -> Problem {
    Problem::new(match refusal {
        ReadRefusal::NotFound => ProblemCode::NotFound,
        ReadRefusal::PositionInvalid => ProblemCode::ReadPositionInvalid,
        ReadRefusal::PositionAhead => ProblemCode::ReadPositionAhead,
        ReadRefusal::CursorInvalid => ProblemCode::InvalidId,
        ReadRefusal::Unavailable => ProblemCode::Busy,
    })
}

fn single<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

/// The caller of a request, from its single `Authorization` and `DPoP` headers only.
///
/// # Errors
/// The `401` or `503` answer.
pub async fn caller_of(
    services: &ApiServices,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Caller, Box<Response>> {
    let url = format!("{}{}", services.origin, uri.path());
    let presented = Presented {
        authorization: single(headers, &header::AUTHORIZATION),
        dpop: single(headers, &DPOP),
        method: method.as_str(),
        url: &url,
    };
    services
        .auth
        .authenticate(presented)
        .await
        .map_err(|r| Box::new(caller_problem(r)))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            s.extend(DIGITS.get(usize::from(nibble)).map(|&c| char::from(c)));
        }
    }
    s
}

fn digest_hex(digest: &Digest) -> String {
    hex(digest.as_bytes())
}

fn time(ms: i64) -> String {
    rfc3339_millis(ms).unwrap_or_default()
}

fn parsed<T: work_proto::id::ExternalId>(text: &str) -> Result<T, Box<Response>> {
    T::parse_external(text)
        .map_err(|_| Box::new(Problem::new(ProblemCode::InvalidId).into_response()))
}

fn answered(body: &impl Serialize, position: &PositionToken) -> Response {
    let json = HeaderValue::from_static("application/json");
    let mut response = (
        [(header::CONTENT_TYPE, json)],
        serde_json::to_vec(body).unwrap_or_default(),
    )
        .into_response();
    response
        .headers_mut()
        .insert(WORK_POSITION, position_header(position));
    response
}

/// A Work as its caller reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct WorkAnswer {
    /// The ledger, `led_…`.
    pub ledger: String,
    /// The Work, `wrk_…`.
    pub work: String,
    /// The item version, also the `ETag`.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub version: u64,
    /// The position of its first record.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub first_pos: u64,
    /// The position of its last record.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub last_pos: u64,
    /// Ledger time of its first record, RFC 3339 UTC.
    pub opened_at: String,
    /// Ledger time of its last record, RFC 3339 UTC.
    pub updated_at: String,
    /// The positions the answer reflects, `pos_…` (T-97 item 2).
    pub position: String,
}

impl WorkAnswer {
    fn of(view: &WorkView) -> Self {
        Self {
            ledger: view.ledger.to_external(),
            work: view.work.to_external(),
            version: view.version,
            first_pos: view.first_pos,
            last_pos: view.last_pos,
            opened_at: time(view.opened_at_ms),
            updated_at: time(view.updated_at_ms),
            position: view.position.to_external(),
        }
    }
}

/// One Work that changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ChangeEntry {
    /// The Work, `wrk_…`.
    pub work: String,
    /// Its version now.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub version: u64,
    /// The position that last changed it.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub pos: u64,
}

/// One page of the Works that changed after a cursor (P-57, T-26).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ChangesAnswer {
    /// The Works, in the order of the position that last changed them.
    pub changes: Vec<ChangeEntry>,
    /// The cursor to ask with next, `cur_…`.
    pub next_cursor: String,
    /// True when more changes follow at once.
    pub more: bool,
    /// True when the cursor no longer opens a difference: read every Work again; nothing is
    /// missing silently.
    pub resync: bool,
    /// The positions the answer reflects, `pos_…` (T-97 item 2).
    pub position: String,
}

impl ChangesAnswer {
    fn of(changes: &Changes) -> Self {
        Self {
            changes: changes
                .changes
                .iter()
                .map(|c| ChangeEntry {
                    work: c.work.to_external(),
                    version: c.version,
                    pos: c.pos,
                })
                .collect(),
            next_cursor: changes.next.to_external(),
            more: changes.more,
            resync: changes.resync,
            position: changes.position.to_external(),
        }
    }
}

/// The author's own signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AuthorSignature {
    /// The `COSE_Sign1` as received, lower-case hex.
    pub cose_sign1: String,
}

/// The Access authentication context an unsigned human record names; not an author signature
/// (P-21 item 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AuthContextAnswer {
    /// Access's digest of the artifact, lower-case hex.
    pub digest: String,
}

/// The ledger's acceptance of the record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct LedgerAttestation {
    /// The position.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub pos: u64,
    /// The fencing epoch it was sequenced in.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub epoch: u64,
    /// Ledger time, RFC 3339 UTC.
    pub recorded_at: String,
    /// The RFC 9162 leaf hash of its envelope, lower-case hex.
    pub leaf_hash: String,
}

/// A checkpoint of the ledger's transparency log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct CheckpointAnswer {
    /// Its tree size.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub size: u64,
    /// Its root hash, lower-case hex.
    pub root: String,
    /// The C2SP signed note.
    pub signed_note: String,
    /// When it was issued, RFC 3339 UTC.
    pub issued_at: String,
}

/// Whether the record is in the transparency log, and the proof that it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct InclusionAnswer {
    /// `pending` before a checkpoint covers it, `proven` with an audit path, `covered` when the
    /// tree is too large to prove in a request.
    pub status: String,
    /// The first checkpoint that covers it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointAnswer>,
    /// The RFC 9162 audit path, leaf side first, lower-case hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
}

/// A witness cosignature or time stamp of the covering checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct WitnessAnswer {
    /// The witness.
    pub witness: String,
    /// `witness` or `rfc3161`.
    pub kind: String,
    /// The time it signs, RFC 3339 UTC.
    pub cosigned_at: String,
}

/// A record's evidence, each kind apart (P-20): an author signature, the ledger's acceptance,
/// the inclusion proof and the external time and witnesses are never shown as one another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct EvidenceAnswer {
    /// The ledger, `led_…`.
    pub ledger: String,
    /// The record, `rec_…`.
    pub record: String,
    /// The Party that wrote it, `pty_…`.
    pub author: String,
    /// The author's signature; absent for a record its author did not sign.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_signature: Option<AuthorSignature>,
    /// The Access authentication context of an unsigned human record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<AuthContextAnswer>,
    /// The ledger's acceptance.
    pub ledger_attestation: LedgerAttestation,
    /// The inclusion in the transparency log.
    pub inclusion: InclusionAnswer,
    /// The external time stamps and witness cosignatures of the covering checkpoint.
    pub witnesses: Vec<WitnessAnswer>,
    /// The positions the answer reflects, `pos_…` (T-97 item 2).
    pub position: String,
}

fn checkpoint_body(c: &work_query::domain::reads::CheckpointRef) -> CheckpointAnswer {
    CheckpointAnswer {
        size: c.size,
        root: digest_hex(&c.root),
        signed_note: c.signed_note.clone(),
        issued_at: time(c.issued_at_ms),
    }
}

impl EvidenceAnswer {
    fn of(e: &Evidence) -> Self {
        let author =
            work_kernel::id::PartyRef::new(&e.author).map_or_else(String::new, |p| p.to_external());
        let inclusion = match &e.inclusion {
            Inclusion::Pending => InclusionAnswer {
                status: "pending".to_owned(),
                checkpoint: None,
                path: None,
            },
            Inclusion::Proven { checkpoint, path } => InclusionAnswer {
                status: "proven".to_owned(),
                checkpoint: Some(checkpoint_body(checkpoint)),
                path: Some(path.iter().map(digest_hex).collect()),
            },
            Inclusion::Covered { checkpoint } => InclusionAnswer {
                status: "covered".to_owned(),
                checkpoint: Some(checkpoint_body(checkpoint)),
                path: None,
            },
        };
        Self {
            ledger: e.ledger.to_external(),
            record: e.record.to_external(),
            author,
            author_signature: e
                .author_signature
                .as_deref()
                .map(|b| AuthorSignature { cose_sign1: hex(b) }),
            auth_context: e.auth_context.as_ref().map(|d| AuthContextAnswer {
                digest: digest_hex(d),
            }),
            ledger_attestation: LedgerAttestation {
                pos: e.attestation.pos,
                epoch: e.attestation.epoch,
                recorded_at: time(e.attestation.recorded_at_ms),
                leaf_hash: digest_hex(&e.attestation.leaf_hash),
            },
            inclusion,
            witnesses: e
                .witnesses
                .iter()
                .map(|w| WitnessAnswer {
                    witness: w.witness.clone(),
                    kind: w.kind.clone(),
                    cosigned_at: time(w.cosigned_at_ms),
                })
                .collect(),
            position: e.position.to_external(),
        }
    }
}

/// The query of a changes read.
#[derive(Clone, Debug, Default, PartialEq, Eq, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ChangesQuery {
    /// The cursor of the previous answer, `cur_…`; without one, every Work the caller may read.
    pub cursor: Option<String>,
    /// The most Works to answer, 1 to 500; 100 without one.
    pub limit: Option<u32>,
}

impl ChangesQuery {
    /// The query of `uri`: its `cursor` and `limit`, other parameters ignored.
    ///
    /// # Errors
    /// `400 invalid_request` for a repeated parameter or a `limit` that is not a number.
    pub fn of(uri: &Uri) -> Result<Self, Box<Problem>> {
        let bad = || Box::new(Problem::new(ProblemCode::InvalidRequest));
        let mut query = Self::default();
        for pair in uri.query().unwrap_or_default().split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            match name {
                "cursor" if query.cursor.is_none() => query.cursor = Some(value.to_owned()),
                "limit" if query.limit.is_none() => {
                    query.limit = Some(value.parse().map_err(|_| bad())?);
                }
                "cursor" | "limit" => return Err(bad()),
                _ => {}
            }
        }
        Ok(query)
    }
}

/// Reads one Work.
///
/// The state comes from the Work's sync-derived item head; nothing of it is kept in a session.
/// A Work the caller took no part in is `404 not_found`, as one that does not exist.
#[utoipa::path(
    get,
    path = "/v1/ledgers/{ledger}/works/{work}",
    operation_id = "get_work",
    tag = "works",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ("work" = String, Path, description = "The Work, `wrk_…`."),
        ("Work-Min-Position" = Option<String>, Header, description = "A `pos_…` token the answer must reflect at least.")
    ),
    responses(
        (status = 200, description = "The Work.", body = WorkAnswer, headers(
            ("ETag" = String, description = "The item version."),
            ("Work-Position" = String, description = "The positions the answer reflects."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "An identifier or a read position that does not open.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
            content_type = "application/problem+json", headers(
            ("WWW-Authenticate" = String, description = "The DPoP challenge."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 404, description = "No such Work, or not one the caller may read.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 429, description = "The caller has spent its quota.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds until the next window.")
        )),
        (status = 503, description = "Access cannot be reached, so the caller's authority cannot be verified, or the server sheds load.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:read")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn get_work(
    State(services): State<Arc<ApiServices>>,
    Path((ledger, work)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let (ledger, work) = match (parsed::<LedgerId>(&ledger), parsed::<WorkId>(&work)) {
        (Ok(l), Ok(w)) => (l, w),
        (Err(e), _) | (_, Err(e)) => return *e,
    };
    let min = match min_position(&headers) {
        Ok(min) => min,
        Err(refused) => return crate::position::refusal(refused).into_response(),
    };
    match services
        .reads
        .work(&caller, &ledger, &work, min.as_ref())
        .await
    {
        Ok(view) => {
            let mut response = answered(&WorkAnswer::of(&view), &view.position);
            response
                .headers_mut()
                .insert(header::ETAG, etag(view.version));
            response
        }
        Err(refused) => read_problem(refused).into_response(),
    }
}

/// Reads the Works that changed after a cursor.
///
/// The difference comes in the order of the position that last changed each Work, scoped to
/// what the caller may read; a cursor that no longer opens a difference answers `resync` and no
/// change, so the client reads every Work again rather than miss one.
#[utoipa::path(
    get,
    path = "/v1/ledgers/{ledger}/changes",
    operation_id = "list_changes",
    tag = "works",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ChangesQuery
    ),
    responses(
        (status = 200, description = "The changes.", body = ChangesAnswer, headers(
            ("Work-Position" = String, description = "The positions the answer reflects."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "An identifier or a cursor that does not open.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
            content_type = "application/problem+json", headers(
            ("WWW-Authenticate" = String, description = "The DPoP challenge."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 404, description = "No such ledger.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 429, description = "The caller has spent its quota.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds until the next window.")
        )),
        (status = 503, description = "Access cannot be reached, so the caller's authority cannot be verified, or the server sheds load.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:read")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn list_changes(
    State(services): State<Arc<ApiServices>>,
    Path(ledger): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let ledger = match parsed::<LedgerId>(&ledger) {
        Ok(ledger) => ledger,
        Err(e) => return *e,
    };
    let query = match ChangesQuery::of(&uri) {
        Ok(query) => query,
        Err(problem) => return problem.into_response(),
    };
    let cursor: Option<Cursor> = match query.cursor.as_deref().map(parsed::<Cursor>).transpose() {
        Ok(cursor) => cursor,
        Err(e) => return *e,
    };
    let limit = query.limit.unwrap_or(DEFAULT_CHANGES);
    match services
        .reads
        .changes(&caller, &ledger, cursor.as_ref(), limit)
        .await
    {
        Ok(changes) => answered(&ChangesAnswer::of(&changes), &changes.position),
        Err(refused) => read_problem(refused).into_response(),
    }
}

/// Reads a record's evidence, each kind apart.
///
/// The author signature, the ledger's acceptance, the inclusion proof and the witness
/// cosignatures are separate fields; the Access authentication context of an unsigned human
/// record is never shown as an author signature.
#[utoipa::path(
    get,
    path = "/v1/ledgers/{ledger}/records/{record}/evidence",
    operation_id = "get_record_evidence",
    tag = "records",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ("record" = String, Path, description = "The record, `rec_…`.")
    ),
    responses(
        (status = 200, description = "The evidence.", body = EvidenceAnswer, headers(
            ("Work-Position" = String, description = "The positions the answer reflects."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "An identifier that does not open.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
            content_type = "application/problem+json", headers(
            ("WWW-Authenticate" = String, description = "The DPoP challenge."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 404, description = "No such record, or not one the caller may read.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 429, description = "The caller has spent its quota.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds until the next window.")
        )),
        (status = 503, description = "Access cannot be reached, so the caller's authority cannot be verified, or the server sheds load.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:read")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn get_record_evidence(
    State(services): State<Arc<ApiServices>>,
    Path((ledger, record)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let (ledger, record) = match (parsed::<LedgerId>(&ledger), parsed::<RecordId>(&record)) {
        (Ok(l), Ok(r)) => (l, r),
        (Err(e), _) | (_, Err(e)) => return *e,
    };
    match services.reads.evidence(&caller, &ledger, &record).await {
        Ok(evidence) => answered(&EvidenceAnswer::of(&evidence), &evidence.position),
        Err(refused) => read_problem(refused).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::Value;
    use work_query::domain::reads::{Attestation, CheckpointRef, CosignatureView};

    use super::*;

    fn checkpoint() -> CheckpointRef {
        CheckpointRef {
            size: 4,
            root: Digest::sha256([4; 32]),
            signed_note: "work.example/ledger/ab\n4\nroot\n".to_owned(),
            issued_at_ms: 1_792_749_600_000,
        }
    }

    fn evidence(signature: Option<Vec<u8>>, inclusion: Inclusion) -> Value {
        let unsigned = signature.is_none();
        let e = Evidence {
            ledger: LedgerId(Digest::sha256([1; 32])),
            record: RecordId(Digest::sha256([2; 32])),
            author: "party-a".to_owned(),
            author_signature: signature,
            auth_context: unsigned.then_some(Digest::sha256([3; 32])),
            attestation: Attestation {
                pos: 3,
                epoch: 1,
                recorded_at_ms: 1_792_749_600_123,
                leaf_hash: Digest::sha256([5; 32]),
            },
            inclusion,
            witnesses: vec![CosignatureView {
                witness: "w1".to_owned(),
                kind: "witness".to_owned(),
                cosigned_at_ms: 1_792_749_601_000,
            }],
            position: PositionToken::new(vec![1, 2, 3]).unwrap(),
        };
        serde_json::to_value(EvidenceAnswer::of(&e)).unwrap()
    }

    // T-28 E-38 SEC-8 MD-3 E-7
    #[test]
    fn t_28_no_caller_is_401_with_the_dpop_challenge_and_an_unverifiable_one_503() {
        let refused = caller_problem(CallerRefusal::Unauthenticated("token_missing"));
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            refused.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            CHALLENGE
        );
        let unverifiable = caller_problem(CallerRefusal::Unverifiable("access_unreachable"));
        assert_eq!(unverifiable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            unverifiable
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .is_none()
        );
    }

    // P-56 T-13 T-97 P-112
    #[test]
    fn p_56_what_a_caller_may_not_see_is_not_found() {
        for (refusal, code) in [
            (ReadRefusal::NotFound, ProblemCode::NotFound),
            (
                ReadRefusal::PositionInvalid,
                ProblemCode::ReadPositionInvalid,
            ),
            (ReadRefusal::PositionAhead, ProblemCode::ReadPositionAhead),
            (ReadRefusal::CursorInvalid, ProblemCode::InvalidId),
            (ReadRefusal::Unavailable, ProblemCode::Busy),
        ] {
            assert_eq!(read_problem(refusal).code, code);
        }
    }

    // P-57 T-26 P-54
    #[test]
    fn p_57_a_changes_query_names_its_cursor_and_limit_once() {
        let of = |q: &str| ChangesQuery::of(&format!("/v1/ledgers/l/changes{q}").parse().unwrap());
        assert_eq!(of("").unwrap(), ChangesQuery::default());
        let read = of("?cursor=cur_AQ&limit=5&x=1").unwrap();
        assert_eq!(read.cursor.as_deref(), Some("cur_AQ"));
        assert_eq!(read.limit, Some(5));
        for bad in [
            "?limit=five",
            "?limit=-1",
            "?cursor=a&cursor=b",
            "?limit=1&limit=2",
        ] {
            assert_eq!(
                of(bad).unwrap_err().code,
                ProblemCode::InvalidRequest,
                "{bad}"
            );
        }
    }

    // P-20 P-21
    #[test]
    fn p_20_each_kind_of_evidence_is_shown_apart() {
        let proven = Inclusion::Proven {
            checkpoint: checkpoint(),
            path: vec![Digest::sha256([6; 32])],
        };
        let signed = evidence(Some(vec![0xd2, 0x84]), proven);
        assert_eq!(signed["author_signature"]["cose_sign1"], "d284");
        assert!(signed.get("auth_context").is_none());
        assert_eq!(signed["ledger_attestation"]["pos"], "3");
        assert_eq!(
            signed["ledger_attestation"]["recorded_at"],
            "2026-10-23T10:00:00.123Z"
        );
        assert_eq!(signed["ledger_attestation"]["leaf_hash"], "05".repeat(32));
        assert_eq!(signed["inclusion"]["status"], "proven");
        assert_eq!(signed["inclusion"]["path"][0], "06".repeat(32));
        assert_eq!(signed["inclusion"]["checkpoint"]["size"], "4");
        assert_eq!(signed["witnesses"][0]["witness"], "w1");
        assert_eq!(signed["record"], format!("rec_{}", "02".repeat(32)));
        assert!(signed["author"].as_str().unwrap().starts_with("pty_"));
        let unsigned = evidence(None, Inclusion::Pending);
        assert!(unsigned.get("author_signature").is_none());
        assert_eq!(unsigned["auth_context"]["digest"], "03".repeat(32));
        assert_eq!(unsigned["inclusion"]["status"], "pending");
        assert!(unsigned["inclusion"].get("checkpoint").is_none());
        let covered = evidence(
            None,
            Inclusion::Covered {
                checkpoint: checkpoint(),
            },
        );
        assert_eq!(covered["inclusion"]["status"], "covered");
        assert!(covered["inclusion"].get("path").is_none());
    }
}
