//! The external standard mappings of a record through `work-proto` (P-48, P-49, P-51): the binding decodes the bytes with the kernel, maps the context and writes the proto's PROV-JSON document and Activity Streams 2.0 activity unchanged.

use serde_json::{Value, json};
use work_kernel::codec::{Decoded, decode_record, record_id};
use work_kernel::id::RecordId;
use work_kernel::reason::QuarantineReason;
use work_kernel::validate::ActorTypes;
use work_proto::mapping::{as2_activity, prov_document};

use crate::decode::{Mapped, digest, exact_keys, list, object, optional, required};
use crate::project::{accept, fields, quarantine, reject};
use crate::{actor_entry, input_error, parse};

const CONTEXT_FIELDS: &[&str] = &["actor_type", "withheld"];
const ACTOR_FIELDS: &[&str] = &["author", "on_behalf_of"];

struct Context {
    actors: ActorTypes,
    withheld: Vec<RecordId>,
}

fn context(v: &Value) -> Mapped<Context> {
    let m = object(v)?;
    exact_keys(m, CONTEXT_FIELDS)?;
    let actors = object(required(m, "actor_type")?)?;
    exact_keys(actors, ACTOR_FIELDS)?;
    Ok(Context {
        actors: ActorTypes {
            author: actor_entry(required(actors, "author")?)?,
            on_behalf_of: optional(actors, "on_behalf_of", |l| list(l, actor_entry))?
                .unwrap_or_default(),
            evidence: Vec::new(),
        },
        withheld: optional(m, "withheld", |l| list(l, |d| digest(d).map(RecordId)))?
            .unwrap_or_default(),
    })
}

/// The PROV-JSON document and the Activity Streams 2.0 activity of one record given as its `SignedRecord` bytes (P-49, P-51), with a context of `actor_type` (`author` and one `on_behalf_of` entry per principal, as in the envelope's `ActorTypeAnnotation`) and an optional `withheld` list of record digests the viewer may not see (EV-12).
///
/// Returns `{"outcome":"accept","prov":{…},"as2":{"type","vocabulary"}|null}`, `{"outcome":"quarantine","reason":"protocol_version_unknown"}` for a record of a protocol version without a rule set, or `{"outcome":"reject","reason":<code>}` for bytes that do not decode. A context that is not JSON or does not fit, or whose `on_behalf_of` entries do not match the record's chain, returns `{"error":{"code":"invalid_json"}}` or `{"error":{"code":"invalid_context"}}`.
#[must_use]
pub fn map_record(record: &[u8], context_json: &str) -> String {
    let Some(value) = parse(context_json) else {
        return input_error("invalid_json");
    };
    let Ok(ctx) = context(&value) else {
        return input_error("invalid_context");
    };
    match decode_record(record) {
        Ok(Decoded::Record(r)) => {
            let id = record_id(record);
            let Ok(prov) = prov_document(&r, &id, &ctx.actors, &ctx.withheld) else {
                return input_error("invalid_context");
            };
            let as2 = match as2_activity(&r) {
                Some(a) => json!({ "type": a.name, "vocabulary": a.vocabulary }),
                None => Value::Null,
            };
            accept(fields([("prov", prov), ("as2", as2)]))
        }
        Ok(Decoded::UnknownProtocol(_)) => {
            quarantine(&QuarantineReason::ProtocolVersionUnknown.to_string())
        }
        Err(reason) => reject(&reason.to_string()),
    }
}
