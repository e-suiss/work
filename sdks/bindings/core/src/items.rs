//! The work items a record touches, from the kernel's reading of its signed core fields (T-89, P-29): the binding names them and adds nothing.

use serde_json::{Value, json};
use work_kernel::codec::{Decoded, decode_record};
use work_kernel::items::{self, Expect, ItemKey, Touch};
use work_kernel::reason::QuarantineReason;

use crate::input_error;
use crate::project::{accept, fields, hex, quarantine, reject};

fn item(key: &ItemKey) -> Option<Value> {
    Some(match key {
        ItemKey::Work(w) => json!(["work", hex(w.as_bytes())]),
        ItemKey::Commitment(r) => json!(["commitment", hex(r.0.as_bytes())]),
        ItemKey::Condition(r) => json!(["condition", hex(r.0.as_bytes())]),
        _ => return None,
    })
}

fn touch(t: &Touch) -> Option<Value> {
    let expect = match t.expect {
        Expect::Next => json!("next"),
        Expect::Version(v) => json!({ "version": v }),
    };
    let heads = t.heads.as_ref().map(|h| {
        h.iter()
            .map(|r| Value::from(hex(r.0.as_bytes())))
            .collect::<Vec<_>>()
    });
    let item = item(&t.item)?;
    Some(json!({ "item": item, "expect": expect, "heads": heads }))
}

/// The items the protocol 1.0 record of `SignedRecord` bytes touches, in the kernel's order (T-89, P-29, C-34).
///
/// Returns `{"outcome":"accept","touches":[{"item":["work"|"commitment"|"condition",<hex>],"expect":"next"|{"version":<n>},"heads":null|[<hex>]}]}`, `{"outcome":"quarantine","reason":"protocol_version_unknown"}` for a record of a protocol version without a rule set, or `{"outcome":"reject","reason":<code>}` for bytes that do not decode.
#[must_use]
pub fn touched(record: &[u8]) -> String {
    match decode_record(record) {
        Ok(Decoded::Record(r)) => {
            let touches: Option<Vec<Value>> = items::touched(&r).iter().map(touch).collect();
            match touches {
                Some(t) => accept(fields([("touches", Value::Array(t))])),
                None => input_error("unknown_item"),
            }
        }
        Ok(Decoded::UnknownProtocol(_)) => {
            quarantine(&QuarantineReason::ProtocolVersionUnknown.to_string())
        }
        Err(reason) => reject(&reason.to_string()),
    }
}
