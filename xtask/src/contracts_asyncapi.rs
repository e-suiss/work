//! The `AsyncAPI` 3.0 documents (T-98 item 3, P-35, P-37, P-38): `sdks/asyncapi/work-events.yaml` has one message per event type of the `work_proto::events` table in a CloudEvents 1.0 envelope, each `data` schema is JSON Schema 2020-12 at `sdks/asyncapi/schemas/<type>/<version>.json` and named by `dataschema`, and `sdks/asyncapi/work-live.yaml` is the live layer document (T-19). The YAML is written from JSON values with sorted keys and quoted strings, so it is also plain JSON-compatible YAML.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde_json::{Value, json};

use crate::Violation;
use crate::contracts::source::{EVENTS_RS, Event, events};
use crate::contracts::{violation, write};

pub(crate) const DIR: &str = "sdks/asyncapi";
const EVENTS_DOC: &str = "work-events.yaml";
const LIVE_DOC: &str = "work-live.yaml";
const RULE: &str = "asyncapi";
const SCHEMA_FORMAT: &str = "application/schema+json;version=2020-12";
const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const VERSION: u32 = 1;
const HEX64: &str = "^[0-9a-f]{64}$";

fn schema_path(event: &Event) -> String {
    format!("schemas/{}/{VERSION}.json", event.name)
}

fn plain_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned())
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_owned()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(quoted(s)),
        Value::Array(items) if items.is_empty() => Some("[]".to_owned()),
        Value::Object(map) if map.is_empty() => Some("{}".to_owned()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn pad(out: &mut String, indent: usize) {
    out.extend(std::iter::repeat_n(' ', indent));
}

fn emit(value: &Value, indent: usize, out: &mut String) {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            for (key, item) in sorted {
                pad(out, indent);
                let key = if plain_key(key) {
                    key.clone()
                } else {
                    quoted(key)
                };
                match scalar(item) {
                    Some(text) => {
                        let _ = writeln!(out, "{key}: {text}");
                    }
                    None => {
                        let _ = writeln!(out, "{key}:");
                        emit(item, indent.saturating_add(2), out);
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                pad(out, indent);
                match scalar(item) {
                    Some(text) => {
                        let _ = writeln!(out, "- {text}");
                    }
                    None => {
                        let mut nested = String::new();
                        emit(item, indent.saturating_add(2), &mut nested);
                        out.push_str("- ");
                        out.push_str(nested.get(indent.saturating_add(2)..).unwrap_or_default());
                    }
                }
            }
        }
        other => {
            pad(out, indent);
            let _ = writeln!(out, "{}", scalar(other).unwrap_or_default());
        }
    }
}

/// `value` as block YAML.
pub(crate) fn yaml(value: &Value) -> String {
    let mut out = String::new();
    emit(value, 0, &mut out);
    out
}

fn envelope() -> Value {
    json!({
        "type": "object",
        "description": "The CloudEvents 1.0 structured envelope of every Work event (P-35); the event is thin and carries no record body (P-37).",
        "required": [
            "specversion", "id", "source", "type", "time", "subject", "datacontenttype",
            "dataschema", "seq", "recordid", "ledger", "pos", "data"
        ],
        "properties": {
            "specversion": {"type": "string", "const": "1.0"},
            "id": {"type": "string", "description": "Event id, the same in every delivery attempt."},
            "source": {"type": "string", "format": "uri", "description": "The installation URI and the ledger: <installation>/ledgers/<ledger hex> (P-98)."},
            "type": {"type": "string", "description": "<item>.<past tense> (P-38)."},
            "time": {"type": "string", "format": "date-time", "description": "recorded_at of the source record."},
            "subject": {"type": "string", "description": "The prefixed id of the item (P-112)."},
            "datacontenttype": {"type": "string", "const": "application/json"},
            "dataschema": {"type": "string", "description": "The versioned data schema path."},
            "seq": {"type": "string", "pattern": "^[1-9][0-9]*$", "description": "Monotonic version per subject, decimal (T-81)."},
            "traceparent": {"type": "string", "pattern": "^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"},
            "correlationid": {"type": "string"},
            "recordid": {"type": "string", "pattern": HEX64, "description": "Digest of the source record, lower-case hex."},
            "ledger": {"type": "string", "pattern": HEX64, "description": "LedgerID of the source record, lower-case hex."},
            "pos": {"type": "string", "pattern": "^(0|[1-9][0-9]*)$", "description": "Ledger position of the source record, decimal."},
            "data": {"type": "object"}
        }
    })
}

/// The `data` schema of `event`.
pub(crate) fn data_schema(event: &Event, all: &[Event]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = vec![json!("parties")];
    properties.insert(
        "parties".to_owned(),
        json!({
            "type": "array",
            "uniqueItems": true,
            "description": "The related Party ids (P-37).",
            "items": {"type": "string", "pattern": "^pty_[A-Za-z0-9_-]+$"}
        }),
    );
    match event.data.as_str() {
        "Changed" => {
            let causes: Vec<&str> = all
                .iter()
                .filter(|e| e.data != "Changed")
                .map(|e| e.name.as_str())
                .collect();
            properties.insert(
                "cause".to_owned(),
                json!({"type": "string", "enum": causes, "description": "The primary event type of the record (T-98 item 4)."}),
            );
            required.push(json!("cause"));
        }
        "Revoked" => {
            properties.insert(
                "kind".to_owned(),
                json!({"type": "string", "enum": event.sources, "description": "The revoking wire name (T-98 item 5)."}),
            );
            required.push(json!("kind"));
        }
        _ => {}
    }
    json!({
        "$schema": DRAFT,
        "title": format!("{} data, version {VERSION}", event.name),
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn message(event: &Event) -> Value {
    let schema = schema_path(event);
    json!({
        "name": event.name,
        "title": event.name,
        "contentType": "application/cloudevents+json",
        "payload": {
            "schemaFormat": SCHEMA_FORMAT,
            "schema": {
                "allOf": [
                    {"$ref": "#/components/schemas/CloudEvent"},
                    {
                        "type": "object",
                        "properties": {
                            "type": {"const": event.name},
                            "dataschema": {"const": schema},
                            "data": {"$ref": format!("./{schema}")}
                        }
                    }
                ]
            }
        }
    })
}

/// The events document.
pub(crate) fn events_document(all: &[Event]) -> Value {
    let mut channel_messages = serde_json::Map::new();
    let mut messages = serde_json::Map::new();
    let mut refs = Vec::new();
    for event in all {
        channel_messages.insert(
            event.name.clone(),
            json!({"$ref": format!("#/components/messages/{}", event.name)}),
        );
        messages.insert(event.name.clone(), message(event));
        refs.push(json!({"$ref": format!("#/channels/events/messages/{}", event.name)}));
    }
    json!({
        "asyncapi": "3.0.0",
        "info": {
            "title": "Work events",
            "version": "1",
            "description": "Every Work event type: one event per record and affected item, named <item>.<past tense>; the item a record is about takes the type of its wire name and every other item it touches takes <item>.changed (T-98 items 4 and 5). Events are CloudEvents 1.0, thin, and come from the transactional outbox after the record is durable.",
            "license": {"name": "Apache-2.0"}
        },
        "defaultContentType": "application/cloudevents+json",
        "channels": {
            "events": {
                "address": null,
                "title": "events",
                "description": "Work events as subscriptions and webhooks deliver them.",
                "messages": channel_messages
            }
        },
        "operations": {
            "sendEvents": {
                "action": "send",
                "channel": {"$ref": "#/channels/events"},
                "messages": refs
            }
        },
        "components": {
            "schemas": {"CloudEvent": envelope()},
            "messages": messages
        }
    })
}

/// The live layer document; its messages wait for their catalog (T-19, T-98 item 3).
pub(crate) fn live_document() -> Value {
    json!({
        "asyncapi": "3.0.0",
        "info": {
            "title": "Work live layer",
            "version": "1",
            "description": "The thin WebSocket live layer (T-19): presence, shared sessions and control handover. Presence is not a record; a client reads the query service again after a signal. Its messages are added with their catalog.",
            "license": {"name": "Apache-2.0"}
        },
        "channels": {},
        "operations": {}
    })
}

/// Every generated file, by its path under `sdks/asyncapi`.
pub(crate) fn render(all: &[Event]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    out.insert(EVENTS_DOC.to_owned(), yaml(&events_document(all)));
    out.insert(LIVE_DOC.to_owned(), yaml(&live_document()));
    for event in all {
        let mut text = serde_json::to_string_pretty(&data_schema(event, all))
            .map_err(|e| format!("{}: {e}", event.name))?;
        text.push('\n');
        out.insert(schema_path(event), text);
    }
    Ok(out)
}

fn rendered(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let src =
        std::fs::read_to_string(root.join(EVENTS_RS)).map_err(|e| format!("{EVENTS_RS}: {e}"))?;
    render(&events(&src)?)
}

fn committed(dir: &Path, prefix: &str, out: &mut BTreeSet<String>) -> Result<(), String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if entry.path().is_dir() {
            committed(&entry.path(), &rel, out)?;
        } else {
            out.insert(rel);
        }
    }
    Ok(())
}

/// `cargo xtask asyncapi`: writes every file and removes the files no longer generated.
pub(crate) fn write_documents(root: &Path) -> Result<(), String> {
    let files = rendered(root)?;
    let mut existing = BTreeSet::new();
    committed(&root.join(DIR), "", &mut existing)?;
    for stale in existing.iter().filter(|f| !files.contains_key(*f)) {
        let path = root.join(DIR).join(stale);
        std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    for (rel, text) in &files {
        write(root, &format!("{DIR}/{rel}"), text)?;
    }
    Ok(())
}

/// `cargo xtask check asyncapi`, also the `asyncapi` generator of `generated` (T-41 rule 4).
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let files = rendered(root)?;
    let mut existing = BTreeSet::new();
    committed(&root.join(DIR), "", &mut existing)?;
    let mut out = Vec::new();
    for (rel, text) in &files {
        let path = format!("{DIR}/{rel}");
        match std::fs::read_to_string(root.join(&path)) {
            Ok(have) if &have == text => {}
            Ok(_) => out.push(violation(
                RULE,
                &path,
                "differs from the generated document; run `cargo xtask asyncapi` (T-98 item 3)"
                    .to_owned(),
            )),
            Err(_) => out.push(violation(
                RULE,
                &path,
                "is generated but not committed; run `cargo xtask asyncapi` (T-98 item 3)"
                    .to_owned(),
            )),
        }
    }
    for rel in existing.iter().filter(|f| !files.contains_key(*f)) {
        out.push(violation(
            RULE,
            &format!("{DIR}/{rel}"),
            "is committed but no longer generated; run `cargo xtask asyncapi` (T-98 item 3)"
                .to_owned(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(name: &str, item: &str, data: &str, sources: &[&str]) -> Event {
        Event {
            name: name.to_owned(),
            item: item.to_owned(),
            data: data.to_owned(),
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn sample() -> Vec<Event> {
        vec![
            event("commitment.requested", "Commitment", "Thin", &["request"]),
            event(
                "commitment.revoked",
                "Commitment",
                "Revoked",
                &["revoke_request", "revoke_promise"],
            ),
            event("work.changed", "Work", "Changed", &[]),
        ]
    }

    // T-98
    #[test]
    fn t_98_yaml_is_block_style_with_sorted_keys_and_quoted_strings() {
        let text = yaml(&json!({"b": [1, {"y": "two", "x": []}], "$ref": "#/a", "a": {}}));
        assert_eq!(
            text,
            "\"$ref\": \"#/a\"\na: {}\nb:\n  - 1\n  - x: []\n    y: \"two\"\n"
        );
    }

    // T-98
    #[test]
    fn t_98_every_event_type_is_one_message_with_a_versioned_data_schema() {
        let all = sample();
        let doc = events_document(&all);
        assert_eq!(doc["asyncapi"], "3.0.0");
        let messages = doc["components"]["messages"].as_object().unwrap();
        assert_eq!(messages.len(), 3);
        let revoked = &messages["commitment.revoked"]["payload"];
        assert_eq!(revoked["schemaFormat"], SCHEMA_FORMAT);
        assert_eq!(
            revoked["schema"]["allOf"][1]["properties"]["dataschema"]["const"],
            "schemas/commitment.revoked/1.json"
        );
        assert_eq!(
            doc["operations"]["sendEvents"]["messages"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        let data = data_schema(&all[1], &all);
        assert_eq!(data["required"], json!(["parties", "kind"]));
        assert_eq!(
            data["properties"]["kind"]["enum"],
            json!(["revoke_request", "revoke_promise"])
        );
        let changed = data_schema(&all[2], &all);
        assert_eq!(
            changed["properties"]["cause"]["enum"],
            json!(["commitment.requested", "commitment.revoked"])
        );
        assert_eq!(data_schema(&all[0], &all)["required"], json!(["parties"]));
        let files = render(&all).unwrap();
        let names: Vec<&str> = files.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "schemas/commitment.requested/1.json",
                "schemas/commitment.revoked/1.json",
                "schemas/work.changed/1.json",
                "work-events.yaml",
                "work-live.yaml"
            ]
        );
        assert!(files["work-live.yaml"].starts_with("asyncapi: \"3.0.0\"\nchannels: {}\n"));
    }
}
