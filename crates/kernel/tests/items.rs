//! The items each golden record touches (T-89), from `conformance/vectors/kernel/items-touched.json` over the record bytes of `conformance/vectors/records`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::Value;
use work_kernel::codec::{Decoded, decode_record};
use work_kernel::id::{Digest, RecordId, WorkId};
use work_kernel::items::{Expect, ItemKey, Touch, touched};

const ITEMS: &str = include_str!("../../../conformance/vectors/kernel/items-touched.json");
const RECORDS: &str = include_str!("../../../conformance/vectors/records/records.json");
const QUARANTINE: &str =
    include_str!("../../../conformance/vectors/records/records-quarantine.json");

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn record_bytes(files: &[Value], id: &str) -> Vec<u8> {
    for file in files {
        let list = file.get("records").unwrap_or(&file["cases"]);
        if let Some(r) = list.as_array().unwrap().iter().find(|r| r["id"] == id) {
            return hex(r["hex"].as_str().unwrap());
        }
    }
    panic!("{id}");
}

fn expected(touch: &Value) -> Touch {
    let item = touch["item"].as_array().unwrap();
    let id = hex(item[1].as_str().unwrap());
    let item = match item[0].as_str().unwrap() {
        "work" => ItemKey::Work(WorkId::from_bytes(id.try_into().unwrap())),
        other => panic!("{other}"),
    };
    let expect = match &touch["expect"] {
        Value::String(s) if s == "next" => Expect::Next,
        v => Expect::Version(v["version"].as_u64().unwrap()),
    };
    let heads = touch["heads"].as_array().map(|h| {
        h.iter()
            .map(|d| RecordId(Digest::sha256(hex(d.as_str().unwrap()).try_into().unwrap())))
            .collect()
    });
    Touch {
        item,
        expect,
        heads,
    }
}

// T-89 P-29 C-34 P-19
#[test]
fn t_89_every_golden_record_touches_the_works_it_concerns() {
    let files: Vec<Value> = [RECORDS, QUARANTINE]
        .iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect();
    let vectors: Value = serde_json::from_str(ITEMS).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let Ok(Decoded::Record(record)) = decode_record(&record_bytes(&files, id)) else {
            panic!("{id}");
        };
        let want: Vec<Touch> = case["touches"]
            .as_array()
            .unwrap()
            .iter()
            .map(expected)
            .collect();
        assert_eq!(touched(&record), want, "{id}");
    }
}
