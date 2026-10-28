//! The erasure scope list (OP-14 rule 3): every table carrying personal fields, the columns
//! that carry them and the erasure mechanism its `COMMENT ON TABLE` tag declares. A table whose
//! tag is not `erasure=none` and is missing here, or a listed table or column the schema does
//! not have, breaks the erasure scope tests.

/// One table of the erasure scope list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasureScope {
    /// Schema-qualified table name.
    pub table: &'static str,
    /// The table's `erasure=` tag.
    pub erasure: &'static str,
    /// The columns carrying personal fields.
    pub columns: &'static [&'static str],
}

// OP-13 OP-14 OP-15
/// The erasure scope list of the canonical database; the derived database has none.
pub const ERASURE_SCOPE: [ErasureScope; 8] = [
    ErasureScope {
        table: "ledger.log",
        erasure: "pseudonymous_skeleton",
        columns: &["record_bytes"],
    },
    ErasureScope {
        table: "work.record_header",
        erasure: "pseudonymous_skeleton",
        columns: &["author"],
    },
    ErasureScope {
        table: "work.log_relation",
        erasure: "pseudonymous_skeleton",
        columns: &["source_text", "target_text"],
    },
    ErasureScope {
        table: "work.body_part",
        erasure: "crypto_shred",
        columns: &["ciphertext", "object_key"],
    },
    ErasureScope {
        table: "work.body_dek",
        erasure: "pseudonymous_skeleton",
        columns: &["subject_ref"],
    },
    ErasureScope {
        table: "work.retention_hold",
        erasure: "pseudonymous_skeleton",
        columns: &["subject_ref"],
    },
    ErasureScope {
        table: "work.erasure_log",
        erasure: "retention_class:erasure_log",
        columns: &["dek_id"],
    },
    ErasureScope {
        table: "work.idempotency_key",
        erasure: "pseudonymous_skeleton",
        columns: &["caller_ref"],
    },
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn tags() -> BTreeMap<String, String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut tags = BTreeMap::new();
        for dir in ["foundation", "canonical", "derived"] {
            for entry in std::fs::read_dir(root.join(dir)).unwrap() {
                let sql = std::fs::read_to_string(entry.unwrap().path()).unwrap();
                for line in sql.lines() {
                    let Some(rest) = line.strip_prefix("COMMENT ON TABLE ") else {
                        continue;
                    };
                    let (table, descr) = rest.split_once(" IS '").unwrap();
                    let erasure = descr.split_once("erasure=").unwrap().1;
                    let erasure = erasure.strip_suffix("';").unwrap();
                    assert!(
                        tags.insert(table.to_owned(), erasure.to_owned()).is_none(),
                        "{table}"
                    );
                }
            }
        }
        tags
    }

    #[test]
    fn op_14_the_erasure_scope_list_matches_the_migration_tags() {
        let tags = tags();
        let personal: BTreeMap<&str, &str> = tags
            .iter()
            .filter(|(_, e)| e.as_str() != "none")
            .map(|(t, e)| (t.as_str(), e.as_str()))
            .collect();
        let listed: BTreeMap<&str, &str> =
            ERASURE_SCOPE.iter().map(|s| (s.table, s.erasure)).collect();
        assert_eq!(listed.len(), ERASURE_SCOPE.len());
        assert_eq!(listed, personal);
        assert!(ERASURE_SCOPE.iter().all(|s| !s.columns.is_empty()));
    }
}
