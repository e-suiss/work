//! The caller-scoped reads over the golden ledger (P-56, T-13, P-57, T-26, P-20): a Party sees the Works and records it took part in and nothing else, the changes page by position and Work without a gap or a repeat, and a record's author signature and Access `auth_context` are read apart.

use std::collections::{BTreeMap, BTreeSet};

use suiss_crypto::digest::sha256;
use work_kernel::codec::{Decoded, decode_record};
use work_store::ChangeRow;

use super::{Env, golden, golden_ledger};

const STRANGER: &str = "party:nobody:at-all";

// P-56 T-13 P-57 T-26 P-20 P-21
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn p_56_a_party_reads_only_the_works_and_records_it_took_part_in() {
    let env = Env::start().await;
    let ledger = golden_ledger(&env).await;
    let (_, entries) = golden();
    let mut works: BTreeMap<String, BTreeSet<[u8; 16]>> = BTreeMap::new();
    let mut records = Vec::new();
    for g in &entries {
        let Ok(Decoded::Record(record)) = decode_record(&g.record) else {
            continue;
        };
        let core = record.core();
        let author = core.author.as_str().to_owned();
        for work in &core.concerns {
            works
                .entry(author.clone())
                .or_default()
                .insert(*work.as_bytes());
        }
        records.push((sha256(&g.record), author, g.cose.is_some()));
    }
    assert!(!works.is_empty());

    let mut tx = env.read("work_app", &ledger).await;
    let mut seen = 0;
    for (author, concerned) in &works {
        for work in concerned {
            if let Some(row) = tx.visible_work(work, author).await.unwrap() {
                seen += 1;
                assert!(row.version >= 1, "{author}");
                assert!(row.first_pos <= row.last_pos, "{author}");
                assert!(row.opened_at_ms <= row.updated_at_ms, "{author}");
            }
            assert_eq!(tx.visible_work(work, STRANGER).await.unwrap(), None);
        }
        let all = tx.visible_changes(None, 1000, author).await.unwrap();
        let mut paged: Vec<ChangeRow> = Vec::new();
        let mut after = None;
        loop {
            let page = tx.visible_changes(after, 1, author).await.unwrap();
            let Some(last) = page.last() else {
                break;
            };
            after = Some((last.last_pos, last.work));
            paged.extend(page);
        }
        assert_eq!(paged, all, "{author}");
        assert!(
            all.windows(2)
                .all(|w| (w[0].last_pos, w[0].work) < (w[1].last_pos, w[1].work))
        );
    }
    assert!(seen > 0);
    let none = tx.visible_changes(None, 1000, STRANGER).await.unwrap();
    assert_eq!(none, Vec::<ChangeRow>::new());

    let mut kinds = BTreeSet::new();
    for (id, author, signed) in &records {
        assert_eq!(tx.visible_record(id, STRANGER).await.unwrap(), None);
        let Some(row) = tx.visible_record(id, author).await.unwrap() else {
            continue;
        };
        assert_eq!(&row.author, author);
        assert_eq!(row.author_signature.is_some(), *signed, "{author}");
        assert_eq!(row.auth_context_ref.is_some(), !*signed, "{author}");
        kinds.insert(*signed);
        let leaves = tx
            .leaf_hashes(row.pos.checked_add(1).unwrap())
            .await
            .unwrap();
        assert_eq!(leaves.last(), Some(&row.leaf_hash));
        assert_eq!(tx.covering_checkpoint(row.pos).await.unwrap(), None);
    }
    assert_eq!(kinds, BTreeSet::from([false, true]));
    tx.rollback().await.unwrap();
}
