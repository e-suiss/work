use sqlx::{Connection, Executor, PgConnection, Row};
use work_store::Cluster;

use crate::env::Env;

/// The schema security checks (T-36 rule 6): one row `(check_id, object)` per violation,
/// none when the schema is sound. Read from the catalog, so new tables are covered unlisted.
const CHECKS: &str = r"WITH
roles AS (
    SELECT rolname FROM pg_catalog.pg_roles WHERE rolname LIKE 'work\_%'
),
t AS (
    SELECT c.oid,
           n.nspname || '.' || c.relname AS fq,
           n.nspname,
           c.relname,
           c.relkind,
           c.relrowsecurity,
           c.relforcerowsecurity,
           c.relpersistence,
           c.reloptions,
           c.relispartition,
           pg_catalog.pg_get_userbyid(c.relowner) AS owner,
           COALESCE(pg_catalog.obj_description(c.oid, 'pg_class'), '') AS descr
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('ledger', 'work', 'derived', 'projection')
       AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
),
tab AS (
    SELECT * FROM t WHERE relkind IN ('r', 'p')
),
cols AS (
    SELECT tab.oid, tab.fq, tab.nspname, tab.relname, tab.descr, a.attnum, a.attname,
           pg_catalog.format_type(a.atttypid, a.atttypmod) AS typ,
           ty.typname, tn.nspname AS typnsp, a.attidentity,
           pg_catalog.pg_get_expr(d.adbin, d.adrelid) AS dflt
      FROM tab
      JOIN pg_catalog.pg_attribute a ON a.attrelid = tab.oid AND a.attnum > 0 AND NOT a.attisdropped
      JOIN pg_catalog.pg_type ty ON ty.oid = a.atttypid
      JOIN pg_catalog.pg_namespace tn ON tn.oid = ty.typnamespace
      LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
),
reject_fn AS (
    SELECT 'ledger.reject_mutation'::regproc::oid AS oid
),
job_queue_delete (fq, rolname) AS (
    VALUES ('ledger.outbox', 'work_publisher'),
           ('derived.reconcile_queue', 'work_reconciler')
),
funcs AS (
    SELECT p.oid,
           n.nspname || '.' || p.proname AS fq,
           p.prosecdef,
           COALESCE(pg_catalog.array_to_string(p.proconfig, ' '), '') AS config,
           pg_catalog.pg_get_userbyid(p.proowner) AS owner
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('ledger', 'work', 'derived', 'projection')
),
definer_allowed (fq, rolname) AS (
    VALUES ('work.drop_archived_partition', 'work_archive'),
           ('ledger.outbox_ledgers', 'work_publisher')
),
scope_exception_allowed (fq) AS (
    VALUES ('ledger.outbox')
),
partitioned_allowed (fq) AS (
    VALUES ('work.idempotency_key'), ('work.inbound_seen')
),
violations (check_id, object) AS (
    SELECT 'rls_enable_force', fq FROM tab
     WHERE NOT (relrowsecurity AND relforcerowsecurity)
    UNION ALL
    SELECT 'rls_ledger_scope_policy', fq FROM tab
     WHERE NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_policy p
          WHERE p.polrelid = tab.oid AND NOT p.polpermissive AND p.polname = 'ledger_scope'
            AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%current_ledger_id()%'
            AND pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%current_ledger_id()%')
    UNION ALL
    SELECT 'pk_ledger_prefix', fq FROM tab
     WHERE NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_constraint k
           JOIN pg_catalog.pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
          WHERE k.conrelid = tab.oid AND k.contype = 'p' AND a.attname = 'ledger_id')
    UNION ALL
    SELECT 'index_ledger_prefix', tab.fq || ' ' || ic.relname FROM tab
      JOIN pg_catalog.pg_index i ON i.indrelid = tab.oid
      JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
      LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = tab.oid AND a.attnum = i.indkey[0]
     WHERE a.attname IS DISTINCT FROM 'ledger_id'
    UNION ALL
    SELECT 'fk_composite_ledger', tab.fq || ' ' || k.conname FROM tab
      JOIN pg_catalog.pg_constraint k ON k.conrelid = tab.oid AND k.contype = 'f'
      JOIN pg_catalog.pg_attribute la ON la.attrelid = k.conrelid AND la.attnum = k.conkey[1]
      JOIN pg_catalog.pg_attribute ra ON ra.attrelid = k.confrelid AND ra.attnum = k.confkey[1]
     WHERE la.attname <> 'ledger_id' OR ra.attname <> 'ledger_id'
    UNION ALL
    SELECT 'owner_is_work_owner', fq FROM t WHERE owner <> 'work_owner'
    UNION ALL
    SELECT 'no_truncate_grant', r.rolname || ' ' || tab.fq FROM tab CROSS JOIN roles r
     WHERE pg_catalog.has_table_privilege(r.rolname, tab.oid, 'TRUNCATE')
    UNION ALL
    SELECT 'no_delete_grant', r.rolname || ' ' || tab.fq FROM tab CROSS JOIN roles r
     WHERE pg_catalog.has_table_privilege(r.rolname, tab.oid, 'DELETE')
       AND NOT EXISTS (SELECT 1 FROM job_queue_delete j WHERE j.fq = tab.fq AND j.rolname = r.rolname)
    UNION ALL
    SELECT 'no_delete_grant_public', tab.fq FROM tab
     WHERE pg_catalog.has_table_privilege('public', tab.oid, 'DELETE')
    UNION ALL
    SELECT 'job_queue_delete_present', j.rolname || ' ' || j.fq FROM job_queue_delete j
     WHERE pg_catalog.to_regclass(j.fq) IS NOT NULL
       AND NOT pg_catalog.has_table_privilege(j.rolname, pg_catalog.to_regclass(j.fq), 'DELETE')
    UNION ALL
    SELECT 'job_queue_set_exact', fq FROM tab
     WHERE (descr LIKE '%guard=job_queue;%') <> EXISTS (SELECT 1 FROM job_queue_delete j WHERE j.fq = tab.fq)
    UNION ALL
    SELECT 'partitioned_set_exact', fq FROM tab
     WHERE relkind = 'p' AND fq NOT IN (SELECT fq FROM partitioned_allowed)
    UNION ALL
    SELECT 'partition_of_allowed_parent', fq FROM tab
     WHERE relispartition
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_inherits h
             JOIN pg_catalog.pg_class pc ON pc.oid = h.inhparent
             JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace
            WHERE h.inhrelid = tab.oid AND pn.nspname || '.' || pc.relname IN (SELECT fq FROM partitioned_allowed))
    UNION ALL
    SELECT 'log_not_partitioned', 'ledger.log' FROM tab
     WHERE fq = 'ledger.log' AND relkind <> 'r'
    UNION ALL
    SELECT 'no_update_on_append_only', r.rolname || ' ' || tab.fq FROM tab CROSS JOIN roles r
     WHERE (tab.descr LIKE '%guard=append_only;%' OR tab.descr LIKE '%guard=job_queue;%')
       AND r.rolname <> 'work_owner'
       AND pg_catalog.has_any_column_privilege(r.rolname, tab.oid, 'UPDATE')
    UNION ALL
    SELECT 'no_public_grant', tab.fq FROM tab
     WHERE pg_catalog.has_table_privilege('public', tab.oid, 'SELECT')
    UNION ALL
    SELECT 'trigger_reject_truncate', fq FROM tab
     WHERE NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_trigger g, reject_fn
          WHERE g.tgrelid = tab.oid AND g.tgfoid = reject_fn.oid AND (g.tgtype & 32) <> 0)
    UNION ALL
    SELECT 'trigger_reject_delete', fq FROM tab
     WHERE descr NOT LIKE '%guard=job_queue;%'
       AND NOT relispartition
       AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_trigger g, reject_fn
          WHERE g.tgrelid = tab.oid AND g.tgfoid = reject_fn.oid AND (g.tgtype & 8) <> 0)
    UNION ALL
    SELECT 'trigger_reject_update', fq FROM tab
     WHERE (descr LIKE '%guard=append_only;%' OR descr LIKE '%guard=job_queue;%')
       AND NOT relispartition
       AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_trigger g, reject_fn
          WHERE g.tgrelid = tab.oid AND g.tgfoid = reject_fn.oid AND (g.tgtype & 16) <> 0)
    UNION ALL
    SELECT 'component_label', fq FROM t
     WHERE relkind <> 'S'
       AND descr !~ '^label=(CANONICAL|SYNC-DERIVED|DERIVED|PROJECTION|OPERATIONAL); home=(canonical|derived); guard=(append_only|mutable|job_queue|view); erasure=[a-z_:]+$'
    UNION ALL
    SELECT 'home_matches_cluster', fq FROM t
     WHERE (pg_catalog.current_database() = 'work' AND descr LIKE '%home=derived;%')
        OR (pg_catalog.current_database() = 'work_derived' AND descr LIKE '%home=canonical;%' AND nspname <> 'work')
    UNION ALL
    SELECT 'derived_cluster_no_canonical_tables', fq FROM tab
     WHERE pg_catalog.current_database() = 'work_derived' AND nspname IN ('ledger', 'work')
    UNION ALL
    SELECT 'timer_only_in_derived', fq FROM t
     WHERE pg_catalog.current_database() = 'work' AND relname LIKE '%timer%'
    UNION ALL
    SELECT 'job_queue_identity_only', fq || '.' || attname FROM cols
     WHERE descr LIKE '%guard=job_queue;%'
       AND (typname IN ('party_ref', 'text', 'bytea', 'jsonb', 'json') AND attname NOT IN ('key_kind', 'cause'))
    UNION ALL
    SELECT 'erasure_scope_listed', fq || '.' || attname FROM cols
     WHERE (typnsp = 'work' AND typname = 'party_ref' OR attname IN ('ciphertext', 'source_text', 'target_text'))
       AND descr LIKE '%erasure=none%'
    UNION ALL
    SELECT 'no_secret_columns', fq || '.' || attname FROM cols
     WHERE attname ~ '(password|passwd|passphrase|secret|token|api_?key|private_?key|otp|cookie|session|card|pan$|cvv|cvc|iban|account_number|wrapped_dek|dek_material)'
    UNION ALL
    SELECT 'no_derived_concept_columns', fq || '.' || attname FROM cols
     WHERE nspname IN ('ledger', 'work', 'derived')
       AND attname ~ '(^|_)(status|progress|attention|blocked|waiting|next_move|handoff|lease_state|clock_state|budget_state|wip|context|perspective|trust|assurance|counterparty|shared_work|track_record|support_chain|ping_pong|priority|urgency|owner|title|name|summary|briefing)($|_)'
       AND attname NOT IN ('hsm_key_label', 'auth_context_ref')
    UNION ALL
    SELECT 'work_root_identity_only', fq || '.' || attname FROM cols
     WHERE fq = 'work.work_root' AND attname NOT IN ('ledger_id', 'work_id', 'first_pos')
    UNION ALL
    SELECT 'no_sequences', fq FROM t WHERE relkind = 'S'
    UNION ALL
    SELECT 'no_identity_or_serial', fq || '.' || attname FROM cols
     WHERE attidentity <> '' OR dflt LIKE 'nextval(%'
    UNION ALL
    SELECT 'uuid_defaults_are_v7', fq || '.' || attname FROM cols
     WHERE typname = 'uuid' AND dflt IS NOT NULL AND dflt <> 'uuidv7()'
    UNION ALL
    SELECT 'no_unlogged', fq FROM t WHERE relpersistence = 'u'
    UNION ALL
    SELECT 'no_timestamp_without_tz', fq || '.' || attname FROM cols
     WHERE typ IN ('timestamp without time zone', 'json')
    UNION ALL
    SELECT 'no_jsonb', fq || '.' || attname FROM cols
     WHERE typname = 'jsonb'
    UNION ALL
    SELECT 'status_columns_checked', fq || '.' || attname FROM cols
     WHERE typname IN ('text')
       AND attname ~ '(^|_)(state|kind|outcome|ingest|verdict|cause|family|storage|rel|profile|source)$'
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_constraint k
            WHERE k.conrelid = cols.oid AND k.contype = 'c' AND cols.attnum = ANY (k.conkey))
    UNION ALL
    SELECT 'views_security_invoker', fq FROM t
     WHERE relkind = 'v' AND NOT COALESCE('security_invoker=true' = ANY (reloptions), false)
    UNION ALL
    SELECT 'app_role_read_only', tab.fq FROM tab
     WHERE pg_catalog.has_any_column_privilege('work_app', tab.oid, 'INSERT')
        OR pg_catalog.has_any_column_privilege('work_app', tab.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('work_app', tab.oid, 'DELETE')
    UNION ALL
    SELECT 'function_owner_is_work_owner', fq FROM funcs WHERE owner <> 'work_owner'
    UNION ALL
    SELECT 'security_definer_exact', fq FROM funcs
     WHERE prosecdef <> (fq IN (SELECT fq FROM definer_allowed))
    UNION ALL
    SELECT 'definer_search_path_pinned', fq FROM funcs
     WHERE prosecdef AND config NOT LIKE '%search_path=pg_catalog, pg_temp%'
    UNION ALL
    SELECT 'definer_execute_exact', r.rolname || ' ' || f.fq FROM funcs f CROSS JOIN roles r
     WHERE f.prosecdef AND r.rolname <> 'work_owner'
       AND pg_catalog.has_function_privilege(r.rolname, f.oid, 'EXECUTE')
       AND NOT EXISTS (SELECT 1 FROM definer_allowed d WHERE d.fq = f.fq AND d.rolname = r.rolname)
    UNION ALL
    SELECT 'definer_execute_exact', 'public ' || fq FROM funcs
     WHERE prosecdef AND pg_catalog.has_function_privilege('public', oid, 'EXECUTE')
    UNION ALL
    SELECT 'definer_execute_present', d.rolname || ' ' || d.fq FROM definer_allowed d
     WHERE NOT EXISTS (
         SELECT 1 FROM funcs f
          WHERE f.fq = d.fq AND f.prosecdef AND pg_catalog.has_function_privilege(d.rolname, f.oid, 'EXECUTE'))
       AND pg_catalog.current_database() = 'work'
    UNION ALL
    SELECT 'scope_exception_exact', tab.fq || ' ' || p.polname FROM tab
      JOIN pg_catalog.pg_policy p ON p.polrelid = tab.oid
     WHERE (COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '') ~* 'outbox_scan|session_user|current_user'
            OR COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '') ~* 'outbox_scan|session_user|current_user')
       AND (tab.fq NOT IN (SELECT fq FROM scope_exception_allowed)
            OR p.polname <> 'ledger_scope'
            OR pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) ~* 'outbox_scan|session_user|current_user'
            OR pg_catalog.pg_get_expr(p.polqual, p.polrelid) !~
               '^\(\([^ ]*ledger_id[^ ]* = ledger\.current_ledger_id\(\)\) OR \(\(CURRENT_USER = ''work_owner''::name\) AND \((pg_catalog\.)?current_setting\(''app\.outbox_scan''::text, true\) = ''on''::text\)\)\)$')
    UNION ALL
    SELECT 'scope_exception_present', fq FROM scope_exception_allowed a
     WHERE pg_catalog.current_database() = 'work'
       AND NOT EXISTS (
           SELECT 1 FROM funcs f
            WHERE f.fq = 'ledger.outbox_ledgers' AND f.prosecdef AND f.config LIKE '%app.outbox_scan=on%')
    UNION ALL
    SELECT 'scope_exception_setter_exact', fq FROM funcs
     WHERE config LIKE '%outbox_scan%' AND fq <> 'ledger.outbox_ledgers'
    UNION ALL
    SELECT 'definer_result_ids_only', fq FROM funcs
     WHERE fq = 'ledger.outbox_ledgers'
       AND pg_catalog.pg_get_function_result(oid) <> 'SETOF ledger.digest32'
    UNION ALL
    SELECT 'role_attributes', rolname FROM pg_catalog.pg_roles
     WHERE rolname LIKE 'work\_%' AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
    UNION ALL
    SELECT 'role_no_membership', r.rolname || ' in ' || g.rolname
      FROM pg_catalog.pg_auth_members m
      JOIN pg_catalog.pg_roles r ON r.oid = m.member
      JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
     WHERE r.rolname LIKE 'work\_%' AND g.rolname LIKE 'work\_%'
)
SELECT check_id, object FROM violations ORDER BY check_id, object;";

async fn violations(c: &mut PgConnection) -> Vec<(String, String)> {
    sqlx::query(CHECKS)
        .fetch_all(c)
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get::<String, _>(0), r.get::<String, _>(1)))
        .collect()
}

// T-36 OP-12 OP-14 T-17 C-8 C-40 P-17 SEC-13
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_36_both_schemas_pass_the_security_checks() {
    let env = Env::start().await;
    for cluster in Cluster::ALL {
        let mut c = env.admin(cluster).await;
        let v = violations(&mut c).await;
        assert!(v.is_empty(), "{cluster:?}: {v:#?}");
    }
}

// T-36 OP-12
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_36_the_security_checks_catch_injected_violations() {
    let env = Env::start().await;
    let mut c = env.admin(Cluster::Canonical).await;
    let mut tx = c.begin().await.unwrap();
    tx.execute(
        "GRANT DELETE ON ledger.log TO work_app;
         GRANT INSERT ON work.record_header TO work_app;
         ALTER TABLE ledger.outbox NO FORCE ROW LEVEL SECURITY;
         REVOKE DELETE ON ledger.outbox FROM work_publisher;
         GRANT UPDATE ON work.body_part TO work_sequencer;
         CREATE TABLE work.stray (id uuid PRIMARY KEY);
         ALTER FUNCTION work.partition_slice(regclass) SECURITY DEFINER;
         GRANT EXECUTE ON FUNCTION work.drop_archived_partition(regclass, ledger.digest32) TO work_app;
         GRANT EXECUTE ON FUNCTION ledger.outbox_ledgers(bigint) TO work_sequencer;
         ALTER POLICY ledger_scope ON ledger.log
             USING (ledger_id = ledger.current_ledger_id()
                    OR (CURRENT_USER = 'work_owner' AND current_setting('app.outbox_scan', true) = 'on'));",
    )
    .await
    .unwrap();
    let found: Vec<String> = violations(&mut tx)
        .await
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    for want in [
        "no_delete_grant",
        "app_role_read_only",
        "rls_enable_force",
        "job_queue_delete_present",
        "no_update_on_append_only",
        "owner_is_work_owner",
        "pk_ledger_prefix",
        "component_label",
        "rls_ledger_scope_policy",
        "security_definer_exact",
        "definer_search_path_pinned",
        "definer_execute_exact",
        "scope_exception_exact",
    ] {
        assert!(
            found.iter().any(|f| f == want),
            "{want} not reported: {found:?}"
        );
    }
    tx.rollback().await.unwrap();
}

// OP-13 OP-15 T-36
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_14_every_table_with_personal_fields_is_in_the_erasure_scope_list() {
    let env = Env::start().await;
    for cluster in Cluster::ALL {
        let mut c = env.admin(cluster).await;
        let tagged: Vec<(String, String)> = sqlx::query_as(
            "SELECT n.nspname || '.' || c.relname, \
                    substring(pg_catalog.obj_description(c.oid, 'pg_class') FROM 'erasure=([a-z_:]+)$') \
               FROM pg_catalog.pg_class c \
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname IN ('ledger', 'work', 'derived', 'projection') \
                AND c.relkind IN ('r', 'p') AND NOT c.relispartition \
                AND pg_catalog.obj_description(c.oid, 'pg_class') !~ 'erasure=none$' \
              ORDER BY 1",
        )
        .fetch_all(&mut c)
        .await
        .unwrap();
        let mut listed: Vec<(String, String)> = match cluster {
            Cluster::Canonical => work_store::ERASURE_SCOPE
                .iter()
                .map(|s| (s.table.to_owned(), s.erasure.to_owned()))
                .collect(),
            Cluster::Derived => Vec::new(),
        };
        listed.sort();
        assert_eq!(tagged, listed, "{cluster:?}");
    }
    let mut c = env.admin(Cluster::Canonical).await;
    for scope in work_store::ERASURE_SCOPE {
        for column in scope.columns {
            let found: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute \
                  WHERE attrelid = pg_catalog.to_regclass($1) AND attname = $2 \
                    AND attnum > 0 AND NOT attisdropped)",
            )
            .bind(scope.table)
            .bind(column)
            .fetch_one(&mut c)
            .await
            .unwrap();
            assert!(found, "{}.{column}", scope.table);
        }
    }
}
