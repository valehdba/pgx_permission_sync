-- pgx_permission_sync regression test (no remote target required)
\set VERBOSITY terse
SET client_min_messages = warning;
CREATE EXTENSION pgx_permission_sync CASCADE;
SELECT value FROM dba_pgx_permission_sync.extension_metadata WHERE key = 'version';

-- 1. password masking
SELECT dba_pgx_permission_sync.mask_secrets(
  $$CREATE ROLE a PASSWORD 'p''w d' LOGIN; ALTER ROLE b ENCRYPTED password E'x\'y'$$);
SELECT dba_pgx_permission_sync.mask_secrets('GRANT SELECT ON t TO r');

-- 2. role exclusion: regex metacharacters are literal, * is a wildcard
SELECT dba_pgx_permission_sync.is_role_excluded(r) AS excluded, r
FROM unnest(ARRAY['postgres','postgres_x','pg_monitor','pgxadmin']) AS r;
SELECT dba_pgx_permission_sync.set_config_param('excluded_roles', 'svc.acct');
SELECT dba_pgx_permission_sync.is_role_excluded('svc.acct') AS dot_literal,
       dba_pgx_permission_sync.is_role_excluded('svcXacct') AS dot_not_wildcard;

-- 3. conninfo quoting
SELECT dba_pgx_permission_sync.conninfo_quote($$a b'c\d$$);

-- 4. key handling: short key rejected, rotation re-encrypts, config no longer holds the key
SELECT count(*) AS key_in_config FROM dba_pgx_permission_sync.config WHERE param_name = 'encryption_key_ref';
SELECT dba_pgx_permission_sync.set_encryption_key('short');
SELECT dba_pgx_permission_sync.set_encryption_key('first-key-0123456789');
SELECT dba_pgx_permission_sync.add_environment('t1','127.0.0.1','db','u',$$pa ss'w\ord$$,1,'prefer');
SELECT dba_pgx_permission_sync.set_encryption_key('second-key-0123456789') AS reencrypted;
SELECT dba_pgx_permission_sync.build_connstr(1);

-- 5. privileges: reader/operator cannot read secrets, passwords or raw retry SQL
CREATE ROLE regress_reader LOGIN;
CREATE ROLE regress_operator LOGIN;
GRANT pgsync_reader TO regress_reader;
GRANT pgsync_operator TO regress_operator;
SET ROLE regress_reader;
SELECT count(*) FROM dba_pgx_permission_sync.secrets;
SELECT password_enc FROM dba_pgx_permission_sync.environments;
SELECT count(*) FROM dba_pgx_permission_sync.retry_queue;
SELECT env_name FROM dba_pgx_permission_sync.environments;
SELECT dba_pgx_permission_sync.build_connstr(1);
RESET ROLE;
SET ROLE regress_operator;
SELECT dba_pgx_permission_sync.set_encryption_key('operator-key-0123456789');
SELECT dba_pgx_permission_sync.execute_on_environment(1, 'SELECT 1', 1);
SELECT processed FROM dba_pgx_permission_sync.process_retry_queue();
RESET ROLE;

-- 6. GRANT is audited, SQL is masked; object name pg_* is not mistaken for a role
SELECT dba_pgx_permission_sync.disable_sync();
SELECT dba_pgx_permission_sync.enable_sync();
SELECT dba_pgx_permission_sync.set_config_param('max_retries', '0');
SELECT dba_pgx_permission_sync.set_config_param('excluded_roles', 'postgres,replication,pg_*');
CREATE TABLE pg_regress_obj (i int);
GRANT SELECT ON pg_regress_obj TO regress_reader;
SELECT command_tag, sync_enabled, batch_id IS NOT NULL AS linked
FROM dba_pgx_permission_sync.permission_audit_log ORDER BY audit_id DESC LIMIT 1;

-- 7. retention: audit rows outlive their batches (FK must not block cleanup)
UPDATE dba_pgx_permission_sync.sync_batches
SET completed_at = now() - interval '200 days';
SELECT sync_logs_deleted > 0 AS batches_deleted, audit_logs_deleted
FROM dba_pgx_permission_sync.cleanup_old_logs();
SELECT count(*) > 0 AS audit_kept,
       count(batch_id) AS still_linked
FROM dba_pgx_permission_sync.permission_audit_log;

-- cleanup
DROP TABLE pg_regress_obj;
DROP EXTENSION pgx_permission_sync CASCADE;
DROP ROLE regress_reader, regress_operator;
