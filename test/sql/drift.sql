-- drift detection & reconcile (source = regression db, target = second db
-- in the same cluster, reached over the unix socket)
\set VERBOSITY terse
SET client_min_messages = warning;

CREATE ROLE regress_drift_app NOLOGIN;
CREATE ROLE regress_drift_ro  NOLOGIN;
CREATE DATABASE pgsync_drift_tgt;
CREATE EXTENSION pgx_permission_sync CASCADE;
SELECT dba_pgx_permission_sync.disable_sync();

SELECT split_part(setting, ',', 1) AS sockdir
FROM pg_settings WHERE name = 'unix_socket_directories' \gset
SELECT current_setting('port') AS port \gset
SELECT format('host=%s port=%s dbname=pgsync_drift_tgt user=%s', trim(:'sockdir'), :'port', current_user) AS tgtconn \gset

-- source
CREATE SCHEMA s1;
CREATE TABLE s1.t (a int, b int);
CREATE TABLE s1.only_src (a int);
CREATE SEQUENCE s1.sq;
CREATE FUNCTION s1.f(int) RETURNS int LANGUAGE sql AS 'SELECT $1';
GRANT USAGE ON SCHEMA s1 TO regress_drift_ro;
GRANT SELECT ON s1.t TO regress_drift_ro;
GRANT INSERT ON s1.t TO regress_drift_app WITH GRANT OPTION;
GRANT SELECT (a) ON s1.t TO regress_drift_ro;
GRANT USAGE ON SEQUENCE s1.sq TO regress_drift_app;
GRANT SELECT ON s1.only_src TO regress_drift_ro;
REVOKE EXECUTE ON FUNCTION s1.f(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s1.f(int) TO regress_drift_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA s1 GRANT SELECT ON TABLES TO regress_drift_ro;

-- target: same objects, different privileges
SELECT dblink_exec(:'tgtconn', $t$
  CREATE SCHEMA s1;
  CREATE TABLE s1.t (a int, b int);
  CREATE SEQUENCE s1.sq;
  CREATE FUNCTION s1.f(int) RETURNS int LANGUAGE sql AS 'SELECT $1';
  GRANT SELECT ON s1.t TO regress_drift_ro;
  GRANT DELETE ON s1.t TO regress_drift_app;
  GRANT INSERT ON s1.t TO regress_drift_app
$t$);

SELECT dba_pgx_permission_sync.add_environment(
    'drift_tgt', trim(:'sockdir'), 'pgsync_drift_tgt', current_user, NULL, :'port'::int, 'disable');

-- 1. detect
SELECT dba_pgx_permission_sync.detect_drift('drift_tgt') > 0 AS ran;
SELECT run_type, status, missing_count, extra_count, different_count, blocked_count
FROM dba_pgx_permission_sync.v_drift_latest;
SELECT kind, objtype, objname, subname, grantee, priv, drift_type, fix_action, fix_sql
FROM dba_pgx_permission_sync.v_drift_open_items
ORDER BY kind COLLATE "C", objtype COLLATE "C", objname COLLATE "C", subname COLLATE "C",
         grantee COLLATE "C", priv COLLATE "C";

-- 2. dry run changes nothing
SELECT kind, drift_type, action, status, fix_sql
FROM dba_pgx_permission_sync.reconcile('drift_tgt') ORDER BY kind COLLATE "C", fix_sql COLLATE "C";
SELECT * FROM dblink(:'tgtconn',
    $t$SELECT has_schema_privilege('regress_drift_ro','s1','USAGE')::text$t$) AS t(usage_after_dry_run text);

-- 3. apply, revokes not allowed
SELECT kind, drift_type, action, status, error_message
FROM dba_pgx_permission_sync.reconcile('drift_tgt', p_dry_run => false) ORDER BY kind COLLATE "C", fix_sql COLLATE "C";
SELECT run_type, dry_run, status, missing_count, extra_count, different_count,
       blocked_count, applied_count, failed_count
FROM dba_pgx_permission_sync.drift_runs ORDER BY run_id;

-- 4. apply revokes too
SELECT kind, action, status FROM dba_pgx_permission_sync.reconcile('drift_tgt', false, true)
WHERE action = 'revoke' ORDER BY fix_sql COLLATE "C";
SELECT run_type, status, missing_count, extra_count, different_count, blocked_count
FROM dba_pgx_permission_sync.v_drift_latest;

-- 5. reconcile is recorded in the audit trail
SELECT b.source_command, b.batch_status, b.success_count, b.failure_count
FROM dba_pgx_permission_sync.sync_batches b WHERE b.source_command = 'RECONCILE' ORDER BY b.batch_id;

-- 6. global dry_run setting forces dry run
SELECT dba_pgx_permission_sync.enable_dry_run();
SELECT count(*) AS applied_in_forced_dry_run
FROM dba_pgx_permission_sync.reconcile('drift_tgt', p_dry_run => false) WHERE status = 'applied';
SELECT dba_pgx_permission_sync.disable_dry_run();

-- 7. unreachable target is recorded, not raised
SELECT dba_pgx_permission_sync.add_environment('drift_dead', '127.0.0.1', 'x', 'u', NULL, 1);
SELECT env_name, status FROM dba_pgx_permission_sync.detect_drift_all() ORDER BY env_name COLLATE "C";

-- 8. SQL generation for role-level drift
SELECT d, fix, action FROM (
  SELECT d, k, o,
         dba_pgx_permission_sync.drift_fix_sql(k,'ROLE',o,'',g,'',d,s,t) AS fix,
         dba_pgx_permission_sync.drift_fix_action(k,d,s,
             dba_pgx_permission_sync.drift_fix_sql(k,'ROLE',o,'',g,'',d,s,t), false) AS action
  FROM (VALUES
   ('role','app_user','','missing_on_target','NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5',NULL),
   ('role','Weird"Name','','different','NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1','x'),
   ('role','evil','','missing_on_target','SUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1',NULL),
   ('role','gone','','extra_on_target',NULL,'LOGIN'),
   ('member','dev_grp','alice','missing_on_target','ADMIN true',NULL),
   ('member','dev_grp','bob','extra_on_target',NULL,'ADMIN false'),
   ('member','dev_grp','carol','different','ADMIN false','ADMIN true')
  ) v(k,o,g,d,s,t)) z ORDER BY o COLLATE "C", d COLLATE "C";

-- 9. privilege names are allow-listed before being pasted into SQL
SELECT dba_pgx_permission_sync.drift_fix_sql('acl','TABLE','s1.t','','r',
       'SELECT; DROP TABLE x','extra_on_target',NULL,NULL) IS NULL AS rejected;

-- 10. only admin may reconcile
CREATE ROLE regress_drift_operator LOGIN;
GRANT pgsync_operator TO regress_drift_operator;
SET ROLE regress_drift_operator;
SELECT dba_pgx_permission_sync.detect_drift('drift_tgt') > 0 AS operator_can_detect;
SELECT * FROM dba_pgx_permission_sync.reconcile('drift_tgt', false, true);
RESET ROLE;

-- cleanup
DROP EXTENSION pgx_permission_sync CASCADE;
DROP OWNED BY regress_drift_app, regress_drift_ro, regress_drift_operator;
DROP DATABASE pgsync_drift_tgt;
DROP SCHEMA IF EXISTS s1 CASCADE;
DROP ROLE regress_drift_app, regress_drift_ro, regress_drift_operator;
