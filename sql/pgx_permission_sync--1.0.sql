-- ============================================================================
-- pgx_permission_sync  --  version 1.0
--
-- Installed via:  CREATE EXTENSION pgx_permission_sync;
--
-- Synchronizes ROLE / GRANT / REVOKE operations across configured
-- PostgreSQL environments and keeps a full audit trail.
--
-- Requires: dblink, pgcrypto  (declared in .control → auto-installed)
-- ============================================================================

-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
-- SECTION 1 — TABLES
-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

-- 1.1  Extension metadata
CREATE TABLE @extschema@.extension_metadata (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO @extschema@.extension_metadata (key, value)
VALUES ('version','1.0'), ('installed_at', now()::text), ('author','DBA Team');

-- 1.2  Environment registry
CREATE TABLE @extschema@.environments (
    environment_id   SERIAL       PRIMARY KEY,
    env_name         TEXT         NOT NULL UNIQUE,
    env_label        TEXT,
    host             TEXT         NOT NULL,
    port             INTEGER      NOT NULL DEFAULT 5432,
    dbname           TEXT         NOT NULL,
    username         TEXT         NOT NULL,
    password_enc     TEXT,
    sslmode          TEXT         NOT NULL DEFAULT 'prefer',
    connection_opts  JSONB        DEFAULT '{}',
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    priority         INTEGER      NOT NULL DEFAULT 100,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_by       TEXT         NOT NULL DEFAULT current_user,
    notes            TEXT
);

COMMENT ON TABLE @extschema@.environments IS
    'Registry of target PostgreSQL environments to which permission changes are replicated.';

-- 1.3  Sync rules / filters
CREATE TABLE @extschema@.sync_rules (
    rule_id         SERIAL       PRIMARY KEY,
    environment_id  INTEGER      REFERENCES @extschema@.environments(environment_id) ON DELETE CASCADE,
    rule_type       TEXT         NOT NULL CHECK (rule_type IN ('include','exclude')),
    command_tag     TEXT,
    role_pattern    TEXT,
    object_pattern  TEXT,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_by      TEXT         NOT NULL DEFAULT current_user,
    notes           TEXT
);

COMMENT ON TABLE @extschema@.sync_rules IS
    'Include / exclude rules controlling which commands replicate to each environment.';

-- 1.4  Sync batches
CREATE TABLE @extschema@.sync_batches (
    batch_id          BIGSERIAL    PRIMARY KEY,
    source_command    TEXT         NOT NULL,
    source_sql        TEXT         NOT NULL,
    source_user       TEXT         NOT NULL DEFAULT current_user,
    source_ip         INET,
    source_app        TEXT,
    source_pid        INTEGER,
    source_txid       BIGINT,
    captured_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    object_type       TEXT,
    object_identity   TEXT,
    batch_status      TEXT         NOT NULL DEFAULT 'pending'
                                   CHECK (batch_status IN ('pending','in_progress','completed','partial','failed','skipped')),
    completed_at      TIMESTAMPTZ,
    total_targets     INTEGER      NOT NULL DEFAULT 0,
    success_count     INTEGER      NOT NULL DEFAULT 0,
    failure_count     INTEGER      NOT NULL DEFAULT 0,
    skip_count        INTEGER      NOT NULL DEFAULT 0,
    execution_time_ms BIGINT,
    notes             TEXT
);

CREATE INDEX idx_sync_batches_status   ON @extschema@.sync_batches (batch_status);
CREATE INDEX idx_sync_batches_captured ON @extschema@.sync_batches (captured_at DESC);
CREATE INDEX idx_sync_batches_command  ON @extschema@.sync_batches (source_command);

COMMENT ON TABLE @extschema@.sync_batches IS
    'One row per intercepted permission DDL event. Groups per-environment results.';

-- 1.5  Execution log (per-environment)
CREATE TABLE @extschema@.sync_execution_log (
    execution_id       BIGSERIAL    PRIMARY KEY,
    batch_id           BIGINT       NOT NULL REFERENCES @extschema@.sync_batches(batch_id) ON DELETE CASCADE,
    environment_id     INTEGER      NOT NULL REFERENCES @extschema@.environments(environment_id) ON DELETE CASCADE,
    env_name           TEXT         NOT NULL,
    applied_sql        TEXT         NOT NULL,
    execution_status   TEXT         NOT NULL DEFAULT 'pending'
                                    CHECK (execution_status IN ('pending','running','success','failed','skipped','rollback')),
    started_at         TIMESTAMPTZ,
    finished_at        TIMESTAMPTZ,
    duration_ms        BIGINT,
    result_message     TEXT,
    error_code         TEXT,
    error_detail       TEXT,
    error_hint         TEXT,
    retry_count        INTEGER      NOT NULL DEFAULT 0,
    last_retry_at      TIMESTAMPTZ,
    executed_by        TEXT         NOT NULL DEFAULT current_user,
    server_version     TEXT,
    connection_time_ms BIGINT
);

CREATE INDEX idx_exec_log_batch    ON @extschema@.sync_execution_log (batch_id);
CREATE INDEX idx_exec_log_env      ON @extschema@.sync_execution_log (environment_id);
CREATE INDEX idx_exec_log_status   ON @extschema@.sync_execution_log (execution_status);
CREATE INDEX idx_exec_log_finished ON @extschema@.sync_execution_log (finished_at DESC);

COMMENT ON TABLE @extschema@.sync_execution_log IS
    'Per-environment execution result for every sync batch.';

-- 1.6  Audit trail (immutable)
CREATE TABLE @extschema@.permission_audit_log (
    audit_id          BIGSERIAL    PRIMARY KEY,
    event_time        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    command_tag       TEXT         NOT NULL,
    full_sql          TEXT         NOT NULL,
    object_type       TEXT,
    object_identity   TEXT,
    schema_name       TEXT,
    executed_by       TEXT         NOT NULL DEFAULT current_user,
    client_addr       INET,
    application_name  TEXT,
    backend_pid       INTEGER,
    transaction_id    BIGINT,
    session_id        TEXT,
    sync_enabled      BOOLEAN      NOT NULL DEFAULT TRUE,
    batch_id          BIGINT       REFERENCES @extschema@.sync_batches(batch_id)
);

CREATE INDEX idx_audit_time    ON @extschema@.permission_audit_log (event_time DESC);
CREATE INDEX idx_audit_command ON @extschema@.permission_audit_log (command_tag);
CREATE INDEX idx_audit_user    ON @extschema@.permission_audit_log (executed_by);

COMMENT ON TABLE @extschema@.permission_audit_log IS
    'Immutable audit log of every permission DDL on the source database.';

-- 1.7  Configuration
CREATE TABLE @extschema@.config (
    param_name   TEXT PRIMARY KEY,
    param_value  TEXT NOT NULL,
    description  TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by   TEXT NOT NULL DEFAULT current_user
);

INSERT INTO @extschema@.config (param_name, param_value, description) VALUES
    ('sync_enabled',          'true',  'Master switch for all synchronization'),
    ('sync_mode',             'async', 'sync or async execution mode'),
    ('max_retries',           '3',     'Max retry attempts per environment on failure'),
    ('retry_delay_seconds',   '5',     'Seconds between retries'),
    ('connection_timeout_ms', '5000',  'Connection timeout for remote environments (ms)'),
    ('statement_timeout_ms',  '30000', 'Statement timeout for remote execution (ms)'),
    ('log_retention_days',    '90',    'Days to keep sync logs'),
    ('audit_retention_days',  '365',   'Days to keep audit logs'),
    ('encrypt_passwords',     'true',  'Store environment passwords encrypted'),
    ('encryption_key_ref',    '',      'Reference to encryption key (env var name or value)'),
    ('notify_on_failure',     'true',  'pg_notify on sync failure'),
    ('notify_channel',        'dba_pgx_permission_sync_alerts', 'Notification channel'),
    ('dry_run',               'false', 'Log SQL but do not execute on targets'),
    ('exclude_superusers',    'true',  'Skip superuser attribute changes'),
    ('excluded_roles',        'postgres,replication,pg_*', 'Role patterns to never sync');

COMMENT ON TABLE @extschema@.config IS
    'Key-value runtime configuration for the permission sync extension.';

-- 1.8  Retry queue
CREATE TABLE @extschema@.retry_queue (
    queue_id        BIGSERIAL    PRIMARY KEY,
    execution_id    BIGINT       NOT NULL REFERENCES @extschema@.sync_execution_log(execution_id),
    batch_id        BIGINT       NOT NULL,
    environment_id  INTEGER      NOT NULL,
    applied_sql     TEXT         NOT NULL,
    retry_number    INTEGER      NOT NULL DEFAULT 1,
    scheduled_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    status          TEXT         NOT NULL DEFAULT 'queued'
                                 CHECK (status IN ('queued','processing','completed','abandoned')),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_retry_queue_status ON @extschema@.retry_queue (status) WHERE status = 'queued';

COMMENT ON TABLE @extschema@.retry_queue IS
    'Failed executions scheduled for automatic or manual retry.';


-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
-- SECTION 2 — CORE UTILITY FUNCTIONS
-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

-- 2.1  get_config
CREATE OR REPLACE FUNCTION @extschema@.get_config(
    p_param_name TEXT,
    p_default    TEXT DEFAULT NULL
) RETURNS TEXT LANGUAGE plpgsql STABLE AS $$
DECLARE v_value TEXT;
BEGIN
    SELECT param_value INTO v_value
    FROM @extschema@.config WHERE param_name = p_param_name;
    RETURN COALESCE(v_value, p_default);
END;
$$;

-- 2.2  set_config_param
CREATE OR REPLACE FUNCTION @extschema@.set_config_param(
    p_param_name  TEXT,
    p_param_value TEXT
) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO @extschema@.config (param_name, param_value, updated_at, updated_by)
    VALUES (p_param_name, p_param_value, now(), current_user)
    ON CONFLICT (param_name)
    DO UPDATE SET param_value = EXCLUDED.param_value,
                  updated_at  = now(),
                  updated_by  = current_user;
END;
$$;

-- 2.3  is_sync_enabled
CREATE OR REPLACE FUNCTION @extschema@.is_sync_enabled()
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT COALESCE(
        (SELECT param_value::boolean FROM @extschema@.config
         WHERE param_name = 'sync_enabled'), FALSE);
$$;

-- 2.4  encrypt_password
CREATE OR REPLACE FUNCTION @extschema@.encrypt_password(p_plain TEXT)
RETURNS TEXT LANGUAGE plpgsql AS $$
DECLARE v_key TEXT;
BEGIN
    v_key := @extschema@.get_config('encryption_key_ref',
                                     'DEFAULT_CHANGE_ME_KEY_32CHR!!!');
    RETURN encode(pgp_sym_encrypt(p_plain, v_key), 'base64');
END;
$$;

-- 2.5  decrypt_password  (SECURITY DEFINER — access restricted)
CREATE OR REPLACE FUNCTION @extschema@.decrypt_password(p_enc TEXT)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_key TEXT;
BEGIN
    v_key := @extschema@.get_config('encryption_key_ref',
                                     'DEFAULT_CHANGE_ME_KEY_32CHR!!!');
    RETURN pgp_sym_decrypt(decode(p_enc, 'base64'), v_key);
END;
$$;
REVOKE ALL ON FUNCTION @extschema@.decrypt_password(TEXT) FROM PUBLIC;

-- 2.6  build_connstr  (SECURITY DEFINER)
CREATE OR REPLACE FUNCTION @extschema@.build_connstr(p_environment_id INTEGER)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_env   RECORD;
    v_pass  TEXT;
    v_timeout TEXT;
BEGIN
    SELECT * INTO v_env FROM @extschema@.environments
    WHERE environment_id = p_environment_id AND is_active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Environment ID % not found or inactive', p_environment_id;
    END IF;

    IF @extschema@.get_config('encrypt_passwords','true')::boolean
       AND v_env.password_enc IS NOT NULL THEN
        v_pass := @extschema@.decrypt_password(v_env.password_enc);
    ELSE
        v_pass := v_env.password_enc;
    END IF;

    v_timeout := @extschema@.get_config('connection_timeout_ms','5000');

    RETURN format('host=%s port=%s dbname=%s user=%s sslmode=%s connect_timeout=%s',
        v_env.host, v_env.port, v_env.dbname, v_env.username,
        v_env.sslmode, (v_timeout::int / 1000)::text)
        || CASE WHEN v_pass IS NOT NULL AND v_pass <> ''
                THEN format(' password=%s', v_pass) ELSE '' END;
END;
$$;
REVOKE ALL ON FUNCTION @extschema@.build_connstr(INTEGER) FROM PUBLIC;

-- 2.7  is_role_excluded
CREATE OR REPLACE FUNCTION @extschema@.is_role_excluded(p_role_name TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_excluded TEXT;
    v_pattern  TEXT;
BEGIN
    v_excluded := @extschema@.get_config('excluded_roles',
                                          'postgres,replication,pg_*');
    FOREACH v_pattern IN ARRAY string_to_array(v_excluded, ',')
    LOOP
        v_pattern := trim(v_pattern);
        v_pattern := '^' || replace(v_pattern, '*', '.*') || '$';
        IF p_role_name ~ v_pattern THEN RETURN TRUE; END IF;
    END LOOP;
    RETURN FALSE;
END;
$$;

-- 2.8  check_sync_rules
CREATE OR REPLACE FUNCTION @extschema@.check_sync_rules(
    p_environment_id INTEGER,
    p_command_tag    TEXT,
    p_role_name      TEXT DEFAULT NULL,
    p_object_name    TEXT DEFAULT NULL
) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_rule       RECORD;
    v_matched    BOOLEAN := FALSE;
    v_has_include BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM @extschema@.sync_rules
        WHERE environment_id = p_environment_id
          AND rule_type = 'include' AND is_active
    ) INTO v_has_include;

    FOR v_rule IN
        SELECT * FROM @extschema@.sync_rules
        WHERE environment_id = p_environment_id AND is_active
        ORDER BY rule_type DESC
    LOOP
        IF v_rule.command_tag IS NOT NULL AND v_rule.command_tag <> p_command_tag THEN CONTINUE; END IF;
        IF v_rule.role_pattern IS NOT NULL AND p_role_name IS NOT NULL
           AND p_role_name !~ v_rule.role_pattern THEN CONTINUE; END IF;
        IF v_rule.object_pattern IS NOT NULL AND p_object_name IS NOT NULL
           AND p_object_name !~ v_rule.object_pattern THEN CONTINUE; END IF;

        IF v_rule.rule_type = 'exclude' THEN RETURN FALSE;
        ELSIF v_rule.rule_type = 'include' THEN v_matched := TRUE;
        END IF;
    END LOOP;

    IF v_has_include AND NOT v_matched THEN RETURN FALSE; END IF;
    RETURN TRUE;
END;
$$;

-- 2.9  test_environment_connection
CREATE OR REPLACE FUNCTION @extschema@.test_environment_connection(
    p_environment_id INTEGER
) RETURNS TABLE(connected BOOLEAN, server_version TEXT, message TEXT)
LANGUAGE plpgsql AS $$
DECLARE
    v_connstr   TEXT;
    v_conn_name TEXT;
    v_version   TEXT;
BEGIN
    v_connstr   := @extschema@.build_connstr(p_environment_id);
    v_conn_name := 'pgsync_test_' || p_environment_id;
    BEGIN
        PERFORM dblink_connect(v_conn_name, v_connstr);
        SELECT val INTO v_version
        FROM dblink(v_conn_name, 'SELECT version()') AS t(val TEXT);
        PERFORM dblink_disconnect(v_conn_name);
        RETURN QUERY SELECT TRUE, v_version, 'Connection successful'::TEXT;
    EXCEPTION WHEN OTHERS THEN
        BEGIN PERFORM dblink_disconnect(v_conn_name); EXCEPTION WHEN OTHERS THEN NULL; END;
        RETURN QUERY SELECT FALSE, NULL::TEXT, SQLERRM::TEXT;
    END;
END;
$$;


-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
-- SECTION 3 — SYNC ENGINE
-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

-- 3.1  execute_on_environment
CREATE OR REPLACE FUNCTION @extschema@.execute_on_environment(
    p_environment_id INTEGER,
    p_sql            TEXT,
    p_batch_id       BIGINT
) RETURNS TABLE(
    exec_status    TEXT,
    exec_message   TEXT,
    exec_errcode   TEXT,
    exec_detail    TEXT,
    exec_hint      TEXT,
    exec_duration  BIGINT,
    exec_conn_time BIGINT,
    server_ver     TEXT
) LANGUAGE plpgsql AS $$
DECLARE
    v_connstr    TEXT;
    v_conn_name  TEXT;
    v_start      TIMESTAMPTZ;
    v_conn_start TIMESTAMPTZ;
    v_conn_end   TIMESTAMPTZ;
    v_version    TEXT;
    v_stmt_timeout TEXT;
    v_dry_run    BOOLEAN;
BEGIN
    v_dry_run      := @extschema@.get_config('dry_run','false')::boolean;
    v_stmt_timeout := @extschema@.get_config('statement_timeout_ms','30000');
    v_connstr      := @extschema@.build_connstr(p_environment_id);
    v_conn_name    := format('pgsync_%s_%s', p_batch_id, p_environment_id);

    v_conn_start := clock_timestamp();
    BEGIN
        PERFORM dblink_connect(v_conn_name, v_connstr);
    EXCEPTION WHEN OTHERS THEN
        RETURN QUERY SELECT 'failed'::TEXT,
            ('Connection failed: ' || SQLERRM)::TEXT,
            SQLSTATE::TEXT, NULL::TEXT, NULL::TEXT,
            NULL::BIGINT, NULL::BIGINT, NULL::TEXT;
        RETURN;
    END;
    v_conn_end := clock_timestamp();

    BEGIN
        SELECT val INTO v_version
        FROM dblink(v_conn_name, 'SELECT version()') AS t(val TEXT);
    EXCEPTION WHEN OTHERS THEN v_version := 'unknown';
    END;

    BEGIN
        PERFORM dblink_exec(v_conn_name,
            format('SET statement_timeout = %s', quote_literal(v_stmt_timeout)));
    EXCEPTION WHEN OTHERS THEN NULL;
    END;

    IF v_dry_run THEN
        PERFORM dblink_disconnect(v_conn_name);
        RETURN QUERY SELECT 'skipped'::TEXT,
            'Dry run — SQL not executed'::TEXT,
            NULL::TEXT, NULL::TEXT, NULL::TEXT, 0::BIGINT,
            (EXTRACT(EPOCH FROM (v_conn_end - v_conn_start))*1000)::BIGINT,
            v_version;
        RETURN;
    END IF;

    v_start := clock_timestamp();
    BEGIN
        PERFORM dblink_exec(v_conn_name, p_sql);
        PERFORM dblink_disconnect(v_conn_name);
        RETURN QUERY SELECT 'success'::TEXT,
            'Executed successfully'::TEXT,
            NULL::TEXT, NULL::TEXT, NULL::TEXT,
            (EXTRACT(EPOCH FROM (clock_timestamp()-v_start))*1000)::BIGINT,
            (EXTRACT(EPOCH FROM (v_conn_end-v_conn_start))*1000)::BIGINT,
            v_version;
    EXCEPTION WHEN OTHERS THEN
        BEGIN PERFORM dblink_disconnect(v_conn_name); EXCEPTION WHEN OTHERS THEN NULL; END;
        RETURN QUERY SELECT 'failed'::TEXT, SQLERRM::TEXT, SQLSTATE::TEXT,
            NULL::TEXT, NULL::TEXT,
            (EXTRACT(EPOCH FROM (clock_timestamp()-v_start))*1000)::BIGINT,
            (EXTRACT(EPOCH FROM (v_conn_end-v_conn_start))*1000)::BIGINT,
            v_version;
    END;
END;
$$;

-- 3.2  sync_to_all_environments  (core dispatcher)
CREATE OR REPLACE FUNCTION @extschema@.sync_to_all_environments(
    p_command_tag     TEXT,
    p_sql             TEXT,
    p_object_type     TEXT DEFAULT NULL,
    p_object_identity TEXT DEFAULT NULL,
    p_role_name       TEXT DEFAULT NULL
) RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE
    v_batch_id       BIGINT;
    v_env            RECORD;
    v_result         RECORD;
    v_exec_id        BIGINT;
    v_total          INTEGER := 0;
    v_success        INTEGER := 0;
    v_fail           INTEGER := 0;
    v_skip           INTEGER := 0;
    v_batch_start    TIMESTAMPTZ;
    v_max_retries    INTEGER;
    v_retry_delay    INTEGER;
    v_notify_fail    BOOLEAN;
    v_notify_channel TEXT;
BEGIN
    v_batch_start    := clock_timestamp();
    v_max_retries    := @extschema@.get_config('max_retries','3')::int;
    v_retry_delay    := @extschema@.get_config('retry_delay_seconds','5')::int;
    v_notify_fail    := @extschema@.get_config('notify_on_failure','true')::boolean;
    v_notify_channel := @extschema@.get_config('notify_channel',
                                                'dba_pgx_permission_sync_alerts');

    INSERT INTO @extschema@.sync_batches (
        source_command, source_sql, source_user, source_ip,
        source_app, source_pid, source_txid,
        object_type, object_identity, batch_status
    ) VALUES (
        p_command_tag, p_sql, current_user, inet_client_addr(),
        current_setting('application_name',true), pg_backend_pid(), txid_current(),
        p_object_type, p_object_identity, 'in_progress'
    ) RETURNING batch_id INTO v_batch_id;

    FOR v_env IN
        SELECT * FROM @extschema@.environments
        WHERE is_active ORDER BY priority, environment_id
    LOOP
        v_total := v_total + 1;

        IF NOT @extschema@.check_sync_rules(
            v_env.environment_id, p_command_tag, p_role_name, p_object_identity
        ) THEN
            INSERT INTO @extschema@.sync_execution_log (
                batch_id, environment_id, env_name, applied_sql,
                execution_status, started_at, finished_at, result_message
            ) VALUES (
                v_batch_id, v_env.environment_id, v_env.env_name, p_sql,
                'skipped', now(), now(), 'Filtered by sync rules'
            );
            v_skip := v_skip + 1;
            CONTINUE;
        END IF;

        SELECT * INTO v_result
        FROM @extschema@.execute_on_environment(
            v_env.environment_id, p_sql, v_batch_id);

        INSERT INTO @extschema@.sync_execution_log (
            batch_id, environment_id, env_name, applied_sql,
            execution_status, started_at, finished_at, duration_ms,
            result_message, error_code, error_detail, error_hint,
            server_version, connection_time_ms
        ) VALUES (
            v_batch_id, v_env.environment_id, v_env.env_name, p_sql,
            v_result.exec_status, now(), now(), v_result.exec_duration,
            v_result.exec_message, v_result.exec_errcode, v_result.exec_detail,
            v_result.exec_hint, v_result.server_ver, v_result.exec_conn_time
        ) RETURNING execution_id INTO v_exec_id;

        IF v_result.exec_status = 'success' THEN
            v_success := v_success + 1;
        ELSIF v_result.exec_status = 'skipped' THEN
            v_skip := v_skip + 1;
        ELSE
            v_fail := v_fail + 1;
            IF v_max_retries > 0 THEN
                INSERT INTO @extschema@.retry_queue (
                    execution_id, batch_id, environment_id, applied_sql,
                    retry_number, scheduled_at
                ) VALUES (
                    v_exec_id, v_batch_id, v_env.environment_id, p_sql,
                    1, now() + (v_retry_delay || ' seconds')::interval);
            END IF;
            IF v_notify_fail THEN
                PERFORM pg_notify(v_notify_channel, json_build_object(
                    'event','sync_failure', 'batch_id',v_batch_id,
                    'environment',v_env.env_name, 'command',p_command_tag,
                    'error',v_result.exec_message,
                    'sql',left(p_sql,500))::text);
            END IF;
        END IF;
    END LOOP;

    UPDATE @extschema@.sync_batches SET
        total_targets   = v_total,
        success_count   = v_success,
        failure_count   = v_fail,
        skip_count      = v_skip,
        completed_at    = now(),
        execution_time_ms = (EXTRACT(EPOCH FROM (clock_timestamp()-v_batch_start))*1000)::bigint,
        batch_status    = CASE
            WHEN v_fail=0 AND v_total>0 THEN 'completed'
            WHEN v_fail>0 AND v_success>0 THEN 'partial'
            WHEN v_fail>0 AND v_success=0 THEN 'failed'
            WHEN v_total=0 THEN 'skipped' ELSE 'completed' END
    WHERE batch_id = v_batch_id;

    RETURN v_batch_id;
END;
$$;

-- 3.3  process_retry_queue
CREATE OR REPLACE FUNCTION @extschema@.process_retry_queue()
RETURNS TABLE(processed INTEGER, succeeded INTEGER, abandoned INTEGER)
LANGUAGE plpgsql AS $$
DECLARE
    v_item       RECORD;
    v_result     RECORD;
    v_max_retries INTEGER;
    v_retry_delay INTEGER;
    v_processed  INTEGER := 0;
    v_succeeded  INTEGER := 0;
    v_abandoned  INTEGER := 0;
BEGIN
    v_max_retries := @extschema@.get_config('max_retries','3')::int;
    v_retry_delay := @extschema@.get_config('retry_delay_seconds','5')::int;

    FOR v_item IN
        SELECT * FROM @extschema@.retry_queue
        WHERE status = 'queued' AND scheduled_at <= now()
        ORDER BY scheduled_at
        FOR UPDATE SKIP LOCKED
    LOOP
        v_processed := v_processed + 1;
        UPDATE @extschema@.retry_queue SET status = 'processing'
        WHERE queue_id = v_item.queue_id;

        SELECT * INTO v_result FROM @extschema@.execute_on_environment(
            v_item.environment_id, v_item.applied_sql, v_item.batch_id);

        IF v_result.exec_status = 'success' THEN
            v_succeeded := v_succeeded + 1;
            UPDATE @extschema@.retry_queue SET status = 'completed'
            WHERE queue_id = v_item.queue_id;
            UPDATE @extschema@.sync_execution_log SET
                execution_status = 'success',
                result_message = 'Succeeded on retry #' || v_item.retry_number,
                retry_count = v_item.retry_number, last_retry_at = now(), finished_at = now()
            WHERE execution_id = v_item.execution_id;
            -- Recalculate batch
            UPDATE @extschema@.sync_batches b SET
                success_count = (SELECT count(*) FROM @extschema@.sync_execution_log
                                 WHERE batch_id=b.batch_id AND execution_status='success'),
                failure_count = (SELECT count(*) FROM @extschema@.sync_execution_log
                                 WHERE batch_id=b.batch_id AND execution_status='failed'),
                batch_status = CASE WHEN (SELECT count(*) FROM @extschema@.sync_execution_log
                    WHERE batch_id=b.batch_id AND execution_status='failed')=0
                    THEN 'completed' ELSE 'partial' END
            WHERE batch_id = v_item.batch_id;
        ELSE
            IF v_item.retry_number >= v_max_retries THEN
                v_abandoned := v_abandoned + 1;
                UPDATE @extschema@.retry_queue SET status = 'abandoned'
                WHERE queue_id = v_item.queue_id;
                UPDATE @extschema@.sync_execution_log SET
                    result_message = format('Abandoned after %s retries. Last: %s',
                                            v_max_retries, v_result.exec_message),
                    retry_count = v_item.retry_number, last_retry_at = now()
                WHERE execution_id = v_item.execution_id;
            ELSE
                UPDATE @extschema@.retry_queue SET
                    status = 'queued',
                    retry_number = v_item.retry_number + 1,
                    scheduled_at = now() + (v_retry_delay * v_item.retry_number || ' seconds')::interval
                WHERE queue_id = v_item.queue_id;
                UPDATE @extschema@.sync_execution_log SET
                    retry_count = v_item.retry_number, last_retry_at = now(),
                    result_message = format('Retry %s failed: %s',
                                            v_item.retry_number, v_result.exec_message)
                WHERE execution_id = v_item.execution_id;
            END IF;
        END IF;
    END LOOP;
    RETURN QUERY SELECT v_processed, v_succeeded, v_abandoned;
END;
$$;


-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
-- SECTION 4 — EVENT TRIGGERS
-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

-- 4.1  ddl_command_end handler
CREATE OR REPLACE FUNCTION @extschema@.on_ddl_command_end()
RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_obj       RECORD;
    v_sql       TEXT;
    v_cmd_tag   TEXT;
    v_batch_id  BIGINT;
    v_role_name TEXT;
BEGIN
    IF NOT @extschema@.is_sync_enabled() THEN RETURN; END IF;

    FOR v_obj IN SELECT * FROM pg_event_trigger_ddl_commands()
    LOOP
        v_cmd_tag := v_obj.command_tag;
        IF v_cmd_tag NOT IN (
            'CREATE ROLE','ALTER ROLE','DROP ROLE',
            'GRANT','REVOKE',
            'CREATE POLICY','ALTER POLICY','DROP POLICY',
            'ALTER DEFAULT PRIVILEGES',
            'CREATE SCHEMA','ALTER SCHEMA'
        ) THEN CONTINUE; END IF;

        v_sql       := current_query();
        v_role_name := v_obj.object_identity;

        IF v_role_name IS NOT NULL AND @extschema@.is_role_excluded(v_role_name) THEN
            INSERT INTO @extschema@.permission_audit_log (
                command_tag, full_sql, object_type, object_identity, schema_name,
                client_addr, application_name, backend_pid, transaction_id, sync_enabled
            ) VALUES (
                v_cmd_tag, v_sql, v_obj.object_type, v_obj.object_identity,
                v_obj.schema_name, inet_client_addr(),
                current_setting('application_name',true),
                pg_backend_pid(), txid_current(), FALSE);
            CONTINUE;
        END IF;

        INSERT INTO @extschema@.permission_audit_log (
            command_tag, full_sql, object_type, object_identity, schema_name,
            client_addr, application_name, backend_pid, transaction_id, sync_enabled
        ) VALUES (
            v_cmd_tag, v_sql, v_obj.object_type, v_obj.object_identity,
            v_obj.schema_name, inet_client_addr(),
            current_setting('application_name',true),
            pg_backend_pid(), txid_current(), TRUE);

        BEGIN
            v_batch_id := @extschema@.sync_to_all_environments(
                v_cmd_tag, v_sql, v_obj.object_type, v_obj.object_identity, v_role_name);
            UPDATE @extschema@.permission_audit_log SET batch_id = v_batch_id
            WHERE audit_id = (
                SELECT max(audit_id) FROM @extschema@.permission_audit_log
                WHERE transaction_id = txid_current() AND command_tag = v_cmd_tag);
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'pgx_permission_sync: sync failed for % — %: %',
                v_cmd_tag, SQLSTATE, SQLERRM;
        END;
    END LOOP;
END;
$$;

-- 4.2  sql_drop handler
CREATE OR REPLACE FUNCTION @extschema@.on_sql_drop()
RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_obj      RECORD;
    v_sql      TEXT;
    v_batch_id BIGINT;
BEGIN
    IF NOT @extschema@.is_sync_enabled() THEN RETURN; END IF;

    FOR v_obj IN SELECT * FROM pg_event_trigger_dropped_objects()
    LOOP
        IF v_obj.object_type NOT IN ('role') THEN CONTINUE; END IF;
        v_sql := current_query();

        IF @extschema@.is_role_excluded(v_obj.object_identity) THEN
            INSERT INTO @extschema@.permission_audit_log (
                command_tag, full_sql, object_type, object_identity,
                client_addr, application_name, backend_pid, transaction_id, sync_enabled
            ) VALUES ('DROP ROLE', v_sql, 'ROLE', v_obj.object_identity,
                inet_client_addr(), current_setting('application_name',true),
                pg_backend_pid(), txid_current(), FALSE);
            CONTINUE;
        END IF;

        INSERT INTO @extschema@.permission_audit_log (
            command_tag, full_sql, object_type, object_identity,
            client_addr, application_name, backend_pid, transaction_id, sync_enabled
        ) VALUES ('DROP ROLE', v_sql, 'ROLE', v_obj.object_identity,
            inet_client_addr(), current_setting('application_name',true),
            pg_backend_pid(), txid_current(), TRUE);

        BEGIN
            v_batch_id := @extschema@.sync_to_all_environments(
                'DROP ROLE', v_sql, 'ROLE', v_obj.object_identity, v_obj.object_identity);
            UPDATE @extschema@.permission_audit_log SET batch_id = v_batch_id
            WHERE audit_id = (
                SELECT max(audit_id) FROM @extschema@.permission_audit_log
                WHERE transaction_id = txid_current() AND command_tag = 'DROP ROLE');
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'pgx_permission_sync: DROP ROLE sync failed — %: %',
                SQLSTATE, SQLERRM;
        END;
    END LOOP;
END;
$$;

-- 4.3  Create the event triggers
DROP EVENT TRIGGER IF EXISTS pgsync_ddl_command_end;
DROP EVENT TRIGGER IF EXISTS pgsync_sql_drop;

CREATE EVENT TRIGGER pgsync_ddl_command_end
    ON ddl_command_end
    WHEN TAG IN (
        'CREATE ROLE','ALTER ROLE','DROP ROLE',
        'GRANT','REVOKE',
        'CREATE POLICY','ALTER POLICY','DROP POLICY',
        'ALTER DEFAULT PRIVILEGES','CREATE SCHEMA','ALTER SCHEMA')
    EXECUTE FUNCTION @extschema@.on_ddl_command_end();

CREATE EVENT TRIGGER pgsync_sql_drop
    ON sql_drop
    EXECUTE FUNCTION @extschema@.on_sql_drop();


-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
-- SECTION 5 — ADMIN FUNCTIONS
-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

-- 5.1  add_environment
CREATE OR REPLACE FUNCTION @extschema@.add_environment(
    p_env_name   TEXT, p_host TEXT, p_dbname TEXT, p_username TEXT,
    p_password   TEXT    DEFAULT NULL,
    p_port       INTEGER DEFAULT 5432,
    p_sslmode    TEXT    DEFAULT 'prefer',
    p_env_label  TEXT    DEFAULT NULL,
    p_priority   INTEGER DEFAULT 100,
    p_notes      TEXT    DEFAULT NULL
) RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE v_enc_pass TEXT; v_env_id INTEGER;
BEGIN
    IF p_password IS NOT NULL
       AND @extschema@.get_config('encrypt_passwords','true')::boolean THEN
        v_enc_pass := @extschema@.encrypt_password(p_password);
    ELSE
        v_enc_pass := p_password;
    END IF;
    INSERT INTO @extschema@.environments (
        env_name, env_label, host, port, dbname, username,
        password_enc, sslmode, priority, notes
    ) VALUES (
        p_env_name, COALESCE(p_env_label,p_env_name), p_host, p_port, p_dbname,
        p_username, v_enc_pass, p_sslmode, p_priority, p_notes
    ) RETURNING environment_id INTO v_env_id;
    RETURN v_env_id;
END;
$$;

-- 5.2  remove_environment
CREATE OR REPLACE FUNCTION @extschema@.remove_environment(
    p_env_name TEXT, p_hard_delete BOOLEAN DEFAULT FALSE
) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
BEGIN
    IF p_hard_delete THEN
        DELETE FROM @extschema@.environments WHERE env_name = p_env_name;
    ELSE
        UPDATE @extschema@.environments
        SET is_active = FALSE, updated_at = now()
        WHERE env_name = p_env_name;
    END IF;
    RETURN FOUND;
END;
$$;

-- 5.3  manual_sync
CREATE OR REPLACE FUNCTION @extschema@.manual_sync(
    p_sql      TEXT,
    p_env_name TEXT DEFAULT NULL
) RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE v_batch_id BIGINT; v_env_id INTEGER; v_result RECORD;
BEGIN
    IF p_env_name IS NOT NULL THEN
        INSERT INTO @extschema@.sync_batches (
            source_command, source_sql, source_user, object_type, batch_status
        ) VALUES ('MANUAL_SYNC', p_sql, current_user, 'MANUAL', 'in_progress')
        RETURNING batch_id INTO v_batch_id;

        SELECT environment_id INTO v_env_id
        FROM @extschema@.environments WHERE env_name = p_env_name AND is_active;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Environment "%" not found or inactive', p_env_name;
        END IF;

        SELECT * INTO v_result
        FROM @extschema@.execute_on_environment(v_env_id, p_sql, v_batch_id);

        INSERT INTO @extschema@.sync_execution_log (
            batch_id, environment_id, env_name, applied_sql,
            execution_status, started_at, finished_at, duration_ms,
            result_message, error_code, server_version, connection_time_ms
        ) VALUES (v_batch_id, v_env_id, p_env_name, p_sql,
            v_result.exec_status, now(), now(), v_result.exec_duration,
            v_result.exec_message, v_result.exec_errcode,
            v_result.server_ver, v_result.exec_conn_time);

        UPDATE @extschema@.sync_batches SET
            total_targets = 1,
            success_count = CASE WHEN v_result.exec_status='success' THEN 1 ELSE 0 END,
            failure_count = CASE WHEN v_result.exec_status='failed' THEN 1 ELSE 0 END,
            completed_at = now(),
            batch_status = CASE WHEN v_result.exec_status='success' THEN 'completed' ELSE 'failed' END
        WHERE batch_id = v_batch_id;
    ELSE
        v_batch_id := @extschema@.sync_to_all_environments('MANUAL_SYNC', p_sql);
    END IF;
    RETURN v_batch_id;
END;
$$;

-- 5.4  enable / disable helpers
CREATE OR REPLACE FUNCTION @extschema@.enable_sync()
RETURNS VOID LANGUAGE sql AS $$
    SELECT @extschema@.set_config_param('sync_enabled','true');
$$;

CREATE OR REPLACE FUNCTION @extschema@.disable_sync()
RETURNS VOID LANGUAGE sql AS $$
    SELECT @extschema@.set_config_param('sync_enabled','false');
$$;

CREATE OR REPLACE FUNCTION @extschema@.enable_dry_run()
RETURNS VOID LANGUAGE sql AS $$
    SELECT @extschema@.set_config_param('dry_run','true');
$$;

CREATE OR REPLACE FUNCTION @extschema@.disable_dry_run()
RETURNS VOID LANGUAGE sql AS $$
    SELECT @extschema@.set_config_param('dry_run','false');
$$;

-- 5.5  cleanup_old_logs
CREATE OR REPLACE FUNCTION @extschema@.cleanup_old_logs()
RETURNS TABLE(sync_logs_deleted BIGINT, audit_logs_deleted BIGINT, retries_deleted BIGINT)
LANGUAGE plpgsql AS $$
DECLARE
    v_sync_days  INTEGER; v_audit_days INTEGER;
    v_sd BIGINT := 0; v_ad BIGINT := 0; v_rd BIGINT := 0;
BEGIN
    v_sync_days  := @extschema@.get_config('log_retention_days','90')::int;
    v_audit_days := @extschema@.get_config('audit_retention_days','365')::int;

    WITH d AS (DELETE FROM @extschema@.sync_batches
        WHERE completed_at < now()-(v_sync_days||' days')::interval RETURNING 1)
    SELECT count(*) INTO v_sd FROM d;

    WITH d AS (DELETE FROM @extschema@.permission_audit_log
        WHERE event_time < now()-(v_audit_days||' days')::interval RETURNING 1)
    SELECT count(*) INTO v_ad FROM d;

    WITH d AS (DELETE FROM @extschema@.retry_queue
        WHERE status IN ('completed','abandoned')
          AND created_at < now()-(v_sync_days||' days')::interval RETURNING 1)
    SELECT count(*) INTO v_rd FROM d;

    RETURN QUERY SELECT v_sd, v_ad, v_rd;
END;
$$;

-- 5.6  get_sync_status
CREATE OR REPLACE FUNCTION @extschema@.get_sync_status(p_hours INTEGER DEFAULT 24)
RETURNS TABLE(metric TEXT, value TEXT) LANGUAGE sql STABLE AS $$
    SELECT 'Sync Enabled',            @extschema@.get_config('sync_enabled')
    UNION ALL SELECT 'Dry Run Mode',  @extschema@.get_config('dry_run')
    UNION ALL SELECT 'Active Environments',
        (SELECT count(*)::text FROM @extschema@.environments WHERE is_active)
    UNION ALL SELECT 'Batches (last '||p_hours||'h)',
        (SELECT count(*)::text FROM @extschema@.sync_batches
         WHERE captured_at > now()-(p_hours||' hours')::interval)
    UNION ALL SELECT 'Successful (last '||p_hours||'h)',
        (SELECT count(*)::text FROM @extschema@.sync_execution_log
         WHERE finished_at > now()-(p_hours||' hours')::interval AND execution_status='success')
    UNION ALL SELECT 'Failed (last '||p_hours||'h)',
        (SELECT count(*)::text FROM @extschema@.sync_execution_log
         WHERE finished_at > now()-(p_hours||' hours')::interval AND execution_status='failed')
    UNION ALL SELECT 'Pending Retries',
        (SELECT count(*)::text FROM @extschema@.retry_queue WHERE status='queued');
$$;


-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
-- SECTION 6 — VIEWS
-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

CREATE OR REPLACE VIEW @extschema@.v_environment_status AS
SELECT e.environment_id, e.env_name, e.env_label, e.host, e.port,
       e.dbname, e.is_active, e.priority,
       le.last_sync_at, le.last_status, le.last_message,
       st.total_24h, st.success_24h, st.failed_24h, st.avg_ms_24h
FROM @extschema@.environments e
LEFT JOIN LATERAL (
    SELECT finished_at AS last_sync_at, execution_status AS last_status,
           result_message AS last_message
    FROM @extschema@.sync_execution_log
    WHERE environment_id = e.environment_id
    ORDER BY finished_at DESC NULLS LAST LIMIT 1
) le ON TRUE
LEFT JOIN LATERAL (
    SELECT count(*) AS total_24h,
           count(*) FILTER (WHERE execution_status='success') AS success_24h,
           count(*) FILTER (WHERE execution_status='failed')  AS failed_24h,
           round(avg(duration_ms) FILTER (WHERE execution_status='success'),1) AS avg_ms_24h
    FROM @extschema@.sync_execution_log
    WHERE environment_id = e.environment_id
      AND finished_at > now()-interval '24 hours'
) st ON TRUE
ORDER BY e.priority, e.env_name;

CREATE OR REPLACE VIEW @extschema@.v_recent_batches AS
SELECT batch_id, captured_at, source_command, object_type, object_identity,
       source_user, batch_status, total_targets, success_count, failure_count,
       skip_count, execution_time_ms, left(source_sql,200) AS sql_preview
FROM @extschema@.sync_batches ORDER BY captured_at DESC;

CREATE OR REPLACE VIEW @extschema@.v_execution_details AS
SELECT el.execution_id, el.batch_id, b.captured_at, b.source_command,
       el.env_name, el.execution_status, el.duration_ms, el.connection_time_ms,
       el.result_message, el.error_code, el.retry_count,
       el.server_version, left(el.applied_sql,300) AS sql_preview
FROM @extschema@.sync_execution_log el
JOIN @extschema@.sync_batches b ON b.batch_id = el.batch_id
ORDER BY el.finished_at DESC NULLS LAST;

CREATE OR REPLACE VIEW @extschema@.v_failed_syncs AS
SELECT el.execution_id, el.batch_id, b.captured_at, b.source_command,
       b.object_identity, el.env_name, el.result_message AS error_message,
       el.error_code, el.retry_count, rq.status AS retry_status,
       rq.scheduled_at AS next_retry_at, el.applied_sql
FROM @extschema@.sync_execution_log el
JOIN @extschema@.sync_batches b ON b.batch_id = el.batch_id
LEFT JOIN @extschema@.retry_queue rq
    ON rq.execution_id = el.execution_id AND rq.status = 'queued'
WHERE el.execution_status = 'failed'
ORDER BY el.finished_at DESC NULLS LAST;

CREATE OR REPLACE VIEW @extschema@.v_audit_trail AS
SELECT a.audit_id, a.event_time, a.command_tag, a.object_type,
       a.object_identity, a.executed_by, a.sync_enabled,
       a.batch_id, b.batch_status, b.success_count, b.failure_count,
       left(a.full_sql,300) AS sql_preview
FROM @extschema@.permission_audit_log a
LEFT JOIN @extschema@.sync_batches b ON b.batch_id = a.batch_id
ORDER BY a.event_time DESC;

CREATE OR REPLACE VIEW @extschema@.v_sync_daily_summary AS
SELECT date_trunc('day',captured_at)::date AS sync_date,
       count(DISTINCT batch_id) AS total_batches,
       sum(success_count) AS total_successes,
       sum(failure_count) AS total_failures,
       round(avg(execution_time_ms),1) AS avg_batch_ms,
       count(DISTINCT source_user) AS distinct_users
FROM @extschema@.sync_batches GROUP BY 1 ORDER BY 1 DESC;


-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
-- SECTION 7 — SECURITY ROLES & GRANTS
-- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pgsync_admin')    THEN CREATE ROLE pgsync_admin    NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pgsync_operator') THEN CREATE ROLE pgsync_operator NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pgsync_reader')   THEN CREATE ROLE pgsync_reader   NOLOGIN; END IF;
END $$;

GRANT USAGE ON SCHEMA @extschema@ TO pgsync_admin, pgsync_operator, pgsync_reader;
GRANT ALL   ON ALL TABLES    IN SCHEMA @extschema@ TO pgsync_admin;
GRANT ALL   ON ALL SEQUENCES IN SCHEMA @extschema@ TO pgsync_admin;
GRANT SELECT ON ALL TABLES   IN SCHEMA @extschema@ TO pgsync_operator;
GRANT INSERT, UPDATE ON @extschema@.retry_queue TO pgsync_operator;
GRANT SELECT ON ALL TABLES   IN SCHEMA @extschema@ TO pgsync_reader;

-- Function grants
GRANT EXECUTE ON FUNCTION @extschema@.add_environment          TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.remove_environment       TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.set_config_param         TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.enable_sync()            TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.disable_sync()           TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.enable_dry_run()         TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.disable_dry_run()        TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.cleanup_old_logs()       TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.encrypt_password         TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.decrypt_password(TEXT)   TO pgsync_admin;
GRANT EXECUTE ON FUNCTION @extschema@.build_connstr(INTEGER)   TO pgsync_admin;

GRANT EXECUTE ON FUNCTION @extschema@.manual_sync              TO pgsync_admin, pgsync_operator;
GRANT EXECUTE ON FUNCTION @extschema@.process_retry_queue()    TO pgsync_admin, pgsync_operator;
GRANT EXECUTE ON FUNCTION @extschema@.test_environment_connection TO pgsync_admin, pgsync_operator;

GRANT EXECUTE ON FUNCTION @extschema@.get_config               TO pgsync_admin, pgsync_operator, pgsync_reader;
GRANT EXECUTE ON FUNCTION @extschema@.is_sync_enabled()        TO pgsync_admin, pgsync_operator, pgsync_reader;
GRANT EXECUTE ON FUNCTION @extschema@.get_sync_status          TO pgsync_admin, pgsync_operator, pgsync_reader;
GRANT EXECUTE ON FUNCTION @extschema@.is_role_excluded         TO pgsync_admin, pgsync_operator, pgsync_reader;
GRANT EXECUTE ON FUNCTION @extschema@.check_sync_rules         TO pgsync_admin, pgsync_operator, pgsync_reader;

ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@
    GRANT SELECT ON TABLES TO pgsync_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@
    GRANT SELECT ON TABLES TO pgsync_operator;
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@
    GRANT ALL ON TABLES TO pgsync_admin;
