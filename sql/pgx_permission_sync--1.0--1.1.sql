-- ============================================================================
-- pgx_permission_sync  --  upgrade 1.0 -> 1.1   (correctness & security)
--
--   ALTER EXTENSION pgx_permission_sync UPDATE TO '1.1';
--
-- Changes
--   * FIX   cleanup_old_logs() FK violations (audit_log -> batches,
--           retry_queue -> execution_log)
--   * SEC   passwords in SQL text are masked in every log table and in
--           pg_notify payloads (mask_secrets)
--   * SEC   encryption key moved out of the readable `config` table into a
--           locked-down `secrets` table; set_encryption_key() rotates it
--   * SEC   SECURITY DEFINER functions get a pinned search_path
--   * SEC   connection string values are quoted (no option injection)
--   * SEC   pgsync_reader / pgsync_operator can no longer read
--           environments.password_enc or retry_queue (raw SQL)
--   * FIX   operator-callable functions (manual_sync, process_retry_queue,
--           test_environment_connection) now actually work for operators
--   * FIX   GRANT/REVOKE object names are no longer matched against
--           excluded_roles; role-name patterns are regex-escaped
--   * FIX   audit -> batch back-link uses the inserted audit_id
--   * CHG   txid_current() -> pg_current_xact_id()
--
-- NOTE: CREATE/ALTER/DROP ROLE are shared objects; PostgreSQL event triggers
-- do not fire for them. See README "Known limitations".
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Foreign keys that broke cleanup_old_logs()
-- ---------------------------------------------------------------------------
ALTER TABLE @extschema@.permission_audit_log
    DROP CONSTRAINT IF EXISTS permission_audit_log_batch_id_fkey;
ALTER TABLE @extschema@.permission_audit_log
    ADD CONSTRAINT permission_audit_log_batch_id_fkey
    FOREIGN KEY (batch_id) REFERENCES @extschema@.sync_batches(batch_id)
    ON DELETE SET NULL;

ALTER TABLE @extschema@.retry_queue
    DROP CONSTRAINT IF EXISTS retry_queue_execution_id_fkey;
ALTER TABLE @extschema@.retry_queue
    ADD CONSTRAINT retry_queue_execution_id_fkey
    FOREIGN KEY (execution_id) REFERENCES @extschema@.sync_execution_log(execution_id)
    ON DELETE CASCADE;

-- ---------------------------------------------------------------------------
-- 2. Secrets: masking + encryption key storage
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@.mask_secrets(p_sql TEXT)
RETURNS TEXT LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    -- Masks  PASSWORD 'xxx'  /  ENCRYPTED PASSWORD E'xxx'  (case-insensitive)
    SELECT regexp_replace(p_sql,
        $re$(\mPASSWORD\M\s+)(?:E'(?:[^'\\]|\\.|'')*'|'(?:[^']|'')*')$re$,
        $rep$\1'********'$rep$, 'gi');
$$;

CREATE TABLE @extschema@.secrets (
    key_name    TEXT PRIMARY KEY,
    key_value   TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE @extschema@.secrets IS
    'Encryption key material. No role other than the owner may read it.';

-- Preserve the key currently in use (1.0 stored it in config; empty = no key set)
INSERT INTO @extschema@.secrets (key_name, key_value)
SELECT 'encryption_key', COALESCE(
    (SELECT param_value FROM @extschema@.config WHERE param_name = 'encryption_key_ref'), '');
DELETE FROM @extschema@.config WHERE param_name = 'encryption_key_ref';

-- default privileges from 1.0 would otherwise hand SELECT to reader/operator
REVOKE ALL ON @extschema@.secrets FROM PUBLIC, pgsync_admin, pgsync_operator, pgsync_reader;

CREATE OR REPLACE FUNCTION @extschema@.encrypt_password(p_plain TEXT)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE v_key TEXT;
BEGIN
    SELECT key_value INTO v_key FROM @extschema@.secrets WHERE key_name = 'encryption_key';
    IF v_key IS NULL OR v_key = '' THEN
        RAISE WARNING 'pgx_permission_sync: no encryption key set; call set_encryption_key()';
    END IF;
    RETURN encode(pgp_sym_encrypt(p_plain, COALESCE(v_key, '')), 'base64');
END;
$$;

CREATE OR REPLACE FUNCTION @extschema@.decrypt_password(p_enc TEXT)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE v_key TEXT;
BEGIN
    SELECT key_value INTO v_key FROM @extschema@.secrets WHERE key_name = 'encryption_key';
    RETURN pgp_sym_decrypt(decode(p_enc, 'base64'), COALESCE(v_key, ''));
END;
$$;

-- Rotates the key and re-encrypts every stored environment password.
-- Returns the number of environments re-encrypted.
CREATE OR REPLACE FUNCTION @extschema@.set_encryption_key(p_new_key TEXT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE v_old TEXT; v_n INTEGER := 0;
BEGIN
    IF length(COALESCE(p_new_key, '')) < 16 THEN
        RAISE EXCEPTION 'encryption key must be at least 16 characters';
    END IF;
    SELECT key_value INTO v_old FROM @extschema@.secrets WHERE key_name = 'encryption_key';

    IF @extschema@.get_config('encrypt_passwords','true')::boolean THEN
        UPDATE @extschema@.environments SET
            password_enc = encode(pgp_sym_encrypt(
                pgp_sym_decrypt(decode(password_enc,'base64'), COALESCE(v_old,'')),
                p_new_key), 'base64'),
            updated_at = now()
        WHERE password_enc IS NOT NULL;
        GET DIAGNOSTICS v_n = ROW_COUNT;
    END IF;

    INSERT INTO @extschema@.secrets (key_name, key_value)
    VALUES ('encryption_key', p_new_key)
    ON CONFLICT (key_name) DO UPDATE SET key_value = EXCLUDED.key_value, updated_at = now();
    RETURN v_n;
END;
$$;
REVOKE ALL ON FUNCTION @extschema@.set_encryption_key(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.set_encryption_key(TEXT) TO pgsync_admin;

-- ---------------------------------------------------------------------------
-- 3. Connection string quoting
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@.conninfo_quote(p_value TEXT)
RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
    SELECT '''' || replace(replace(p_value, '\', '\\'), '''', '\''') || '''';
$$;

CREATE OR REPLACE FUNCTION @extschema@.build_connstr(p_environment_id INTEGER)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE
    v_env     RECORD;
    v_pass    TEXT;
    v_timeout INTEGER;
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

    v_timeout := GREATEST(1, @extschema@.get_config('connection_timeout_ms','5000')::int / 1000);

    RETURN format('host=%s port=%s dbname=%s user=%s sslmode=%s connect_timeout=%s',
            @extschema@.conninfo_quote(v_env.host),
            v_env.port,
            @extschema@.conninfo_quote(v_env.dbname),
            @extschema@.conninfo_quote(v_env.username),
            @extschema@.conninfo_quote(v_env.sslmode),
            v_timeout)
        || CASE WHEN v_pass IS NOT NULL AND v_pass <> ''
                THEN ' password=' || @extschema@.conninfo_quote(v_pass) ELSE '' END;
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. Role-exclusion patterns: escape regex metacharacters (only * is a wildcard)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@.is_role_excluded(p_role_name TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_excluded TEXT;
    v_pattern  TEXT;
BEGIN
    v_excluded := @extschema@.get_config('excluded_roles', 'postgres,replication,pg_*');
    FOREACH v_pattern IN ARRAY string_to_array(v_excluded, ',')
    LOOP
        v_pattern := trim(v_pattern);
        CONTINUE WHEN v_pattern = '';
        v_pattern := regexp_replace(v_pattern, '([.+?^$(){}|\[\]\\])', '\\\1', 'g');
        v_pattern := '^' || replace(v_pattern, '*', '.*') || '$';
        IF p_role_name ~ v_pattern THEN RETURN TRUE; END IF;
    END LOOP;
    RETURN FALSE;
END;
$$;

-- ---------------------------------------------------------------------------
-- 5. Sync engine: masked logging, pg_current_xact_id()
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@.sync_to_all_environments(
    p_command_tag     TEXT,
    p_sql             TEXT,
    p_object_type     TEXT DEFAULT NULL,
    p_object_identity TEXT DEFAULT NULL,
    p_role_name       TEXT DEFAULT NULL
) RETURNS BIGINT LANGUAGE plpgsql
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
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
    v_safe_sql       TEXT := @extschema@.mask_secrets(p_sql);
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
        p_command_tag, v_safe_sql, current_user, inet_client_addr(),
        current_setting('application_name',true), pg_backend_pid(),
        pg_current_xact_id()::text::bigint,
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
                v_batch_id, v_env.environment_id, v_env.env_name, v_safe_sql,
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
            v_batch_id, v_env.environment_id, v_env.env_name, v_safe_sql,
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
                -- retry_queue keeps the raw SQL (needed to replay); it is not
                -- readable by pgsync_reader / pgsync_operator.
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
                    'sql',left(v_safe_sql,500))::text);
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

CREATE OR REPLACE FUNCTION @extschema@.manual_sync(
    p_sql      TEXT,
    p_env_name TEXT DEFAULT NULL
) RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE
    v_batch_id BIGINT; v_env_id INTEGER; v_result RECORD;
    v_safe_sql TEXT := @extschema@.mask_secrets(p_sql);
BEGIN
    IF p_env_name IS NOT NULL THEN
        SELECT environment_id INTO v_env_id
        FROM @extschema@.environments WHERE env_name = p_env_name AND is_active;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Environment "%" not found or inactive', p_env_name;
        END IF;

        INSERT INTO @extschema@.sync_batches (
            source_command, source_sql, source_user, object_type, batch_status
        ) VALUES ('MANUAL_SYNC', v_safe_sql, session_user, 'MANUAL', 'in_progress')
        RETURNING batch_id INTO v_batch_id;

        SELECT * INTO v_result
        FROM @extschema@.execute_on_environment(v_env_id, p_sql, v_batch_id);

        INSERT INTO @extschema@.sync_execution_log (
            batch_id, environment_id, env_name, applied_sql,
            execution_status, started_at, finished_at, duration_ms,
            result_message, error_code, error_detail, error_hint,
            server_version, connection_time_ms
        ) VALUES (v_batch_id, v_env_id, p_env_name, v_safe_sql,
            v_result.exec_status, now(), now(), v_result.exec_duration,
            v_result.exec_message, v_result.exec_errcode,
            v_result.exec_detail, v_result.exec_hint,
            v_result.server_ver, v_result.exec_conn_time);

        UPDATE @extschema@.sync_batches SET
            total_targets = 1,
            success_count = CASE WHEN v_result.exec_status='success' THEN 1 ELSE 0 END,
            failure_count = CASE WHEN v_result.exec_status='failed'  THEN 1 ELSE 0 END,
            skip_count    = CASE WHEN v_result.exec_status='skipped' THEN 1 ELSE 0 END,
            completed_at  = now(),
            batch_status  = CASE v_result.exec_status
                                WHEN 'success' THEN 'completed'
                                WHEN 'skipped' THEN 'skipped'
                                ELSE 'failed' END
        WHERE batch_id = v_batch_id;
    ELSE
        v_batch_id := @extschema@.sync_to_all_environments('MANUAL_SYNC', p_sql);
    END IF;
    RETURN v_batch_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- 6. Event trigger handlers
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@.on_ddl_command_end()
RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE
    v_obj       RECORD;
    v_sql       TEXT;
    v_cmd_tag   TEXT;
    v_batch_id  BIGINT;
    v_audit_id  BIGINT;
    v_is_role   BOOLEAN;
    v_excluded  BOOLEAN;
BEGIN
    IF NOT @extschema@.is_sync_enabled() THEN RETURN; END IF;
    v_sql := current_query();

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

        -- object_identity is a role name only for role commands; for
        -- GRANT/REVOKE it is the granted-on object, so don't test it.
        v_is_role  := v_cmd_tag IN ('CREATE ROLE','ALTER ROLE','DROP ROLE');
        v_excluded := v_is_role AND v_obj.object_identity IS NOT NULL
                      AND @extschema@.is_role_excluded(v_obj.object_identity);

        INSERT INTO @extschema@.permission_audit_log (
            command_tag, full_sql, object_type, object_identity, schema_name,
            client_addr, application_name, backend_pid, transaction_id, sync_enabled
        ) VALUES (
            v_cmd_tag, @extschema@.mask_secrets(v_sql), v_obj.object_type,
            v_obj.object_identity, v_obj.schema_name, inet_client_addr(),
            current_setting('application_name',true), pg_backend_pid(),
            pg_current_xact_id()::text::bigint, NOT v_excluded
        ) RETURNING audit_id INTO v_audit_id;

        CONTINUE WHEN v_excluded;

        BEGIN
            v_batch_id := @extschema@.sync_to_all_environments(
                v_cmd_tag, v_sql, v_obj.object_type, v_obj.object_identity,
                CASE WHEN v_is_role THEN v_obj.object_identity END);
            UPDATE @extschema@.permission_audit_log SET batch_id = v_batch_id
            WHERE audit_id = v_audit_id;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'pgx_permission_sync: sync failed for % — %: %',
                v_cmd_tag, SQLSTATE, SQLERRM;
        END;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION @extschema@.on_sql_drop()
RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE
    v_obj      RECORD;
    v_sql      TEXT;
    v_batch_id BIGINT;
    v_audit_id BIGINT;
    v_excluded BOOLEAN;
BEGIN
    IF NOT @extschema@.is_sync_enabled() THEN RETURN; END IF;
    v_sql := current_query();

    FOR v_obj IN SELECT * FROM pg_event_trigger_dropped_objects()
    LOOP
        IF v_obj.object_type NOT IN ('role') THEN CONTINUE; END IF;
        v_excluded := @extschema@.is_role_excluded(v_obj.object_identity);

        INSERT INTO @extschema@.permission_audit_log (
            command_tag, full_sql, object_type, object_identity,
            client_addr, application_name, backend_pid, transaction_id, sync_enabled
        ) VALUES ('DROP ROLE', @extschema@.mask_secrets(v_sql), 'ROLE', v_obj.object_identity,
            inet_client_addr(), current_setting('application_name',true),
            pg_backend_pid(), pg_current_xact_id()::text::bigint, NOT v_excluded)
        RETURNING audit_id INTO v_audit_id;

        CONTINUE WHEN v_excluded;

        BEGIN
            v_batch_id := @extschema@.sync_to_all_environments(
                'DROP ROLE', v_sql, 'ROLE', v_obj.object_identity, v_obj.object_identity);
            UPDATE @extschema@.permission_audit_log SET batch_id = v_batch_id
            WHERE audit_id = v_audit_id;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'pgx_permission_sync: DROP ROLE sync failed — %: %',
                SQLSTATE, SQLERRM;
        END;
    END LOOP;
END;
$$;

-- ---------------------------------------------------------------------------
-- 7. Privileges
-- ---------------------------------------------------------------------------
-- Functions the operator role can call but which touch restricted tables
ALTER FUNCTION @extschema@.process_retry_queue()
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION @extschema@.test_environment_connection(INTEGER)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION @extschema@.execute_on_environment(INTEGER, TEXT, BIGINT)
    SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION @extschema@.check_sync_rules(INTEGER, TEXT, TEXT, TEXT)
    SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION @extschema@.cleanup_old_logs()
    SET search_path = @extschema@, pg_catalog, pg_temp;

-- Internal engine functions must not be callable by arbitrary roles
REVOKE ALL ON FUNCTION @extschema@.execute_on_environment(INTEGER, TEXT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.sync_to_all_environments(TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.manual_sync(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.process_retry_queue() FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.test_environment_connection(INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.manual_sync(TEXT, TEXT) TO pgsync_admin, pgsync_operator;
GRANT EXECUTE ON FUNCTION @extschema@.process_retry_queue() TO pgsync_admin, pgsync_operator;
GRANT EXECUTE ON FUNCTION @extschema@.test_environment_connection(INTEGER) TO pgsync_admin, pgsync_operator;

-- Reader / operator: no raw SQL (retry_queue) and no stored passwords
REVOKE ALL ON @extschema@.retry_queue FROM pgsync_reader, pgsync_operator;
REVOKE ALL ON @extschema@.environments FROM pgsync_reader, pgsync_operator;
GRANT SELECT (environment_id, env_name, env_label, host, port, dbname, username,
              sslmode, connection_opts, is_active, priority, created_at,
              updated_at, created_by, notes)
    ON @extschema@.environments TO pgsync_reader, pgsync_operator;

-- Views that expose retry_queue.status/scheduled_at (v_failed_syncs) run with
-- the view owner's rights, so reader/operator still see them.

-- ---------------------------------------------------------------------------
-- 8. Pin search_path to the schemas that actually hold dblink / pgcrypto
--    (CREATE EXTENSION ... CASCADE puts them in public unless told otherwise).
--    Re-run this block if you later relocate either extension.
-- ---------------------------------------------------------------------------
DO $pin$
DECLARE
    v_path TEXT;
    v_fn   RECORD;
BEGIN
    SELECT string_agg(DISTINCT quote_ident(n.nspname), ', ')
      INTO v_path
      FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
     WHERE e.extname IN ('dblink','pgcrypto')
       AND n.nspname NOT IN ('@extschema@','pg_catalog');

    FOR v_fn IN
        SELECT p.oid::regprocedure AS sig
          FROM pg_proc p
         WHERE p.pronamespace = '@extschema@'::regnamespace
           AND EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%')
    LOOP
        EXECUTE format('ALTER FUNCTION %s SET search_path = %s',
            v_fn.sig,
            concat_ws(', ', quote_ident('@extschema@'), 'pg_catalog', v_path, 'pg_temp'));
    END LOOP;
END
$pin$;

-- ---------------------------------------------------------------------------
-- 9. Version bookkeeping
-- ---------------------------------------------------------------------------
UPDATE @extschema@.extension_metadata SET value = '1.1', updated_at = now()
WHERE key = 'version';
