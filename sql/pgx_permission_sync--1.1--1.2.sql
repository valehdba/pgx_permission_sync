-- ============================================================================
-- pgx_permission_sync  --  upgrade 1.1 -> 1.2   (drift detection & reconcile)
--
--   ALTER EXTENSION pgx_permission_sync UPDATE TO '1.2';
--
-- New
--   detect_drift(env)            compare source vs. one environment
--   detect_drift_all()           compare source vs. every active environment
--   reconcile(env, dry_run, allow_revoke)
--                                generate and (optionally) apply the SQL that
--                                makes the environment match the source
--   v_drift_latest / v_drift_open_items
--
-- What is compared: roles + attributes, role memberships, table / column /
-- sequence / schema / function ACLs, and default privileges.
--
-- Safety model for reconcile():
--   * dry run by default (also forced by the global `dry_run` setting)
--   * never DROPs a role; roles that exist only on the target are report-only
--   * REVOKEs (privileges the target has but the source does not) are only
--     applied with allow_revoke => true
--   * SUPERUSER / REPLICATION / BYPASSRLS are not granted to a role on the
--     target unless config `reconcile_allow_superuser` = 'true'
--   * grants on objects that do not exist on the target are "blocked"
--   * passwords are never read or copied
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Configuration
-- ---------------------------------------------------------------------------
INSERT INTO @extschema@.config (param_name, param_value, description) VALUES
    ('reconcile_excluded_schemas', 'pg_catalog,information_schema,pg_toast,@extschema@',
     'Schemas ignored by drift detection (comma separated)'),
    ('reconcile_allow_superuser', 'false',
     'Allow reconcile to give SUPERUSER / REPLICATION / BYPASSRLS to target roles'),
    ('notify_on_drift', 'true', 'pg_notify when detect_drift finds differences')
ON CONFLICT (param_name) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Tables
-- ---------------------------------------------------------------------------
CREATE TABLE @extschema@.drift_runs (
    run_id          BIGSERIAL    PRIMARY KEY,
    environment_id  INTEGER      NOT NULL REFERENCES @extschema@.environments(environment_id) ON DELETE CASCADE,
    env_name        TEXT         NOT NULL,
    run_type        TEXT         NOT NULL CHECK (run_type IN ('detect','reconcile','verify')),
    parent_run_id   BIGINT       REFERENCES @extschema@.drift_runs(run_id) ON DELETE SET NULL,
    dry_run         BOOLEAN      NOT NULL DEFAULT FALSE,
    started_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    status          TEXT         NOT NULL DEFAULT 'running'
                                 CHECK (status IN ('running','clean','drift','error')),
    missing_count   INTEGER      NOT NULL DEFAULT 0,
    extra_count     INTEGER      NOT NULL DEFAULT 0,
    different_count INTEGER      NOT NULL DEFAULT 0,
    blocked_count   INTEGER      NOT NULL DEFAULT 0,
    applied_count   INTEGER      NOT NULL DEFAULT 0,
    failed_count    INTEGER      NOT NULL DEFAULT 0,
    batch_id        BIGINT,
    error_message   TEXT,
    run_by          TEXT         NOT NULL DEFAULT session_user
);
CREATE INDEX idx_drift_runs_env ON @extschema@.drift_runs (environment_id, started_at DESC);

CREATE TABLE @extschema@.drift_items (
    item_id        BIGSERIAL PRIMARY KEY,
    run_id         BIGINT    NOT NULL REFERENCES @extschema@.drift_runs(run_id) ON DELETE CASCADE,
    kind           TEXT      NOT NULL,   -- role | member | acl | defacl
    objtype        TEXT      NOT NULL,
    objname        TEXT      NOT NULL,   -- role: raw name; others: ready-to-use quoted identifier
    subname        TEXT      NOT NULL DEFAULT '',  -- column name (acl) / owner role (defacl)
    grantee        TEXT      NOT NULL DEFAULT '',
    priv           TEXT      NOT NULL DEFAULT '',
    drift_type     TEXT      NOT NULL
                   CHECK (drift_type IN ('missing_on_target','extra_on_target','different','object_missing')),
    source_detail  TEXT,
    target_detail  TEXT,
    fix_sql        TEXT,
    fix_action     TEXT      CHECK (fix_action IN ('apply','revoke','blocked','report_only')),
    status         TEXT      NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open','applied','failed')),
    error_message  TEXT
);
CREATE INDEX idx_drift_items_run ON @extschema@.drift_items (run_id);

COMMENT ON TABLE @extschema@.drift_runs  IS 'One row per drift check / reconcile / verify run.';
COMMENT ON TABLE @extschema@.drift_items IS 'Differences found between the source and a target environment.';

GRANT SELECT ON @extschema@.drift_runs, @extschema@.drift_items TO pgsync_reader, pgsync_operator;
GRANT ALL    ON @extschema@.drift_runs, @extschema@.drift_items TO pgsync_admin;
GRANT ALL    ON SEQUENCE @extschema@.drift_runs_run_id_seq, @extschema@.drift_items_item_id_seq TO pgsync_admin;

-- ---------------------------------------------------------------------------
-- 3. Catalog snapshot query (identical SQL runs on source and on target)
--
-- Output columns: kind, objtype, objname, subname, grantee, priv, detail
--   kind='object' rows only record that an object exists (used to tell
--   "privilege missing" from "object missing on target").
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@.drift_state_sql(p_excluded_schemas TEXT[])
RETURNS TEXT LANGUAGE plpgsql STABLE AS $fn$
DECLARE
    v_nsp TEXT := $n$n.nspname <> ALL (__EXCL__)
        AND n.nspname NOT LIKE 'pg\_temp\_%' AND n.nspname NOT LIKE 'pg\_toast\_temp\_%'$n$;
    v_ext_c TEXT := $e$NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
        WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = c.oid
          AND d.refclassid = 'pg_catalog.pg_extension'::regclass AND d.deptype = 'e')$e$;
    v_ext_p TEXT := $e$NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
        WHERE d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = p.oid
          AND d.refclassid = 'pg_catalog.pg_extension'::regclass AND d.deptype = 'e')$e$;
    v_sql TEXT;
BEGIN
    v_sql := $tmpl$
SELECT 'role'::text AS kind, 'ROLE'::text AS objtype, r.rolname::text AS objname,
       ''::text AS subname, ''::text AS grantee, ''::text AS priv,
       concat_ws(' ',
         CASE WHEN r.rolsuper       THEN 'SUPERUSER'    ELSE 'NOSUPERUSER'    END,
         CASE WHEN r.rolinherit     THEN 'INHERIT'      ELSE 'NOINHERIT'      END,
         CASE WHEN r.rolcreaterole  THEN 'CREATEROLE'   ELSE 'NOCREATEROLE'   END,
         CASE WHEN r.rolcreatedb    THEN 'CREATEDB'     ELSE 'NOCREATEDB'     END,
         CASE WHEN r.rolcanlogin    THEN 'LOGIN'        ELSE 'NOLOGIN'        END,
         CASE WHEN r.rolreplication THEN 'REPLICATION'  ELSE 'NOREPLICATION'  END,
         CASE WHEN r.rolbypassrls   THEN 'BYPASSRLS'    ELSE 'NOBYPASSRLS'    END,
         'CONNECTION LIMIT ' || r.rolconnlimit)::text AS detail
  FROM pg_catalog.pg_roles r
UNION ALL
SELECT 'member', 'ROLE', gr.rolname::text, '', mr.rolname::text, '',
       'ADMIN ' || bool_or(am.admin_option)::text
  FROM pg_catalog.pg_auth_members am
  JOIN pg_catalog.pg_roles gr ON gr.oid = am.roleid
  JOIN pg_catalog.pg_roles mr ON mr.oid = am.member
 GROUP BY gr.rolname, mr.rolname
UNION ALL
SELECT 'object', CASE c.relkind WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
       format('%I.%I', n.nspname, c.relname), '', '', '', ''
  FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r','v','m','f','p','S') AND __NSP__ AND __EXTC__
UNION ALL
SELECT 'object', 'SCHEMA', quote_ident(n.nspname), '', '', '', ''
  FROM pg_catalog.pg_namespace n WHERE __NSP__
UNION ALL
SELECT 'object', CASE p.prokind WHEN 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
       format('%I.%I(%s)', n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid)),
       '', '', '', ''
  FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
 WHERE __NSP__ AND __EXTP__
UNION ALL
SELECT 'acl', CASE c.relkind WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
       format('%I.%I', n.nspname, c.relname), '',
       COALESCE(g.rolname, 'PUBLIC')::text, x.privilege_type::text,
       CASE WHEN x.is_grantable THEN 'GRANTABLE' ELSE '' END
  FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,
        pg_catalog.acldefault((CASE c.relkind WHEN 'S' THEN 's' ELSE 'r' END)::"char", c.relowner))) x
  LEFT JOIN pg_catalog.pg_roles g ON g.oid = x.grantee
 WHERE c.relkind IN ('r','v','m','f','p','S') AND x.grantee <> c.relowner
   AND __NSP__ AND __EXTC__
UNION ALL
SELECT 'acl', 'TABLE', format('%I.%I', n.nspname, c.relname), a.attname::text,
       COALESCE(g.rolname, 'PUBLIC')::text, x.privilege_type::text,
       CASE WHEN x.is_grantable THEN 'GRANTABLE' ELSE '' END
  FROM pg_catalog.pg_attribute a
  JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) x
  LEFT JOIN pg_catalog.pg_roles g ON g.oid = x.grantee
 WHERE a.attacl IS NOT NULL AND NOT a.attisdropped
   AND c.relkind IN ('r','v','m','f','p') AND __NSP__ AND __EXTC__
UNION ALL
SELECT 'acl', 'SCHEMA', quote_ident(n.nspname), '',
       COALESCE(g.rolname, 'PUBLIC')::text, x.privilege_type::text,
       CASE WHEN x.is_grantable THEN 'GRANTABLE' ELSE '' END
  FROM pg_catalog.pg_namespace n
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,
        pg_catalog.acldefault('n', n.nspowner))) x
  LEFT JOIN pg_catalog.pg_roles g ON g.oid = x.grantee
 WHERE x.grantee <> n.nspowner AND __NSP__
UNION ALL
SELECT 'acl', CASE p.prokind WHEN 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
       format('%I.%I(%s)', n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid)),
       '', COALESCE(g.rolname, 'PUBLIC')::text, x.privilege_type::text,
       CASE WHEN x.is_grantable THEN 'GRANTABLE' ELSE '' END
  FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,
        pg_catalog.acldefault('f', p.proowner))) x
  LEFT JOIN pg_catalog.pg_roles g ON g.oid = x.grantee
 WHERE x.grantee <> p.proowner AND __NSP__ AND __EXTP__
UNION ALL
SELECT 'defacl',
       CASE d.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES'
            WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' WHEN 'n' THEN 'SCHEMAS'
            ELSE d.defaclobjtype::text END,
       COALESCE(quote_ident(n.nspname), ''), r.rolname::text,
       COALESCE(g.rolname, 'PUBLIC')::text, x.privilege_type::text,
       CASE WHEN x.is_grantable THEN 'GRANTABLE' ELSE '' END
  FROM pg_catalog.pg_default_acl d
  JOIN pg_catalog.pg_roles r ON r.oid = d.defaclrole
  LEFT JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) x
  LEFT JOIN pg_catalog.pg_roles g ON g.oid = x.grantee
 WHERE x.grantee <> d.defaclrole AND (n.oid IS NULL OR (__NSP__))
$tmpl$;

    v_sql := replace(v_sql, '__NSP__',  v_nsp);
    v_sql := replace(v_sql, '__EXTC__', v_ext_c);
    v_sql := replace(v_sql, '__EXTP__', v_ext_p);
    v_sql := replace(v_sql, '__EXCL__', format('%L::text[]', p_excluded_schemas));
    RETURN v_sql;
END;
$fn$;

-- ---------------------------------------------------------------------------
-- 4. Fix-SQL generation (pure functions, unit-testable)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@.drift_fix_sql(
    p_kind TEXT, p_objtype TEXT, p_objname TEXT, p_subname TEXT,
    p_grantee TEXT, p_priv TEXT, p_drift_type TEXT,
    p_source_detail TEXT, p_target_detail TEXT
) RETURNS TEXT LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_who     TEXT;
    v_priv    TEXT;
    v_on      TEXT;
    v_opt     TEXT := '';
    v_grant   BOOLEAN;
BEGIN
    IF p_drift_type = 'object_missing' THEN RETURN NULL; END IF;

    -- ---- roles
    IF p_kind = 'role' THEN
        RETURN CASE p_drift_type
            WHEN 'missing_on_target' THEN format('CREATE ROLE %I %s', p_objname, p_source_detail)
            WHEN 'different'         THEN format('ALTER ROLE %I %s',  p_objname, p_source_detail)
            ELSE NULL END;     -- never drop roles
    END IF;

    -- ---- memberships
    IF p_kind = 'member' THEN
        RETURN CASE
            WHEN p_drift_type = 'missing_on_target' OR
                 (p_drift_type = 'different' AND p_source_detail = 'ADMIN true') THEN
                format('GRANT %I TO %I%s', p_objname, p_grantee,
                       CASE WHEN p_source_detail = 'ADMIN true' THEN ' WITH ADMIN OPTION' ELSE '' END)
            WHEN p_drift_type = 'different' THEN
                format('REVOKE ADMIN OPTION FOR %I FROM %I', p_objname, p_grantee)
            WHEN p_drift_type = 'extra_on_target' THEN
                format('REVOKE %I FROM %I', p_objname, p_grantee)
            END;
    END IF;

    -- ---- privileges: allow-list what gets pasted into SQL
    IF p_priv !~ '^[A-Z]+$' THEN RETURN NULL; END IF;
    v_who := CASE WHEN p_grantee = 'PUBLIC' THEN 'PUBLIC' ELSE quote_ident(p_grantee) END;

    -- "grant" when the source has it (missing, or different grant option set)
    v_grant := p_drift_type = 'missing_on_target'
            OR (p_drift_type = 'different' AND p_source_detail = 'GRANTABLE');

    IF p_kind = 'acl' THEN
        IF p_objtype NOT IN ('TABLE','SEQUENCE','SCHEMA','FUNCTION','PROCEDURE') THEN RETURN NULL; END IF;
        v_priv := p_priv || CASE WHEN p_subname <> '' THEN format(' (%I)', p_subname) ELSE '' END;
        v_on   := ' ON ' || p_objtype || ' ' || p_objname;
        IF v_grant THEN
            RETURN format('GRANT %s%s TO %s%s', v_priv, v_on, v_who,
                          CASE WHEN p_source_detail = 'GRANTABLE' THEN ' WITH GRANT OPTION' ELSE '' END);
        ELSIF p_drift_type = 'different' THEN
            RETURN format('REVOKE GRANT OPTION FOR %s%s FROM %s', v_priv, v_on, v_who);
        ELSE
            RETURN format('REVOKE %s%s FROM %s', v_priv, v_on, v_who);
        END IF;
    END IF;

    IF p_kind = 'defacl' THEN
        IF p_objtype NOT IN ('TABLES','SEQUENCES','FUNCTIONS','TYPES','SCHEMAS') THEN RETURN NULL; END IF;
        v_on := format('ALTER DEFAULT PRIVILEGES FOR ROLE %I%s ', p_subname,
                       CASE WHEN p_objname <> '' THEN ' IN SCHEMA ' || p_objname ELSE '' END);
        IF v_grant THEN
            RETURN format('%sGRANT %s ON %s TO %s%s', v_on, p_priv, p_objtype, v_who,
                          CASE WHEN p_source_detail = 'GRANTABLE' THEN ' WITH GRANT OPTION' ELSE '' END);
        ELSIF p_drift_type = 'different' THEN
            RETURN format('%sREVOKE GRANT OPTION FOR %s ON %s FROM %s', v_on, p_priv, p_objtype, v_who);
        ELSE
            RETURN format('%sREVOKE %s ON %s FROM %s', v_on, p_priv, p_objtype, v_who);
        END IF;
    END IF;

    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION @extschema@.drift_fix_action(
    p_kind TEXT, p_drift_type TEXT, p_source_detail TEXT,
    p_fix_sql TEXT, p_allow_privileged BOOLEAN
) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN p_drift_type = 'object_missing'              THEN 'blocked'
        WHEN p_fix_sql IS NULL                            THEN 'report_only'
        WHEN p_drift_type = 'extra_on_target'             THEN 'revoke'
        WHEN p_kind = 'role' AND NOT p_allow_privileged
             AND p_source_detail ~ '(^|\s)(SUPERUSER|REPLICATION|BYPASSRLS)(\s|$)'
                                                          THEN 'blocked'
        ELSE 'apply' END;
$$;

-- ---------------------------------------------------------------------------
-- 5. Drift check engine
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@._drift_check(
    p_environment_id INTEGER,
    p_run_type       TEXT    DEFAULT 'detect',
    p_parent_run_id  BIGINT  DEFAULT NULL
) RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE
    v_env_name TEXT;
    v_run      BIGINT;
    v_conn     TEXT;
    v_excl     TEXT[];
    v_sql      TEXT;
    v_allow    BOOLEAN;
    v_missing  INTEGER; v_extra INTEGER; v_diff INTEGER; v_blocked INTEGER; v_total INTEGER;
    v_channel  TEXT;
BEGIN
    SELECT env_name INTO v_env_name FROM @extschema@.environments
    WHERE environment_id = p_environment_id AND is_active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Environment ID % not found or inactive', p_environment_id;
    END IF;

    INSERT INTO @extschema@.drift_runs (environment_id, env_name, run_type, parent_run_id)
    VALUES (p_environment_id, v_env_name, p_run_type, p_parent_run_id)
    RETURNING run_id INTO v_run;

    v_conn := format('pgsync_drift_%s', p_environment_id);

    BEGIN
        BEGIN PERFORM dblink_disconnect(v_conn); EXCEPTION WHEN OTHERS THEN NULL; END;
        PERFORM dblink_connect(v_conn, @extschema@.build_connstr(p_environment_id));
        PERFORM dblink_exec(v_conn, format('SET statement_timeout = %L',
                    @extschema@.get_config('statement_timeout_ms','30000')));

        SELECT array_agg(trim(s)) INTO v_excl
        FROM unnest(string_to_array(@extschema@.get_config('reconcile_excluded_schemas',
             'pg_catalog,information_schema,pg_toast,@extschema@'), ',')) s
        WHERE trim(s) <> '';
        v_sql := @extschema@.drift_state_sql(COALESCE(v_excl, ARRAY[]::text[]));

        EXECUTE format($q$
            INSERT INTO @extschema@.drift_items
                (run_id, kind, objtype, objname, subname, grantee, priv,
                 drift_type, source_detail, target_detail)
            WITH s AS (%1$s),
                 t AS (SELECT * FROM dblink(%2$L, %3$L) AS x(
                           kind text, objtype text, objname text, subname text,
                           grantee text, priv text, detail text))
            SELECT %4$s,
                   COALESCE(s.kind, t.kind), COALESCE(s.objtype, t.objtype),
                   COALESCE(s.objname, t.objname), COALESCE(s.subname, t.subname),
                   COALESCE(s.grantee, t.grantee), COALESCE(s.priv, t.priv),
                   CASE
                     WHEN t.kind IS NULL THEN
                       CASE WHEN (s.kind = 'acl' AND NOT EXISTS (
                                    SELECT 1 FROM t o WHERE o.kind = 'object'
                                      AND o.objtype = s.objtype AND o.objname = s.objname))
                              OR (s.kind = 'defacl' AND s.objname <> '' AND NOT EXISTS (
                                    SELECT 1 FROM t o WHERE o.kind = 'object'
                                      AND o.objtype = 'SCHEMA' AND o.objname = s.objname))
                            THEN 'object_missing' ELSE 'missing_on_target' END
                     WHEN s.kind IS NULL THEN 'extra_on_target'
                     ELSE 'different' END,
                   s.detail, t.detail
              FROM s FULL JOIN t
                ON (s.kind, s.objtype, s.objname, s.subname, s.grantee, s.priv)
                 = (t.kind, t.objtype, t.objname, t.subname, t.grantee, t.priv)
             WHERE COALESCE(s.kind, t.kind) <> 'object'
               AND (s.kind IS NULL OR t.kind IS NULL OR s.detail IS DISTINCT FROM t.detail)
            $q$, v_sql, v_conn, v_sql, v_run);

        PERFORM dblink_disconnect(v_conn);
    EXCEPTION WHEN OTHERS THEN
        BEGIN PERFORM dblink_disconnect(v_conn); EXCEPTION WHEN OTHERS THEN NULL; END;
        DELETE FROM @extschema@.drift_items WHERE run_id = v_run;
        UPDATE @extschema@.drift_runs
           SET status = 'error', error_message = SQLERRM, finished_at = now()
         WHERE run_id = v_run;
        RETURN v_run;
    END;

    -- Honour excluded_roles (pg_*, postgres, ...)
    DELETE FROM @extschema@.drift_items WHERE run_id = v_run AND (
        (kind = 'role'   AND @extschema@.is_role_excluded(objname))
     OR (kind = 'member' AND (@extschema@.is_role_excluded(objname)
                           OR @extschema@.is_role_excluded(grantee)))
     OR (kind IN ('acl','defacl') AND grantee <> 'PUBLIC'
                                  AND @extschema@.is_role_excluded(grantee)));
    -- (the owner of a default ACL is deliberately not filtered: it is usually
    --  the bootstrap superuser, which is exactly who a DBA runs ALTER DEFAULT
    --  PRIVILEGES as)

    v_allow := @extschema@.get_config('reconcile_allow_superuser','false')::boolean;
    UPDATE @extschema@.drift_items SET fix_sql = @extschema@.drift_fix_sql(
        kind, objtype, objname, subname, grantee, priv, drift_type, source_detail, target_detail)
    WHERE run_id = v_run;
    UPDATE @extschema@.drift_items SET fix_action = @extschema@.drift_fix_action(
        kind, drift_type, source_detail, fix_sql, v_allow)
    WHERE run_id = v_run;

    SELECT count(*) FILTER (WHERE drift_type = 'missing_on_target'),
           count(*) FILTER (WHERE drift_type = 'extra_on_target'),
           count(*) FILTER (WHERE drift_type = 'different'),
           count(*) FILTER (WHERE fix_action = 'blocked'),
           count(*)
      INTO v_missing, v_extra, v_diff, v_blocked, v_total
      FROM @extschema@.drift_items WHERE run_id = v_run;

    UPDATE @extschema@.drift_runs SET
        status = CASE WHEN v_total = 0 THEN 'clean' ELSE 'drift' END,
        missing_count = v_missing, extra_count = v_extra,
        different_count = v_diff, blocked_count = v_blocked,
        finished_at = now()
    WHERE run_id = v_run;

    IF v_total > 0 AND p_run_type = 'detect'
       AND @extschema@.get_config('notify_on_drift','true')::boolean THEN
        v_channel := @extschema@.get_config('notify_channel','dba_pgx_permission_sync_alerts');
        PERFORM pg_notify(v_channel, json_build_object(
            'event','drift_detected', 'environment',v_env_name, 'run_id',v_run,
            'missing',v_missing, 'extra',v_extra, 'different',v_diff,
            'blocked',v_blocked)::text);
    END IF;

    RETURN v_run;
END;
$$;

-- ---------------------------------------------------------------------------
-- 6. Public API
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@.detect_drift(p_env_name TEXT)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE v_env_id INTEGER;
BEGIN
    SELECT environment_id INTO v_env_id FROM @extschema@.environments
    WHERE env_name = p_env_name AND is_active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Environment "%" not found or inactive', p_env_name;
    END IF;
    RETURN @extschema@._drift_check(v_env_id, 'detect');
END;
$$;

CREATE OR REPLACE FUNCTION @extschema@.detect_drift_all()
RETURNS TABLE(env_name TEXT, run_id BIGINT, status TEXT,
              missing INTEGER, extra INTEGER, different INTEGER, blocked INTEGER)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE v_env RECORD; v_run BIGINT;
BEGIN
    FOR v_env IN SELECT e.environment_id, e.env_name FROM @extschema@.environments e
                 WHERE e.is_active ORDER BY e.priority, e.environment_id
    LOOP
        v_run := @extschema@._drift_check(v_env.environment_id, 'detect');
        RETURN QUERY
            SELECT v_env.env_name, r.run_id, r.status, r.missing_count,
                   r.extra_count, r.different_count, r.blocked_count
            FROM @extschema@.drift_runs r WHERE r.run_id = v_run;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION @extschema@.reconcile(
    p_env_name     TEXT,
    p_dry_run      BOOLEAN DEFAULT TRUE,
    p_allow_revoke BOOLEAN DEFAULT FALSE
) RETURNS TABLE(item_id BIGINT, kind TEXT, drift_type TEXT, action TEXT,
                fix_sql TEXT, status TEXT, error_message TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@, pg_catalog, pg_temp AS $$
DECLARE
    v_env_id   INTEGER;
    v_run      BIGINT;
    v_dry      BOOLEAN;
    v_conn     TEXT;
    v_item     RECORD;
    v_batch    BIGINT;
    v_start    TIMESTAMPTZ;
    v_applied  INTEGER := 0;
    v_failed   INTEGER := 0;
    v_status   TEXT;
    v_err      TEXT;
    v_msg      TEXT;
BEGIN
    SELECT environment_id INTO v_env_id FROM @extschema@.environments
    WHERE env_name = p_env_name AND is_active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Environment "%" not found or inactive', p_env_name;
    END IF;

    IF NOT pg_try_advisory_xact_lock(hashtext('pgx_permission_sync.reconcile'), v_env_id) THEN
        RAISE EXCEPTION 'A reconcile for environment "%" is already running', p_env_name;
    END IF;

    v_dry := p_dry_run OR @extschema@.get_config('dry_run','false')::boolean;

    v_run := @extschema@._drift_check(v_env_id, 'reconcile');
    SELECT r.status, r.error_message INTO v_status, v_err
    FROM @extschema@.drift_runs r WHERE r.run_id = v_run;
    IF v_status = 'error' THEN
        RAISE EXCEPTION 'Drift check failed for "%": %', p_env_name, v_err;
    END IF;

    UPDATE @extschema@.drift_runs SET dry_run = v_dry WHERE run_id = v_run;

    IF NOT v_dry THEN
        v_conn  := format('pgsync_reconcile_%s', v_env_id);
        v_start := clock_timestamp();

        INSERT INTO @extschema@.sync_batches (
            source_command, source_sql, source_user, object_type, batch_status)
        VALUES ('RECONCILE', format('reconcile run %s on %s', v_run, p_env_name),
                session_user, 'DRIFT', 'in_progress')
        RETURNING batch_id INTO v_batch;

        BEGIN PERFORM dblink_disconnect(v_conn); EXCEPTION WHEN OTHERS THEN NULL; END;
        PERFORM dblink_connect(v_conn, @extschema@.build_connstr(v_env_id));
        PERFORM dblink_exec(v_conn, format('SET statement_timeout = %L',
                    @extschema@.get_config('statement_timeout_ms','30000')));

        FOR v_item IN
            SELECT i.* FROM @extschema@.drift_items i
            WHERE i.run_id = v_run
              AND (i.fix_action = 'apply' OR (i.fix_action = 'revoke' AND p_allow_revoke))
            ORDER BY CASE i.kind WHEN 'role' THEN 1 WHEN 'member' THEN 2
                                 WHEN 'acl' THEN 3 ELSE 4 END,
                     CASE i.fix_action WHEN 'apply' THEN 1 ELSE 2 END,
                     CASE i.drift_type WHEN 'missing_on_target' THEN 1 ELSE 2 END,
                     i.item_id
        LOOP
            v_start := clock_timestamp();
            BEGIN
                PERFORM dblink_exec(v_conn, v_item.fix_sql);
                UPDATE @extschema@.drift_items SET status = 'applied'
                WHERE drift_items.item_id = v_item.item_id;
                INSERT INTO @extschema@.sync_execution_log (
                    batch_id, environment_id, env_name, applied_sql, execution_status,
                    started_at, finished_at, duration_ms, result_message)
                VALUES (v_batch, v_env_id, p_env_name, v_item.fix_sql, 'success',
                        v_start, now(),
                        (EXTRACT(EPOCH FROM (clock_timestamp() - v_start)) * 1000)::bigint,
                        'Reconciled');
                v_applied := v_applied + 1;
            EXCEPTION WHEN OTHERS THEN
                v_msg := SQLERRM;
                UPDATE @extschema@.drift_items SET status = 'failed', error_message = v_msg
                WHERE drift_items.item_id = v_item.item_id;
                INSERT INTO @extschema@.sync_execution_log (
                    batch_id, environment_id, env_name, applied_sql, execution_status,
                    started_at, finished_at, duration_ms, result_message, error_code)
                VALUES (v_batch, v_env_id, p_env_name, v_item.fix_sql, 'failed',
                        v_start, now(),
                        (EXTRACT(EPOCH FROM (clock_timestamp() - v_start)) * 1000)::bigint,
                        v_msg, SQLSTATE);
                v_failed := v_failed + 1;
            END;
        END LOOP;

        PERFORM dblink_disconnect(v_conn);

        UPDATE @extschema@.sync_batches SET
            total_targets = v_applied + v_failed, success_count = v_applied,
            failure_count = v_failed, completed_at = now(),
            batch_status = CASE WHEN v_failed = 0 THEN 'completed'
                                WHEN v_applied = 0 THEN 'failed' ELSE 'partial' END
        WHERE batch_id = v_batch;

        UPDATE @extschema@.drift_runs SET
            applied_count = v_applied, failed_count = v_failed, batch_id = v_batch
        WHERE run_id = v_run;

        -- re-check so the operator can see what is still different
        PERFORM @extschema@._drift_check(v_env_id, 'verify', v_run);
    END IF;

    RETURN QUERY
        SELECT i.item_id, i.kind, i.drift_type, i.fix_action, i.fix_sql,
               CASE WHEN i.status <> 'open' THEN i.status
                    WHEN i.fix_action = 'apply'
                      OR (i.fix_action = 'revoke' AND p_allow_revoke)
                         THEN CASE WHEN v_dry THEN 'planned' ELSE 'open' END
                    ELSE 'skipped' END,
               i.error_message
        FROM @extschema@.drift_items i
        WHERE i.run_id = v_run
        ORDER BY CASE i.kind WHEN 'role' THEN 1 WHEN 'member' THEN 2
                             WHEN 'acl' THEN 3 ELSE 4 END, i.item_id;
EXCEPTION WHEN OTHERS THEN
    BEGIN PERFORM dblink_disconnect(format('pgsync_reconcile_%s', v_env_id));
    EXCEPTION WHEN OTHERS THEN NULL; END;
    RAISE;
END;
$$;

-- ---------------------------------------------------------------------------
-- 7. Views
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW @extschema@.v_drift_latest AS
SELECT DISTINCT ON (r.environment_id)
       r.environment_id, r.env_name, r.run_id, r.run_type, r.started_at, r.finished_at,
       r.status, r.missing_count, r.extra_count, r.different_count, r.blocked_count,
       r.applied_count, r.failed_count, r.error_message
FROM @extschema@.drift_runs r
ORDER BY r.environment_id, r.run_id DESC;

CREATE OR REPLACE VIEW @extschema@.v_drift_open_items AS
SELECT l.env_name, l.run_id, i.item_id, i.kind, i.objtype, i.objname, i.subname,
       i.grantee, i.priv, i.drift_type, i.fix_action, i.fix_sql
FROM @extschema@.v_drift_latest l
JOIN @extschema@.drift_items i ON i.run_id = l.run_id
WHERE l.status = 'drift'
ORDER BY l.env_name, i.item_id;

GRANT SELECT ON @extschema@.v_drift_latest, @extschema@.v_drift_open_items
    TO pgsync_reader, pgsync_operator, pgsync_admin;

-- ---------------------------------------------------------------------------
-- 8. Retention: drift history follows log_retention_days
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION @extschema@.cleanup_old_logs()
RETURNS TABLE(sync_logs_deleted BIGINT, audit_logs_deleted BIGINT, retries_deleted BIGINT)
LANGUAGE plpgsql SET search_path = @extschema@, pg_catalog, pg_temp AS $$
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

    DELETE FROM @extschema@.drift_runs
    WHERE started_at < now()-(v_sync_days||' days')::interval;

    RETURN QUERY SELECT v_sd, v_ad, v_rd;
END;
$$;

-- ---------------------------------------------------------------------------
-- 9. Privileges
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION @extschema@._drift_check(INTEGER, TEXT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.detect_drift(TEXT)                  FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.detect_drift_all()                  FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.reconcile(TEXT, BOOLEAN, BOOLEAN)   FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.detect_drift(TEXT)     TO pgsync_admin, pgsync_operator;
GRANT EXECUTE ON FUNCTION @extschema@.detect_drift_all()     TO pgsync_admin, pgsync_operator;
GRANT EXECUTE ON FUNCTION @extschema@.reconcile(TEXT, BOOLEAN, BOOLEAN) TO pgsync_admin;

-- ---------------------------------------------------------------------------
-- 10. Pin search_path to the schemas that hold dblink / pgcrypto (see 1.1)
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

UPDATE @extschema@.extension_metadata SET value = '1.2', updated_at = now()
WHERE key = 'version';
