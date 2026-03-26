-- ============================================================================
-- pgx_permission_sync  --  uninstall (run before DROP EXTENSION if needed)
--
-- Event triggers are NOT schema-scoped, so they must be dropped explicitly
-- before DROP EXTENSION can succeed.  Run this script, then:
--     DROP EXTENSION pgx_permission_sync CASCADE;
-- ============================================================================

DROP EVENT TRIGGER IF EXISTS pgsync_ddl_command_end;
DROP EVENT TRIGGER IF EXISTS pgsync_sql_drop;

-- Roles are cluster-wide; clean them up if no longer needed
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pgsync_reader') THEN
        REASSIGN OWNED BY pgsync_reader   TO postgres;
        DROP OWNED BY pgsync_reader;
        DROP ROLE pgsync_reader;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pgsync_operator') THEN
        REASSIGN OWNED BY pgsync_operator TO postgres;
        DROP OWNED BY pgsync_operator;
        DROP ROLE pgsync_operator;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pgsync_admin') THEN
        REASSIGN OWNED BY pgsync_admin    TO postgres;
        DROP OWNED BY pgsync_admin;
        DROP ROLE pgsync_admin;
    END IF;
END $$;
