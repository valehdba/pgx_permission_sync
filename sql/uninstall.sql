-- ============================================================================
-- pgx_permission_sync  --  post-uninstall role cleanup
--
-- Usage (order matters):
--     DROP EXTENSION pgx_permission_sync CASCADE;   -- removes event triggers too
--     \i sql/uninstall.sql                          -- drops the cluster-wide roles
--
-- The event triggers are members of the extension and cannot be dropped on
-- their own; DROP EXTENSION removes them.
--
-- Roles are cluster-wide. If the extension is installed in several databases,
-- run DROP EXTENSION in all of them first, otherwise DROP ROLE fails with
-- "role ... cannot be dropped because some objects depend on it".
-- ============================================================================

DO $$
DECLARE
    v_role TEXT;
BEGIN
    FOREACH v_role IN ARRAY ARRAY['pgsync_reader','pgsync_operator','pgsync_admin']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_role) THEN
            EXECUTE format('REASSIGN OWNED BY %I TO %I', v_role, current_user);
            EXECUTE format('DROP OWNED BY %I', v_role);
            EXECUTE format('DROP ROLE %I', v_role);
        END IF;
    END LOOP;
END $$;
