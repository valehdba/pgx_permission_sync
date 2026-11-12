# pgx_permission_sync

A PostgreSQL extension that automatically synchronizes role and permission changes (CREATE ROLE, GRANT, REVOKE, ALTER ROLE, DROP ROLE, etc.) across all configured environments — dev, test, pre-prod, production — with full audit logging and retry capabilities.

## Installation

### Prerequisites

- PostgreSQL 14+
- `pgcrypto` and `dblink` extensions (auto-installed as dependencies)
- Superuser access on the source database
- The sync user on each target must have `CREATEROLE` and relevant `GRANT` privileges
- Network connectivity from source to all target hosts

### Install

```bash
# Clone the repository
git clone https://github.com/valehdba/pgx_permission_sync.git
cd pgx_permission_sync

# Build and install (requires pg_config in PATH)
make install

# Or specify pg_config location
make PG_CONFIG=/usr/lib/postgresql/16/bin/pg_config install
```

### Upgrade from 1.0

```sql
ALTER EXTENSION pgx_permission_sync UPDATE TO '1.1';
-- Then set a real encryption key (re-encrypts stored environment passwords):
SELECT dba_pgx_permission_sync.set_encryption_key('at-least-16-characters-long');
```

### Enable in your database

```sql
-- Install the extension (auto-installs dblink and pgcrypto)
CREATE EXTENSION pgx_permission_sync CASCADE;

-- Verify
SELECT * FROM dba_pgx_permission_sync.extension_metadata;
```

### Uninstall

```sql
-- 1. Drop the extension (this also removes its event triggers)
DROP EXTENSION pgx_permission_sync CASCADE;

-- 2. Optionally drop the cluster-wide pgsync_* roles
\i /path/to/sql/uninstall.sql
```

---

## Known limitations

- **CREATE ROLE / ALTER ROLE / DROP ROLE are not replicated.** Roles are shared
  (cluster-wide) objects and PostgreSQL does not allow event triggers for them.
  Replicated today: `GRANT`, `REVOKE`, `ALTER DEFAULT PRIVILEGES`, policies and
  schema commands, plus anything sent through `manual_sync()`. Role replication
  is planned (reconcile / `ProcessUtility` hook).
- Sync runs synchronously inside the DDL transaction; an unreachable target
  slows the originating statement down (async outbox is planned).
- `GRANT`/`REVOKE` rules cannot match on the grantee yet; `role_pattern` only
  applies to role commands.
- `dblink` and `pgcrypto` are located via their install schema when the
  extension is created; re-run the search_path block at the end of
  `pgx_permission_sync--1.0--1.1.sql` if you relocate either one.

---

## Quick Start

### 1. Register environments

```sql
SELECT dba_pgx_permission_sync.add_environment(
    p_env_name  := 'dev',
    p_host      := 'dev-db.internal',
    p_dbname    := 'appdb',
    p_username  := 'sync_admin',
    p_password  := 'secret',
    p_port      := 5432,
    p_sslmode   := 'require',
    p_env_label := 'Development',
    p_priority  := 10
);

SELECT dba_pgx_permission_sync.add_environment(
    'test', 'test-db.internal', 'appdb', 'sync_admin', 'secret',
    5432, 'require', 'Testing', 20
);

SELECT dba_pgx_permission_sync.add_environment(
    'preprod', 'preprod-db.internal', 'appdb', 'sync_admin', 'secret',
    5432, 'require', 'Pre-Production', 30
);

SELECT dba_pgx_permission_sync.add_environment(
    'prod', 'prod-db.internal', 'appdb', 'sync_admin', 'secret',
    5432, 'verify-full', 'Production', 40
);
```

### 2. Test connectivity

```sql
SELECT * FROM dba_pgx_permission_sync.test_environment_connection(1);
SELECT * FROM dba_pgx_permission_sync.test_environment_connection(2);
```

### 3. Enable sync

```sql
SELECT dba_pgx_permission_sync.enable_sync();
```

### 4. Use normally

```sql
-- This automatically replicates to all environments:
CREATE ROLE app_reader LOGIN PASSWORD 'reader_pass';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;
```

### 5. Monitor

```sql
SELECT * FROM dba_pgx_permission_sync.get_sync_status();
SELECT * FROM dba_pgx_permission_sync.v_environment_status;
SELECT * FROM dba_pgx_permission_sync.v_failed_syncs;
```

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Source Database                                     │
│                                                      │
│  DBA:  CREATE ROLE app_reader LOGIN;                 │
│        GRANT SELECT ON schema.table TO app_reader;   │
│        │                                             │
│        ▼                                             │
│  ┌─────────────────────────┐                         │
│  │  Event Trigger          │──▶ Audit Log            │
│  │  (ddl_command_end)      │                         │
│  └──────────┬──────────────┘                         │
│             ▼                                        │
│  ┌─────────────────────────┐                         │
│  │  Sync Engine            │──▶ Execution Log        │
│  │  • Check sync rules     │                         │
│  │  • Execute via dblink   │──▶ Retry Queue          │
│  │  • Record results       │                         │
│  └───┬────┬────┬────┬──────┘                         │
└──────┼────┼────┼────┼────────────────────────────────┘
       │    │    │    │
   ┌───▼┐┌──▼─┐┌▼───┐┌▼────┐
   │DEV ││TEST││PRE ││PROD │
   └────┘└────┘└────┘└─────┘
```

---

## Tables (under `dba_pgx_permission_sync` schema)

| Table | Purpose |
|---|---|
| `environments` | Target PostgreSQL instances |
| `sync_rules` | Include/exclude filters per environment |
| `sync_batches` | One row per intercepted DDL event |
| `sync_execution_log` | Per-environment result for each batch |
| `permission_audit_log` | Immutable audit trail of all permission DDL |
| `retry_queue` | Failed executions queued for retry |
| `config` | Runtime configuration key-value store |
| `secrets` | Encryption key (no role except the owner can read it) |

### Key columns in `sync_execution_log`

| Column | Description |
|---|---|
| `applied_sql` | Exact SQL sent to the target |
| `execution_status` | success / failed / skipped / rollback |
| `started_at` / `finished_at` | Execution timestamps |
| `duration_ms` | Execution time |
| `result_message` | Success details or error text |
| `error_code` / `error_detail` / `error_hint` | SQLSTATE + PG error context |
| `retry_count` / `last_retry_at` | Retry history |
| `server_version` | Target PG version |
| `connection_time_ms` | Connection establishment time |

---

## Functions

| Function | Description |
|---|---|
| `add_environment(...)` | Register a target environment |
| `remove_environment(name, hard?)` | Deactivate or delete environment |
| `test_environment_connection(id)` | Verify connectivity |
| `enable_sync()` / `disable_sync()` | Master switch |
| `enable_dry_run()` / `disable_dry_run()` | Log without executing |
| `manual_sync(sql, env?)` | Ad-hoc sync to all or one environment |
| `set_encryption_key(key)` | Rotate the key and re-encrypt stored passwords (admin only) |
| `process_retry_queue()` | Re-attempt failed syncs |
| `cleanup_old_logs()` | Purge old records per retention config |
| `get_sync_status(hours?)` | Quick dashboard |

---

## Views

| View | Shows |
|---|---|
| `v_environment_status` | Each environment + last sync + 24h stats |
| `v_recent_batches` | Recent sync batches with summaries |
| `v_execution_details` | Full per-environment execution details |
| `v_failed_syncs` | Failed executions with retry status |
| `v_audit_trail` | Audit log with sync outcome |
| `v_sync_daily_summary` | Aggregated daily statistics |

---

## Sync Rules

```sql
-- Only sync GRANT/REVOKE to production
INSERT INTO dba_pgx_permission_sync.sync_rules
    (environment_id, rule_type, command_tag)
VALUES (4, 'include', 'GRANT'), (4, 'include', 'REVOKE');

-- Exclude test roles from production
INSERT INTO dba_pgx_permission_sync.sync_rules
    (environment_id, rule_type, role_pattern)
VALUES (4, 'exclude', '^test_.*');
```

---

## Configuration

| Parameter | Default | Description |
|---|---|---|
| `sync_enabled` | `true` | Master on/off switch |
| `max_retries` | `3` | Retry attempts per failure |
| `retry_delay_seconds` | `5` | Delay between retries |
| `connection_timeout_ms` | `5000` | Connect timeout (ms) |
| `statement_timeout_ms` | `30000` | Statement timeout (ms) |
| `log_retention_days` | `90` | Sync log retention |
| `audit_retention_days` | `365` | Audit log retention |
| `encrypt_passwords` | `true` | Encrypt stored passwords (key lives in the restricted `secrets` table; rotate with `set_encryption_key()`) |
| `dry_run` | `false` | Log only, don't execute |
| `notify_on_failure` | `true` | pg_notify on failure |
| `excluded_roles` | `postgres,replication,pg_*` | Never-sync patterns |

---

## Security Roles

| Role | Capabilities |
|---|---|
| `pgsync_admin` | Full control |
| `pgsync_operator` | View logs, manual sync, test connections, process retries |
| `pgsync_reader` | Read-only access (cannot see stored passwords or raw retry SQL) |

Passwords in SQL text (`PASSWORD '...'`) are masked in `sync_batches`,
`sync_execution_log`, `permission_audit_log` and `pg_notify` payloads.

```sql
GRANT pgsync_admin TO dba_lead;
GRANT pgsync_operator TO dba_team;
GRANT pgsync_reader TO dev_lead;
```

---

## Scheduled Jobs (pg_cron)

```sql
-- Retry queue every 2 minutes
SELECT cron.schedule('pgsync-retries', '*/2 * * * *',
    $$SELECT * FROM dba_pgx_permission_sync.process_retry_queue()$$);

-- Cleanup daily at 3 AM
SELECT cron.schedule('pgsync-cleanup', '0 3 * * *',
    $$SELECT * FROM dba_pgx_permission_sync.cleanup_old_logs()$$);
```

---

## License

PostgreSQL License
