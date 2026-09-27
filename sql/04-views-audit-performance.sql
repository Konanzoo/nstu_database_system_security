\set ON_ERROR_STOP on
\pset pager off

\echo '== 04-views-audit-performance: safe views, change audit and RLS benchmark =='

SET ROLE app_owner;

CREATE OR REPLACE VIEW app.v_open_task
WITH (security_invoker = true)
AS
SELECT
    task_id,
    segment_id,
    project_id,
    assignee_actor_id,
    title,
    status_code,
    priority,
    due_date,
    updated_at
FROM app.task
WHERE status_code IN ('new', 'in_progress', 'blocked')
  AND priority BETWEEN 1 AND 3
WITH CASCADED CHECK OPTION;

CREATE OR REPLACE VIEW app.v_task_summary
WITH (
    security_barrier = true,
    security_invoker = true
)
AS
SELECT
    segment_id,
    status_code,
    count(*) AS task_count,
    sum(planned_hours) AS planned_hours_sum,
    sum(COALESCE(actual_hours, 0)) AS actual_hours_sum
FROM app.task
GROUP BY segment_id, status_code;

GRANT SELECT ON app.v_open_task TO app_reader;
GRANT UPDATE (assignee_actor_id, title, priority, due_date)
ON app.v_open_task TO app_writer;
GRANT SELECT ON app.v_task_summary TO app_writer, auditor;

RESET ROLE;

SET ROLE audit_owner;

CREATE TABLE IF NOT EXISTS audit.row_change_log (
    change_id       bigint GENERATED ALWAYS AS IDENTITY,
    changed_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor_role      name        NOT NULL,
    effective_role  name        NOT NULL,
    schema_name     name        NOT NULL,
    table_name      name        NOT NULL,
    operation       text        NOT NULL,
    segment_id      smallint,
    row_pk          jsonb       NOT NULL,
    old_data        jsonb,
    new_data        jsonb,
    txid            xid8        DEFAULT pg_current_xact_id_if_assigned(),
    CONSTRAINT pk_row_change_log PRIMARY KEY (change_id),
    CONSTRAINT ck_row_change_log_operation
        CHECK (operation IN ('UPDATE', 'DELETE'))
);

CREATE INDEX IF NOT EXISTS ix_row_change_log_time
    ON audit.row_change_log (changed_at DESC);
CREATE INDEX IF NOT EXISTS ix_row_change_log_table_time
    ON audit.row_change_log (schema_name, table_name, changed_at DESC);
CREATE INDEX IF NOT EXISTS ix_row_change_log_actor_time
    ON audit.row_change_log (actor_role, changed_at DESC);

CREATE TABLE IF NOT EXISTS audit.row_change_log_archive (
    change_id       bigint      NOT NULL,
    changed_at      timestamptz NOT NULL,
    actor_role      name        NOT NULL,
    effective_role  name        NOT NULL,
    schema_name     name        NOT NULL,
    table_name      name        NOT NULL,
    operation       text        NOT NULL,
    segment_id      smallint,
    row_pk          jsonb       NOT NULL,
    old_data        jsonb,
    new_data        jsonb,
    txid            xid8,
    archived_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_row_change_log_archive PRIMARY KEY (change_id),
    CONSTRAINT ck_row_change_log_archive_operation
        CHECK (operation IN ('UPDATE', 'DELETE'))
);

CREATE INDEX IF NOT EXISTS ix_row_change_log_archive_time
    ON audit.row_change_log_archive (changed_at DESC);

CREATE OR REPLACE FUNCTION audit.mask_audit_row(
    p_table_name text,
    p_row jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, audit, pg_temp
AS $function$
DECLARE
    v_result jsonb;
    v_email text;
BEGIN
    IF p_row IS NULL THEN
        RETURN NULL;
    END IF;

    v_result := p_row;
    IF p_table_name = 'actor' THEN
        v_email := p_row ->> 'email';
        v_result := v_result - 'email' - 'phone';
        IF v_email IS NOT NULL THEN
            v_result := v_result || jsonb_build_object(
                'email_sha256',
                encode(sha256(convert_to(lower(v_email), 'UTF8')), 'hex')
            );
        END IF;
        v_result := v_result || jsonb_build_object('phone', '[REDACTED]');
    END IF;

    RETURN v_result;
END;
$function$;

CREATE OR REPLACE FUNCTION audit.capture_row_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, pg_temp
AS $function$
DECLARE
    v_old jsonb;
    v_new jsonb;
    v_source jsonb;
    v_pk jsonb;
    v_segment_id smallint;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        v_old := to_jsonb(OLD);
        v_new := to_jsonb(NEW);
        v_source := v_new;
    ELSIF TG_OP = 'DELETE' THEN
        v_old := to_jsonb(OLD);
        v_new := NULL;
        v_source := v_old;
    ELSE
        RAISE EXCEPTION 'Unsupported operation: %', TG_OP;
    END IF;

    v_segment_id := NULLIF(v_source ->> 'segment_id', '')::smallint;
    v_pk := CASE TG_TABLE_NAME
        WHEN 'actor' THEN jsonb_build_object('actor_id', v_source -> 'actor_id')
        WHEN 'project' THEN jsonb_build_object('project_id', v_source -> 'project_id')
        WHEN 'task' THEN jsonb_build_object('task_id', v_source -> 'task_id')
        ELSE jsonb_build_object('unknown', NULL)
    END;

    INSERT INTO audit.row_change_log (
        changed_at, actor_role, effective_role, schema_name,
        table_name, operation, segment_id, row_pk,
        old_data, new_data, txid
    )
    VALUES (
        clock_timestamp(), session_user, current_user, TG_TABLE_SCHEMA,
        TG_TABLE_NAME, TG_OP, v_segment_id, v_pk,
        audit.mask_audit_row(TG_TABLE_NAME, v_old),
        audit.mask_audit_row(TG_TABLE_NAME, v_new),
        pg_current_xact_id_if_assigned()
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION audit.backup_audit_logs(
    p_days_interval integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, pg_temp
AS $function$
DECLARE
    v_moved integer;
BEGIN
    IF p_days_interval IS NULL
       OR p_days_interval < 1 OR p_days_interval > 3650 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'days_interval должен быть в диапазоне 1..3650';
    END IF;

    WITH moved AS (
        DELETE FROM audit.row_change_log
        WHERE changed_at < clock_timestamp()
                         - make_interval(days => p_days_interval)
        RETURNING
            change_id, changed_at, actor_role, effective_role,
            schema_name, table_name, operation, segment_id,
            row_pk, old_data, new_data, txid
    )
    INSERT INTO audit.row_change_log_archive (
        change_id, changed_at, actor_role, effective_role,
        schema_name, table_name, operation, segment_id,
        row_pk, old_data, new_data, txid, archived_at
    )
    SELECT
        change_id, changed_at, actor_role, effective_role,
        schema_name, table_name, operation, segment_id,
        row_pk, old_data, new_data, txid, clock_timestamp()
    FROM moved;

    GET DIAGNOSTICS v_moved = ROW_COUNT;
    RETURN v_moved;
END;
$function$;

REVOKE ALL ON FUNCTION audit.mask_audit_row(text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.capture_row_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.backup_audit_logs(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.capture_row_change() TO app_owner;
GRANT SELECT ON audit.row_change_log, audit.row_change_log_archive TO auditor;

RESET ROLE;

GRANT USAGE ON SCHEMA audit TO dml_admin;
GRANT EXECUTE ON FUNCTION audit.backup_audit_logs(integer) TO dml_admin;

SET ROLE app_owner;

DROP TRIGGER IF EXISTS trg_audit_actor_change ON app.actor;
DROP TRIGGER IF EXISTS trg_audit_project_change ON app.project;
DROP TRIGGER IF EXISTS trg_audit_task_change ON app.task;

CREATE TRIGGER trg_audit_actor_change
AFTER UPDATE OR DELETE ON app.actor
FOR EACH ROW EXECUTE FUNCTION audit.capture_row_change();
CREATE TRIGGER trg_audit_project_change
AFTER UPDATE OR DELETE ON app.project
FOR EACH ROW EXECUTE FUNCTION audit.capture_row_change();
CREATE TRIGGER trg_audit_task_change
AFTER UPDATE OR DELETE ON app.task
FOR EACH ROW EXECUTE FUNCTION audit.capture_row_change();

-- Performance test tables are created once; bulk loading is optional below.
CREATE TABLE IF NOT EXISTS stg.task_perf_no_rls (
    task_id     bigint   NOT NULL,
    segment_id smallint NOT NULL,
    status_code text     NOT NULL,
    due_date    date,
    payload     text     NOT NULL,
    CONSTRAINT pk_task_perf_no_rls PRIMARY KEY (task_id),
    CONSTRAINT ck_task_perf_no_rls_segment CHECK (segment_id BETWEEN 1 AND 3),
    CONSTRAINT ck_task_perf_no_rls_status
        CHECK (status_code IN ('new', 'in_progress', 'blocked', 'done'))
);

CREATE TABLE IF NOT EXISTS stg.task_perf_rls
(LIKE stg.task_perf_no_rls INCLUDING ALL);

ALTER TABLE stg.task_perf_rls ENABLE ROW LEVEL SECURITY;
ALTER TABLE stg.task_perf_rls FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS task_perf_segment ON stg.task_perf_rls;
DROP POLICY IF EXISTS task_perf_load ON stg.task_perf_rls;
CREATE POLICY task_perf_segment ON stg.task_perf_rls
FOR SELECT TO app_reader, app_owner
USING (segment_id = app.effective_segment_id());
CREATE POLICY task_perf_load ON stg.task_perf_rls
FOR INSERT TO app_owner
WITH CHECK (true);

RESET ROLE;

GRANT USAGE ON SCHEMA stg TO app_reader;
GRANT SELECT ON stg.task_perf_no_rls, stg.task_perf_rls TO app_reader;

\if :{?run_perf_setup}
\else
    \set run_perf_setup 0
\endif

\if :run_perf_setup
    \echo 'Loading 300,000 rows and running pre/post-index EXPLAIN plans'
    SET ROLE app_owner;
    DROP INDEX IF EXISTS stg.ix_task_perf_no_rls_segment_status_due;
    DROP INDEX IF EXISTS stg.ix_task_perf_rls_segment_status_due;
    DROP INDEX IF EXISTS stg.ix_task_perf_rls_segment_due_id;
    TRUNCATE stg.task_perf_no_rls, stg.task_perf_rls;

    INSERT INTO stg.task_perf_no_rls (
        task_id, segment_id, status_code, due_date, payload
    )
    SELECT
        g,
        (((g - 1) % 3) + 1)::smallint,
        CASE g % 4
            WHEN 0 THEN 'new'
            WHEN 1 THEN 'in_progress'
            WHEN 2 THEN 'blocked'
            ELSE 'done'
        END,
        DATE '2026-01-01' + (g % 365)::integer,
        repeat('x', 100)
    FROM generate_series(1, 300000) AS g;

    INSERT INTO stg.task_perf_rls
    SELECT * FROM stg.task_perf_no_rls;
    RESET ROLE;

    ANALYZE stg.task_perf_no_rls;
    ANALYZE stg.task_perf_rls;

    SET SESSION AUTHORIZATION lab_alice;
    \echo 'Pre-index control plan'
    EXPLAIN (ANALYZE, BUFFERS, TIMING OFF, SUMMARY ON)
    SELECT count(*)
    FROM stg.task_perf_no_rls
    WHERE segment_id = 1
      AND status_code = 'in_progress'
      AND due_date BETWEEN DATE '2026-04-01' AND DATE '2026-06-30';

    \echo 'Pre-index RLS plan'
    EXPLAIN (ANALYZE, BUFFERS, TIMING OFF, SUMMARY ON)
    SELECT count(*)
    FROM stg.task_perf_rls
    WHERE status_code = 'in_progress'
      AND due_date BETWEEN DATE '2026-04-01' AND DATE '2026-06-30';
    RESET SESSION AUTHORIZATION;

    SET ROLE app_owner;
    CREATE INDEX ix_task_perf_no_rls_segment_status_due
        ON stg.task_perf_no_rls (segment_id, status_code, due_date);
    CREATE INDEX ix_task_perf_rls_segment_status_due
        ON stg.task_perf_rls (segment_id, status_code, due_date);
    CREATE INDEX ix_task_perf_rls_segment_due_id
        ON stg.task_perf_rls (segment_id, due_date, task_id)
        INCLUDE (status_code);
    RESET ROLE;

    VACUUM (ANALYZE) stg.task_perf_no_rls;
    VACUUM (ANALYZE) stg.task_perf_rls;

    SET SESSION AUTHORIZATION lab_alice;
    \echo 'Post-index control plan'
    EXPLAIN (ANALYZE, BUFFERS, TIMING OFF, SUMMARY ON)
    SELECT count(*)
    FROM stg.task_perf_no_rls
    WHERE segment_id = 1
      AND status_code = 'in_progress'
      AND due_date BETWEEN DATE '2026-04-01' AND DATE '2026-06-30';

    \echo 'Post-index RLS plan'
    EXPLAIN (ANALYZE, BUFFERS, TIMING OFF, SUMMARY ON)
    SELECT count(*)
    FROM stg.task_perf_rls
    WHERE status_code = 'in_progress'
      AND due_date BETWEEN DATE '2026-04-01' AND DATE '2026-06-30';
    RESET SESSION AUTHORIZATION;
\else
    \echo 'Performance data skipped; rerun with -v run_perf_setup=1 to benchmark'
\endif

\echo '04-views-audit-performance completed'
