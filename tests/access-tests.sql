\set ON_ERROR_STOP on
\pset pager off
\timing on

\echo '== Access and security regression tests =='
\echo 'Run as a local superuser after sql/init.sql'

-- Test 1: deployment inventory.
DO $test$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace
        WHERE nspname IN ('app', 'ref', 'audit', 'stg')
        GROUP BY true HAVING count(*) = 4
    ) THEN
        RAISE EXCEPTION 'T01: required schemas are missing';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname IN ('app_owner', 'app_writer', 'app_reader', 'auditor')
          AND (rolsuper OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'T01: an application role can bypass RLS';
    END IF;
END
$test$;
\echo 'PASS T01: objects and role attributes'

-- Test 2: Alice sees only segment 1.
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
DO $test$
DECLARE
    v_rows integer;
    v_foreign integer;
BEGIN
    SELECT count(project_id), count(project_id) FILTER (WHERE segment_id <> 1)
    INTO v_rows, v_foreign
    FROM app.project;
    IF v_rows <> 4 OR v_foreign <> 0 THEN
        RAISE EXCEPTION 'T02: Alice saw rows %, foreign rows %', v_rows, v_foreign;
    END IF;
END
$test$;
ROLLBACK;
RESET SESSION AUTHORIZATION;
\echo 'PASS T02: Alice RLS isolation'

-- Test 3: Bob sees only segment 2.
BEGIN;
SET SESSION AUTHORIZATION lab_bob;
DO $test$
DECLARE
    v_rows integer;
    v_foreign integer;
BEGIN
    SELECT count(task_id), count(task_id) FILTER (WHERE segment_id <> 2)
    INTO v_rows, v_foreign
    FROM app.task;
    IF v_rows <> 5 OR v_foreign <> 0 THEN
        RAISE EXCEPTION 'T03: Bob saw rows %, foreign rows %', v_rows, v_foreign;
    END IF;
END
$test$;
ROLLBACK;
RESET SESSION AUTHORIZATION;
\echo 'PASS T03: Bob RLS isolation'

-- Test 4: auditor sees all segments but has no write role.
BEGIN;
SET SESSION AUTHORIZATION lab_auditor;
DO $test$
DECLARE
    v_rows integer;
    v_segments integer;
BEGIN
    SELECT count(project_id), count(DISTINCT segment_id)
    INTO v_rows, v_segments
    FROM app.project;
    IF v_rows <> 12 OR v_segments <> 3 THEN
        RAISE EXCEPTION 'T04: auditor saw rows %, segments %', v_rows, v_segments;
    END IF;
END
$test$;
ROLLBACK;
RESET SESSION AUTHORIZATION;
\echo 'PASS T04: auditor read-all RLS policy'

-- Test 5: validated SET LOCAL context works in the same transaction.
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
SELECT app.set_session_ctx(1, 1);
DO $test$
BEGIN
    IF current_setting('app.segment_id', true) <> '1'
       OR current_setting('app.actor_id', true) <> '1' THEN
        RAISE EXCEPTION 'T05: context was not installed';
    END IF;
END
$test$;
ROLLBACK;
RESET SESSION AUTHORIZATION;
\echo 'PASS T05: valid session context'

-- Test 6: foreign context is rejected.
\set ON_ERROR_STOP off
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
SELECT app.set_session_ctx(2, 5);
\if :ERROR
    \echo 'PASS T06: foreign context rejected'
\else
    \echo 'FAIL T06: foreign context unexpectedly accepted'
    ROLLBACK;
    RESET SESSION AUTHORIZATION;
    \quit 1
\endif
ROLLBACK;
RESET SESSION AUTHORIZATION;
\set ON_ERROR_STOP on

-- Test 7: a cross-segment INSERT is rejected by WITH CHECK.
\set ON_ERROR_STOP off
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
INSERT INTO app.task (
    segment_id, project_id, assignee_actor_id, title,
    status_code, priority, planned_hours
)
VALUES (2, 201, 5, 'Cross-segment test', 'new', 3, 1);
\if :ERROR
    \echo 'PASS T07: cross-segment INSERT rejected'
\else
    \echo 'FAIL T07: cross-segment INSERT succeeded'
    ROLLBACK;
    RESET SESSION AUTHORIZATION;
    \quit 1
\endif
ROLLBACK;
RESET SESSION AUTHORIZATION;
\set ON_ERROR_STOP on

-- Test 8: an allowed update in the caller's segment succeeds.
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
UPDATE app.task SET title = 'Allowed local update' WHERE task_id = 1001;
DO $test$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM app.task
        WHERE task_id = 1001 AND title = 'Allowed local update'
    ) THEN
        RAISE EXCEPTION 'T08: local update did not affect the task';
    END IF;
END
$test$;
ROLLBACK;
RESET SESSION AUTHORIZATION;
\echo 'PASS T08: local UPDATE accepted'

-- Test 9: PII cannot be selected by an ordinary writer.
\set ON_ERROR_STOP off
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
SELECT email FROM app.actor LIMIT 1;
\if :ERROR
    \echo 'PASS T09: PII column access rejected'
\else
    \echo 'FAIL T09: PII column was readable'
    ROLLBACK;
    RESET SESSION AUTHORIZATION;
    \quit 1
\endif
ROLLBACK;
RESET SESSION AUTHORIZATION;
\set ON_ERROR_STOP on

-- Test 10: non-administrator cannot execute DDL in app.
\set ON_ERROR_STOP off
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
CREATE TABLE app.should_not_exist (id integer);
\if :ERROR
    \echo 'PASS T10: unauthorized DDL rejected'
\else
    \echo 'FAIL T10: unauthorized DDL succeeded'
    ROLLBACK;
    RESET SESSION AUTHORIZATION;
    \quit 1
\endif
ROLLBACK;
RESET SESSION AUTHORIZATION;
\set ON_ERROR_STOP on

-- Test 11: direct DML into audit is prohibited.
\set ON_ERROR_STOP off
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
INSERT INTO audit.function_calls (
    function_name, caller_role, success, error_message
)
VALUES ('forged.call', 'lab_alice', true, NULL);
\if :ERROR
    \echo 'PASS T11: direct audit INSERT rejected'
\else
    \echo 'FAIL T11: direct audit INSERT succeeded'
    ROLLBACK;
    RESET SESSION AUTHORIZATION;
    \quit 1
\endif
ROLLBACK;
RESET SESSION AUTHORIZATION;
\set ON_ERROR_STOP on

-- Test 12: valid SECURITY DEFINER operation succeeds and is logged.
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
DO $test$
DECLARE
    v_ok boolean;
BEGIN
    SELECT r.ok INTO v_ok
    FROM app.create_project(
        'Automated access test', 'Temporary test row', 1000,
        DATE '2026-09-01', NULL
    ) AS r;
    IF v_ok IS NOT TRUE THEN
        RAISE EXCEPTION 'T12: create_project returned false';
    END IF;
END
$test$;
RESET SESSION AUTHORIZATION;
DO $test$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit.function_calls
        WHERE function_name = 'app.create_project'
          AND caller_role = 'lab_alice'
          AND success
    ) THEN
        RAISE EXCEPTION 'T12: successful call was not logged';
    END IF;
END
$test$;
ROLLBACK;
\echo 'PASS T12: valid SECURITY DEFINER call and log'

-- Test 13: invalid SECURITY DEFINER input returns a controlled failure and log.
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
DO $test$
DECLARE
    v_ok boolean;
BEGIN
    SELECT r.ok INTO v_ok
    FROM app.create_project(
        'x', 'Invalid test', -1,
        DATE '2026-09-01', NULL
    ) AS r;
    IF v_ok IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'T13: invalid input was not rejected';
    END IF;
END
$test$;
RESET SESSION AUTHORIZATION;
DO $test$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit.function_calls
        WHERE function_name = 'app.create_project'
          AND caller_role = 'lab_alice'
          AND NOT success
    ) THEN
        RAISE EXCEPTION 'T13: failed call was not logged';
    END IF;
END
$test$;
ROLLBACK;
\echo 'PASS T13: invalid SECURITY DEFINER call and log'

-- Test 14: WITH CHECK OPTION prevents a row from leaving the view predicate.
\set ON_ERROR_STOP off
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
UPDATE app.v_open_task SET priority = 5 WHERE task_id = 1001;
\if :ERROR
    \echo 'PASS T14: WITH CHECK OPTION enforced'
\else
    \echo 'FAIL T14: view predicate was bypassed'
    ROLLBACK;
    RESET SESSION AUTHORIZATION;
    \quit 1
\endif
ROLLBACK;
RESET SESSION AUTHORIZATION;
\set ON_ERROR_STOP on

-- Test 15: a real UPDATE produces a masked, attributable audit event.
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
UPDATE app.actor
SET email = 'anna.audit-test@example.test', phone = '+7-999-999-9999'
WHERE actor_id = 1;
RESET SESSION AUTHORIZATION;
DO $test$
DECLARE
    v_old jsonb;
    v_new jsonb;
BEGIN
    SELECT old_data, new_data
    INTO v_old, v_new
    FROM audit.row_change_log
    WHERE table_name = 'actor' AND actor_role = 'lab_alice'
    ORDER BY change_id DESC
    LIMIT 1;

    IF v_new IS NULL
       OR v_new ? 'email'
       OR NOT (v_new ? 'email_sha256')
       OR v_new ->> 'phone' <> '[REDACTED]' THEN
        RAISE EXCEPTION 'T15: PII masking or audit capture failed: %', v_new;
    END IF;
END
$test$;
ROLLBACK;
\echo 'PASS T15: change audit and PII masking'

-- Test 16: sensitive deletion fails without an active grant.
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
DO $test$
DECLARE
    v_ok boolean;
BEGIN
    SELECT r.ok INTO v_ok FROM app.delete_task_jit(1002) AS r;
    IF v_ok IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'T16: deletion succeeded without JIT grant';
    END IF;
END
$test$;
ROLLBACK;
RESET SESSION AUTHORIZATION;
\echo 'PASS T16: missing JIT grant rejected'

-- Test 17: request -> operation succeeds in the same backend and segment.
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
DO $test$
DECLARE
    v_granted boolean;
    v_deleted boolean;
BEGIN
    SELECT r.ok INTO v_granted
    FROM audit.request_temp_privilege('task.delete', 1) AS r;
    SELECT r.ok INTO v_deleted FROM app.delete_task_jit(1002) AS r;
    IF v_granted IS NOT TRUE OR v_deleted IS NOT TRUE THEN
        RAISE EXCEPTION 'T17: grant %, delete %', v_granted, v_deleted;
    END IF;
END
$test$;
ROLLBACK;
RESET SESSION AUTHORIZATION;
\echo 'PASS T17: active JIT grant accepted'

-- Test 18: simulate TTL expiry server-side; a forged GUC cannot extend it.
BEGIN;
SET SESSION AUTHORIZATION lab_alice;
SELECT ok FROM audit.request_temp_privilege('task.delete', 1);
RESET SESSION AUTHORIZATION;
SET ROLE audit_owner;
UPDATE audit.temp_access_grant
SET granted_at = clock_timestamp() - interval '2 minutes',
    expires_at = clock_timestamp() - interval '1 second'
WHERE caller_role = 'lab_alice'
  AND backend_pid = pg_backend_pid()
  AND revoked_at IS NULL;
RESET ROLE;
SET SESSION AUTHORIZATION lab_alice;
SELECT set_config('app.temp_privilege_until', '2999-01-01 00:00:00+00', false);
DO $test$
DECLARE
    v_ok boolean;
BEGIN
    SELECT r.ok INTO v_ok FROM app.delete_task_jit(1002) AS r;
    IF v_ok IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'T18: expired server-side grant was accepted';
    END IF;
END
$test$;
ROLLBACK;
RESET SESSION AUTHORIZATION;
\echo 'PASS T18: expiry enforced despite forged GUC'

\echo 'All access tests passed'
