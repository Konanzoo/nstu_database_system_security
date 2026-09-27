\set ON_ERROR_STOP on
\pset pager off

\echo '== 03-rls: validated session context and row-level security =='

SET ROLE app_owner;

CREATE OR REPLACE FUNCTION app.effective_segment_id()
RETURNS smallint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, ref, pg_temp
AS $function$
DECLARE
    v_mapped_segment smallint;
    v_requested_text text;
    v_requested_segment smallint;
BEGIN
    SELECT rs.segment_id
    INTO v_mapped_segment
    FROM ref.role_segment AS rs
    WHERE rs.login_role = session_user
      AND rs.is_active
      AND rs.valid_from <= statement_timestamp()
      AND (rs.valid_until IS NULL OR rs.valid_until > statement_timestamp());

    IF v_mapped_segment IS NULL THEN
        RETURN NULL;
    END IF;

    v_requested_text := current_setting('app.segment_id', true);
    IF v_requested_text IS NULL OR v_requested_text = '' THEN
        RETURN v_mapped_segment;
    END IF;

    BEGIN
        v_requested_segment := v_requested_text::smallint;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'Некорректное значение app.segment_id';
    END;

    IF v_requested_segment <> v_mapped_segment THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Запрошенный сегмент не принадлежит роли сеанса';
    END IF;

    RETURN v_mapped_segment;
END;
$function$;

CREATE OR REPLACE FUNCTION app.effective_actor_id()
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, ref, pg_temp
AS $function$
DECLARE
    v_mapped_actor bigint;
    v_requested_text text;
    v_requested_actor bigint;
BEGIN
    SELECT rs.actor_id
    INTO v_mapped_actor
    FROM ref.role_segment AS rs
    WHERE rs.login_role = session_user
      AND rs.is_active
      AND rs.valid_from <= statement_timestamp()
      AND (rs.valid_until IS NULL OR rs.valid_until > statement_timestamp());

    IF v_mapped_actor IS NULL THEN
        RETURN NULL;
    END IF;

    v_requested_text := current_setting('app.actor_id', true);
    IF v_requested_text IS NULL OR v_requested_text = '' THEN
        RETURN v_mapped_actor;
    END IF;

    BEGIN
        v_requested_actor := v_requested_text::bigint;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'Некорректное значение app.actor_id';
    END;

    IF v_requested_actor <> v_mapped_actor THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Запрошенный actor_id не принадлежит роли сеанса';
    END IF;

    RETURN v_mapped_actor;
END;
$function$;

CREATE OR REPLACE FUNCTION app.is_auditor()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT pg_has_role(session_user, 'auditor', 'member');
$function$;

CREATE OR REPLACE FUNCTION app.set_session_ctx(
    p_segment_id smallint,
    p_actor_id bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ref, pg_temp
AS $function$
DECLARE
    v_allowed boolean;
BEGIN
    SELECT true
    INTO v_allowed
    FROM ref.role_segment AS rs
    WHERE rs.login_role = session_user
      AND rs.segment_id = p_segment_id
      AND rs.actor_id = p_actor_id
      AND rs.is_active
      AND rs.valid_from <= clock_timestamp()
      AND (rs.valid_until IS NULL OR rs.valid_until > clock_timestamp());

    IF COALESCE(v_allowed, false) IS NOT TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Роль не связана с указанными segment_id и actor_id';
    END IF;

    -- true gives the settings transaction-local scope, equivalent to SET LOCAL.
    PERFORM set_config('app.segment_id', p_segment_id::text, true);
    PERFORM set_config('app.actor_id', p_actor_id::text, true);
END;
$function$;

REVOKE ALL ON FUNCTION app.effective_segment_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.effective_actor_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.is_auditor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.set_session_ctx(smallint, bigint) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.effective_segment_id()
TO app_reader, app_writer, auditor, dml_admin;
GRANT EXECUTE ON FUNCTION app.effective_actor_id()
TO app_reader, app_writer, auditor, dml_admin;
GRANT EXECUTE ON FUNCTION app.is_auditor() TO auditor;
GRANT EXECUTE ON FUNCTION app.set_session_ctx(smallint, bigint)
TO app_reader, app_writer;

ALTER TABLE app.actor   ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.project ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.task    ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.actor   FORCE ROW LEVEL SECURITY;
ALTER TABLE app.project FORCE ROW LEVEL SECURITY;
ALTER TABLE app.task    FORCE ROW LEVEL SECURITY;

-- Recreate only this project's policies so that reruns remain predictable.
DROP POLICY IF EXISTS actor_select_segment ON app.actor;
DROP POLICY IF EXISTS actor_insert_segment ON app.actor;
DROP POLICY IF EXISTS actor_update_segment ON app.actor;
DROP POLICY IF EXISTS actor_delete_segment ON app.actor;
DROP POLICY IF EXISTS actor_auditor_all ON app.actor;
DROP POLICY IF EXISTS actor_dml_admin_all ON app.actor;

CREATE POLICY actor_select_segment ON app.actor
FOR SELECT TO app_reader, app_owner
USING (segment_id = app.effective_segment_id());
CREATE POLICY actor_insert_segment ON app.actor
FOR INSERT TO app_writer, app_owner
WITH CHECK (segment_id = app.effective_segment_id());
CREATE POLICY actor_update_segment ON app.actor
FOR UPDATE TO app_writer, app_owner
USING (segment_id = app.effective_segment_id())
WITH CHECK (segment_id = app.effective_segment_id());
CREATE POLICY actor_delete_segment ON app.actor
FOR DELETE TO app_writer, app_owner
USING (segment_id = app.effective_segment_id());
CREATE POLICY actor_auditor_all ON app.actor
FOR SELECT TO auditor
USING (app.is_auditor());
CREATE POLICY actor_dml_admin_all ON app.actor
FOR ALL TO dml_admin
USING (pg_has_role(current_user, 'dml_admin', 'member'))
WITH CHECK (pg_has_role(current_user, 'dml_admin', 'member'));

DROP POLICY IF EXISTS project_select_segment ON app.project;
DROP POLICY IF EXISTS project_insert_segment ON app.project;
DROP POLICY IF EXISTS project_update_segment ON app.project;
DROP POLICY IF EXISTS project_delete_segment ON app.project;
DROP POLICY IF EXISTS project_auditor_all ON app.project;
DROP POLICY IF EXISTS project_dml_admin_all ON app.project;

CREATE POLICY project_select_segment ON app.project
FOR SELECT TO app_reader, app_owner
USING (segment_id = app.effective_segment_id());
CREATE POLICY project_insert_segment ON app.project
FOR INSERT TO app_writer, app_owner
WITH CHECK (segment_id = app.effective_segment_id());
CREATE POLICY project_update_segment ON app.project
FOR UPDATE TO app_writer, app_owner
USING (segment_id = app.effective_segment_id())
WITH CHECK (segment_id = app.effective_segment_id());
CREATE POLICY project_delete_segment ON app.project
FOR DELETE TO app_writer, app_owner
USING (segment_id = app.effective_segment_id());
CREATE POLICY project_auditor_all ON app.project
FOR SELECT TO auditor
USING (app.is_auditor());
CREATE POLICY project_dml_admin_all ON app.project
FOR ALL TO dml_admin
USING (pg_has_role(current_user, 'dml_admin', 'member'))
WITH CHECK (pg_has_role(current_user, 'dml_admin', 'member'));

DROP POLICY IF EXISTS task_select_segment ON app.task;
DROP POLICY IF EXISTS task_insert_segment ON app.task;
DROP POLICY IF EXISTS task_update_segment ON app.task;
DROP POLICY IF EXISTS task_delete_segment ON app.task;
DROP POLICY IF EXISTS task_auditor_all ON app.task;
DROP POLICY IF EXISTS task_dml_admin_all ON app.task;

CREATE POLICY task_select_segment ON app.task
FOR SELECT TO app_reader, app_owner
USING (segment_id = app.effective_segment_id());
CREATE POLICY task_insert_segment ON app.task
FOR INSERT TO app_writer, app_owner
WITH CHECK (segment_id = app.effective_segment_id());
CREATE POLICY task_update_segment ON app.task
FOR UPDATE TO app_writer, app_owner
USING (segment_id = app.effective_segment_id())
WITH CHECK (segment_id = app.effective_segment_id());
CREATE POLICY task_delete_segment ON app.task
FOR DELETE TO app_writer, app_owner
USING (segment_id = app.effective_segment_id());
CREATE POLICY task_auditor_all ON app.task
FOR SELECT TO auditor
USING (app.is_auditor());
CREATE POLICY task_dml_admin_all ON app.task
FOR ALL TO dml_admin
USING (pg_has_role(current_user, 'dml_admin', 'member'))
WITH CHECK (pg_has_role(current_user, 'dml_admin', 'member'));

RESET ROLE;

SELECT schemaname, tablename, policyname, roles, cmd
FROM pg_catalog.pg_policies
WHERE schemaname = 'app'
ORDER BY tablename, policyname;

\echo '03-rls completed'
