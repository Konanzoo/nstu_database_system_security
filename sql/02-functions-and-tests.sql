\set ON_ERROR_STOP on
\pset pager off

\echo '== 02-functions-and-tests: SECURITY DEFINER and CHECK/trigger benchmark =='

SET ROLE audit_owner;

CREATE TABLE IF NOT EXISTS audit.function_calls (
    call_id        bigint GENERATED ALWAYS AS IDENTITY,
    call_time      timestamptz NOT NULL DEFAULT clock_timestamp(),
    function_name  text        NOT NULL,
    caller_role    name        NOT NULL,
    input_params   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    success        boolean     NOT NULL,
    error_message  text,
    backend_pid    integer     NOT NULL DEFAULT pg_backend_pid(),
    txid           xid8        DEFAULT pg_current_xact_id_if_assigned(),
    CONSTRAINT pk_function_calls PRIMARY KEY (call_id),
    CONSTRAINT ck_function_calls_name CHECK (btrim(function_name) <> ''),
    CONSTRAINT ck_function_calls_result
        CHECK ((success AND error_message IS NULL)
            OR (NOT success AND error_message IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS ix_function_calls_time
    ON audit.function_calls (call_time DESC);
CREATE INDEX IF NOT EXISTS ix_function_calls_caller_time
    ON audit.function_calls (caller_role, call_time DESC);

CREATE OR REPLACE FUNCTION audit.write_function_call(
    p_function_name text,
    p_input_params jsonb,
    p_success boolean,
    p_error_message text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, pg_temp
AS $function$
BEGIN
    IF p_function_name IS NULL OR btrim(p_function_name) = '' THEN
        RAISE EXCEPTION 'function_name must not be empty';
    END IF;
    IF p_success AND p_error_message IS NOT NULL THEN
        RAISE EXCEPTION 'successful call cannot contain error_message';
    END IF;

    INSERT INTO audit.function_calls (
        call_time, function_name, caller_role, input_params,
        success, error_message, backend_pid, txid
    )
    VALUES (
        clock_timestamp(), p_function_name, session_user,
        COALESCE(p_input_params, '{}'::jsonb), p_success,
        p_error_message, pg_backend_pid(), pg_current_xact_id_if_assigned()
    );
END;
$function$;

REVOKE ALL ON FUNCTION audit.write_function_call(text, jsonb, boolean, text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.write_function_call(text, jsonb, boolean, text)
TO app_owner;
GRANT SELECT ON audit.function_calls TO auditor;

RESET ROLE;

-- Sensitive writes are available only through narrow functions.
REVOKE INSERT, UPDATE, DELETE ON app.project FROM app_writer;
REVOKE UPDATE, DELETE ON app.task FROM app_writer;
GRANT UPDATE (name, description, status_code, start_date, end_date)
ON app.project TO app_writer;
GRANT UPDATE (assignee_actor_id, title, priority, planned_hours, due_date)
ON app.task TO app_writer;

SET ROLE app_owner;

CREATE OR REPLACE FUNCTION app.create_project(
    p_name text,
    p_description text,
    p_budget numeric,
    p_start_date date,
    p_end_date date DEFAULT NULL
)
RETURNS TABLE (ok boolean, message text, object_id bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app, ref, audit, pg_temp
AS $function$
DECLARE
    v_segment_id smallint;
    v_project_id bigint;
    v_error text;
    v_params jsonb;
BEGIN
    v_params := jsonb_build_object(
        'name', left(COALESCE(p_name, ''), 100),
        'budget', p_budget,
        'start_date', p_start_date,
        'end_date', p_end_date
    );

    IF p_name IS NULL OR char_length(btrim(p_name)) < 3 THEN
        v_error := 'Название проекта должно содержать не менее 3 символов';
    ELSIF p_budget IS NULL OR p_budget < 0 OR p_budget > 1000000000 THEN
        v_error := 'Бюджет должен быть в диапазоне от 0 до 1 000 000 000';
    ELSIF p_start_date IS NULL
       OR (p_end_date IS NOT NULL AND p_end_date < p_start_date) THEN
        v_error := 'Некорректный период проекта';
    END IF;

    IF v_error IS NOT NULL THEN
        PERFORM audit.write_function_call(
            'app.create_project', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    SELECT rs.segment_id
    INTO v_segment_id
    FROM ref.role_segment AS rs
    WHERE rs.login_role = session_user
      AND rs.is_active
      AND rs.valid_from <= clock_timestamp()
      AND (rs.valid_until IS NULL OR rs.valid_until > clock_timestamp());

    IF v_segment_id IS NULL THEN
        v_error := 'Для вызывающей роли не назначен активный сегмент';
        PERFORM audit.write_function_call(
            'app.create_project', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    INSERT INTO app.project (
        segment_id, name, description, budget,
        status_code, start_date, end_date
    )
    VALUES (
        v_segment_id, btrim(p_name), NULLIF(btrim(p_description), ''),
        p_budget, 'planned', p_start_date, p_end_date
    )
    RETURNING project_id INTO v_project_id;

    PERFORM audit.write_function_call(
        'app.create_project', v_params, true, NULL
    );
    RETURN QUERY SELECT true, 'Проект создан'::text, v_project_id;
EXCEPTION
    WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_error = MESSAGE_TEXT;
        PERFORM audit.write_function_call(
            'app.create_project', COALESCE(v_params, '{}'::jsonb),
            false, left(v_error, 1000)
        );
        RETURN QUERY
            SELECT false, ('Операция отклонена: ' || v_error)::text, NULL::bigint;
END;
$function$;

CREATE OR REPLACE FUNCTION app.change_project_budget(
    p_project_id bigint,
    p_new_budget numeric,
    p_reason text
)
RETURNS TABLE (ok boolean, message text, object_id bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app, ref, audit, pg_temp
AS $function$
DECLARE
    v_segment_id smallint;
    v_error text;
    v_updated_id bigint;
    v_params jsonb;
BEGIN
    v_params := jsonb_build_object(
        'project_id', p_project_id,
        'new_budget', p_new_budget,
        'reason_length', char_length(COALESCE(p_reason, ''))
    );

    IF p_project_id IS NULL THEN
        v_error := 'project_id обязателен';
    ELSIF p_new_budget IS NULL OR p_new_budget < 0
          OR p_new_budget > 1000000000 THEN
        v_error := 'Новый бюджет вне допустимого диапазона';
    ELSIF p_reason IS NULL OR char_length(btrim(p_reason)) < 10 THEN
        v_error := 'Причина изменения должна содержать не менее 10 символов';
    END IF;

    IF v_error IS NOT NULL THEN
        PERFORM audit.write_function_call(
            'app.change_project_budget', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    SELECT rs.segment_id
    INTO v_segment_id
    FROM ref.role_segment AS rs
    WHERE rs.login_role = session_user
      AND rs.is_active
      AND rs.valid_from <= clock_timestamp()
      AND (rs.valid_until IS NULL OR rs.valid_until > clock_timestamp());

    UPDATE app.project
    SET budget = p_new_budget,
        updated_at = clock_timestamp()
    WHERE project_id = p_project_id
      AND segment_id = v_segment_id
    RETURNING project_id INTO v_updated_id;

    IF v_updated_id IS NULL THEN
        v_error := 'Проект не найден или недоступен';
        PERFORM audit.write_function_call(
            'app.change_project_budget', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    PERFORM audit.write_function_call(
        'app.change_project_budget', v_params, true, NULL
    );
    RETURN QUERY SELECT true, 'Бюджет изменён'::text, v_updated_id;
EXCEPTION
    WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_error = MESSAGE_TEXT;
        PERFORM audit.write_function_call(
            'app.change_project_budget', COALESCE(v_params, '{}'::jsonb),
            false, left(v_error, 1000)
        );
        RETURN QUERY
            SELECT false, ('Операция отклонена: ' || v_error)::text, NULL::bigint;
END;
$function$;

CREATE OR REPLACE FUNCTION app.close_task(
    p_task_id bigint,
    p_actual_hours numeric
)
RETURNS TABLE (ok boolean, message text, object_id bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app, ref, audit, pg_temp
AS $function$
DECLARE
    v_segment_id smallint;
    v_error text;
    v_updated_id bigint;
    v_params jsonb;
BEGIN
    v_params := jsonb_build_object(
        'task_id', p_task_id,
        'actual_hours', p_actual_hours
    );

    IF p_task_id IS NULL THEN
        v_error := 'task_id обязателен';
    ELSIF p_actual_hours IS NULL
          OR p_actual_hours < 0 OR p_actual_hours > 10000 THEN
        v_error := 'Фактические трудозатраты вне допустимого диапазона';
    END IF;

    IF v_error IS NOT NULL THEN
        PERFORM audit.write_function_call(
            'app.close_task', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    SELECT rs.segment_id
    INTO v_segment_id
    FROM ref.role_segment AS rs
    WHERE rs.login_role = session_user
      AND rs.is_active
      AND rs.valid_from <= clock_timestamp()
      AND (rs.valid_until IS NULL OR rs.valid_until > clock_timestamp());

    UPDATE app.task
    SET status_code = 'done',
        actual_hours = p_actual_hours,
        updated_at = clock_timestamp()
    WHERE task_id = p_task_id
      AND segment_id = v_segment_id
      AND status_code NOT IN ('done', 'cancelled')
    RETURNING task_id INTO v_updated_id;

    IF v_updated_id IS NULL THEN
        v_error := 'Задача не найдена, недоступна или уже закрыта';
        PERFORM audit.write_function_call(
            'app.close_task', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    PERFORM audit.write_function_call(
        'app.close_task', v_params, true, NULL
    );
    RETURN QUERY SELECT true, 'Задача закрыта'::text, v_updated_id;
EXCEPTION
    WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_error = MESSAGE_TEXT;
        PERFORM audit.write_function_call(
            'app.close_task', COALESCE(v_params, '{}'::jsonb),
            false, left(v_error, 1000)
        );
        RETURN QUERY
            SELECT false, ('Операция отклонена: ' || v_error)::text, NULL::bigint;
END;
$function$;

REVOKE ALL ON FUNCTION app.create_project(text, text, numeric, date, date)
FROM PUBLIC;
REVOKE ALL ON FUNCTION app.change_project_budget(bigint, numeric, text)
FROM PUBLIC;
REVOKE ALL ON FUNCTION app.close_task(bigint, numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.create_project(text, text, numeric, date, date)
TO app_writer;
GRANT EXECUTE ON FUNCTION app.change_project_budget(bigint, numeric, text)
TO app_writer;
GRANT EXECUTE ON FUNCTION app.close_task(bigint, numeric) TO app_writer;

-- Two equivalent implementations for the 10,000-row benchmark.
CREATE TABLE IF NOT EXISTS stg.rule_check (
    row_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    start_date date NOT NULL,
    end_date date,
    CONSTRAINT ck_rule_check_dates
        CHECK (end_date IS NULL OR end_date >= start_date)
);

CREATE TABLE IF NOT EXISTS stg.rule_trigger (
    row_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    start_date date NOT NULL,
    end_date date
);

CREATE OR REPLACE FUNCTION stg.enforce_date_period()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, stg, pg_temp
AS $function$
BEGIN
    IF NEW.end_date IS NOT NULL AND NEW.end_date < NEW.start_date THEN
        RAISE EXCEPTION 'end_date (%) precedes start_date (%)',
            NEW.end_date, NEW.start_date
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_rule_trigger_dates ON stg.rule_trigger;
CREATE TRIGGER trg_rule_trigger_dates
BEFORE INSERT OR UPDATE OF start_date, end_date ON stg.rule_trigger
FOR EACH ROW EXECUTE FUNCTION stg.enforce_date_period();

RESET ROLE;

\if :{?run_benchmark}
\else
    \set run_benchmark 0
\endif

\if :run_benchmark
    \echo 'Running the optional CHECK vs trigger benchmark (10,000 rows each)'
    TRUNCATE stg.rule_check, stg.rule_trigger RESTART IDENTITY;
    EXPLAIN (ANALYZE, BUFFERS, WAL, SUMMARY)
    INSERT INTO stg.rule_check (start_date, end_date)
    SELECT DATE '2026-01-01' + (g % 365), DATE '2026-01-01' + (g % 365) + 7
    FROM generate_series(1, 10000) AS s(g);

    EXPLAIN (ANALYZE, BUFFERS, WAL, SUMMARY)
    INSERT INTO stg.rule_trigger (start_date, end_date)
    SELECT DATE '2026-01-01' + (g % 365), DATE '2026-01-01' + (g % 365) + 7
    FROM generate_series(1, 10000) AS s(g);
\else
    \echo 'Benchmark skipped; rerun with -v run_benchmark=1 to execute it'
\endif

\echo '02-functions-and-tests completed'
