\set ON_ERROR_STOP on
\pset pager off

\echo '== 05-jit-access: temporary privilege with server-side TTL validation =='

SET ROLE app_owner;

CREATE TABLE IF NOT EXISTS ref.temp_operation_rule (
    allowed_role     name    NOT NULL,
    operation_name   text    NOT NULL,
    max_duration_min integer NOT NULL,
    is_active        boolean NOT NULL DEFAULT true,
    CONSTRAINT pk_temp_operation_rule
        PRIMARY KEY (allowed_role, operation_name),
    CONSTRAINT ck_temp_operation_rule_name
        CHECK (operation_name ~ '^[a-z][a-z0-9_.]{2,63}$'),
    CONSTRAINT ck_temp_operation_rule_duration
        CHECK (max_duration_min BETWEEN 1 AND 120)
);

INSERT INTO ref.temp_operation_rule (
    allowed_role, operation_name, max_duration_min
)
VALUES ('app_writer', 'task.delete', 15)
ON CONFLICT (allowed_role, operation_name) DO UPDATE
SET max_duration_min = EXCLUDED.max_duration_min,
    is_active = true;

RESET ROLE;

REVOKE DELETE ON app.task FROM app_writer;
GRANT USAGE ON SCHEMA ref TO audit_owner;
GRANT SELECT ON ref.temp_operation_rule TO audit_owner;
GRANT USAGE ON SCHEMA audit TO app_writer;

SET ROLE audit_owner;

CREATE TABLE IF NOT EXISTS audit.temp_access_log (
    request_id              bigint GENERATED ALWAYS AS IDENTITY,
    request_time            timestamptz NOT NULL DEFAULT clock_timestamp(),
    caller_role             name        NOT NULL,
    operation               text        NOT NULL,
    requested_duration_min  integer,
    expires_at              timestamptz,
    approved                boolean     NOT NULL,
    denial_reason           text,
    backend_pid             integer     NOT NULL,
    CONSTRAINT pk_temp_access_log PRIMARY KEY (request_id),
    CONSTRAINT ck_temp_access_log_result
        CHECK ((approved AND expires_at IS NOT NULL AND denial_reason IS NULL)
            OR (NOT approved AND denial_reason IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS ix_temp_access_log_role_time
    ON audit.temp_access_log (caller_role, request_time DESC);

CREATE TABLE IF NOT EXISTS audit.temp_access_grant (
    grant_id       uuid        NOT NULL,
    request_id     bigint      NOT NULL,
    caller_role    name        NOT NULL,
    operation      text        NOT NULL,
    backend_pid    integer     NOT NULL,
    backend_start  timestamptz NOT NULL,
    granted_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    CONSTRAINT pk_temp_access_grant PRIMARY KEY (grant_id),
    CONSTRAINT fk_temp_access_grant_request
        FOREIGN KEY (request_id) REFERENCES audit.temp_access_log(request_id),
    CONSTRAINT ck_temp_access_grant_period CHECK (expires_at > granted_at),
    CONSTRAINT ck_temp_access_grant_revoke
        CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

CREATE INDEX IF NOT EXISTS ix_temp_access_grant_lookup
    ON audit.temp_access_grant (
        caller_role, operation, backend_pid, backend_start, expires_at
    )
    WHERE revoked_at IS NULL;

CREATE OR REPLACE FUNCTION audit.request_temp_privilege(
    p_operation_name text,
    p_duration_min integer
)
RETURNS TABLE (
    ok boolean,
    message text,
    grant_id uuid,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, ref, pg_temp
AS $function$
DECLARE
    v_operation text;
    v_allowed_role name;
    v_max_duration integer;
    v_expires_at timestamptz;
    v_grant_id uuid;
    v_request_id bigint;
    v_backend_start timestamptz;
    v_reason text;
BEGIN
    v_operation := lower(btrim(COALESCE(p_operation_name, '')));

    IF v_operation = '' THEN
        v_reason := 'Имя операции не задано';
    ELSIF p_duration_min IS NULL OR p_duration_min < 1 THEN
        v_reason := 'Длительность должна быть не менее одной минуты';
    END IF;

    IF v_reason IS NULL THEN
        SELECT r.allowed_role, r.max_duration_min
        INTO v_allowed_role, v_max_duration
        FROM ref.temp_operation_rule AS r
        WHERE r.operation_name = v_operation
          AND r.is_active
          AND pg_has_role(session_user, r.allowed_role, 'member')
        ORDER BY r.max_duration_min
        LIMIT 1;

        IF v_allowed_role IS NULL THEN
            v_reason := 'Операция не разрешена вызывающей роли';
        ELSIF p_duration_min > v_max_duration THEN
            v_reason := format(
                'Запрошенная длительность превышает максимум %s мин.',
                v_max_duration
            );
        END IF;
    END IF;

    IF v_reason IS NOT NULL THEN
        INSERT INTO audit.temp_access_log (
            caller_role, operation, requested_duration_min,
            expires_at, approved, denial_reason, backend_pid
        )
        VALUES (
            session_user, COALESCE(NULLIF(v_operation, ''), '<empty>'),
            p_duration_min, NULL, false, v_reason, pg_backend_pid()
        );
        RETURN QUERY SELECT false, v_reason, NULL::uuid, NULL::timestamptz;
        RETURN;
    END IF;

    SELECT a.backend_start
    INTO v_backend_start
    FROM pg_catalog.pg_stat_activity AS a
    WHERE a.pid = pg_backend_pid();

    IF v_backend_start IS NULL THEN
        v_reason := 'Не удалось определить идентификатор backend-сеанса';
        INSERT INTO audit.temp_access_log (
            caller_role, operation, requested_duration_min,
            approved, denial_reason, backend_pid
        )
        VALUES (
            session_user, v_operation, p_duration_min,
            false, v_reason, pg_backend_pid()
        );
        RETURN QUERY SELECT false, v_reason, NULL::uuid, NULL::timestamptz;
        RETURN;
    END IF;

    v_grant_id := gen_random_uuid();
    v_expires_at := clock_timestamp() + make_interval(mins => p_duration_min);

    INSERT INTO audit.temp_access_log (
        caller_role, operation, requested_duration_min, expires_at,
        approved, denial_reason, backend_pid
    )
    VALUES (
        session_user, v_operation, p_duration_min, v_expires_at,
        true, NULL, pg_backend_pid()
    )
    RETURNING request_id INTO v_request_id;

    INSERT INTO audit.temp_access_grant (
        grant_id, request_id, caller_role, operation,
        backend_pid, backend_start, granted_at, expires_at
    )
    VALUES (
        v_grant_id, v_request_id, session_user, v_operation,
        pg_backend_pid(), v_backend_start, clock_timestamp(), v_expires_at
    );

    -- Client-visible GUCs are markers only. The protected table is authoritative.
    PERFORM set_config('app.temp_privilege_token', v_grant_id::text, false);
    PERFORM set_config('app.temp_privilege_until', v_expires_at::text, false);

    RETURN QUERY
        SELECT true, 'Временный допуск выдан'::text,
               v_grant_id, v_expires_at;
END;
$function$;

CREATE OR REPLACE FUNCTION audit.has_temp_privilege(
    p_operation_name text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, audit, pg_temp
AS $function$
DECLARE
    v_token_text text;
    v_token uuid;
    v_backend_start timestamptz;
    v_result boolean;
BEGIN
    v_token_text := current_setting('app.temp_privilege_token', true);
    IF v_token_text IS NULL OR v_token_text = '' THEN
        RETURN false;
    END IF;

    BEGIN
        v_token := v_token_text::uuid;
    EXCEPTION
        WHEN invalid_text_representation THEN
            RETURN false;
    END;

    SELECT a.backend_start
    INTO v_backend_start
    FROM pg_catalog.pg_stat_activity AS a
    WHERE a.pid = pg_backend_pid();

    SELECT EXISTS (
        SELECT 1
        FROM audit.temp_access_grant AS g
        WHERE g.grant_id = v_token
          AND g.caller_role = session_user
          AND g.operation = lower(btrim(p_operation_name))
          AND g.backend_pid = pg_backend_pid()
          AND g.backend_start = v_backend_start
          AND g.revoked_at IS NULL
          AND g.granted_at <= clock_timestamp()
          AND g.expires_at > clock_timestamp()
    )
    INTO v_result;

    RETURN COALESCE(v_result, false);
END;
$function$;

REVOKE ALL ON FUNCTION audit.request_temp_privilege(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.has_temp_privilege(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.request_temp_privilege(text, integer)
TO app_writer;
GRANT EXECUTE ON FUNCTION audit.has_temp_privilege(text) TO app_owner;
GRANT SELECT ON audit.temp_access_log, audit.temp_access_grant TO auditor;

RESET ROLE;

SET ROLE app_owner;

CREATE OR REPLACE FUNCTION app.delete_task_jit(
    p_task_id bigint
)
RETURNS TABLE (ok boolean, message text, object_id bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app, audit, pg_temp
AS $function$
DECLARE
    v_deleted_id bigint;
    v_error text;
    v_params jsonb;
BEGIN
    v_params := jsonb_build_object('task_id', p_task_id);

    IF p_task_id IS NULL THEN
        v_error := 'task_id обязателен';
        PERFORM audit.write_function_call(
            'app.delete_task_jit', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    IF NOT audit.has_temp_privilege('task.delete') THEN
        v_error := 'Активный временный допуск task.delete отсутствует';
        PERFORM audit.write_function_call(
            'app.delete_task_jit', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    DELETE FROM app.task
    WHERE task_id = p_task_id
    RETURNING task_id INTO v_deleted_id;

    IF v_deleted_id IS NULL THEN
        v_error := 'Задача не найдена или недоступна';
        PERFORM audit.write_function_call(
            'app.delete_task_jit', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    PERFORM audit.write_function_call(
        'app.delete_task_jit', v_params, true, NULL
    );
    RETURN QUERY SELECT true, 'Задача удалена'::text, v_deleted_id;
EXCEPTION
    WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_error = MESSAGE_TEXT;
        PERFORM audit.write_function_call(
            'app.delete_task_jit', COALESCE(v_params, '{}'::jsonb),
            false, left(v_error, 1000)
        );
        RETURN QUERY
            SELECT false, ('Операция отклонена: ' || v_error)::text, NULL::bigint;
END;
$function$;

REVOKE ALL ON FUNCTION app.delete_task_jit(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.delete_task_jit(bigint) TO app_writer;

RESET ROLE;

\echo '05-jit-access completed'
