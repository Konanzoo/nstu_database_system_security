# Лабораторная работа № 2

## Точечное повышение привилегий и контроль бизнес-логики

[← Лабораторная работа № 1](01-lab-1-design-and-rbac.md) · [К содержанию](../README.md) · [Лабораторная работа № 3 →](03-lab-3-rls.md)

## 1. Цель и модель угроз

`app_writer` должен выполнять отдельные чувствительные операции, но не должен получать широкие табличные права. Для этого создаются узкие функции `SECURITY DEFINER`:

- создать проект в собственном филиале;
- изменить бюджет проекта своего филиала;
- закрыть задачу с фиксацией фактических трудозатрат.

Функция исполняется с правами владельца, но идентификатор исходной login-роли сохраняется в `session_user`. Каждая функция:

1. проверяет входные данные;
2. сама определяет сегмент вызывающей роли;
3. использует квалифицированные имена объектов;
4. имеет фиксированный безопасный `search_path`;
5. недоступна роли `PUBLIC`;
6. возвращает `ok`, `message`, `object_id`;
7. регистрирует успешный или ожидаемо неуспешный вызов.

## 2. Почему SECURITY DEFINER требует специальных мер

Опасный пример:

```sql
CREATE FUNCTION update_budget(...)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE project SET budget = ...;
END;
$$;
```

Проблемы такого определения:

- `project` разрешается через изменяемый `search_path`;
- временная таблица вызывающего пользователя может подменить объект;
- функция по умолчанию может получить `EXECUTE` для `PUBLIC`;
- нет проверки принадлежности проекта вызывающему сегменту;
- параметры могут попасть в журнал без фильтрации;
- владелец функции может иметь избыточные права.

Безопасный шаблон:

```sql
CREATE FUNCTION app.example_function(...)
RETURNS ...
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app, ref, audit, pg_temp
AS $$
BEGIN
    -- Все прикладные объекты дополнительно указываются с именем схемы.
    ...
END;
$$;

REVOKE ALL ON FUNCTION app.example_function(...) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.example_function(...) TO app_writer;
```

`pg_temp` ставится последним. Это препятствует подмене таблицы или функции одноимённым временным объектом.

## 3. Журнал вызовов

### 3.1. Таблица

```sql
SET ROLE audit_owner;

CREATE TABLE audit.function_calls (
    call_id        bigint GENERATED ALWAYS AS IDENTITY,
    call_time      timestamptz NOT NULL DEFAULT clock_timestamp(),
    function_name  text        NOT NULL,
    caller_role    name        NOT NULL,
    input_params   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    success        boolean     NOT NULL,
    error_message  text,
    backend_pid    integer     NOT NULL DEFAULT pg_backend_pid(),
    txid            xid8        DEFAULT pg_current_xact_id_if_assigned(),

    CONSTRAINT pk_function_calls PRIMARY KEY (call_id),
    CONSTRAINT ck_function_calls_name CHECK (btrim(function_name) <> ''),
    CONSTRAINT ck_function_calls_result
        CHECK ((success AND error_message IS NULL)
            OR (NOT success AND error_message IS NOT NULL))
);

CREATE INDEX ix_function_calls_time
    ON audit.function_calls (call_time DESC);

CREATE INDEX ix_function_calls_caller_time
    ON audit.function_calls (caller_role, call_time DESC);

GRANT SELECT ON audit.function_calls TO auditor;

RESET ROLE;
```

Поле `input_params` не должно содержать пароль, токен, полный номер документа или открытое PII. Для чувствительных параметров записывают категорию, длину, технический идентификатор или криптографический хэш.

### 3.2. Узкая функция записи в аудит

Прямой `INSERT` в `audit.function_calls` не выдаётся прикладному владельцу. Вместо этого создаётся отдельная функция, принадлежащая `audit_owner`.

```sql
GRANT USAGE ON SCHEMA audit TO app_owner;

SET ROLE audit_owner;

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
AS $$
BEGIN
    IF p_function_name IS NULL OR btrim(p_function_name) = '' THEN
        RAISE EXCEPTION 'function_name must not be empty';
    END IF;

    IF p_success AND p_error_message IS NOT NULL THEN
        RAISE EXCEPTION 'successful call cannot contain error_message';
    END IF;

    INSERT INTO audit.function_calls (
        call_time,
        function_name,
        caller_role,
        input_params,
        success,
        error_message,
        backend_pid,
        txid
    )
    VALUES (
        clock_timestamp(),
        p_function_name,
        session_user,
        COALESCE(p_input_params, '{}'::jsonb),
        p_success,
        p_error_message,
        pg_backend_pid(),
        pg_current_xact_id_if_assigned()
    );
END;
$$;

REVOKE ALL ON FUNCTION audit.write_function_call(text, jsonb, boolean, text)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION audit.write_function_call(text, jsonb, boolean, text)
TO app_owner;

RESET ROLE;
```

## 4. Ограничение прямых полномочий app_writer

Сначала отзываются права, которые позволили бы обойти функции:

```sql
REVOKE INSERT, UPDATE, DELETE ON app.project FROM app_writer;
REVOKE UPDATE, DELETE ON app.task FROM app_writer;

-- Несекретные поля существующего проекта можно менять напрямую.
GRANT UPDATE (name, description, status_code, start_date, end_date)
ON app.project TO app_writer;

-- Оперативные поля задачи разрешены; status_code и actual_hours
-- изменяются функцией закрытия задачи.
GRANT UPDATE (
    assignee_actor_id,
    title,
    priority,
    planned_hours,
    due_date
)
ON app.task TO app_writer;
```

`app_writer` не получает прямого `INSERT` в `app.project`, прямого изменения `budget`, `status_code`/`actual_hours` задачи и `DELETE`.

## 5. Функция создания проекта

### 5.1. Реализация

```sql
SET ROLE app_owner;

CREATE OR REPLACE FUNCTION app.create_project(
    p_name text,
    p_description text,
    p_budget numeric,
    p_start_date date,
    p_end_date date DEFAULT NULL
)
RETURNS TABLE (
    ok boolean,
    message text,
    object_id bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app, ref, audit, pg_temp
AS $$
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
        PERFORM audit.write_function_call(
            'app.create_project', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    IF p_budget IS NULL OR p_budget < 0 OR p_budget > 1000000000 THEN
        v_error := 'Бюджет должен быть в диапазоне от 0 до 1 000 000 000';
        PERFORM audit.write_function_call(
            'app.create_project', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

    IF p_start_date IS NULL
       OR (p_end_date IS NOT NULL AND p_end_date < p_start_date) THEN
        v_error := 'Некорректный период проекта';
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
        segment_id,
        name,
        description,
        budget,
        status_code,
        start_date,
        end_date
    )
    VALUES (
        v_segment_id,
        btrim(p_name),
        NULLIF(btrim(p_description), ''),
        p_budget,
        'planned',
        p_start_date,
        p_end_date
    )
    RETURNING project_id INTO v_project_id;

    PERFORM audit.write_function_call(
        'app.create_project', v_params, true, NULL
    );

    RETURN QUERY
        SELECT true, 'Проект создан'::text, v_project_id;
EXCEPTION
    WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_error = MESSAGE_TEXT;

        -- Изменения основного блока уже откатились до точки входа
        -- в EXCEPTION. Запись аудита выполняется после этого отката.
        PERFORM audit.write_function_call(
            'app.create_project',
            COALESCE(v_params, '{}'::jsonb),
            false,
            left(v_error, 1000)
        );

        RETURN QUERY
            SELECT false, ('Операция отклонена: ' || v_error)::text, NULL::bigint;
END;
$$;

REVOKE ALL ON FUNCTION app.create_project(text, text, numeric, date, date)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.create_project(text, text, numeric, date, date)
TO app_writer;

RESET ROLE;
```

### 5.2. Почему функция возвращает результат вместо повторного RAISE

PostgreSQL не поддерживает автономные транзакции в обычной PL/pgSQL-функции. Если в `EXCEPTION` записать строку аудита, а затем выполнить `RAISE`, весь SQL-оператор откатится вместе с этой строкой. Возврат `ok = false` сохраняет запись отрицательного события.

Если контракт приложения требует SQL-исключение, используйте один из вариантов:

- журнал сервера через `RAISE LOG` и централизованный сбор логов;
- внешнюю службу аудита;
- отдельное соединение через тщательно контролируемый механизм;
- запись попытки до транзакции бизнес-операции на уровне приложения.

## 6. Функция изменения бюджета

Причина изменения не записывается в журнал целиком: свободный текст может содержать PII. Сохраняются только длина причины и технические параметры.

```sql
SET ROLE app_owner;

CREATE OR REPLACE FUNCTION app.change_project_budget(
    p_project_id bigint,
    p_new_budget numeric,
    p_reason text
)
RETURNS TABLE (
    ok boolean,
    message text,
    object_id bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app, ref, audit, pg_temp
AS $$
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

    IF v_segment_id IS NULL THEN
        v_error := 'Для вызывающей роли не назначен активный сегмент';
        PERFORM audit.write_function_call(
            'app.change_project_budget', v_params, false, v_error
        );
        RETURN QUERY SELECT false, v_error, NULL::bigint;
        RETURN;
    END IF;

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
            'app.change_project_budget',
            COALESCE(v_params, '{}'::jsonb),
            false,
            left(v_error, 1000)
        );
        RETURN QUERY
            SELECT false, ('Операция отклонена: ' || v_error)::text, NULL::bigint;
END;
$$;

REVOKE ALL ON FUNCTION app.change_project_budget(bigint, numeric, text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.change_project_budget(bigint, numeric, text)
TO app_writer;

RESET ROLE;
```

## 7. Функция закрытия задачи

```sql
SET ROLE app_owner;

CREATE OR REPLACE FUNCTION app.close_task(
    p_task_id bigint,
    p_actual_hours numeric
)
RETURNS TABLE (
    ok boolean,
    message text,
    object_id bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app, ref, audit, pg_temp
AS $$
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
          OR p_actual_hours < 0
          OR p_actual_hours > 10000 THEN
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
            'app.close_task',
            COALESCE(v_params, '{}'::jsonb),
            false,
            left(v_error, 1000)
        );
        RETURN QUERY
            SELECT false, ('Операция отклонена: ' || v_error)::text, NULL::bigint;
END;
$$;

REVOKE ALL ON FUNCTION app.close_task(bigint, numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.close_task(bigint, numeric) TO app_writer;

RESET ROLE;
```

## 8. Набор тестов прав

Каждый негативный тест лучше выполнять отдельным SQL-оператором. При использовании `\set ON_ERROR_STOP on` ожидаемая ошибка остановит файл; для автоматизации применяйте pgTAP либо отдельные сценарии.

### Тест 1. Разрешённое чтение

```sql
SET SESSION AUTHORIZATION lab_alice;
SELECT project_id, name, status_code
FROM app.project
ORDER BY project_id
LIMIT 5;
RESET SESSION AUTHORIZATION;
```

Ожидание: запрос выполняется.

### Тест 2. Запрещённое чтение PII

```sql
SET SESSION AUTHORIZATION lab_alice;
SELECT actor_id, email, phone FROM app.actor;
RESET SESSION AUTHORIZATION;
```

Ожидание: ошибка табличной/колоночной привилегии.

### Тест 3. DDL неадминистратором

```sql
SET SESSION AUTHORIZATION lab_alice;
ALTER TABLE app.task ADD COLUMN should_not_exist integer;
RESET SESSION AUTHORIZATION;
```

Ожидание: ошибка владения таблицей.

### Тест 4. Прямой DML в audit

```sql
SET SESSION AUTHORIZATION lab_alice;
INSERT INTO audit.function_calls (
    function_name, caller_role, input_params, success
)
VALUES ('fake', 'lab_alice', '{}', true);
RESET SESSION AUTHORIZATION;
```

Ожидание: ошибка доступа к схеме `audit`.

### Тест 5. Успешное создание проекта через функцию

```sql
SET SESSION AUTHORIZATION lab_alice;
SELECT *
FROM app.create_project(
    'NSK Security Review',
    'Проверка модели доступа',
    350000,
    DATE '2026-10-01',
    NULL
);
RESET SESSION AUTHORIZATION;
```

Ожидание: `ok = true`; созданная строка получает `segment_id = 1`, хотя клиент не передавал сегмент.

### Тест 6. Отрицательный бюджет

```sql
SET SESSION AUTHORIZATION lab_alice;
SELECT *
FROM app.create_project(
    'Invalid Budget',
    'Негативная проверка',
    -1,
    DATE '2026-10-01',
    NULL
);
RESET SESSION AUTHORIZATION;
```

Ожидание: `ok = false`, понятное сообщение, строка проекта не создаётся, отрицательный вызов остаётся в журнале.

### Тест 7. Прямая запись бюджета запрещена

```sql
SET SESSION AUTHORIZATION lab_alice;
UPDATE app.project SET budget = 1 WHERE project_id = 101;
RESET SESSION AUTHORIZATION;
```

Ожидание: ошибка колоночной привилегии.

### Тест 8. Изменение бюджета через функцию

```sql
SET SESSION AUTHORIZATION lab_alice;
SELECT *
FROM app.change_project_budget(
    101,
    1250000,
    'Уточнена стоимость лицензий'
);
RESET SESSION AUTHORIZATION;
```

Ожидание: `ok = true`.

### Тест 9. Попытка изменить проект другого филиала

```sql
SET SESSION AUTHORIZATION lab_alice;
SELECT *
FROM app.change_project_budget(
    201,
    1,
    'Попытка изменить чужой проект'
);
RESET SESSION AUTHORIZATION;
```

Ожидание: `ok = false`, сообщение «не найден или недоступен». Формулировка не подтверждает существование чужого объекта.

### Тест 10. Закрытие своей задачи

```sql
SET SESSION AUTHORIZATION lab_alice;
SELECT * FROM app.close_task(1002, 15.5);
RESET SESSION AUTHORIZATION;
```

Ожидание: `ok = true`, статус `done`, `actual_hours = 15.5`.

### Тест 11. Некорректные трудозатраты

```sql
SET SESSION AUTHORIZATION lab_bob;
SELECT * FROM app.close_task(2002, -5);
RESET SESSION AUTHORIZATION;
```

Ожидание: `ok = false`, строка задачи не изменяется.

### Тест 12. Просмотр журнала аудитором

```sql
SET SESSION AUTHORIZATION lab_auditor;

SELECT call_time, function_name, caller_role,
       input_params, success, error_message
FROM audit.function_calls
ORDER BY call_id DESC
LIMIT 20;

RESET SESSION AUTHORIZATION;
```

Ожидание: в журнале есть как успешные, так и отрицательные результаты.

## 9. CHECK и триггер: корректное сравнение

### 9.1. Когда применять CHECK

`CHECK` подходит, если правило:

- определяется значениями текущей строки;
- не требует чтения другой таблицы;
- должно проверяться при любой вставке или модификации;
- не нуждается в собственном журнале действий.

Пример: `end_date IS NULL OR end_date >= start_date`.

PostgreSQL предполагает, что выражение `CHECK` является неизменным относительно одной строки. Ссылки на содержимое других таблиц в `CHECK` методологически некорректны: последующее изменение другой таблицы не инициирует повторную проверку существующих строк.

### 9.2. Когда применять триггер

Триггер оправдан, если требуется:

- сопоставление с другими строками или таблицами;
- сложная процедурная проверка;
- нормализация данных;
- аудит и сохранение дополнительных сведений;
- единая логика для нескольких операций.

Триггер сложнее анализировать, тестировать и сопровождать. Для простого внутристрочного инварианта `CHECK` обычно предпочтительнее.

### 9.3. Две тестовые таблицы

```sql
SET ROLE app_owner;

CREATE TABLE stg.project_check_bench (
    id         bigint NOT NULL,
    start_date date   NOT NULL,
    end_date   date,
    payload    text,
    CONSTRAINT pk_project_check_bench PRIMARY KEY (id),
    CONSTRAINT ck_project_check_bench_dates
        CHECK (end_date IS NULL OR end_date >= start_date)
);

CREATE TABLE stg.project_trigger_bench (
    id         bigint NOT NULL,
    start_date date   NOT NULL,
    end_date   date,
    payload    text,
    CONSTRAINT pk_project_trigger_bench PRIMARY KEY (id)
);

CREATE OR REPLACE FUNCTION stg.enforce_project_dates()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, stg, pg_temp
AS $$
BEGIN
    IF NEW.end_date IS NOT NULL AND NEW.end_date < NEW.start_date THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'end_date must be greater than or equal to start_date',
            CONSTRAINT = 'trg_project_dates';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_project_dates
BEFORE INSERT OR UPDATE OF start_date, end_date
ON stg.project_trigger_bench
FOR EACH ROW
EXECUTE FUNCTION stg.enforce_project_dates();

RESET ROLE;
```

### 9.4. Проверка корректности

Валидная строка:

```sql
INSERT INTO stg.project_check_bench VALUES
    (1, DATE '2026-01-01', DATE '2026-01-31', 'valid');

INSERT INTO stg.project_trigger_bench VALUES
    (1, DATE '2026-01-01', DATE '2026-01-31', 'valid');
```

Невалидная строка — оба варианта должны выдать SQLSTATE `23514`:

```sql
INSERT INTO stg.project_check_bench VALUES
    (2, DATE '2026-02-01', DATE '2026-01-01', 'invalid');

INSERT INTO stg.project_trigger_bench VALUES
    (2, DATE '2026-02-01', DATE '2026-01-01', 'invalid');
```

### 9.5. Вставка 10 000 строк

Сначала обновите статистику и включите вывод времени:

```sql
TRUNCATE stg.project_check_bench, stg.project_trigger_bench;
\timing on
```

Замер `CHECK` без сохранения тестовых строк:

```sql
BEGIN;

EXPLAIN (ANALYZE, BUFFERS, WAL, TIMING OFF, SUMMARY ON)
INSERT INTO stg.project_check_bench (id, start_date, end_date, payload)
SELECT
    g,
    DATE '2026-01-01' + (g % 365)::integer,
    DATE '2026-01-01' + (g % 365)::integer + 30,
    repeat('x', 100)
FROM generate_series(1, 10000) AS g;

ROLLBACK;
```

Замер триггера:

```sql
BEGIN;

EXPLAIN (ANALYZE, BUFFERS, WAL, TIMING OFF, SUMMARY ON)
INSERT INTO stg.project_trigger_bench (id, start_date, end_date, payload)
SELECT
    g,
    DATE '2026-01-01' + (g % 365)::integer,
    DATE '2026-01-01' + (g % 365)::integer + 30,
    repeat('x', 100)
FROM generate_series(1, 10000) AS g;

ROLLBACK;
```

### 9.6. Методика измерения

Для отчёта:

1. Выполните каждый вариант не менее пяти раз.
2. Первый запуск считайте прогревочным и не включайте в итоговую медиану.
3. Не запускайте параллельно резервное копирование, антивирусное сканирование каталога данных или тяжёлые приложения.
4. Зафиксируйте `Execution Time`, `Buffers`, `WAL records`, `WAL bytes`.
5. Рассчитайте медиану, а не выбирайте самый быстрый запуск.
6. Не сравнивайте только «часы на экране»: `EXPLAIN ANALYZE` добавляет собственные накладные расходы.

Шаблон таблицы отчёта:

| Реализация | Прогон | Execution Time, ms | shared hit | dirtied | WAL bytes |
|---|---:|---:|---:|---:|---:|
| CHECK | 1 |  |  |  |  |
| CHECK | 2 |  |  |  |  |
| Trigger | 1 |  |  |  |  |
| Trigger | 2 |  |  |  |  |

Ожидаемая тенденция: для простого внутристрочного правила `CHECK` обычно дешевле row-level триггера. Конкретные числа нельзя переносить между компьютерами; в отчёт включаются только собственные измерения.

## 10. Опциональная автоматизация через pgTAP

pgTAP — расширение для тестов базы данных в формате TAP. Оно не входит в минимальную установку PostgreSQL и устанавливается отдельно.

Пример после установки расширения:

```sql
CREATE EXTENSION IF NOT EXISTS pgtap;

BEGIN;

SELECT plan(3);

SELECT has_function(
    'app',
    'create_project',
    ARRAY['text', 'text', 'numeric', 'date', 'date'],
    'create_project exists'
);

SELECT function_privs_are(
    'app',
    'create_project',
    ARRAY['text', 'text', 'numeric', 'date', 'date'],
    'app_writer',
    ARRAY['EXECUTE'],
    'app_writer can execute create_project'
);

SELECT function_privs_are(
    'app',
    'create_project',
    ARRAY['text', 'text', 'numeric', 'date', 'date'],
    'public',
    ARRAY[]::text[],
    'PUBLIC has no privileges'
);

SELECT * FROM finish();
ROLLBACK;
```

Точные имена проверочных функций зависят от версии pgTAP; сверяйте их с установленной документацией.

## 11. Что включить в отчёт

1. Краткую модель угроз для функций повышенных полномочий.
2. Код трёх функций.
3. Обоснование владельца функций и его прав.
4. Доказательство безопасного `search_path`.
5. Вывод `\df+ app.*` и `\dp audit.*`.
6. Не менее восьми тестов с ожидаемым и фактическим результатом.
7. Журнал успешных и отрицательных вызовов.
8. Объяснение транзакционной проблемы аудита неуспешного исключения.
9. Определения тестовых таблиц и триггера.
10. Собственные результаты пяти прогонов на 10 000 строк.
11. Вывод: почему для выбранного правила используется `CHECK` либо триггер.

## 12. Контрольные вопросы

1. Чем `SECURITY DEFINER` отличается от `SECURITY INVOKER`?
2. Почему для авторизации используется `session_user`, а не только `current_user`?
3. Как временная таблица может атаковать небезопасный `search_path`?
4. Почему необходимо отозвать `EXECUTE` у `PUBLIC`?
5. Почему владелец функции не должен быть superuser?
6. Почему запись отрицательного события откатывается после повторного `RAISE`?
7. Почему свободный текст причины не следует безусловно писать в аудит?
8. В каком случае `CHECK` нельзя использовать для межтабличного правила?
9. Почему один замер на 10 000 строк не является надёжным сравнением?
10. Какие права всё ещё позволяют обойти функцию?

## 13. Материалы для изучения

- [PostgreSQL: CREATE FUNCTION](https://www.postgresql.org/docs/18/sql-createfunction.html)
- [Writing SECURITY DEFINER Functions Safely](https://www.postgresql.org/docs/18/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY)
- [PostgreSQL: Function Security](https://www.postgresql.org/docs/18/perm-functions.html)
- [PostgreSQL: PL/pgSQL Errors and Messages](https://www.postgresql.org/docs/18/plpgsql-errors-and-messages.html)
- [PostgreSQL: Obtaining Information About an Error](https://www.postgresql.org/docs/18/plpgsql-control-structures.html#PLPGSQL-EXCEPTION-DIAGNOSTICS)
- [PostgreSQL: Constraints](https://www.postgresql.org/docs/18/ddl-constraints.html)
- [PostgreSQL: Trigger Functions](https://www.postgresql.org/docs/18/plpgsql-trigger.html)
- [PostgreSQL: EXPLAIN](https://www.postgresql.org/docs/18/sql-explain.html)
- [pgTAP documentation](https://pgtap.org/documentation.html)
- [OWASP: Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)

## 14. Критерий готовности

Лабораторная работа завершена, если прямые чувствительные DML-операции отклоняются, три функции выполняют только разрешённые действия своего сегмента, `PUBLIC` не имеет `EXECUTE`, отрицательные и положительные вызовы видны аудитору, а сравнение `CHECK`/триггера основано на повторных измерениях.

