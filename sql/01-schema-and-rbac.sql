\set ON_ERROR_STOP on
\pset pager off

\echo '== 01-schema-and-rbac: domain DDL, seed data, ACL and login audit =='

SET ROLE app_owner;

CREATE TABLE IF NOT EXISTS ref.segment (
    segment_id  smallint GENERATED ALWAYS AS IDENTITY,
    code        text     NOT NULL,
    name        text     NOT NULL,
    is_active   boolean  NOT NULL DEFAULT true,
    CONSTRAINT pk_segment PRIMARY KEY (segment_id),
    CONSTRAINT uq_segment_code UNIQUE (code),
    CONSTRAINT ck_segment_code CHECK (code ~ '^[A-Z][A-Z0-9_]{1,15}$'),
    CONSTRAINT ck_segment_name CHECK (btrim(name) <> '')
);

CREATE TABLE IF NOT EXISTS ref.project_status (
    status_code  text NOT NULL,
    display_name text NOT NULL,
    CONSTRAINT pk_project_status PRIMARY KEY (status_code),
    CONSTRAINT ck_project_status_code
        CHECK (status_code IN ('planned', 'active', 'closed', 'cancelled'))
);

CREATE TABLE IF NOT EXISTS ref.task_status (
    status_code  text NOT NULL,
    display_name text NOT NULL,
    CONSTRAINT pk_task_status PRIMARY KEY (status_code),
    CONSTRAINT ck_task_status_code
        CHECK (status_code IN ('new', 'in_progress', 'blocked', 'done', 'cancelled'))
);

CREATE TABLE IF NOT EXISTS app.actor (
    actor_id      bigint GENERATED ALWAYS AS IDENTITY,
    segment_id    smallint    NOT NULL,
    employee_no   text        NOT NULL,
    full_name     text        NOT NULL,
    email         text        NOT NULL,
    phone         text,
    is_active     boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_actor PRIMARY KEY (actor_id),
    CONSTRAINT fk_actor_segment
        FOREIGN KEY (segment_id) REFERENCES ref.segment(segment_id),
    CONSTRAINT uq_actor_segment_id UNIQUE (segment_id, actor_id),
    CONSTRAINT uq_actor_employee UNIQUE (segment_id, employee_no),
    CONSTRAINT ck_actor_employee_no CHECK (employee_no ~ '^[A-Z0-9-]{3,20}$'),
    CONSTRAINT ck_actor_full_name CHECK (char_length(btrim(full_name)) >= 3),
    CONSTRAINT ck_actor_email CHECK (position('@' IN email) > 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_actor_segment_email_ci
    ON app.actor (segment_id, lower(email));
CREATE INDEX IF NOT EXISTS ix_actor_segment_active
    ON app.actor (segment_id, is_active);

CREATE TABLE IF NOT EXISTS app.project (
    project_id    bigint GENERATED ALWAYS AS IDENTITY,
    segment_id    smallint      NOT NULL,
    name          text          NOT NULL,
    description   text,
    budget        numeric(14,2) NOT NULL DEFAULT 0,
    status_code   text          NOT NULL DEFAULT 'planned',
    start_date    date          NOT NULL,
    end_date      date,
    created_at    timestamptz   NOT NULL DEFAULT clock_timestamp(),
    updated_at    timestamptz   NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_project PRIMARY KEY (project_id),
    CONSTRAINT fk_project_segment
        FOREIGN KEY (segment_id) REFERENCES ref.segment(segment_id),
    CONSTRAINT fk_project_status
        FOREIGN KEY (status_code) REFERENCES ref.project_status(status_code),
    CONSTRAINT uq_project_segment_id UNIQUE (segment_id, project_id),
    CONSTRAINT uq_project_segment_name UNIQUE (segment_id, name),
    CONSTRAINT ck_project_name CHECK (char_length(btrim(name)) >= 3),
    CONSTRAINT ck_project_budget CHECK (budget >= 0),
    CONSTRAINT ck_project_dates CHECK (end_date IS NULL OR end_date >= start_date)
);

CREATE INDEX IF NOT EXISTS ix_project_segment_status
    ON app.project (segment_id, status_code);
CREATE INDEX IF NOT EXISTS ix_project_segment_dates
    ON app.project (segment_id, start_date, end_date);

CREATE TABLE IF NOT EXISTS app.task (
    task_id            bigint GENERATED ALWAYS AS IDENTITY,
    segment_id         smallint      NOT NULL,
    project_id         bigint        NOT NULL,
    assignee_actor_id  bigint,
    title              text          NOT NULL,
    status_code        text          NOT NULL DEFAULT 'new',
    priority           smallint      NOT NULL DEFAULT 3,
    planned_hours      numeric(8,2)  NOT NULL DEFAULT 0,
    actual_hours       numeric(8,2),
    due_date           date,
    created_at         timestamptz   NOT NULL DEFAULT clock_timestamp(),
    updated_at         timestamptz   NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_task PRIMARY KEY (task_id),
    CONSTRAINT uq_task_segment_id UNIQUE (segment_id, task_id),
    CONSTRAINT fk_task_project_segment
        FOREIGN KEY (segment_id, project_id)
        REFERENCES app.project(segment_id, project_id),
    CONSTRAINT fk_task_actor_segment
        FOREIGN KEY (segment_id, assignee_actor_id)
        REFERENCES app.actor(segment_id, actor_id),
    CONSTRAINT fk_task_status
        FOREIGN KEY (status_code) REFERENCES ref.task_status(status_code),
    CONSTRAINT ck_task_title CHECK (char_length(btrim(title)) >= 3),
    CONSTRAINT ck_task_priority CHECK (priority BETWEEN 1 AND 5),
    CONSTRAINT ck_task_planned_hours CHECK (planned_hours >= 0),
    CONSTRAINT ck_task_actual_hours CHECK (actual_hours IS NULL OR actual_hours >= 0)
);

CREATE INDEX IF NOT EXISTS ix_task_segment_status
    ON app.task (segment_id, status_code);
CREATE INDEX IF NOT EXISTS ix_task_segment_project_status
    ON app.task (segment_id, project_id, status_code);
CREATE INDEX IF NOT EXISTS ix_task_segment_assignee
    ON app.task (segment_id, assignee_actor_id)
    WHERE assignee_actor_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ref.role_segment (
    login_role  name        NOT NULL,
    segment_id  smallint    NOT NULL,
    actor_id    bigint      NOT NULL,
    is_active   boolean     NOT NULL DEFAULT true,
    valid_from  timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz,
    CONSTRAINT pk_role_segment PRIMARY KEY (login_role),
    CONSTRAINT fk_role_segment_segment
        FOREIGN KEY (segment_id) REFERENCES ref.segment(segment_id),
    CONSTRAINT fk_role_segment_actor
        FOREIGN KEY (segment_id, actor_id)
        REFERENCES app.actor(segment_id, actor_id),
    CONSTRAINT ck_role_segment_period
        CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE INDEX IF NOT EXISTS ix_role_segment_active
    ON ref.role_segment (login_role, segment_id)
    WHERE is_active;

-- Synthetic reference and domain data.
INSERT INTO ref.segment (segment_id, code, name)
OVERRIDING SYSTEM VALUE
VALUES
    (1, 'NSK', 'Новосибирский филиал'),
    (2, 'MSK', 'Московский филиал'),
    (3, 'SPB', 'Санкт-Петербургский филиал')
ON CONFLICT (segment_id) DO UPDATE
SET code = EXCLUDED.code, name = EXCLUDED.name;

INSERT INTO ref.project_status (status_code, display_name) VALUES
    ('planned', 'Запланирован'),
    ('active', 'Выполняется'),
    ('closed', 'Завершён'),
    ('cancelled', 'Отменён')
ON CONFLICT (status_code) DO UPDATE SET display_name = EXCLUDED.display_name;

INSERT INTO ref.task_status (status_code, display_name) VALUES
    ('new', 'Новая'),
    ('in_progress', 'В работе'),
    ('blocked', 'Заблокирована'),
    ('done', 'Выполнена'),
    ('cancelled', 'Отменена')
ON CONFLICT (status_code) DO UPDATE SET display_name = EXCLUDED.display_name;

INSERT INTO app.actor (
    actor_id, segment_id, employee_no, full_name, email, phone
)
OVERRIDING SYSTEM VALUE
VALUES
    (1,  1, 'NSK-001', 'Анна Орлова',    'anna.orlova@example.test',   '+7-900-000-0001'),
    (2,  1, 'NSK-002', 'Илья Соколов',   'ilya.sokolov@example.test',  '+7-900-000-0002'),
    (3,  1, 'NSK-003', 'Мария Белова',   'maria.belova@example.test',  '+7-900-000-0003'),
    (4,  1, 'NSK-004', 'Олег Васильев',  'oleg.vasiliev@example.test', '+7-900-000-0004'),
    (5,  2, 'MSK-001', 'Борис Волков',   'boris.volkov@example.test',  '+7-900-000-0005'),
    (6,  2, 'MSK-002', 'Елена Морозова', 'elena.moroz@example.test',   '+7-900-000-0006'),
    (7,  2, 'MSK-003', 'Денис Павлов',   'denis.pavlov@example.test',  '+7-900-000-0007'),
    (8,  2, 'MSK-004', 'Ирина Фролова',  'irina.frolova@example.test', '+7-900-000-0008'),
    (9,  3, 'SPB-001', 'Павел Егоров',   'pavel.egorov@example.test',  '+7-900-000-0009'),
    (10, 3, 'SPB-002', 'Ольга Крылова',   'olga.krylova@example.test',  '+7-900-000-0010'),
    (11, 3, 'SPB-003', 'Роман Жуков',    'roman.zhukov@example.test',  '+7-900-000-0011'),
    (12, 3, 'SPB-004', 'Нина Комарова',  'nina.komarova@example.test', '+7-900-000-0012')
ON CONFLICT (actor_id) DO NOTHING;

INSERT INTO app.project (
    project_id, segment_id, name, description, budget,
    status_code, start_date, end_date
)
OVERRIDING SYSTEM VALUE
VALUES
    (101, 1, 'NSK Portal',      'Портал филиала',          1200000, 'active',  '2026-01-10', NULL),
    (102, 1, 'NSK Analytics',   'Витрина аналитики',        850000, 'planned', '2026-04-01', NULL),
    (103, 1, 'NSK Archive',     'Архив документов',         430000, 'active',  '2026-02-15', NULL),
    (104, 1, 'NSK Migration',   'Миграция справочников',    280000, 'closed',  '2025-10-01', '2026-02-01'),
    (201, 2, 'MSK Billing',     'Расчёт начислений',       2100000, 'active',  '2026-01-05', NULL),
    (202, 2, 'MSK CRM',         'Учёт взаимодействий',     1750000, 'planned', '2026-05-10', NULL),
    (203, 2, 'MSK Integration', 'Интеграционная шина',      990000, 'active',  '2026-03-01', NULL),
    (204, 2, 'MSK Legacy Exit', 'Вывод старой системы',     510000, 'closed',  '2025-08-10', '2026-01-20'),
    (301, 3, 'SPB Warehouse',   'Учёт оборудования',       1350000, 'active',  '2026-02-01', NULL),
    (302, 3, 'SPB Helpdesk',    'Сервис заявок',            760000, 'planned', '2026-06-01', NULL),
    (303, 3, 'SPB Reports',     'Регламентная отчётность',   640000, 'active',  '2026-03-12', NULL),
    (304, 3, 'SPB Pilot',       'Завершённый пилот',         300000, 'closed',  '2025-11-01', '2026-02-28')
ON CONFLICT (project_id) DO NOTHING;

INSERT INTO app.task (
    task_id, segment_id, project_id, assignee_actor_id, title,
    status_code, priority, planned_hours, actual_hours, due_date
)
OVERRIDING SYSTEM VALUE
VALUES
    (1001, 1, 101, 1,  'Спроектировать API',         'in_progress', 1, 40, 18, '2026-10-05'),
    (1002, 1, 101, 2,  'Настроить CI',               'new',         2, 16, NULL, '2026-10-08'),
    (1003, 1, 102, 3,  'Согласовать метрики',         'blocked',     2, 24,  6, '2026-10-10'),
    (1004, 1, 103, 4,  'Описать формат архива',       'done',        3, 12, 11, '2026-09-20'),
    (1005, 1, 104, 1,  'Проверить миграцию',          'done',        2, 20, 19, '2026-02-01'),
    (2001, 2, 201, 5,  'Проверить формулы',           'in_progress', 1, 32, 12, '2026-10-04'),
    (2002, 2, 201, 6,  'Подготовить тестовые счета',  'new',         2, 20, NULL, '2026-10-09'),
    (2003, 2, 202, 7,  'Описать карточку клиента',    'new',         3, 16, NULL, '2026-10-15'),
    (2004, 2, 203, 8,  'Настроить очередь событий',   'blocked',     1, 36,  8, '2026-10-07'),
    (2005, 2, 204, 5,  'Закрыть старый контур',       'done',        2, 14, 13, '2026-01-20'),
    (3001, 3, 301, 9,  'Импортировать оборудование',  'in_progress', 2, 28, 10, '2026-10-06'),
    (3002, 3, 301, 10, 'Проверить остатки',           'new',         2, 18, NULL, '2026-10-12'),
    (3003, 3, 302, 11, 'Настроить категории заявок',  'new',         3, 12, NULL, '2026-10-14'),
    (3004, 3, 303, 12, 'Сверить отчёт',               'in_progress', 1, 24,  9, '2026-10-03'),
    (3005, 3, 304, 9,  'Оформить результаты пилота',  'done',        3, 10, 10, '2026-02-28')
ON CONFLICT (task_id) DO NOTHING;

INSERT INTO ref.role_segment (login_role, segment_id, actor_id) VALUES
    ('lab_alice', 1, 1),
    ('lab_bob',   2, 5)
ON CONFLICT (login_role) DO UPDATE
SET segment_id = EXCLUDED.segment_id,
    actor_id = EXCLUDED.actor_id,
    is_active = true,
    valid_until = NULL;

SELECT setval(pg_get_serial_sequence('ref.segment', 'segment_id'),
              (SELECT max(segment_id) FROM ref.segment), true);
SELECT setval(pg_get_serial_sequence('app.actor', 'actor_id'),
              (SELECT max(actor_id) FROM app.actor), true);
SELECT setval(pg_get_serial_sequence('app.project', 'project_id'),
              (SELECT max(project_id) FROM app.project), true);
SELECT setval(pg_get_serial_sequence('app.task', 'task_id'),
              (SELECT max(task_id) FROM app.task), true);

RESET ROLE;

-- RBAC. Confidential columns are granted explicitly, not via SELECT *.
GRANT SELECT ON ref.segment, ref.project_status, ref.task_status
TO app_reader, app_writer, auditor;

GRANT SELECT (
    project_id, segment_id, name, description, status_code,
    start_date, end_date, created_at, updated_at
) ON app.project TO app_reader;
GRANT SELECT (
    task_id, segment_id, project_id, assignee_actor_id, title,
    status_code, priority, due_date, created_at, updated_at
) ON app.task TO app_reader;
GRANT SELECT (actor_id, segment_id, employee_no, full_name, is_active)
ON app.actor TO app_reader;

GRANT SELECT (budget) ON app.project TO app_writer;
GRANT SELECT (planned_hours, actual_hours) ON app.task TO app_writer;
GRANT INSERT, UPDATE ON app.project, app.task TO app_writer;
GRANT INSERT (segment_id, employee_no, full_name, email, phone, is_active),
      UPDATE (employee_no, full_name, email, phone, is_active)
ON app.actor TO app_writer;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO app_writer;
REVOKE DELETE ON app.project, app.task, app.actor FROM app_writer;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO dml_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA stg TO dml_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app, stg TO dml_admin;
GRANT SELECT ON app.actor, app.project, app.task TO auditor;
REVOKE ALL ON ref.role_segment FROM app_reader, app_writer, auditor, PUBLIC;

-- Connection audit. PostgreSQL 17+ supports event triggers on LOGIN.
SET ROLE audit_owner;

CREATE TABLE IF NOT EXISTS audit.login_log (
    login_id          bigint GENERATED ALWAYS AS IDENTITY,
    login_time        timestamptz NOT NULL DEFAULT clock_timestamp(),
    username          name        NOT NULL,
    client_ip         inet,
    database_name     name        NOT NULL,
    application_name  text,
    backend_pid       integer     NOT NULL,
    CONSTRAINT pk_login_log PRIMARY KEY (login_id)
);

CREATE INDEX IF NOT EXISTS ix_login_log_time
    ON audit.login_log (login_time DESC);
CREATE INDEX IF NOT EXISTS ix_login_log_user_time
    ON audit.login_log (username, login_time DESC);

CREATE OR REPLACE FUNCTION audit.capture_login()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit, pg_temp
AS $function$
BEGIN
    IF pg_is_in_recovery() THEN
        RETURN;
    END IF;

    INSERT INTO audit.login_log (
        login_time, username, client_ip, database_name,
        application_name, backend_pid
    )
    VALUES (
        clock_timestamp(), session_user, inet_client_addr(), current_database(),
        current_setting('application_name', true), pg_backend_pid()
    );
EXCEPTION
    WHEN OTHERS THEN
        RAISE LOG 'capture_login failed for role %: %', session_user, SQLERRM;
END;
$function$;

REVOKE ALL ON FUNCTION audit.capture_login() FROM PUBLIC;
GRANT SELECT ON audit.login_log TO auditor;

RESET ROLE;

DROP EVENT TRIGGER IF EXISTS et_capture_login;
CREATE EVENT TRIGGER et_capture_login
    ON login
    EXECUTE FUNCTION audit.capture_login();
ALTER EVENT TRIGGER et_capture_login ENABLE ALWAYS;

\echo '01-schema-and-rbac completed'
