\set ON_ERROR_STOP on
\pset pager off

\echo '== 00-bootstrap: roles, schemas and baseline hardening =='

-- The script is intended to be executed by a local PostgreSQL administrator.
DO $bootstrap$
DECLARE
    v_role text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY[
        'app_reader', 'app_writer', 'app_owner', 'audit_owner',
        'auditor', 'ddl_admin', 'dml_admin', 'security_admin'
    ]
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                v_role
            );
        END IF;
    END LOOP;

    FOREACH v_role IN ARRAY ARRAY['lab_alice', 'lab_bob', 'lab_auditor']
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
            EXECUTE format(
                'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                v_role
            );
        END IF;
    END LOOP;
END
$bootstrap$;

-- Reassert security-sensitive attributes if this script is rerun.
ALTER ROLE app_reader    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE app_writer    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE app_owner     NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE audit_owner   NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE auditor       NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ddl_admin     NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE dml_admin     NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE security_admin NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

GRANT app_reader TO app_writer;
GRANT app_owner, audit_owner TO ddl_admin
    WITH INHERIT FALSE, SET TRUE;
GRANT app_reader, app_writer, auditor TO security_admin
    WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT app_writer TO lab_alice, lab_bob;
GRANT auditor TO lab_auditor;

-- PUBLIC receives neither implicit database access nor schema creation rights.
DO $database_acl$
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO app_reader, app_writer, auditor, ddl_admin, dml_admin, security_admin, lab_alice, lab_bob, lab_auditor',
        current_database()
    );
END
$database_acl$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS app   AUTHORIZATION app_owner;
CREATE SCHEMA IF NOT EXISTS ref   AUTHORIZATION app_owner;
CREATE SCHEMA IF NOT EXISTS stg   AUTHORIZATION app_owner;
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION audit_owner;

REVOKE ALL ON SCHEMA app, ref, stg, audit FROM PUBLIC;
GRANT USAGE ON SCHEMA app, ref TO app_reader, app_writer;
GRANT USAGE ON SCHEMA app, ref, audit TO auditor;
GRANT USAGE ON SCHEMA app, ref, stg TO dml_admin;
GRANT USAGE ON SCHEMA audit TO app_owner;

-- Future routines must never become executable by PUBLIC implicitly.
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner
    REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE audit_owner
    REVOKE EXECUTE ON ROUTINES FROM PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app
    GRANT SELECT ON TABLES TO auditor;
ALTER DEFAULT PRIVILEGES FOR ROLE audit_owner IN SCHEMA audit
    GRANT SELECT ON TABLES TO auditor;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app
    GRANT USAGE, SELECT ON SEQUENCES TO app_writer;

\echo '00-bootstrap completed'
