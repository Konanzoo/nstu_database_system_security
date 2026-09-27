\set ON_ERROR_STOP on
\pset pager off
\timing on

\echo 'Deploying PostgreSQL security labs into:' :DBNAME

\ir 00-bootstrap.sql
\ir 01-schema-and-rbac.sql
\ir 02-functions-and-tests.sql
\ir 03-rls.sql
\ir 04-views-audit-performance.sql
\ir 05-jit-access.sql

\echo '== Deployment summary =='
SELECT current_database() AS database_name,
       current_setting('server_version') AS server_version;

SELECT n.nspname AS schema_name,
       count(c.oid) FILTER (WHERE c.relkind IN ('r', 'p')) AS tables,
       count(c.oid) FILTER (WHERE c.relkind = 'v') AS views
FROM pg_catalog.pg_namespace AS n
LEFT JOIN pg_catalog.pg_class AS c ON c.relnamespace = n.oid
WHERE n.nspname IN ('app', 'ref', 'audit', 'stg')
GROUP BY n.nspname
ORDER BY n.nspname;

SELECT c.oid::regclass AS table_name,
       c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS rls_forced
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'app'
  AND c.relname IN ('actor', 'project', 'task')
ORDER BY c.relname;

\echo 'Deployment completed successfully'
