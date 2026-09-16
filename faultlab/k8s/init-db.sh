#!/bin/sh
# Runs once on first Postgres start (docker-entrypoint-initdb.d), as the superuser $POSTGRES_USER
# against $POSTGRES_DB. Creates pg_stat_statements and the read-only role used by the separate
# postgres-readonly-mcp server.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

CREATE ROLE mcp_readonly LOGIN PASSWORD '${MCP_READONLY_PASSWORD}';
GRANT CONNECT ON DATABASE "$POSTGRES_DB" TO mcp_readonly;
GRANT USAGE ON SCHEMA public TO mcp_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;
-- tables the services create later (schema.sql) are owned by $POSTGRES_USER, so grant by default
ALTER DEFAULT PRIVILEGES FOR ROLE "$POSTGRES_USER" IN SCHEMA public GRANT SELECT ON TABLES TO mcp_readonly;
-- lets the read-only role see pg_stat_statements / pg_stat_activity rows for every user
GRANT pg_read_all_stats TO mcp_readonly;
SQL
