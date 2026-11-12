#!/usr/bin/env bash
# Run the suite against any Postgres.
#
#   DATABASE_URL=postgresql://... ./run.sh              # your Supabase project (dev branch, please)
#   ./run.sh --local                                    # plain Postgres on localhost: creates the
#                                                       #   Supabase roles + auth.uid() shim first
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-}" == "--local" ]]; then
  DATABASE_URL="${DATABASE_URL:-postgresql://postgres:postgres@localhost:5432/rls_harness}"
  psql "${DATABASE_URL%/*}/postgres" -v ON_ERROR_STOP=1 -q <<'SQL'
    DROP DATABASE IF EXISTS rls_harness;
    CREATE DATABASE rls_harness;
SQL
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f harness/supabase-shim.sql
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f example/schema.sql
fi

: "${DATABASE_URL:?set DATABASE_URL or pass --local}"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -o /dev/null -f example/rls.sql
