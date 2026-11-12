-- harness/supabase-shim.sql
--
-- Only for plain Postgres (CI, local). Creates the pieces Supabase already has so the
-- same schema and suite run unchanged: the anon/authenticated roles and auth.uid().
-- Never run this on a Supabase project.

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
END $$;

GRANT USAGE ON SCHEMA public TO anon, authenticated;
-- Mirror Supabase's default privileges so "anon holds no grant" is a real test, not a freebie.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated;

CREATE SCHEMA IF NOT EXISTS auth;
GRANT USAGE ON SCHEMA auth TO anon, authenticated;
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT (nullif(current_setting('request.jwt.claims', true), '')::json ->> 'sub')::uuid
$$;
