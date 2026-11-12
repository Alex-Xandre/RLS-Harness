-- rls-harness/harness.sql
--
-- A small test harness for Postgres row-level security, as used on Supabase.
-- It runs inside one transaction, signs in as whoever you name by setting the
-- same JWT claims PostgREST sets, and records a pass or fail per check. At the
-- end it raises if anything failed, so `psql -v ON_ERROR_STOP=1` goes red in CI.
--
-- SECURITY INVOKER throughout: every query runs as the acting role, never as
-- the owner. Each check runs in its own subtransaction and is undone, so the
-- suite is also safe to run on a seeded database. It writes nothing that lasts.
--
-- Usage: see example/rls.sql and README.md.

CREATE SCHEMA rls_test;
CREATE TABLE rls_test.ids (slot text PRIMARY KEY, val uuid NOT NULL);
CREATE TABLE rls_test.results (n serial PRIMARY KEY, label text NOT NULL, ok boolean NOT NULL, detail text);

GRANT USAGE ON SCHEMA rls_test TO authenticated, anon;
GRANT SELECT ON rls_test.ids TO authenticated, anon;
GRANT INSERT ON rls_test.results TO authenticated, anon;
GRANT USAGE ON SEQUENCE rls_test.results_n_seq TO authenticated, anon;

-- Named ids, so a check can say rls_test.id('b.user') instead of pasting a uuid.
CREATE FUNCTION rls_test.id(name text) RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT val FROM rls_test.ids WHERE slot = name
$$;

-- Sign in as a person: the claims PostgREST would set for a verified JWT.
-- Follow it with SET LOCAL ROLE authenticated; both end with the transaction.
CREATE FUNCTION rls_test.login(who text) RETURNS void LANGUAGE sql AS $$
  SELECT set_config('request.jwt.claims',
    json_build_object('sub', rls_test.id(who), 'role', 'authenticated')::text, true)
$$;

CREATE FUNCTION rls_test.logout() RETURNS void LANGUAGE sql AS $$
  SELECT set_config('request.jwt.claims', '', true)
$$;

CREATE FUNCTION rls_test.record(label text, ok boolean, detail text) RETURNS void LANGUAGE sql AS $$
  INSERT INTO rls_test.results (label, ok, detail) VALUES (label, ok, detail)
$$;

-- The query must return exactly `expected` rows.
CREATE FUNCTION rls_test.sees(label text, q text, expected bigint) RETURNS void LANGUAGE plpgsql AS $$
DECLARE got bigint;
BEGIN
  EXECUTE format('SELECT count(*) FROM (%s) s', q) INTO got;
  PERFORM rls_test.record(label, got = expected, format('expected %s, got %s', expected, got));
EXCEPTION WHEN others THEN
  PERFORM rls_test.record(label, false, format('error %s: %s', SQLSTATE, SQLERRM));
END $$;

-- The statement must change exactly `expected` rows. Undone afterwards.
CREATE FUNCTION rls_test.changes(label text, q text, expected int) RETURNS void LANGUAGE plpgsql AS $$
DECLARE got int; st text; msg text;
BEGIN
  BEGIN
    EXECUTE q;
    GET DIAGNOSTICS got = ROW_COUNT;
    RAISE EXCEPTION USING ERRCODE = 'P0099', MESSAGE = got::text;
  EXCEPTION WHEN others THEN st := SQLSTATE; msg := SQLERRM;
  END;
  IF st = 'P0099' THEN
    PERFORM rls_test.record(label, msg::int = expected, format('expected %s row(s), got %s', expected, msg));
  ELSE
    PERFORM rls_test.record(label, false, format('error %s: %s', st, msg));
  END IF;
END $$;

-- The statement must fail with this SQLSTATE ('42501' = permission denied). Undone either way.
CREATE FUNCTION rls_test.refuses(label text, q text, code text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE st text; msg text;
BEGIN
  BEGIN
    EXECUTE q;
    RAISE EXCEPTION USING ERRCODE = 'P0099', MESSAGE = 'no error';
  EXCEPTION WHEN others THEN st := SQLSTATE; msg := SQLERRM;
  END;
  PERFORM rls_test.record(label, st = code, format('expected %s, got %s: %s', code, st, msg));
END $$;

-- The statement runs and its effect is kept, for multi-step checks.
CREATE FUNCTION rls_test.does(label text, q text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE q;
  PERFORM rls_test.record(label, true, 'ok');
EXCEPTION WHEN others THEN
  PERFORM rls_test.record(label, false, format('error %s: %s', SQLSTATE, SQLERRM));
END $$;

-- A single value must equal `expected` (compared as text).
CREATE FUNCTION rls_test.equals(label text, q text, expected text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE got text;
BEGIN
  EXECUTE q INTO got;
  PERFORM rls_test.record(label, got IS NOT DISTINCT FROM expected, format('expected %s, got %s', expected, got));
EXCEPTION WHEN others THEN
  PERFORM rls_test.record(label, false, format('error %s: %s', SQLSTATE, SQLERRM));
END $$;

-- Print every failure, then raise if there were any. Call last, before ROLLBACK.
CREATE FUNCTION rls_test.report() RETURNS void LANGUAGE plpgsql AS $$
DECLARE r record; failed int; total int;
BEGIN
  SELECT count(*) FILTER (WHERE NOT ok), count(*) INTO failed, total FROM rls_test.results;
  FOR r IN SELECT * FROM rls_test.results WHERE NOT ok ORDER BY n LOOP
    RAISE WARNING 'FAIL  %  (%)', r.label, r.detail;
  END LOOP;
  IF failed > 0 THEN
    RAISE EXCEPTION 'RLS tests: % of % checks failed', failed, total;
  END IF;
  RAISE NOTICE 'RLS tests: all % checks passed', total;
END $$;
