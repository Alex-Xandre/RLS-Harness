# RLS Harness

Test your Postgres row-level security the way the app hits it: signed in as a real user, as `anon`, as the wrong tenant. Plus a one-command checker that lists every public table that is still open.

Extracted from a multi-tenant SaaS where the suite runs 591 checks on every push. Write-up: [591 checks before every deploy](https://xandremicua.vercel.app/blogs/591-checks).

## 1. The checker

```bash
DATABASE_URL=postgresql://... npx github:Alex-Xandre/RLS-Harness
```

Prints the public tables that are **RLS off**, **not forced** (the owner bypasses policies), **granted to `anon`** (Supabase's default on every new table) or have **no policy**. Exits 1 if it finds any, so it can gate a deploy.

```
12 table(s) in public, 2 with findings

  invites      ANON GRANT (DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE)
  backup_runs  NOT FORCED
```

Use a read-only or dev connection string. It only reads catalogs.

## 2. The harness

`harness/harness.sql` gives you six functions. Each check runs as the role you set, in its own subtransaction, and is undone, so the suite is safe to run against a seeded dev database. The whole file is wrapped in `BEGIN … ROLLBACK`.

| call | passes when |
|---|---|
| `sees(label, query, n)` | the query returns exactly `n` rows |
| `changes(label, stmt, n)` | the statement changes exactly `n` rows (then undone) |
| `refuses(label, stmt, '42501')` | the statement fails with that SQLSTATE |
| `does(label, stmt)` | the statement runs; effect kept for later checks |
| `equals(label, query, 'x')` | the single value equals `'x'` |
| `report()` | prints every failure and raises if there were any |

Sign in with `login('alice')` + `SET LOCAL ROLE authenticated`. It sets the same `request.jwt.claims` PostgREST sets, so `auth.uid()` and your policies behave exactly as in production.

```sql
SELECT rls_test.login('alice');
SET LOCAL ROLE authenticated;
SELECT rls_test.sees('alice sees only her workspace', $q$SELECT * FROM workspaces$q$, 1);
SELECT rls_test.refuses('alice cannot post as bob',
  $q$INSERT INTO notes (workspace_id, author_id, body) VALUES (rls_test.id('ws.a'), rls_test.id('bob'), 'x')$q$, '42501');
RESET ROLE;
```

`harness/structure.sql` adds four checks that test the schema itself: every public table has RLS on and forced, `anon` holds no grant, every helper in `private` pins its `search_path`. These are the ones that catch the table you added last week.

### Run it

```bash
./run.sh --local                                # plain Postgres on localhost, creates the DB + Supabase shim
DATABASE_URL=postgresql://... ./run.sh          # your Supabase dev branch
```

`example/` has a two-tenant schema (workspaces, memberships, notes; owner vs member) and a 29-check suite against it. Copy the pattern, replace with your tables.

### In CI

`.github/workflows/rls.yml` runs the suite on a Postgres 16 service, then runs the checker and proves it fails on a deliberately open table. Point `DATABASE_URL` at a dev branch instead if your policies depend on Supabase-only pieces.

## The three rules the schema follows

1. `ENABLE` **and** `FORCE` row level security on every table. Forced means the owner (and anything `SECURITY DEFINER`) goes through policies too.
2. `REVOKE ALL … FROM anon, authenticated` in the same migration that creates the table, then `GRANT` back only what the app uses. Column-level grants (`GRANT UPDATE (name)`) for the rest.
3. Policy helpers live in a `private` schema, are `SECURITY DEFINER`, and `SET search_path = ''`. They are the only things that read membership tables without recursing.

## Layout

```
harness/harness.sql        the six functions + report
harness/structure.sql      schema-level checks
harness/supabase-shim.sql  anon/authenticated roles + auth.uid() for plain Postgres (never run on Supabase)
example/schema.sql         two-tenant schema done right
example/rls.sql            the suite
bin/check.mjs              the checker
run.sh                     local or remote runner
```

MIT. Questions and audits: [xandremicua.vercel.app/services](https://xandremicua.vercel.app/services).
