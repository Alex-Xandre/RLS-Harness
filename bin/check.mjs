#!/usr/bin/env node
// rls-check: list the public tables on a Postgres/Supabase database that are not locked down.
//
//   DATABASE_URL=postgresql://... npx rls-check
//   npx rls-check postgresql://...
//
// Reports, per table in schema public:
//   RLS OFF     row-level security not enabled   -> every grant is a full read/write
//   NOT FORCED  the table owner bypasses policies -> SECURITY DEFINER helpers and the
//               dashboard see everything; also hides bugs from owner-run tests
//   ANON GRANT  the anon role holds a privilege   -> Supabase's default; reachable with
//               the publishable key and no sign-in
//   NO POLICY   RLS on, but no policy exists      -> fine if intentional (nobody can read),
//               listed so you can confirm it
// Exits 1 when anything is listed, so it can gate a deploy.

import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { Client } = require("pg");

const url = process.argv[2] || process.env.DATABASE_URL;
if (!url) {
  console.error("usage: DATABASE_URL=postgresql://... rls-check   (or pass the URL as the first argument)");
  process.exit(2);
}

const SQL = `
WITH t AS (
  SELECT c.oid, c.relname AS name, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
),
anon AS (
  SELECT table_name AS name, string_agg(DISTINCT privilege_type, ',' ORDER BY privilege_type) AS privs
  FROM information_schema.role_table_grants
  WHERE grantee = 'anon' AND table_schema = 'public'
  GROUP BY table_name
),
pol AS (
  SELECT polrelid AS oid, count(*) AS n FROM pg_policy GROUP BY polrelid
)
SELECT t.name, t.rls, t.forced, anon.privs, coalesce(pol.n, 0)::int AS policies
FROM t LEFT JOIN anon USING (name) LEFT JOIN pol USING (oid)
ORDER BY t.name;`;

const client = new Client({ connectionString: url, ssl: url.includes("localhost") || url.includes("127.0.0.1") ? false : { rejectUnauthorized: false } });
await client.connect();
const { rows } = await client.query(SQL);
await client.end();

const findings = [];
for (const r of rows) {
  const flags = [];
  if (!r.rls) flags.push("RLS OFF");
  else if (!r.forced) flags.push("NOT FORCED");
  if (r.privs) flags.push(`ANON GRANT (${r.privs})`);
  if (r.rls && r.policies === 0) flags.push("NO POLICY");
  if (flags.length) findings.push({ table: r.name, flags });
}

const pad = (s, n) => String(s).padEnd(n);
const w = Math.max(5, ...rows.map((r) => r.name.length));
console.log(`${rows.length} table(s) in public, ${findings.length} with findings\n`);
if (findings.length) {
  for (const f of findings) console.log(`  ${pad(f.table, w)}  ${f.flags.join("  ")}`);
  console.log(`
Fix in a migration:
  ALTER TABLE public.<t> ENABLE ROW LEVEL SECURITY;
  ALTER TABLE public.<t> FORCE ROW LEVEL SECURITY;
  REVOKE ALL ON public.<t> FROM anon, authenticated;   -- then GRANT back only what the app uses
Then prove it: https://github.com/Alex-Xandre/RLS-Harness`);
  process.exit(1);
}
console.log("  every public table: RLS on, forced, no anon grants, at least one policy.");
