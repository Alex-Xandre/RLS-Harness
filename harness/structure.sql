-- rls-harness/structure.sql
--
-- Three checks that test the schema, not a feature. Include after harness.sql.
-- They are what catches the table you added last week and forgot about.

SELECT rls_test.sees('every public table has RLS on',
  $q$SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'r' AND NOT c.relrowsecurity$q$, 0);

SELECT rls_test.sees('every public table has RLS forced (the owner goes through policies too)',
  $q$SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'r' AND NOT c.relforcerowsecurity$q$, 0);

-- Supabase grants every new table to anon by default. Revoke it in the migration; this proves you did.
SELECT rls_test.sees('anon holds no table privilege in public',
  $q$SELECT 1 FROM information_schema.role_table_grants WHERE grantee = 'anon' AND table_schema = 'public'$q$, 0);

-- Helpers called from policies run as their owner: a search_path they don't pin is an injection point.
SELECT rls_test.sees('every function in private pins its search_path',
  $q$SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'private' AND NOT coalesce(p.proconfig::text, '') LIKE '%search_path%'$q$, 0);
