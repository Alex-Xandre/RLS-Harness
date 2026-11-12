-- example/rls.sql
--
-- The suite. Run with:  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f example/rls.sql
-- Everything happens inside one transaction that is rolled back at the end.

BEGIN;
\i harness/harness.sql
\i harness/structure.sql

-- ---------------------------------------------------------------- fixtures
-- Two workspaces, three people. Carol belongs to nothing.
INSERT INTO rls_test.ids VALUES
  ('ws.a', gen_random_uuid()), ('ws.b', gen_random_uuid()),
  ('alice', gen_random_uuid()), ('bob', gen_random_uuid()), ('carol', gen_random_uuid()),
  ('note.a1', gen_random_uuid()), ('note.a2', gen_random_uuid()), ('note.b1', gen_random_uuid());

INSERT INTO public.workspaces (id, name) VALUES (rls_test.id('ws.a'), 'A'), (rls_test.id('ws.b'), 'B');
INSERT INTO public.memberships VALUES
  (rls_test.id('ws.a'), rls_test.id('alice'), 'owner'),
  (rls_test.id('ws.a'), rls_test.id('bob'),   'member'),
  (rls_test.id('ws.b'), rls_test.id('bob'),   'owner');
INSERT INTO public.notes (id, workspace_id, author_id, body) VALUES
  (rls_test.id('note.a1'), rls_test.id('ws.a'), rls_test.id('alice'), 'alice in A'),
  (rls_test.id('note.a2'), rls_test.id('ws.a'), rls_test.id('bob'),   'bob in A'),
  (rls_test.id('note.b1'), rls_test.id('ws.b'), rls_test.id('bob'),   'bob in B');

-- ---------------------------------------------------------------- anon
SET LOCAL ROLE anon;
SELECT rls_test.refuses('anon cannot read workspaces', $q$SELECT * FROM public.workspaces$q$, '42501');
SELECT rls_test.refuses('anon cannot read notes',      $q$SELECT * FROM public.notes$q$, '42501');
SELECT rls_test.refuses('anon cannot insert notes',
  $q$INSERT INTO public.notes (workspace_id, author_id, body) VALUES (rls_test.id('ws.a'), rls_test.id('alice'), 'x')$q$, '42501');
RESET ROLE;

-- ---------------------------------------------------------------- alice: owner of A
SELECT rls_test.login('alice');
SET LOCAL ROLE authenticated;
SELECT rls_test.sees('alice sees only workspace A', $q$SELECT * FROM public.workspaces$q$, 1);
SELECT rls_test.sees('alice sees both notes in A',  $q$SELECT * FROM public.notes$q$, 2);
SELECT rls_test.sees('alice sees nothing of B by id',
  $q$SELECT * FROM public.notes WHERE id = rls_test.id('note.b1')$q$, 0);
SELECT rls_test.changes('alice can rename A',
  $q$UPDATE public.workspaces SET name = 'A2' WHERE id = rls_test.id('ws.a')$q$, 1);
SELECT rls_test.changes('alice renaming B touches nothing',
  $q$UPDATE public.workspaces SET name = 'B2' WHERE id = rls_test.id('ws.b')$q$, 0);
SELECT rls_test.changes('alice can insert a note in A as herself',
  $q$INSERT INTO public.notes (workspace_id, author_id, body) VALUES (rls_test.id('ws.a'), rls_test.id('alice'), 'new')$q$, 1);
SELECT rls_test.refuses('alice cannot insert a note in B',
  $q$INSERT INTO public.notes (workspace_id, author_id, body) VALUES (rls_test.id('ws.b'), rls_test.id('alice'), 'new')$q$, '42501');
SELECT rls_test.refuses('alice cannot post as bob',
  $q$INSERT INTO public.notes (workspace_id, author_id, body) VALUES (rls_test.id('ws.a'), rls_test.id('bob'), 'forged')$q$, '42501');
SELECT rls_test.changes('alice cannot edit bob''s note',
  $q$UPDATE public.notes SET body = 'edited' WHERE id = rls_test.id('note.a2')$q$, 0);
SELECT rls_test.changes('alice as owner can delete bob''s note in A',
  $q$DELETE FROM public.notes WHERE id = rls_test.id('note.a2')$q$, 1);
SELECT rls_test.refuses('alice cannot delete a workspace (no grant)',
  $q$DELETE FROM public.workspaces WHERE id = rls_test.id('ws.a')$q$, '42501');
SELECT rls_test.refuses('alice cannot insert memberships (no grant)',
  $q$INSERT INTO public.memberships VALUES (rls_test.id('ws.a'), rls_test.id('carol'), 'member')$q$, '42501');
RESET ROLE;
SELECT rls_test.logout();

-- ---------------------------------------------------------------- bob: member of A, owner of B
SELECT rls_test.login('bob');
SET LOCAL ROLE authenticated;
SELECT rls_test.sees('bob sees both workspaces', $q$SELECT * FROM public.workspaces$q$, 2);
SELECT rls_test.sees('bob sees all three notes',  $q$SELECT * FROM public.notes$q$, 3);
SELECT rls_test.changes('bob (member) cannot rename A',
  $q$UPDATE public.workspaces SET name = 'A3' WHERE id = rls_test.id('ws.a')$q$, 0);
SELECT rls_test.changes('bob (owner) can rename B',
  $q$UPDATE public.workspaces SET name = 'B3' WHERE id = rls_test.id('ws.b')$q$, 1);
SELECT rls_test.changes('bob cannot delete alice''s note in A (member, not author)',
  $q$DELETE FROM public.notes WHERE id = rls_test.id('note.a1')$q$, 0);
SELECT rls_test.refuses('bob cannot move his note into a workspace he is not in',
  $q$UPDATE public.notes SET workspace_id = gen_random_uuid() WHERE id = rls_test.id('note.a2')$q$, '42501');
RESET ROLE;
SELECT rls_test.logout();

-- ---------------------------------------------------------------- carol: signed in, no memberships
SELECT rls_test.login('carol');
SET LOCAL ROLE authenticated;
SELECT rls_test.sees('carol sees no workspaces', $q$SELECT * FROM public.workspaces$q$, 0);
SELECT rls_test.sees('carol sees no notes',      $q$SELECT * FROM public.notes$q$, 0);
SELECT rls_test.sees('carol sees no memberships', $q$SELECT * FROM public.memberships$q$, 0);
SELECT rls_test.refuses('carol cannot insert a note anywhere',
  $q$INSERT INTO public.notes (workspace_id, author_id, body) VALUES (rls_test.id('ws.a'), rls_test.id('carol'), 'x')$q$, '42501');
RESET ROLE;
SELECT rls_test.logout();

-- ---------------------------------------------------------------- report
SELECT rls_test.report();
ROLLBACK;
