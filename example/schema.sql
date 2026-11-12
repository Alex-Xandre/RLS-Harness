-- example/schema.sql
--
-- A two-tenant schema with the pattern the harness is built to test:
--   * a private schema for helpers the policies call (SECURITY DEFINER, pinned search_path)
--   * RLS enabled AND forced on every public table
--   * the default Supabase grants to anon revoked, authenticated granted only what it needs
--
-- On Supabase the `anon`/`authenticated` roles and auth.uid() already exist; on a plain
-- Postgres the run.sh shim creates stand-ins so the same file runs in CI.

CREATE SCHEMA IF NOT EXISTS private;
REVOKE ALL ON SCHEMA private FROM PUBLIC;

CREATE TABLE public.workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);

CREATE TABLE public.memberships (
  workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('owner', 'member')),
  PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE public.notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  author_id uuid NOT NULL,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Helpers run as their owner (postgres) so they can read memberships without
-- recursing through the memberships policy. search_path is pinned: see structure.sql.
CREATE FUNCTION private.is_member(ws uuid) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (SELECT 1 FROM public.memberships m WHERE m.workspace_id = ws AND m.user_id = auth.uid())
$$;

CREATE FUNCTION private.is_owner(ws uuid) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (SELECT 1 FROM public.memberships m
                 WHERE m.workspace_id = ws AND m.user_id = auth.uid() AND m.role = 'owner')
$$;

REVOKE ALL ON FUNCTION private.is_member(uuid), private.is_owner(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.is_member(uuid), private.is_owner(uuid) TO authenticated;

-- Supabase grants ALL on every new public table to anon and authenticated. Take it back.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;
GRANT SELECT ON public.workspaces, public.memberships TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.notes TO authenticated;
GRANT UPDATE (name) ON public.workspaces TO authenticated;   -- column-level: owners rename, nothing else

ALTER TABLE public.workspaces  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notes       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspaces  FORCE ROW LEVEL SECURITY;
ALTER TABLE public.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE public.notes       FORCE ROW LEVEL SECURITY;

CREATE POLICY ws_select ON public.workspaces FOR SELECT TO authenticated
  USING (private.is_member(id));
CREATE POLICY ws_rename ON public.workspaces FOR UPDATE TO authenticated
  USING (private.is_owner(id)) WITH CHECK (private.is_owner(id));

CREATE POLICY mem_select ON public.memberships FOR SELECT TO authenticated
  USING (private.is_member(workspace_id));

CREATE POLICY notes_select ON public.notes FOR SELECT TO authenticated
  USING (private.is_member(workspace_id));
CREATE POLICY notes_insert ON public.notes FOR INSERT TO authenticated
  WITH CHECK (private.is_member(workspace_id) AND author_id = auth.uid());
CREATE POLICY notes_update ON public.notes FOR UPDATE TO authenticated
  USING (author_id = auth.uid()) WITH CHECK (author_id = auth.uid() AND private.is_member(workspace_id));
CREATE POLICY notes_delete ON public.notes FOR DELETE TO authenticated
  USING (author_id = auth.uid() OR private.is_owner(workspace_id));
