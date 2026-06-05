--
-- PostgreSQL database dump
--

\restrict HzXpOAQF3dfFDGmBlhiHKQudfRvyu5FHutkvuVEV2gQqcSPOabMEZOcM9WqyBbE

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.10 (Debian 17.10-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: auth; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA auth;


--
-- Name: extensions; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA extensions;


--
-- Name: graphql; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA graphql;


--
-- Name: graphql_public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA graphql_public;


--
-- Name: pgbouncer; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA pgbouncer;


--
-- Name: realtime; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA realtime;


--
-- Name: storage; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA storage;


--
-- Name: vault; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA vault;


--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA extensions;


--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_stat_statements IS 'track planning and execution statistics of all SQL statements executed';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: supabase_vault; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS supabase_vault WITH SCHEMA vault;


--
-- Name: EXTENSION supabase_vault; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION supabase_vault IS 'Supabase Vault Extension';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: aal_level; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.aal_level AS ENUM (
    'aal1',
    'aal2',
    'aal3'
);


--
-- Name: code_challenge_method; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.code_challenge_method AS ENUM (
    's256',
    'plain'
);


--
-- Name: factor_status; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.factor_status AS ENUM (
    'unverified',
    'verified'
);


--
-- Name: factor_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.factor_type AS ENUM (
    'totp',
    'webauthn',
    'phone'
);


--
-- Name: oauth_authorization_status; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.oauth_authorization_status AS ENUM (
    'pending',
    'approved',
    'denied',
    'expired'
);


--
-- Name: oauth_client_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.oauth_client_type AS ENUM (
    'public',
    'confidential'
);


--
-- Name: oauth_registration_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.oauth_registration_type AS ENUM (
    'dynamic',
    'manual'
);


--
-- Name: oauth_response_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.oauth_response_type AS ENUM (
    'code'
);


--
-- Name: one_time_token_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.one_time_token_type AS ENUM (
    'confirmation_token',
    'reauthentication_token',
    'recovery_token',
    'email_change_token_new',
    'email_change_token_current',
    'phone_change_token'
);


--
-- Name: action; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.action AS ENUM (
    'INSERT',
    'UPDATE',
    'DELETE',
    'TRUNCATE',
    'ERROR'
);


--
-- Name: equality_op; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.equality_op AS ENUM (
    'eq',
    'neq',
    'lt',
    'lte',
    'gt',
    'gte',
    'in'
);


--
-- Name: user_defined_filter; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.user_defined_filter AS (
	column_name text,
	op realtime.equality_op,
	value text
);


--
-- Name: wal_column; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.wal_column AS (
	name text,
	type_name text,
	type_oid oid,
	value jsonb,
	is_pkey boolean,
	is_selectable boolean
);


--
-- Name: wal_rls; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.wal_rls AS (
	wal jsonb,
	is_rls_enabled boolean,
	subscription_ids uuid[],
	errors text[]
);


--
-- Name: buckettype; Type: TYPE; Schema: storage; Owner: -
--

CREATE TYPE storage.buckettype AS ENUM (
    'STANDARD',
    'ANALYTICS',
    'VECTOR'
);


--
-- Name: email(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.email() RETURNS text
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;


--
-- Name: FUNCTION email(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.email() IS 'Deprecated. Use auth.jwt() -> ''email'' instead.';


--
-- Name: jwt(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.jwt() RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
  select 
    coalesce(
        nullif(current_setting('request.jwt.claim', true), ''),
        nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;


--
-- Name: role(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.role() RETURNS text
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;


--
-- Name: FUNCTION role(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.role() IS 'Deprecated. Use auth.jwt() -> ''role'' instead.';


--
-- Name: uid(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.uid() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;


--
-- Name: FUNCTION uid(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.uid() IS 'Deprecated. Use auth.jwt() -> ''sub'' instead.';


--
-- Name: grant_pg_cron_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_cron_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (
    SELECT
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_cron'
  )
  THEN
    grant usage on schema cron to postgres with grant option;

    alter default privileges in schema cron grant all on tables to postgres with grant option;
    alter default privileges in schema cron grant all on functions to postgres with grant option;
    alter default privileges in schema cron grant all on sequences to postgres with grant option;

    alter default privileges for user supabase_admin in schema cron grant all
        on sequences to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on tables to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on functions to postgres with grant option;

    grant all privileges on all tables in schema cron to postgres with grant option;
    revoke all on table cron.job from postgres;
    grant select on table cron.job to postgres with grant option;
  END IF;
END;
$$;


--
-- Name: FUNCTION grant_pg_cron_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_cron_access() IS 'Grants access to pg_cron';


--
-- Name: grant_pg_graphql_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_graphql_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    func_is_graphql_resolve bool;
BEGIN
    func_is_graphql_resolve = (
        SELECT n.proname = 'resolve'
        FROM pg_event_trigger_ddl_commands() AS ev
        LEFT JOIN pg_catalog.pg_proc AS n
        ON ev.objid = n.oid
    );

    IF func_is_graphql_resolve
    THEN
        -- Update public wrapper to pass all arguments through to the pg_graphql resolve func
        DROP FUNCTION IF EXISTS graphql_public.graphql;
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language sql
        as $$
            select graphql.resolve(
                query := query,
                variables := coalesce(variables, '{}'),
                "operationName" := "operationName",
                extensions := extensions
            );
        $$;

        -- This hook executes when `graphql.resolve` is created. That is not necessarily the last
        -- function in the extension so we need to grant permissions on existing entities AND
        -- update default permissions to any others that are created after `graphql.resolve`
        grant usage on schema graphql to postgres, anon, authenticated, service_role;
        grant select on all tables in schema graphql to postgres, anon, authenticated, service_role;
        grant execute on all functions in schema graphql to postgres, anon, authenticated, service_role;
        grant all on all sequences in schema graphql to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on tables to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on functions to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on sequences to postgres, anon, authenticated, service_role;

        -- Allow postgres role to allow granting usage on graphql and graphql_public schemas to custom roles
        grant usage on schema graphql_public to postgres with grant option;
        grant usage on schema graphql to postgres with grant option;
    END IF;

END;
$_$;


--
-- Name: FUNCTION grant_pg_graphql_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_graphql_access() IS 'Grants access to pg_graphql';


--
-- Name: grant_pg_net_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_net_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_net'
  )
  THEN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_roles
      WHERE rolname = 'supabase_functions_admin'
    )
    THEN
      CREATE USER supabase_functions_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION;
    END IF;

    GRANT USAGE ON SCHEMA net TO supabase_functions_admin, postgres, anon, authenticated, service_role;

    IF EXISTS (
      SELECT FROM pg_extension
      WHERE extname = 'pg_net'
      -- all versions in use on existing projects as of 2025-02-20
      -- version 0.12.0 onwards don't need these applied
      AND extversion IN ('0.2', '0.6', '0.7', '0.7.1', '0.8', '0.10.0', '0.11.0')
    ) THEN
      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;

      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;

      REVOKE ALL ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
      REVOKE ALL ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;

      GRANT EXECUTE ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
      GRANT EXECUTE ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
    END IF;
  END IF;
END;
$$;


--
-- Name: FUNCTION grant_pg_net_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_net_access() IS 'Grants access to pg_net';


--
-- Name: pgrst_ddl_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.pgrst_ddl_watch() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands()
  LOOP
    IF cmd.command_tag IN (
      'CREATE SCHEMA', 'ALTER SCHEMA'
    , 'CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO', 'ALTER TABLE'
    , 'CREATE FOREIGN TABLE', 'ALTER FOREIGN TABLE'
    , 'CREATE VIEW', 'ALTER VIEW'
    , 'CREATE MATERIALIZED VIEW', 'ALTER MATERIALIZED VIEW'
    , 'CREATE FUNCTION', 'ALTER FUNCTION'
    , 'CREATE TRIGGER'
    , 'CREATE TYPE', 'ALTER TYPE'
    , 'CREATE RULE'
    , 'COMMENT'
    )
    -- don't notify in case of CREATE TEMP table or other objects created on pg_temp
    AND cmd.schema_name is distinct from 'pg_temp'
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: pgrst_drop_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.pgrst_drop_watch() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  obj record;
BEGIN
  FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects()
  LOOP
    IF obj.object_type IN (
      'schema'
    , 'table'
    , 'foreign table'
    , 'view'
    , 'materialized view'
    , 'function'
    , 'trigger'
    , 'type'
    , 'rule'
    )
    AND obj.is_temporary IS false -- no pg_temp objects
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: set_graphql_placeholder(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.set_graphql_placeholder() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $_$
    DECLARE
    graphql_is_dropped bool;
    BEGIN
    graphql_is_dropped = (
        SELECT ev.schema_name = 'graphql_public'
        FROM pg_event_trigger_dropped_objects() AS ev
        WHERE ev.schema_name = 'graphql_public'
    );

    IF graphql_is_dropped
    THEN
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language plpgsql
        as $$
            DECLARE
                server_version float;
            BEGIN
                server_version = (SELECT (SPLIT_PART((select version()), ' ', 2))::float);

                IF server_version >= 14 THEN
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql extension is not enabled.'
                            )
                        )
                    );
                ELSE
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql is only available on projects running Postgres 14 onwards.'
                            )
                        )
                    );
                END IF;
            END;
        $$;
    END IF;

    END;
$_$;


--
-- Name: FUNCTION set_graphql_placeholder(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.set_graphql_placeholder() IS 'Reintroduces placeholder function for graphql_public.graphql';


--
-- Name: graphql(text, text, jsonb, jsonb); Type: FUNCTION; Schema: graphql_public; Owner: -
--

CREATE FUNCTION graphql_public.graphql("operationName" text DEFAULT NULL::text, query text DEFAULT NULL::text, variables jsonb DEFAULT NULL::jsonb, extensions jsonb DEFAULT NULL::jsonb) RETURNS jsonb
    LANGUAGE plpgsql
    AS $$
            DECLARE
                server_version float;
            BEGIN
                server_version = (SELECT (SPLIT_PART((select version()), ' ', 2))::float);

                IF server_version >= 14 THEN
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql extension is not enabled.'
                            )
                        )
                    );
                ELSE
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql is only available on projects running Postgres 14 onwards.'
                            )
                        )
                    );
                END IF;
            END;
        $$;


--
-- Name: get_auth(text); Type: FUNCTION; Schema: pgbouncer; Owner: -
--

CREATE FUNCTION pgbouncer.get_auth(p_usename text) RETURNS TABLE(username text, password text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $_$
  BEGIN
      RAISE DEBUG 'PgBouncer auth request: %', p_usename;

      RETURN QUERY
      SELECT
          rolname::text,
          CASE WHEN rolvaliduntil < now()
              THEN null
              ELSE rolpassword::text
          END
      FROM pg_authid
      WHERE rolname=$1 and rolcanlogin;
  END;
  $_$;


--
-- Name: _touch_financeiro_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public._touch_financeiro_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
  new.atualizado_em = now();
  return new;
end;
$$;


--
-- Name: _touch_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public._touch_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
  new.atualizado_em = now();
  return new;
end;
$$;


--
-- Name: refresh_dashboard_cache(text, integer, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.refresh_dashboard_cache(p_emp text, p_ano integer, p_mes integer) RETURNS void
    LANGUAGE sql
    AS $$
  insert into public.dashboard_cache (
    emp, vendedor, ano, mes,
    valor_bruto, valor_liquido, devolucoes, cancelamentos, pct_devolucao,
    mix_produtos, mix_marcas, atualizado_em
  )
  select
    v.emp,
    v.vendedor,
    p_ano as ano,
    p_mes as mes,

    -- BRUTO (somente vendas "normais" OA, ajuste se seu sistema considerar outro tipo)
    coalesce(sum(case when v.mov_tipo_movto = 'OA' then v.valor_total else 0 end), 0) as valor_bruto,

    -- DEVOLUÇÕES e CANCELAMENTOS
    coalesce(sum(case when v.mov_tipo_movto = 'DS' then v.valor_total else 0 end), 0) as devolucoes,
    coalesce(sum(case when v.mov_tipo_movto = 'CA' then v.valor_total else 0 end), 0) as cancelamentos,

    -- LIQUIDO = bruto - ds - ca (ajuste conforme sua regra)
    coalesce(sum(case when v.mov_tipo_movto = 'OA' then v.valor_total else 0 end), 0)
    - coalesce(sum(case when v.mov_tipo_movto in ('DS','CA') then v.valor_total else 0 end), 0) as valor_liquido,

    -- % devolução sobre bruto (evita divisão por zero)
    case
      when coalesce(sum(case when v.mov_tipo_movto = 'OA' then v.valor_total else 0 end), 0) = 0 then 0
      else
        (coalesce(sum(case when v.mov_tipo_movto = 'DS' then v.valor_total else 0 end), 0)
         / nullif(sum(case when v.mov_tipo_movto = 'OA' then v.valor_total else 0 end), 0)) * 100
    end as pct_devolucao,

    -- MIX: eu usei o mesmo critério que validamos (distinct mestre / distinct marca)
    count(distinct case when v.mov_tipo_movto = 'OA' then v.mestre end) as mix_produtos,
    count(distinct case when v.mov_tipo_movto = 'OA' then v.marca  end) as mix_marcas,

    now() as atualizado_em
  from public.vendas v
  where v.emp = p_emp
    and extract(year from v.movimento) = p_ano
    and extract(month from v.movimento) = p_mes
  group by v.emp, v.vendedor

  on conflict (emp, vendedor, ano, mes)
  do update set
    valor_bruto = excluded.valor_bruto,
    valor_liquido = excluded.valor_liquido,
    devolucoes = excluded.devolucoes,
    cancelamentos = excluded.cancelamentos,
    pct_devolucao = excluded.pct_devolucao,
    mix_produtos = excluded.mix_produtos,
    mix_marcas = excluded.mix_marcas,
    atualizado_em = now();
$$;


--
-- Name: apply_rls(jsonb, integer); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.apply_rls(wal jsonb, max_record_bytes integer DEFAULT (1024 * 1024)) RETURNS SETOF realtime.wal_rls
    LANGUAGE plpgsql
    AS $$
declare
    -- Regclass of the table e.g. public.notes
    entity_ regclass = (quote_ident(wal ->> 'schema') || '.' || quote_ident(wal ->> 'table'))::regclass;

    -- I, U, D, T: insert, update ...
    action realtime.action = (
        case wal ->> 'action'
            when 'I' then 'INSERT'
            when 'U' then 'UPDATE'
            when 'D' then 'DELETE'
            else 'ERROR'
        end
    );

    -- Is row level security enabled for the table
    is_rls_enabled bool = relrowsecurity from pg_class where oid = entity_;

    subscriptions realtime.subscription[] = array_agg(subs)
        from
            realtime.subscription subs
        where
            subs.entity = entity_
            -- Filter by action early - only get subscriptions interested in this action
            -- action_filter column can be: '*' (all), 'INSERT', 'UPDATE', or 'DELETE'
            and (subs.action_filter = '*' or subs.action_filter = action::text);

    -- Subscription vars
    working_role regrole;
    working_selected_columns text[];
    claimed_role regrole;
    claims jsonb;

    subscription_id uuid;
    subscription_has_access bool;
    visible_to_subscription_ids uuid[] = '{}';

    -- structured info for wal's columns
    columns realtime.wal_column[];
    -- previous identity values for update/delete
    old_columns realtime.wal_column[];

    error_record_exceeds_max_size boolean = octet_length(wal::text) > max_record_bytes;

    -- Primary jsonb output for record
    output jsonb;

    -- Loop record for iterating unique roles (outer loop)
    role_record record;
    -- Loop record for iterating unique selected_columns within a role (inner loop)
    cols_record record;
    -- Subscription ids visible at the role level (before fanning out by selected_columns)
    visible_role_sub_ids uuid[] = '{}';

begin
    perform set_config('role', null, true);

    columns =
        array_agg(
            (
                x->>'name',
                x->>'type',
                x->>'typeoid',
                realtime.cast(
                    (x->'value') #>> '{}',
                    coalesce(
                        (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                        (x->>'type')::regtype
                    )
                ),
                (pks ->> 'name') is not null,
                true
            )::realtime.wal_column
        )
        from
            jsonb_array_elements(wal -> 'columns') x
            left join jsonb_array_elements(wal -> 'pk') pks
                on (x ->> 'name') = (pks ->> 'name');

    old_columns =
        array_agg(
            (
                x->>'name',
                x->>'type',
                x->>'typeoid',
                realtime.cast(
                    (x->'value') #>> '{}',
                    coalesce(
                        (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                        (x->>'type')::regtype
                    )
                ),
                (pks ->> 'name') is not null,
                true
            )::realtime.wal_column
        )
        from
            jsonb_array_elements(wal -> 'identity') x
            left join jsonb_array_elements(wal -> 'pk') pks
                on (x ->> 'name') = (pks ->> 'name');

    for role_record in
        select claims_role
        from (select distinct claims_role from unnest(subscriptions)) t
        order by claims_role::text
    loop
        working_role := role_record.claims_role;

        -- Update `is_selectable` for columns and old_columns (once per role)
        columns =
            array_agg(
                (
                    c.name,
                    c.type_name,
                    c.type_oid,
                    c.value,
                    c.is_pkey,
                    pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
                )::realtime.wal_column
            )
            from
                unnest(columns) c;

        old_columns =
                array_agg(
                    (
                        c.name,
                        c.type_name,
                        c.type_oid,
                        c.value,
                        c.is_pkey,
                        pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
                    )::realtime.wal_column
                )
                from
                    unnest(old_columns) c;

        if action <> 'DELETE' and count(1) = 0 from unnest(columns) c where c.is_pkey then
            -- Fan out 400 error per distinct selected_columns for this role
            for cols_record in
                select selected_columns
                from (select distinct selected_columns from unnest(subscriptions) s where s.claims_role = working_role) t
                order by coalesce(array_to_string(selected_columns, ','), '')
            loop
                working_selected_columns := cols_record.selected_columns;
                return next (
                    jsonb_build_object(
                        'schema', wal ->> 'schema',
                        'table', wal ->> 'table',
                        'type', action
                    ),
                    is_rls_enabled,
                    (select array_agg(s.subscription_id) from unnest(subscriptions) as s where s.claims_role = working_role and (s.selected_columns is not distinct from working_selected_columns)),
                    array['Error 400: Bad Request, no primary key']
                )::realtime.wal_rls;
            end loop;

        -- The claims role does not have SELECT permission to the primary key of entity
        elsif action <> 'DELETE' and sum(c.is_selectable::int) <> count(1) from unnest(columns) c where c.is_pkey then
            -- Fan out 401 error per distinct selected_columns for this role
            for cols_record in
                select selected_columns
                from (select distinct selected_columns from unnest(subscriptions) s where s.claims_role = working_role) t
                order by coalesce(array_to_string(selected_columns, ','), '')
            loop
                working_selected_columns := cols_record.selected_columns;
                return next (
                    jsonb_build_object(
                        'schema', wal ->> 'schema',
                        'table', wal ->> 'table',
                        'type', action
                    ),
                    is_rls_enabled,
                    (select array_agg(s.subscription_id) from unnest(subscriptions) as s where s.claims_role = working_role and (s.selected_columns is not distinct from working_selected_columns)),
                    array['Error 401: Unauthorized']
                )::realtime.wal_rls;
            end loop;

        else
            -- Create the prepared statement (once per role)
            if is_rls_enabled and action <> 'DELETE' then
                if (select 1 from pg_prepared_statements where name = 'walrus_rls_stmt' limit 1) > 0 then
                    deallocate walrus_rls_stmt;
                end if;
                execute realtime.build_prepared_statement_sql('walrus_rls_stmt', entity_, columns);
            end if;

            -- Collect all visible subscription IDs for this role (filter check + RLS check)
            visible_role_sub_ids = '{}';

            for subscription_id, claims in (
                    select
                        subs.subscription_id,
                        subs.claims
                    from
                        unnest(subscriptions) subs
                    where
                        subs.entity = entity_
                        and subs.claims_role = working_role
                        and (
                            realtime.is_visible_through_filters(columns, subs.filters)
                            or (
                              action = 'DELETE'
                              and realtime.is_visible_through_filters(old_columns, subs.filters)
                            )
                        )
            ) loop

                if not is_rls_enabled or action = 'DELETE' then
                    visible_role_sub_ids = visible_role_sub_ids || subscription_id;
                else
                    -- Check if RLS allows the role to see the record
                    perform
                        -- Trim leading and trailing quotes from working_role because set_config
                        -- doesn't recognize the role as valid if they are included
                        set_config('role', trim(both '"' from working_role::text), true),
                        set_config('request.jwt.claims', claims::text, true);

                    execute 'execute walrus_rls_stmt' into subscription_has_access;

                    if subscription_has_access then
                        visible_role_sub_ids = visible_role_sub_ids || subscription_id;
                    end if;
                end if;
            end loop;

            perform set_config('role', null, true);

            -- Inner loop: per distinct selected_columns for this role
            for cols_record in
                select selected_columns
                from (select distinct selected_columns from unnest(subscriptions) s where s.claims_role = working_role) t
                order by coalesce(array_to_string(selected_columns, ','), '')
            loop
                working_selected_columns := cols_record.selected_columns;

                output = jsonb_build_object(
                    'schema', wal ->> 'schema',
                    'table', wal ->> 'table',
                    'type', action,
                    'commit_timestamp', to_char(
                        ((wal ->> 'timestamp')::timestamptz at time zone 'utc'),
                        'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                    ),
                    'columns', (
                        select
                            jsonb_agg(
                                jsonb_build_object(
                                    'name', pa.attname,
                                    'type', pt.typname
                                )
                                order by pa.attnum asc
                            )
                        from
                            pg_attribute pa
                            join pg_type pt
                                on pa.atttypid = pt.oid
                            left join (
                                select unnest(conkey) as pkey_attnum
                                from pg_constraint
                                where conrelid = entity_ and contype = 'p'
                            ) pk on pk.pkey_attnum = pa.attnum
                        where
                            attrelid = entity_
                            and attnum > 0
                            and pg_catalog.has_column_privilege(working_role, entity_, pa.attname, 'SELECT')
                            and (working_selected_columns is null or pa.attname = any(working_selected_columns) or pk.pkey_attnum is not null)
                    )
                )
                -- Add "record" key for insert and update
                || case
                    when action in ('INSERT', 'UPDATE') then
                        jsonb_build_object(
                            'record',
                            (
                                select
                                    jsonb_object_agg(
                                        -- if unchanged toast, get column name and value from old record
                                        coalesce((c).name, (oc).name),
                                        case
                                            when (c).name is null then (oc).value
                                            else (c).value
                                        end
                                    )
                                from
                                    unnest(columns) c
                                    full outer join unnest(old_columns) oc
                                        on (c).name = (oc).name
                                where
                                    coalesce((c).is_selectable, (oc).is_selectable)
                                    and (working_selected_columns is null or coalesce((c).name, (oc).name) = any(working_selected_columns) or coalesce((c).is_pkey, (oc).is_pkey))
                                    and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                            )
                        )
                    else '{}'::jsonb
                end
                -- Add "old_record" key for update and delete
                || case
                    when action = 'UPDATE' then
                        jsonb_build_object(
                                'old_record',
                                (
                                    select jsonb_object_agg((c).name, (c).value)
                                    from unnest(old_columns) c
                                    where
                                        (c).is_selectable
                                        and (working_selected_columns is null or (c).name = any(working_selected_columns) or (c).is_pkey)
                                        and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                                )
                            )
                    when action = 'DELETE' then
                        jsonb_build_object(
                            'old_record',
                            (
                                select jsonb_object_agg((c).name, (c).value)
                                from unnest(old_columns) c
                                where
                                    (c).is_selectable
                                    and (working_selected_columns is null or (c).name = any(working_selected_columns) or (c).is_pkey)
                                    and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                                    and ( not is_rls_enabled or (c).is_pkey ) -- if RLS enabled, we can't secure deletes so filter to pkey
                            )
                        )
                    else '{}'::jsonb
                end;

                -- Filter visible_role_sub_ids to those matching the current selected_columns group
                visible_to_subscription_ids = coalesce(
                    (
                        select array_agg(s.subscription_id)
                        from unnest(subscriptions) s
                        where s.claims_role = working_role
                          and (s.selected_columns is not distinct from working_selected_columns)
                          and s.subscription_id = any(visible_role_sub_ids)
                    ),
                    '{}'::uuid[]
                );

                return next (
                    output,
                    is_rls_enabled,
                    visible_to_subscription_ids,
                    case
                        when error_record_exceeds_max_size then array['Error 413: Payload Too Large']
                        else '{}'
                    end
                )::realtime.wal_rls;
            end loop;

        end if;
    end loop;

    perform set_config('role', null, true);
end;
$$;


--
-- Name: broadcast_changes(text, text, text, text, text, record, record, text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.broadcast_changes(topic_name text, event_name text, operation text, table_name text, table_schema text, new record, old record, level text DEFAULT 'ROW'::text) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    -- Declare a variable to hold the JSONB representation of the row
    row_data jsonb := '{}'::jsonb;
BEGIN
    IF level = 'STATEMENT' THEN
        RAISE EXCEPTION 'function can only be triggered for each row, not for each statement';
    END IF;
    -- Check the operation type and handle accordingly
    IF operation = 'INSERT' OR operation = 'UPDATE' OR operation = 'DELETE' THEN
        row_data := jsonb_build_object('old_record', OLD, 'record', NEW, 'operation', operation, 'table', table_name, 'schema', table_schema);
        PERFORM realtime.send (row_data, event_name, topic_name);
    ELSE
        RAISE EXCEPTION 'Unexpected operation type: %', operation;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Failed to process the row: %', SQLERRM;
END;

$$;


--
-- Name: build_prepared_statement_sql(text, regclass, realtime.wal_column[]); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.build_prepared_statement_sql(prepared_statement_name text, entity regclass, columns realtime.wal_column[]) RETURNS text
    LANGUAGE sql
    AS $$
      /*
      Builds a sql string that, if executed, creates a prepared statement to
      tests retrive a row from *entity* by its primary key columns.
      Example
          select realtime.build_prepared_statement_sql('public.notes', '{"id"}'::text[], '{"bigint"}'::text[])
      */
          select
      'prepare ' || prepared_statement_name || ' as
          select
              exists(
                  select
                      1
                  from
                      ' || entity || '
                  where
                      ' || string_agg(quote_ident(pkc.name) || '=' || quote_nullable(pkc.value #>> '{}') , ' and ') || '
              )'
          from
              unnest(columns) pkc
          where
              pkc.is_pkey
          group by
              entity
      $$;


--
-- Name: cast(text, regtype); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime."cast"(val text, type_ regtype) RETURNS jsonb
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
  res jsonb;
begin
  if type_::text = 'bytea' then
    return to_jsonb(val);
  end if;
  execute format('select to_jsonb(%L::'|| type_::text || ')', val) into res;
  return res;
end
$$;


--
-- Name: check_equality_op(realtime.equality_op, regtype, text, text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
      /*
      Casts *val_1* and *val_2* as type *type_* and check the *op* condition for truthiness
      */
      declare
          op_symbol text = (
              case
                  when op = 'eq' then '='
                  when op = 'neq' then '!='
                  when op = 'lt' then '<'
                  when op = 'lte' then '<='
                  when op = 'gt' then '>'
                  when op = 'gte' then '>='
                  when op = 'in' then '= any'
                  else 'UNKNOWN OP'
              end
          );
          res boolean;
      begin
          execute format(
              'select %L::'|| type_::text || ' ' || op_symbol
              || ' ( %L::'
              || (
                  case
                      when op = 'in' then type_::text || '[]'
                      else type_::text end
              )
              || ')', val_1, val_2) into res;
          return res;
      end;
      $$;


--
-- Name: is_visible_through_filters(realtime.wal_column[], realtime.user_defined_filter[]); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.is_visible_through_filters(columns realtime.wal_column[], filters realtime.user_defined_filter[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $_$
    /*
    Should the record be visible (true) or filtered out (false) after *filters* are applied
    */
        select
            -- Default to allowed when no filters present
            $2 is null -- no filters. this should not happen because subscriptions has a default
            or array_length($2, 1) is null -- array length of an empty array is null
            or bool_and(
                coalesce(
                    realtime.check_equality_op(
                        op:=f.op,
                        type_:=coalesce(
                            col.type_oid::regtype, -- null when wal2json version <= 2.4
                            col.type_name::regtype
                        ),
                        -- cast jsonb to text
                        val_1:=col.value #>> '{}',
                        val_2:=f.value
                    ),
                    false -- if null, filter does not match
                )
            )
        from
            unnest(filters) f
            join unnest(columns) col
                on f.column_name = col.name;
    $_$;


--
-- Name: list_changes(name, name, integer, integer); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer) RETURNS TABLE(wal jsonb, is_rls_enabled boolean, subscription_ids uuid[], errors text[], slot_changes_count bigint)
    LANGUAGE sql
    SET log_min_messages TO 'fatal'
    AS $$
  WITH pub AS (
    SELECT
      concat_ws(
        ',',
        CASE WHEN bool_or(pubinsert) THEN 'insert' ELSE NULL END,
        CASE WHEN bool_or(pubupdate) THEN 'update' ELSE NULL END,
        CASE WHEN bool_or(pubdelete) THEN 'delete' ELSE NULL END
      ) AS w2j_actions,
      coalesce(
        string_agg(
          realtime.quote_wal2json(format('%I.%I', schemaname, tablename)::regclass),
          ','
        ) filter (WHERE ppt.tablename IS NOT NULL),
        ''
      ) AS w2j_add_tables
    FROM pg_publication pp
    LEFT JOIN pg_publication_tables ppt ON pp.pubname = ppt.pubname
    WHERE pp.pubname = publication
    GROUP BY pp.pubname
    LIMIT 1
  ),
  -- MATERIALIZED ensures pg_logical_slot_get_changes is called exactly once
  w2j AS MATERIALIZED (
    SELECT x.*, pub.w2j_add_tables
    FROM pub,
         pg_logical_slot_get_changes(
           slot_name, null, max_changes,
           'include-pk', 'true',
           'include-transaction', 'false',
           'include-timestamp', 'true',
           'include-type-oids', 'true',
           'format-version', '2',
           'actions', pub.w2j_actions,
           'add-tables', pub.w2j_add_tables
         ) x
  ),
  slot_count AS (
    SELECT count(*)::bigint AS cnt
    FROM w2j
    WHERE w2j.w2j_add_tables <> ''
  ),
  rls_filtered AS (
    SELECT xyz.wal, xyz.is_rls_enabled, xyz.subscription_ids, xyz.errors
    FROM w2j,
         realtime.apply_rls(
           wal := w2j.data::jsonb,
           max_record_bytes := max_record_bytes
         ) xyz(wal, is_rls_enabled, subscription_ids, errors)
    WHERE w2j.w2j_add_tables <> ''
      AND xyz.subscription_ids[1] IS NOT NULL
  )
  SELECT rf.wal, rf.is_rls_enabled, rf.subscription_ids, rf.errors, sc.cnt
  FROM rls_filtered rf, slot_count sc

  UNION ALL

  SELECT null, null, null, null, sc.cnt
  FROM slot_count sc
  WHERE NOT EXISTS (SELECT 1 FROM rls_filtered)
$$;


--
-- Name: quote_wal2json(regclass); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.quote_wal2json(entity regclass) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
  SELECT
    realtime.wal2json_escape_identifier(nsp.nspname::text)
    || '.'
    || realtime.wal2json_escape_identifier(pc.relname::text)
  FROM pg_class pc
  JOIN pg_namespace nsp ON pc.relnamespace = nsp.oid
  WHERE pc.oid = entity
$$;


--
-- Name: send(jsonb, text, text, boolean); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.send(payload jsonb, event text, topic text, private boolean DEFAULT true) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
  generated_id uuid;
  final_payload jsonb;
BEGIN
  BEGIN
    -- Generate a new UUID for the id
    generated_id := gen_random_uuid();

    -- Check if payload has an 'id' key, if not, add the generated UUID
    IF payload ? 'id' THEN
      final_payload := payload;
    ELSE
      final_payload := jsonb_set(payload, '{id}', to_jsonb(generated_id));
    END IF;

    -- Set the topic configuration
    EXECUTE format('SET LOCAL realtime.topic TO %L', topic);

    -- Attempt to insert the message
    INSERT INTO realtime.messages (id, payload, event, topic, private, extension)
    VALUES (generated_id, final_payload, event, topic, private, 'broadcast');
  EXCEPTION
    WHEN OTHERS THEN
      -- Capture and notify the error
      RAISE WARNING 'ErrorSendingBroadcastMessage: %', SQLERRM;
  END;
END;
$$;


--
-- Name: send_binary(bytea, text, text, boolean); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.send_binary(payload bytea, event text, topic text, private boolean DEFAULT true) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
  generated_id uuid;
BEGIN
  BEGIN
    generated_id := gen_random_uuid();

    EXECUTE format('SET LOCAL realtime.topic TO %L', topic);

    INSERT INTO realtime.messages (id, binary_payload, event, topic, private, extension)
    VALUES (generated_id, payload, event, topic, private, 'broadcast');
  EXCEPTION
    WHEN OTHERS THEN
      RAISE WARNING 'ErrorSendingBroadcastMessage: %', SQLERRM;
  END;
END;
$$;


--
-- Name: subscription_check_filters(); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.subscription_check_filters() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
declare
    col_names text[] = coalesce(
            array_agg(c.column_name order by c.ordinal_position),
            '{}'::text[]
        )
        from
            information_schema.columns c
        where
            format('%I.%I', c.table_schema, c.table_name)::regclass = new.entity
            and pg_catalog.has_column_privilege(
                (new.claims ->> 'role'),
                format('%I.%I', c.table_schema, c.table_name)::regclass,
                c.column_name,
                'SELECT'
            );
    table_col_names text[] = coalesce(
            array_agg(pa.attname),
            '{}'::text[]
        )
        from
            pg_attribute pa
        where
            pa.attrelid = new.entity
            and pa.attnum > 0;
    filter realtime.user_defined_filter;
    col_type regtype;
    in_val jsonb;
    selected_col text;
begin
    for filter in select * from unnest(new.filters) loop
        -- Filtered column is valid
        if not filter.column_name = any(col_names) then
            raise exception 'invalid column for filter %', filter.column_name;
        end if;

        -- Type is sanitized and safe for string interpolation
        col_type = (
            select atttypid::regtype
            from pg_catalog.pg_attribute
            where attrelid = new.entity
                  and attname = filter.column_name
        );
        if col_type is null then
            raise exception 'failed to lookup type for column %', filter.column_name;
        end if;
        if filter.op = 'in'::realtime.equality_op then
            in_val = realtime.cast(filter.value, (col_type::text || '[]')::regtype);
            if coalesce(jsonb_array_length(in_val), 0) > 100 then
                raise exception 'too many values for `in` filter. Maximum 100';
            end if;
        else
            -- raises an exception if value is not coercable to type
            perform realtime.cast(filter.value, col_type);
        end if;
    end loop;

    -- Validate that selected_columns reference columns the role can SELECT
    if new.selected_columns is not null then
        for selected_col in select * from unnest(new.selected_columns) loop
            if not selected_col = any(col_names) then
                raise exception 'invalid column for select %', selected_col;
            end if;
        end loop;
    end if;

    -- Apply consistent order to filters so the unique constraint on
    -- (subscription_id, entity, filters) can't be tricked by a different filter order
    new.filters = coalesce(
        array_agg(f order by f.column_name, f.op, f.value),
        '{}'
    ) from unnest(new.filters) f;

    -- Normalize selected_columns order so ARRAY['a','b'] and ARRAY['b','a'] are
    -- treated as the same subscription group in apply_rls
    new.selected_columns = (
        select array_agg(c order by c)
        from unnest(new.selected_columns) c
    );

    return new;
end;
$$;


--
-- Name: to_regrole(text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.to_regrole(role_name text) RETURNS regrole
    LANGUAGE sql IMMUTABLE
    AS $$ select role_name::regrole $$;


--
-- Name: topic(); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.topic() RETURNS text
    LANGUAGE sql STABLE
    AS $$
select nullif(current_setting('realtime.topic', true), '')::text;
$$;


--
-- Name: wal2json_escape_identifier(text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.wal2json_escape_identifier(name text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
  -- Prefix `\`, `,`, `.`, and any whitespace with `\`
  SELECT regexp_replace(name, '([\\,.[:space:]])', '\\\1', 'g')
$$;


--
-- Name: allow_any_operation(text[]); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.allow_any_operation(expected_operations text[]) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
  WITH current_operation AS (
    SELECT storage.operation() AS raw_operation
  ),
  normalized AS (
    SELECT CASE
      WHEN raw_operation LIKE 'storage.%' THEN substr(raw_operation, 9)
      ELSE raw_operation
    END AS current_operation
    FROM current_operation
  )
  SELECT EXISTS (
    SELECT 1
    FROM normalized n
    CROSS JOIN LATERAL unnest(expected_operations) AS expected_operation
    WHERE expected_operation IS NOT NULL
      AND expected_operation <> ''
      AND n.current_operation = CASE
        WHEN expected_operation LIKE 'storage.%' THEN substr(expected_operation, 9)
        ELSE expected_operation
      END
  );
$$;


--
-- Name: allow_only_operation(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.allow_only_operation(expected_operation text) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
  WITH current_operation AS (
    SELECT storage.operation() AS raw_operation
  ),
  normalized AS (
    SELECT
      CASE
        WHEN raw_operation LIKE 'storage.%' THEN substr(raw_operation, 9)
        ELSE raw_operation
      END AS current_operation,
      CASE
        WHEN expected_operation LIKE 'storage.%' THEN substr(expected_operation, 9)
        ELSE expected_operation
      END AS requested_operation
    FROM current_operation
  )
  SELECT CASE
    WHEN requested_operation IS NULL OR requested_operation = '' THEN FALSE
    ELSE COALESCE(current_operation = requested_operation, FALSE)
  END
  FROM normalized;
$$;


--
-- Name: can_insert_object(text, text, uuid, jsonb); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.can_insert_object(bucketid text, name text, owner uuid, metadata jsonb) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO "storage"."objects" ("bucket_id", "name", "owner", "metadata") VALUES (bucketid, name, owner, metadata);
  -- hack to rollback the successful insert
  RAISE sqlstate 'PT200' using
  message = 'ROLLBACK',
  detail = 'rollback successful insert';
END
$$;


--
-- Name: enforce_bucket_name_length(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.enforce_bucket_name_length() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if length(new.name) > 100 then
        raise exception 'bucket name "%" is too long (% characters). Max is 100.', new.name, length(new.name);
    end if;
    return new;
end;
$$;


--
-- Name: extension(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.extension(name text) RETURNS text
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    _parts text[];
    _filename text;
BEGIN
    -- Split on "/" to get path segments
    SELECT string_to_array(name, '/') INTO _parts;
    -- Get the last path segment (the actual filename)
    SELECT _parts[array_length(_parts, 1)] INTO _filename;
    -- Extract extension: reverse, split on '.', then reverse again
    RETURN reverse(split_part(reverse(_filename), '.', 1));
END
$$;


--
-- Name: filename(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.filename(name text) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
_parts text[];
BEGIN
	select string_to_array(name, '/') into _parts;
	return _parts[array_length(_parts,1)];
END
$$;


--
-- Name: foldername(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.foldername(name text) RETURNS text[]
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    _parts text[];
BEGIN
    -- Split on "/" to get path segments
    SELECT string_to_array(name, '/') INTO _parts;
    -- Return everything except the last segment
    RETURN _parts[1 : array_length(_parts,1) - 1];
END
$$;


--
-- Name: get_common_prefix(text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.get_common_prefix(p_key text, p_prefix text, p_delimiter text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
SELECT CASE
    WHEN position(p_delimiter IN substring(p_key FROM length(p_prefix) + 1)) > 0
    THEN left(p_key, length(p_prefix) + position(p_delimiter IN substring(p_key FROM length(p_prefix) + 1)))
    ELSE NULL
END;
$$;


--
-- Name: get_size_by_bucket(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.get_size_by_bucket() RETURNS TABLE(size bigint, bucket_id text)
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    return query
        select sum((metadata->>'size')::bigint)::bigint as size, obj.bucket_id
        from "storage".objects as obj
        group by obj.bucket_id;
END
$$;


--
-- Name: list_multipart_uploads_with_delimiter(text, text, text, integer, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.list_multipart_uploads_with_delimiter(bucket_id text, prefix_param text, delimiter_param text, max_keys integer DEFAULT 100, next_key_token text DEFAULT ''::text, next_upload_token text DEFAULT ''::text) RETURNS TABLE(key text, id text, created_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $_$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT DISTINCT ON(key COLLATE "C") * from (
            SELECT
                CASE
                    WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                        substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1)))
                    ELSE
                        key
                END AS key, id, created_at
            FROM
                storage.s3_multipart_uploads
            WHERE
                bucket_id = $5 AND
                key ILIKE $1 || ''%'' AND
                CASE
                    WHEN $4 != '''' AND $6 = '''' THEN
                        CASE
                            WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                                substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1))) COLLATE "C" > $4
                            ELSE
                                key COLLATE "C" > $4
                            END
                    ELSE
                        true
                END AND
                CASE
                    WHEN $6 != '''' THEN
                        id COLLATE "C" > $6
                    ELSE
                        true
                    END
            ORDER BY
                key COLLATE "C" ASC, created_at ASC) as e order by key COLLATE "C" LIMIT $3'
        USING prefix_param, delimiter_param, max_keys, next_key_token, bucket_id, next_upload_token;
END;
$_$;


--
-- Name: list_objects_with_delimiter(text, text, text, integer, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.list_objects_with_delimiter(_bucket_id text, prefix_param text, delimiter_param text, max_keys integer DEFAULT 100, start_after text DEFAULT ''::text, next_token text DEFAULT ''::text, sort_order text DEFAULT 'asc'::text) RETURNS TABLE(name text, id uuid, metadata jsonb, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone)
    LANGUAGE plpgsql STABLE
    AS $_$
DECLARE
    v_peek_name TEXT;
    v_current RECORD;
    v_common_prefix TEXT;

    -- Configuration
    v_is_asc BOOLEAN;
    v_prefix TEXT;
    v_start TEXT;
    v_upper_bound TEXT;
    v_file_batch_size INT;

    -- Seek state
    v_next_seek TEXT;
    v_count INT := 0;

    -- Dynamic SQL for batch query only
    v_batch_query TEXT;

BEGIN
    -- ========================================================================
    -- INITIALIZATION
    -- ========================================================================
    v_is_asc := lower(coalesce(sort_order, 'asc')) = 'asc';
    v_prefix := coalesce(prefix_param, '');
    v_start := CASE WHEN coalesce(next_token, '') <> '' THEN next_token ELSE coalesce(start_after, '') END;
    v_file_batch_size := LEAST(GREATEST(max_keys * 2, 100), 1000);

    -- Calculate upper bound for prefix filtering (bytewise, using COLLATE "C")
    IF v_prefix = '' THEN
        v_upper_bound := NULL;
    ELSIF right(v_prefix, 1) = delimiter_param THEN
        v_upper_bound := left(v_prefix, -1) || chr(ascii(delimiter_param) + 1);
    ELSE
        v_upper_bound := left(v_prefix, -1) || chr(ascii(right(v_prefix, 1)) + 1);
    END IF;

    -- Build batch query (dynamic SQL - called infrequently, amortized over many rows)
    IF v_is_asc THEN
        IF v_upper_bound IS NOT NULL THEN
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND o.name COLLATE "C" >= $2 ' ||
                'AND o.name COLLATE "C" < $3 ORDER BY o.name COLLATE "C" ASC LIMIT $4';
        ELSE
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND o.name COLLATE "C" >= $2 ' ||
                'ORDER BY o.name COLLATE "C" ASC LIMIT $4';
        END IF;
    ELSE
        IF v_upper_bound IS NOT NULL THEN
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND o.name COLLATE "C" < $2 ' ||
                'AND o.name COLLATE "C" >= $3 ORDER BY o.name COLLATE "C" DESC LIMIT $4';
        ELSE
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND o.name COLLATE "C" < $2 ' ||
                'ORDER BY o.name COLLATE "C" DESC LIMIT $4';
        END IF;
    END IF;

    -- ========================================================================
    -- SEEK INITIALIZATION: Determine starting position
    -- ========================================================================
    IF v_start = '' THEN
        IF v_is_asc THEN
            v_next_seek := v_prefix;
        ELSE
            -- DESC without cursor: find the last item in range
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_next_seek FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" >= v_prefix AND o.name COLLATE "C" < v_upper_bound
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            ELSIF v_prefix <> '' THEN
                SELECT o.name INTO v_next_seek FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" >= v_prefix
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            ELSE
                SELECT o.name INTO v_next_seek FROM storage.objects o
                WHERE o.bucket_id = _bucket_id
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            END IF;

            IF v_next_seek IS NOT NULL THEN
                v_next_seek := v_next_seek || delimiter_param;
            ELSE
                RETURN;
            END IF;
        END IF;
    ELSE
        -- Cursor provided: determine if it refers to a folder or leaf
        IF EXISTS (
            SELECT 1 FROM storage.objects o
            WHERE o.bucket_id = _bucket_id
              AND o.name COLLATE "C" LIKE v_start || delimiter_param || '%'
            LIMIT 1
        ) THEN
            -- Cursor refers to a folder
            IF v_is_asc THEN
                v_next_seek := v_start || chr(ascii(delimiter_param) + 1);
            ELSE
                v_next_seek := v_start || delimiter_param;
            END IF;
        ELSE
            -- Cursor refers to a leaf object
            IF v_is_asc THEN
                v_next_seek := v_start || delimiter_param;
            ELSE
                v_next_seek := v_start;
            END IF;
        END IF;
    END IF;

    -- ========================================================================
    -- MAIN LOOP: Hybrid peek-then-batch algorithm
    -- Uses STATIC SQL for peek (hot path) and DYNAMIC SQL for batch
    -- ========================================================================
    LOOP
        EXIT WHEN v_count >= max_keys;

        -- STEP 1: PEEK using STATIC SQL (plan cached, very fast)
        IF v_is_asc THEN
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" >= v_next_seek AND o.name COLLATE "C" < v_upper_bound
                ORDER BY o.name COLLATE "C" ASC LIMIT 1;
            ELSE
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" >= v_next_seek
                ORDER BY o.name COLLATE "C" ASC LIMIT 1;
            END IF;
        ELSE
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" < v_next_seek AND o.name COLLATE "C" >= v_prefix
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            ELSIF v_prefix <> '' THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" < v_next_seek AND o.name COLLATE "C" >= v_prefix
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            ELSE
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" < v_next_seek
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            END IF;
        END IF;

        EXIT WHEN v_peek_name IS NULL;

        -- STEP 2: Check if this is a FOLDER or FILE
        v_common_prefix := storage.get_common_prefix(v_peek_name, v_prefix, delimiter_param);

        IF v_common_prefix IS NOT NULL THEN
            -- FOLDER: Emit and skip to next folder (no heap access needed)
            name := rtrim(v_common_prefix, delimiter_param);
            id := NULL;
            updated_at := NULL;
            created_at := NULL;
            last_accessed_at := NULL;
            metadata := NULL;
            RETURN NEXT;
            v_count := v_count + 1;

            -- Advance seek past the folder range
            IF v_is_asc THEN
                v_next_seek := left(v_common_prefix, -1) || chr(ascii(delimiter_param) + 1);
            ELSE
                v_next_seek := v_common_prefix;
            END IF;
        ELSE
            -- FILE: Batch fetch using DYNAMIC SQL (overhead amortized over many rows)
            -- For ASC: upper_bound is the exclusive upper limit (< condition)
            -- For DESC: prefix is the inclusive lower limit (>= condition)
            FOR v_current IN EXECUTE v_batch_query USING _bucket_id, v_next_seek,
                CASE WHEN v_is_asc THEN COALESCE(v_upper_bound, v_prefix) ELSE v_prefix END, v_file_batch_size
            LOOP
                v_common_prefix := storage.get_common_prefix(v_current.name, v_prefix, delimiter_param);

                IF v_common_prefix IS NOT NULL THEN
                    -- Hit a folder: exit batch, let peek handle it
                    v_next_seek := v_current.name;
                    EXIT;
                END IF;

                -- Emit file
                name := v_current.name;
                id := v_current.id;
                updated_at := v_current.updated_at;
                created_at := v_current.created_at;
                last_accessed_at := v_current.last_accessed_at;
                metadata := v_current.metadata;
                RETURN NEXT;
                v_count := v_count + 1;

                -- Advance seek past this file
                IF v_is_asc THEN
                    v_next_seek := v_current.name || delimiter_param;
                ELSE
                    v_next_seek := v_current.name;
                END IF;

                EXIT WHEN v_count >= max_keys;
            END LOOP;
        END IF;
    END LOOP;
END;
$_$;


--
-- Name: operation(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.operation() RETURNS text
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    RETURN current_setting('storage.operation', true);
END;
$$;


--
-- Name: protect_delete(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.protect_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Check if storage.allow_delete_query is set to 'true'
    IF COALESCE(current_setting('storage.allow_delete_query', true), 'false') != 'true' THEN
        RAISE EXCEPTION 'Direct deletion from storage tables is not allowed. Use the Storage API instead.'
            USING HINT = 'This prevents accidental data loss from orphaned objects.',
                  ERRCODE = '42501';
    END IF;
    RETURN NULL;
END;
$$;


--
-- Name: search(text, text, integer, integer, integer, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.search(prefix text, bucketname text, limits integer DEFAULT 100, levels integer DEFAULT 1, offsets integer DEFAULT 0, search text DEFAULT ''::text, sortcolumn text DEFAULT 'name'::text, sortorder text DEFAULT 'asc'::text) RETURNS TABLE(name text, id uuid, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone, metadata jsonb)
    LANGUAGE plpgsql STABLE
    AS $_$
DECLARE
    v_peek_name TEXT;
    v_current RECORD;
    v_common_prefix TEXT;
    v_delimiter CONSTANT TEXT := '/';

    -- Configuration
    v_limit INT;
    v_prefix TEXT;
    v_prefix_lower TEXT;
    v_is_asc BOOLEAN;
    v_order_by TEXT;
    v_sort_order TEXT;
    v_upper_bound TEXT;
    v_file_batch_size INT;

    -- Dynamic SQL for batch query only
    v_batch_query TEXT;

    -- Seek state
    v_next_seek TEXT;
    v_count INT := 0;
    v_skipped INT := 0;
BEGIN
    -- ========================================================================
    -- INITIALIZATION
    -- ========================================================================
    v_limit := LEAST(coalesce(limits, 100), 1500);
    v_prefix := coalesce(prefix, '') || coalesce(search, '');
    v_prefix_lower := lower(v_prefix);
    v_is_asc := lower(coalesce(sortorder, 'asc')) = 'asc';
    v_file_batch_size := LEAST(GREATEST(v_limit * 2, 100), 1000);

    -- Validate sort column
    CASE lower(coalesce(sortcolumn, 'name'))
        WHEN 'name' THEN v_order_by := 'name';
        WHEN 'updated_at' THEN v_order_by := 'updated_at';
        WHEN 'created_at' THEN v_order_by := 'created_at';
        WHEN 'last_accessed_at' THEN v_order_by := 'last_accessed_at';
        ELSE v_order_by := 'name';
    END CASE;

    v_sort_order := CASE WHEN v_is_asc THEN 'asc' ELSE 'desc' END;

    -- ========================================================================
    -- NON-NAME SORTING: Use path_tokens approach (unchanged)
    -- ========================================================================
    IF v_order_by != 'name' THEN
        RETURN QUERY EXECUTE format(
            $sql$
            WITH folders AS (
                SELECT path_tokens[$1] AS folder
                FROM storage.objects
                WHERE objects.name ILIKE $2 || '%%'
                  AND bucket_id = $3
                  AND array_length(objects.path_tokens, 1) <> $1
                GROUP BY folder
                ORDER BY folder %s
            )
            (SELECT folder AS "name",
                   NULL::uuid AS id,
                   NULL::timestamptz AS updated_at,
                   NULL::timestamptz AS created_at,
                   NULL::timestamptz AS last_accessed_at,
                   NULL::jsonb AS metadata FROM folders)
            UNION ALL
            (SELECT path_tokens[$1] AS "name",
                   id, updated_at, created_at, last_accessed_at, metadata
             FROM storage.objects
             WHERE objects.name ILIKE $2 || '%%'
               AND bucket_id = $3
               AND array_length(objects.path_tokens, 1) = $1
             ORDER BY %I %s)
            LIMIT $4 OFFSET $5
            $sql$, v_sort_order, v_order_by, v_sort_order
        ) USING levels, v_prefix, bucketname, v_limit, offsets;
        RETURN;
    END IF;

    -- ========================================================================
    -- NAME SORTING: Hybrid skip-scan with batch optimization
    -- ========================================================================

    -- Calculate upper bound for prefix filtering
    IF v_prefix_lower = '' THEN
        v_upper_bound := NULL;
    ELSIF right(v_prefix_lower, 1) = v_delimiter THEN
        v_upper_bound := left(v_prefix_lower, -1) || chr(ascii(v_delimiter) + 1);
    ELSE
        v_upper_bound := left(v_prefix_lower, -1) || chr(ascii(right(v_prefix_lower, 1)) + 1);
    END IF;

    -- Build batch query (dynamic SQL - called infrequently, amortized over many rows)
    IF v_is_asc THEN
        IF v_upper_bound IS NOT NULL THEN
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND lower(o.name) COLLATE "C" >= $2 ' ||
                'AND lower(o.name) COLLATE "C" < $3 ORDER BY lower(o.name) COLLATE "C" ASC LIMIT $4';
        ELSE
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND lower(o.name) COLLATE "C" >= $2 ' ||
                'ORDER BY lower(o.name) COLLATE "C" ASC LIMIT $4';
        END IF;
    ELSE
        IF v_upper_bound IS NOT NULL THEN
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND lower(o.name) COLLATE "C" < $2 ' ||
                'AND lower(o.name) COLLATE "C" >= $3 ORDER BY lower(o.name) COLLATE "C" DESC LIMIT $4';
        ELSE
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND lower(o.name) COLLATE "C" < $2 ' ||
                'ORDER BY lower(o.name) COLLATE "C" DESC LIMIT $4';
        END IF;
    END IF;

    -- Initialize seek position
    IF v_is_asc THEN
        v_next_seek := v_prefix_lower;
    ELSE
        -- DESC: find the last item in range first (static SQL)
        IF v_upper_bound IS NOT NULL THEN
            SELECT o.name INTO v_peek_name FROM storage.objects o
            WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" >= v_prefix_lower AND lower(o.name) COLLATE "C" < v_upper_bound
            ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
        ELSIF v_prefix_lower <> '' THEN
            SELECT o.name INTO v_peek_name FROM storage.objects o
            WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" >= v_prefix_lower
            ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
        ELSE
            SELECT o.name INTO v_peek_name FROM storage.objects o
            WHERE o.bucket_id = bucketname
            ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
        END IF;

        IF v_peek_name IS NOT NULL THEN
            v_next_seek := lower(v_peek_name) || v_delimiter;
        ELSE
            RETURN;
        END IF;
    END IF;

    -- ========================================================================
    -- MAIN LOOP: Hybrid peek-then-batch algorithm
    -- Uses STATIC SQL for peek (hot path) and DYNAMIC SQL for batch
    -- ========================================================================
    LOOP
        EXIT WHEN v_count >= v_limit;

        -- STEP 1: PEEK using STATIC SQL (plan cached, very fast)
        IF v_is_asc THEN
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" >= v_next_seek AND lower(o.name) COLLATE "C" < v_upper_bound
                ORDER BY lower(o.name) COLLATE "C" ASC LIMIT 1;
            ELSE
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" >= v_next_seek
                ORDER BY lower(o.name) COLLATE "C" ASC LIMIT 1;
            END IF;
        ELSE
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" < v_next_seek AND lower(o.name) COLLATE "C" >= v_prefix_lower
                ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
            ELSIF v_prefix_lower <> '' THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" < v_next_seek AND lower(o.name) COLLATE "C" >= v_prefix_lower
                ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
            ELSE
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" < v_next_seek
                ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
            END IF;
        END IF;

        EXIT WHEN v_peek_name IS NULL;

        -- STEP 2: Check if this is a FOLDER or FILE
        v_common_prefix := storage.get_common_prefix(lower(v_peek_name), v_prefix_lower, v_delimiter);

        IF v_common_prefix IS NOT NULL THEN
            -- FOLDER: Handle offset, emit if needed, skip to next folder
            IF v_skipped < offsets THEN
                v_skipped := v_skipped + 1;
            ELSE
                name := split_part(rtrim(storage.get_common_prefix(v_peek_name, v_prefix, v_delimiter), v_delimiter), v_delimiter, levels);
                id := NULL;
                updated_at := NULL;
                created_at := NULL;
                last_accessed_at := NULL;
                metadata := NULL;
                RETURN NEXT;
                v_count := v_count + 1;
            END IF;

            -- Advance seek past the folder range
            IF v_is_asc THEN
                v_next_seek := lower(left(v_common_prefix, -1)) || chr(ascii(v_delimiter) + 1);
            ELSE
                v_next_seek := lower(v_common_prefix);
            END IF;
        ELSE
            -- FILE: Batch fetch using DYNAMIC SQL (overhead amortized over many rows)
            -- For ASC: upper_bound is the exclusive upper limit (< condition)
            -- For DESC: prefix_lower is the inclusive lower limit (>= condition)
            FOR v_current IN EXECUTE v_batch_query
                USING bucketname, v_next_seek,
                    CASE WHEN v_is_asc THEN COALESCE(v_upper_bound, v_prefix_lower) ELSE v_prefix_lower END, v_file_batch_size
            LOOP
                v_common_prefix := storage.get_common_prefix(lower(v_current.name), v_prefix_lower, v_delimiter);

                IF v_common_prefix IS NOT NULL THEN
                    -- Hit a folder: exit batch, let peek handle it
                    v_next_seek := lower(v_current.name);
                    EXIT;
                END IF;

                -- Handle offset skipping
                IF v_skipped < offsets THEN
                    v_skipped := v_skipped + 1;
                ELSE
                    -- Emit file
                    name := split_part(v_current.name, v_delimiter, levels);
                    id := v_current.id;
                    updated_at := v_current.updated_at;
                    created_at := v_current.created_at;
                    last_accessed_at := v_current.last_accessed_at;
                    metadata := v_current.metadata;
                    RETURN NEXT;
                    v_count := v_count + 1;
                END IF;

                -- Advance seek past this file
                IF v_is_asc THEN
                    v_next_seek := lower(v_current.name) || v_delimiter;
                ELSE
                    v_next_seek := lower(v_current.name);
                END IF;

                EXIT WHEN v_count >= v_limit;
            END LOOP;
        END IF;
    END LOOP;
END;
$_$;


--
-- Name: search_by_timestamp(text, text, integer, integer, text, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.search_by_timestamp(p_prefix text, p_bucket_id text, p_limit integer, p_level integer, p_start_after text, p_sort_order text, p_sort_column text, p_sort_column_after text) RETURNS TABLE(key text, name text, id uuid, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone, metadata jsonb)
    LANGUAGE plpgsql STABLE
    AS $_$
DECLARE
    v_cursor_op text;
    v_query text;
    v_prefix text;
BEGIN
    v_prefix := coalesce(p_prefix, '');

    IF p_sort_order = 'asc' THEN
        v_cursor_op := '>';
    ELSE
        v_cursor_op := '<';
    END IF;

    v_query := format($sql$
        WITH raw_objects AS (
            SELECT
                o.name AS obj_name,
                o.id AS obj_id,
                o.updated_at AS obj_updated_at,
                o.created_at AS obj_created_at,
                o.last_accessed_at AS obj_last_accessed_at,
                o.metadata AS obj_metadata,
                storage.get_common_prefix(o.name, $1, '/') AS common_prefix
            FROM storage.objects o
            WHERE o.bucket_id = $2
              AND o.name COLLATE "C" LIKE $1 || '%%'
        ),
        -- Aggregate common prefixes (folders)
        -- Both created_at and updated_at use MIN(obj_created_at) to match the old prefixes table behavior
        aggregated_prefixes AS (
            SELECT
                rtrim(common_prefix, '/') AS name,
                NULL::uuid AS id,
                MIN(obj_created_at) AS updated_at,
                MIN(obj_created_at) AS created_at,
                NULL::timestamptz AS last_accessed_at,
                NULL::jsonb AS metadata,
                TRUE AS is_prefix
            FROM raw_objects
            WHERE common_prefix IS NOT NULL
            GROUP BY common_prefix
        ),
        leaf_objects AS (
            SELECT
                obj_name AS name,
                obj_id AS id,
                obj_updated_at AS updated_at,
                obj_created_at AS created_at,
                obj_last_accessed_at AS last_accessed_at,
                obj_metadata AS metadata,
                FALSE AS is_prefix
            FROM raw_objects
            WHERE common_prefix IS NULL
        ),
        combined AS (
            SELECT * FROM aggregated_prefixes
            UNION ALL
            SELECT * FROM leaf_objects
        ),
        filtered AS (
            SELECT *
            FROM combined
            WHERE (
                $5 = ''
                OR ROW(
                    date_trunc('milliseconds', %I),
                    name COLLATE "C"
                ) %s ROW(
                    COALESCE(NULLIF($6, '')::timestamptz, 'epoch'::timestamptz),
                    $5
                )
            )
        )
        SELECT
            split_part(name, '/', $3) AS key,
            name,
            id,
            updated_at,
            created_at,
            last_accessed_at,
            metadata
        FROM filtered
        ORDER BY
            COALESCE(date_trunc('milliseconds', %I), 'epoch'::timestamptz) %s,
            name COLLATE "C" %s
        LIMIT $4
    $sql$,
        p_sort_column,
        v_cursor_op,
        p_sort_column,
        p_sort_order,
        p_sort_order
    );

    RETURN QUERY EXECUTE v_query
    USING v_prefix, p_bucket_id, p_level, p_limit, p_start_after, p_sort_column_after;
END;
$_$;


--
-- Name: search_v2(text, text, integer, integer, text, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.search_v2(prefix text, bucket_name text, limits integer DEFAULT 100, levels integer DEFAULT 1, start_after text DEFAULT ''::text, sort_order text DEFAULT 'asc'::text, sort_column text DEFAULT 'name'::text, sort_column_after text DEFAULT ''::text) RETURNS TABLE(key text, name text, id uuid, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone, metadata jsonb)
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_sort_col text;
    v_sort_ord text;
    v_limit int;
BEGIN
    -- Cap limit to maximum of 1500 records
    v_limit := LEAST(coalesce(limits, 100), 1500);

    -- Validate and normalize sort_order
    v_sort_ord := lower(coalesce(sort_order, 'asc'));
    IF v_sort_ord NOT IN ('asc', 'desc') THEN
        v_sort_ord := 'asc';
    END IF;

    -- Validate and normalize sort_column
    v_sort_col := lower(coalesce(sort_column, 'name'));
    IF v_sort_col NOT IN ('name', 'updated_at', 'created_at') THEN
        v_sort_col := 'name';
    END IF;

    -- Route to appropriate implementation
    IF v_sort_col = 'name' THEN
        -- Use list_objects_with_delimiter for name sorting (most efficient: O(k * log n))
        RETURN QUERY
        SELECT
            split_part(l.name, '/', levels) AS key,
            l.name AS name,
            l.id,
            l.updated_at,
            l.created_at,
            l.last_accessed_at,
            l.metadata
        FROM storage.list_objects_with_delimiter(
            bucket_name,
            coalesce(prefix, ''),
            '/',
            v_limit,
            start_after,
            '',
            v_sort_ord
        ) l;
    ELSE
        -- Use aggregation approach for timestamp sorting
        -- Not efficient for large datasets but supports correct pagination
        RETURN QUERY SELECT * FROM storage.search_by_timestamp(
            prefix, bucket_name, v_limit, levels, start_after,
            v_sort_ord, v_sort_col, sort_column_after
        );
    END IF;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW; 
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: audit_log_entries; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.audit_log_entries (
    instance_id uuid,
    id uuid NOT NULL,
    payload json,
    created_at timestamp with time zone,
    ip_address character varying(64) DEFAULT ''::character varying NOT NULL
);


--
-- Name: TABLE audit_log_entries; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.audit_log_entries IS 'Auth: Audit trail for user actions.';


--
-- Name: custom_oauth_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.custom_oauth_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider_type text NOT NULL,
    identifier text NOT NULL,
    name text NOT NULL,
    client_id text NOT NULL,
    client_secret text NOT NULL,
    acceptable_client_ids text[] DEFAULT '{}'::text[] NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    pkce_enabled boolean DEFAULT true NOT NULL,
    attribute_mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    authorization_params jsonb DEFAULT '{}'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    email_optional boolean DEFAULT false NOT NULL,
    issuer text,
    discovery_url text,
    skip_nonce_check boolean DEFAULT false NOT NULL,
    cached_discovery jsonb,
    discovery_cached_at timestamp with time zone,
    authorization_url text,
    token_url text,
    userinfo_url text,
    jwks_uri text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT custom_oauth_providers_authorization_url_https CHECK (((authorization_url IS NULL) OR (authorization_url ~~ 'https://%'::text))),
    CONSTRAINT custom_oauth_providers_authorization_url_length CHECK (((authorization_url IS NULL) OR (char_length(authorization_url) <= 2048))),
    CONSTRAINT custom_oauth_providers_client_id_length CHECK (((char_length(client_id) >= 1) AND (char_length(client_id) <= 512))),
    CONSTRAINT custom_oauth_providers_discovery_url_length CHECK (((discovery_url IS NULL) OR (char_length(discovery_url) <= 2048))),
    CONSTRAINT custom_oauth_providers_identifier_format CHECK ((identifier ~ '^[a-z0-9][a-z0-9:-]{0,48}[a-z0-9]$'::text)),
    CONSTRAINT custom_oauth_providers_issuer_length CHECK (((issuer IS NULL) OR ((char_length(issuer) >= 1) AND (char_length(issuer) <= 2048)))),
    CONSTRAINT custom_oauth_providers_jwks_uri_https CHECK (((jwks_uri IS NULL) OR (jwks_uri ~~ 'https://%'::text))),
    CONSTRAINT custom_oauth_providers_jwks_uri_length CHECK (((jwks_uri IS NULL) OR (char_length(jwks_uri) <= 2048))),
    CONSTRAINT custom_oauth_providers_name_length CHECK (((char_length(name) >= 1) AND (char_length(name) <= 100))),
    CONSTRAINT custom_oauth_providers_oauth2_requires_endpoints CHECK (((provider_type <> 'oauth2'::text) OR ((authorization_url IS NOT NULL) AND (token_url IS NOT NULL) AND (userinfo_url IS NOT NULL)))),
    CONSTRAINT custom_oauth_providers_oidc_discovery_url_https CHECK (((provider_type <> 'oidc'::text) OR (discovery_url IS NULL) OR (discovery_url ~~ 'https://%'::text))),
    CONSTRAINT custom_oauth_providers_oidc_issuer_https CHECK (((provider_type <> 'oidc'::text) OR (issuer IS NULL) OR (issuer ~~ 'https://%'::text))),
    CONSTRAINT custom_oauth_providers_oidc_requires_issuer CHECK (((provider_type <> 'oidc'::text) OR (issuer IS NOT NULL))),
    CONSTRAINT custom_oauth_providers_provider_type_check CHECK ((provider_type = ANY (ARRAY['oauth2'::text, 'oidc'::text]))),
    CONSTRAINT custom_oauth_providers_token_url_https CHECK (((token_url IS NULL) OR (token_url ~~ 'https://%'::text))),
    CONSTRAINT custom_oauth_providers_token_url_length CHECK (((token_url IS NULL) OR (char_length(token_url) <= 2048))),
    CONSTRAINT custom_oauth_providers_userinfo_url_https CHECK (((userinfo_url IS NULL) OR (userinfo_url ~~ 'https://%'::text))),
    CONSTRAINT custom_oauth_providers_userinfo_url_length CHECK (((userinfo_url IS NULL) OR (char_length(userinfo_url) <= 2048)))
);


--
-- Name: flow_state; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.flow_state (
    id uuid NOT NULL,
    user_id uuid,
    auth_code text,
    code_challenge_method auth.code_challenge_method,
    code_challenge text,
    provider_type text NOT NULL,
    provider_access_token text,
    provider_refresh_token text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    authentication_method text NOT NULL,
    auth_code_issued_at timestamp with time zone,
    invite_token text,
    referrer text,
    oauth_client_state_id uuid,
    linking_target_id uuid,
    email_optional boolean DEFAULT false NOT NULL
);


--
-- Name: TABLE flow_state; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.flow_state IS 'Stores metadata for all OAuth/SSO login flows';


--
-- Name: identities; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.identities (
    provider_id text NOT NULL,
    user_id uuid NOT NULL,
    identity_data jsonb NOT NULL,
    provider text NOT NULL,
    last_sign_in_at timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    email text GENERATED ALWAYS AS (lower((identity_data ->> 'email'::text))) STORED,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: TABLE identities; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.identities IS 'Auth: Stores identities associated to a user.';


--
-- Name: COLUMN identities.email; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.identities.email IS 'Auth: Email is a generated column that references the optional email property in the identity_data';


--
-- Name: instances; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.instances (
    id uuid NOT NULL,
    uuid uuid,
    raw_base_config text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: TABLE instances; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.instances IS 'Auth: Manages users across multiple sites.';


--
-- Name: mfa_amr_claims; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_amr_claims (
    session_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    authentication_method text NOT NULL,
    id uuid NOT NULL
);


--
-- Name: TABLE mfa_amr_claims; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_amr_claims IS 'auth: stores authenticator method reference claims for multi factor authentication';


--
-- Name: mfa_challenges; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_challenges (
    id uuid NOT NULL,
    factor_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    ip_address inet NOT NULL,
    otp_code text,
    web_authn_session_data jsonb
);


--
-- Name: TABLE mfa_challenges; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_challenges IS 'auth: stores metadata about challenge requests made';


--
-- Name: mfa_factors; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_factors (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    friendly_name text,
    factor_type auth.factor_type NOT NULL,
    status auth.factor_status NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    secret text,
    phone text,
    last_challenged_at timestamp with time zone,
    web_authn_credential jsonb,
    web_authn_aaguid uuid,
    last_webauthn_challenge_data jsonb
);


--
-- Name: TABLE mfa_factors; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_factors IS 'auth: stores metadata about factors';


--
-- Name: COLUMN mfa_factors.last_webauthn_challenge_data; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.mfa_factors.last_webauthn_challenge_data IS 'Stores the latest WebAuthn challenge data including attestation/assertion for customer verification';


--
-- Name: oauth_authorizations; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oauth_authorizations (
    id uuid NOT NULL,
    authorization_id text NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid,
    redirect_uri text NOT NULL,
    scope text NOT NULL,
    state text,
    resource text,
    code_challenge text,
    code_challenge_method auth.code_challenge_method,
    response_type auth.oauth_response_type DEFAULT 'code'::auth.oauth_response_type NOT NULL,
    status auth.oauth_authorization_status DEFAULT 'pending'::auth.oauth_authorization_status NOT NULL,
    authorization_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '00:03:00'::interval) NOT NULL,
    approved_at timestamp with time zone,
    nonce text,
    CONSTRAINT oauth_authorizations_authorization_code_length CHECK ((char_length(authorization_code) <= 255)),
    CONSTRAINT oauth_authorizations_code_challenge_length CHECK ((char_length(code_challenge) <= 128)),
    CONSTRAINT oauth_authorizations_expires_at_future CHECK ((expires_at > created_at)),
    CONSTRAINT oauth_authorizations_nonce_length CHECK ((char_length(nonce) <= 255)),
    CONSTRAINT oauth_authorizations_redirect_uri_length CHECK ((char_length(redirect_uri) <= 2048)),
    CONSTRAINT oauth_authorizations_resource_length CHECK ((char_length(resource) <= 2048)),
    CONSTRAINT oauth_authorizations_scope_length CHECK ((char_length(scope) <= 4096)),
    CONSTRAINT oauth_authorizations_state_length CHECK ((char_length(state) <= 4096))
);


--
-- Name: oauth_client_states; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oauth_client_states (
    id uuid NOT NULL,
    provider_type text NOT NULL,
    code_verifier text,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: TABLE oauth_client_states; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.oauth_client_states IS 'Stores OAuth states for third-party provider authentication flows where Supabase acts as the OAuth client.';


--
-- Name: oauth_clients; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oauth_clients (
    id uuid NOT NULL,
    client_secret_hash text,
    registration_type auth.oauth_registration_type NOT NULL,
    redirect_uris text NOT NULL,
    grant_types text NOT NULL,
    client_name text,
    client_uri text,
    logo_uri text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    client_type auth.oauth_client_type DEFAULT 'confidential'::auth.oauth_client_type NOT NULL,
    token_endpoint_auth_method text NOT NULL,
    CONSTRAINT oauth_clients_client_name_length CHECK ((char_length(client_name) <= 1024)),
    CONSTRAINT oauth_clients_client_uri_length CHECK ((char_length(client_uri) <= 2048)),
    CONSTRAINT oauth_clients_logo_uri_length CHECK ((char_length(logo_uri) <= 2048)),
    CONSTRAINT oauth_clients_token_endpoint_auth_method_check CHECK ((token_endpoint_auth_method = ANY (ARRAY['client_secret_basic'::text, 'client_secret_post'::text, 'none'::text])))
);


--
-- Name: oauth_consents; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oauth_consents (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    scopes text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT oauth_consents_revoked_after_granted CHECK (((revoked_at IS NULL) OR (revoked_at >= granted_at))),
    CONSTRAINT oauth_consents_scopes_length CHECK ((char_length(scopes) <= 2048)),
    CONSTRAINT oauth_consents_scopes_not_empty CHECK ((char_length(TRIM(BOTH FROM scopes)) > 0))
);


--
-- Name: one_time_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.one_time_tokens (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_type auth.one_time_token_type NOT NULL,
    token_hash text NOT NULL,
    relates_to text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT one_time_tokens_token_hash_check CHECK ((char_length(token_hash) > 0))
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.refresh_tokens (
    instance_id uuid,
    id bigint NOT NULL,
    token character varying(255),
    user_id character varying(255),
    revoked boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    parent character varying(255),
    session_id uuid
);


--
-- Name: TABLE refresh_tokens; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.refresh_tokens IS 'Auth: Store of tokens used to refresh JWT tokens once they expire.';


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE; Schema: auth; Owner: -
--

CREATE SEQUENCE auth.refresh_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: auth; Owner: -
--

ALTER SEQUENCE auth.refresh_tokens_id_seq OWNED BY auth.refresh_tokens.id;


--
-- Name: saml_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.saml_providers (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    entity_id text NOT NULL,
    metadata_xml text NOT NULL,
    metadata_url text,
    attribute_mapping jsonb,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name_id_format text,
    CONSTRAINT "entity_id not empty" CHECK ((char_length(entity_id) > 0)),
    CONSTRAINT "metadata_url not empty" CHECK (((metadata_url = NULL::text) OR (char_length(metadata_url) > 0))),
    CONSTRAINT "metadata_xml not empty" CHECK ((char_length(metadata_xml) > 0))
);


--
-- Name: TABLE saml_providers; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.saml_providers IS 'Auth: Manages SAML Identity Provider connections.';


--
-- Name: saml_relay_states; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.saml_relay_states (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    request_id text NOT NULL,
    for_email text,
    redirect_to text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    flow_state_id uuid,
    CONSTRAINT "request_id not empty" CHECK ((char_length(request_id) > 0))
);


--
-- Name: TABLE saml_relay_states; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.saml_relay_states IS 'Auth: Contains SAML Relay State information for each Service Provider initiated login.';


--
-- Name: schema_migrations; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.schema_migrations (
    version character varying(255) NOT NULL
);


--
-- Name: TABLE schema_migrations; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.schema_migrations IS 'Auth: Manages updates to the auth system.';


--
-- Name: sessions; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sessions (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    factor_id uuid,
    aal auth.aal_level,
    not_after timestamp with time zone,
    refreshed_at timestamp without time zone,
    user_agent text,
    ip inet,
    tag text,
    oauth_client_id uuid,
    refresh_token_hmac_key text,
    refresh_token_counter bigint,
    scopes text,
    CONSTRAINT sessions_scopes_length CHECK ((char_length(scopes) <= 4096))
);


--
-- Name: TABLE sessions; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sessions IS 'Auth: Stores session data associated to a user.';


--
-- Name: COLUMN sessions.not_after; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sessions.not_after IS 'Auth: Not after is a nullable column that contains a timestamp after which the session should be regarded as expired.';


--
-- Name: COLUMN sessions.refresh_token_hmac_key; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sessions.refresh_token_hmac_key IS 'Holds a HMAC-SHA256 key used to sign refresh tokens for this session.';


--
-- Name: COLUMN sessions.refresh_token_counter; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sessions.refresh_token_counter IS 'Holds the ID (counter) of the last issued refresh token.';


--
-- Name: sso_domains; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sso_domains (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    domain text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    CONSTRAINT "domain not empty" CHECK ((char_length(domain) > 0))
);


--
-- Name: TABLE sso_domains; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sso_domains IS 'Auth: Manages SSO email address domain mapping to an SSO Identity Provider.';


--
-- Name: sso_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sso_providers (
    id uuid NOT NULL,
    resource_id text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    disabled boolean,
    CONSTRAINT "resource_id not empty" CHECK (((resource_id = NULL::text) OR (char_length(resource_id) > 0)))
);


--
-- Name: TABLE sso_providers; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sso_providers IS 'Auth: Manages SSO identity provider information; see saml_providers for SAML.';


--
-- Name: COLUMN sso_providers.resource_id; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sso_providers.resource_id IS 'Auth: Uniquely identifies a SSO provider according to a user-chosen resource ID (case insensitive), useful in infrastructure as code.';


--
-- Name: users; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.users (
    instance_id uuid,
    id uuid NOT NULL,
    aud character varying(255),
    role character varying(255),
    email character varying(255),
    encrypted_password character varying(255),
    email_confirmed_at timestamp with time zone,
    invited_at timestamp with time zone,
    confirmation_token character varying(255),
    confirmation_sent_at timestamp with time zone,
    recovery_token character varying(255),
    recovery_sent_at timestamp with time zone,
    email_change_token_new character varying(255),
    email_change character varying(255),
    email_change_sent_at timestamp with time zone,
    last_sign_in_at timestamp with time zone,
    raw_app_meta_data jsonb,
    raw_user_meta_data jsonb,
    is_super_admin boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    phone text DEFAULT NULL::character varying,
    phone_confirmed_at timestamp with time zone,
    phone_change text DEFAULT ''::character varying,
    phone_change_token character varying(255) DEFAULT ''::character varying,
    phone_change_sent_at timestamp with time zone,
    confirmed_at timestamp with time zone GENERATED ALWAYS AS (LEAST(email_confirmed_at, phone_confirmed_at)) STORED,
    email_change_token_current character varying(255) DEFAULT ''::character varying,
    email_change_confirm_status smallint DEFAULT 0,
    banned_until timestamp with time zone,
    reauthentication_token character varying(255) DEFAULT ''::character varying,
    reauthentication_sent_at timestamp with time zone,
    is_sso_user boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone,
    is_anonymous boolean DEFAULT false NOT NULL,
    CONSTRAINT users_email_change_confirm_status_check CHECK (((email_change_confirm_status >= 0) AND (email_change_confirm_status <= 2)))
);


--
-- Name: TABLE users; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.users IS 'Auth: Stores user login data within a secure schema.';


--
-- Name: COLUMN users.is_sso_user; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.users.is_sso_user IS 'Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.';


--
-- Name: webauthn_challenges; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.webauthn_challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    challenge_type text NOT NULL,
    session_data jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT webauthn_challenges_challenge_type_check CHECK ((challenge_type = ANY (ARRAY['signup'::text, 'registration'::text, 'authentication'::text])))
);


--
-- Name: webauthn_credentials; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.webauthn_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    attestation_type text DEFAULT ''::text NOT NULL,
    aaguid uuid,
    sign_count bigint DEFAULT 0 NOT NULL,
    transports jsonb DEFAULT '[]'::jsonb NOT NULL,
    backup_eligible boolean DEFAULT false NOT NULL,
    backed_up boolean DEFAULT false NOT NULL,
    friendly_name text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);


--
-- Name: app_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_settings (
    id integer NOT NULL,
    key character varying(120) NOT NULL,
    value text,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: app_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.app_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: app_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.app_settings_id_seq OWNED BY public.app_settings.id;


--
-- Name: backup_usuarios; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.backup_usuarios (
    id integer,
    username character varying(50),
    senha_hash character varying(255),
    role character varying(20),
    emp text
);


--
-- Name: branding_themes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.branding_themes (
    id integer NOT NULL,
    name character varying(120) NOT NULL,
    start_date date NOT NULL,
    end_date date NOT NULL,
    logo_url text,
    favicon_url text,
    is_active boolean NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: branding_themes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.branding_themes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: branding_themes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.branding_themes_id_seq OWNED BY public.branding_themes.id;


--
-- Name: cache_cidades_emp; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cache_cidades_emp (
    id bigint NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    emp integer NOT NULL,
    vendedor text,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: cache_cidades_emp_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cache_cidades_emp_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cache_cidades_emp_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cache_cidades_emp_id_seq OWNED BY public.cache_cidades_emp.id;


--
-- Name: cache_cliente_marcas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cache_cliente_marcas (
    id bigint NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    emp integer NOT NULL,
    vendedor text,
    cliente_id text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: cache_cliente_marcas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cache_cliente_marcas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cache_cliente_marcas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cache_cliente_marcas_id_seq OWNED BY public.cache_cliente_marcas.id;


--
-- Name: cache_clientes_emp; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cache_clientes_emp (
    id bigint NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    emp integer NOT NULL,
    vendedor text,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: cache_clientes_emp_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cache_clientes_emp_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cache_clientes_emp_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cache_clientes_emp_id_seq OWNED BY public.cache_clientes_emp.id;


--
-- Name: campanhas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas (
    id bigint NOT NULL,
    tipo text NOT NULL,
    titulo text NOT NULL,
    descricao text,
    escopo text DEFAULT 'GLOBAL'::text NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    data_inicio date,
    data_fim date,
    regra_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    premiacao_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: campanhas_audit_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_audit_v2 (
    id bigint NOT NULL,
    campanha_id bigint,
    competencia_ano integer,
    competencia_mes integer,
    emp integer,
    vendedor character varying(80),
    acao character varying(60) NOT NULL,
    de_status character varying(20),
    para_status character varying(20),
    actor character varying(60),
    payload_json text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: campanhas_audit_v2_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_audit_v2_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_audit_v2_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_audit_v2_id_seq OWNED BY public.campanhas_audit_v2.id;


--
-- Name: campanhas_combo; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_combo (
    id integer NOT NULL,
    nome character varying(120) NOT NULL,
    mes integer NOT NULL,
    ano integer NOT NULL,
    emp character varying(30),
    marca character varying(120) NOT NULL,
    valor_unitario_global double precision,
    ativo boolean NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    data_inicio date,
    data_fim date,
    titulo character varying(160),
    criado_em timestamp with time zone DEFAULT now(),
    atualizado_em timestamp with time zone,
    modelo_pagamento character varying(20) DEFAULT 'TODOS_ITENS'::character varying NOT NULL,
    filtro_marca character varying(120),
    filtro_descricao_prefixo character varying(200),
    valor_unitario_modelo2 double precision
);


--
-- Name: campanhas_combo_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_combo_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_combo_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_combo_id_seq OWNED BY public.campanhas_combo.id;


--
-- Name: campanhas_combo_itens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_combo_itens (
    id integer NOT NULL,
    combo_id integer NOT NULL,
    nome_item character varying(120),
    match_mestre character varying(160) NOT NULL,
    minimo_qtd integer NOT NULL,
    valor_unitario double precision,
    ordem integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    mestre_prefixo character varying(120),
    descricao_contains character varying(200),
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: campanhas_combo_itens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_combo_itens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_combo_itens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_combo_itens_id_seq OWNED BY public.campanhas_combo_itens.id;


--
-- Name: campanhas_combo_resultados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_combo_resultados (
    id integer NOT NULL,
    combo_id integer NOT NULL,
    competencia_ano integer NOT NULL,
    competencia_mes integer NOT NULL,
    emp character varying(30) NOT NULL,
    vendedor character varying(80) NOT NULL,
    titulo character varying(160) NOT NULL,
    marca character varying(120) NOT NULL,
    data_inicio date NOT NULL,
    data_fim date NOT NULL,
    atingiu_gate integer NOT NULL,
    valor_recompensa double precision NOT NULL,
    status_pagamento character varying(20) NOT NULL,
    pago_em timestamp without time zone,
    atualizado_em timestamp without time zone NOT NULL
);


--
-- Name: campanhas_combo_resultados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_combo_resultados_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_combo_resultados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_combo_resultados_id_seq OWNED BY public.campanhas_combo_resultados.id;


--
-- Name: campanhas_emps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_emps (
    id bigint NOT NULL,
    campanha_id bigint NOT NULL,
    emp integer NOT NULL
);


--
-- Name: campanhas_emps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_emps_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_emps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_emps_id_seq OWNED BY public.campanhas_emps.id;


--
-- Name: campanhas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_id_seq OWNED BY public.campanhas.id;


--
-- Name: campanhas_master_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_master_v2 (
    id bigint NOT NULL,
    titulo character varying(160) NOT NULL,
    tipo character varying(40) NOT NULL,
    escopo character varying(20) DEFAULT 'EMP'::character varying NOT NULL,
    emps_json text,
    vigencia_ini date NOT NULL,
    vigencia_fim date NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    regras_json text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: campanhas_master_v2_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_master_v2_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_master_v2_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_master_v2_id_seq OWNED BY public.campanhas_master_v2.id;


--
-- Name: campanhas_qtd; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_qtd (
    id integer NOT NULL,
    emp character varying(30) NOT NULL,
    vendedor character varying(80),
    titulo character varying(120),
    produto_prefixo character varying(200) NOT NULL,
    marca character varying(120) NOT NULL,
    recompensa_unit numeric(18,2) DEFAULT 0 NOT NULL,
    qtd_minima double precision,
    data_inicio date NOT NULL,
    data_fim date NOT NULL,
    ativo integer NOT NULL,
    criado_em timestamp without time zone NOT NULL,
    atualizado_em timestamp without time zone NOT NULL,
    campo_match character varying(20) DEFAULT 'codigo'::character varying,
    descricao_prefixo character varying(200),
    valor_minimo numeric(18,2),
    tipo_base character varying(10) DEFAULT 'QTD'::character varying NOT NULL,
    recompensa_percentual double precision,
    faturamento_minimo_emp double precision,
    campanha_tipo character varying(20) DEFAULT 'VENDEDOR'::character varying NOT NULL
);


--
-- Name: campanhas_qtd_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_qtd_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_qtd_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_qtd_id_seq OWNED BY public.campanhas_qtd.id;


--
-- Name: campanhas_qtd_resultados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_qtd_resultados (
    id integer NOT NULL,
    campanha_id integer NOT NULL,
    competencia_ano integer NOT NULL,
    competencia_mes integer NOT NULL,
    emp character varying(30) NOT NULL,
    vendedor character varying(80) NOT NULL,
    titulo character varying(120),
    produto_prefixo character varying(200) NOT NULL,
    marca character varying(120) NOT NULL,
    recompensa_unit numeric(18,2) DEFAULT 0 NOT NULL,
    qtd_minima double precision,
    data_inicio date NOT NULL,
    data_fim date NOT NULL,
    qtd_vendida double precision NOT NULL,
    valor_vendido numeric(18,2) DEFAULT 0 NOT NULL,
    atingiu_minimo integer NOT NULL,
    valor_recompensa numeric(18,2) DEFAULT 0 NOT NULL,
    status_pagamento character varying(20) NOT NULL,
    pago_em timestamp without time zone,
    atualizado_em timestamp without time zone NOT NULL,
    tipo_base character varying(10),
    recompensa_percentual double precision,
    premio_potencial double precision,
    faturamento_minimo_emp double precision,
    faturamento_emp double precision,
    faltante_faturamento_emp double precision,
    bloqueado_faturamento_emp integer DEFAULT 0 NOT NULL,
    campanha_tipo character varying(20) DEFAULT 'VENDEDOR'::character varying NOT NULL
);


--
-- Name: campanhas_qtd_resultados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_qtd_resultados_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_qtd_resultados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_qtd_resultados_id_seq OWNED BY public.campanhas_qtd_resultados.id;


--
-- Name: campanhas_ranking_marca; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_ranking_marca (
    id integer NOT NULL,
    titulo character varying(200) NOT NULL,
    marca character varying(120) NOT NULL,
    data_inicio date NOT NULL,
    data_fim date NOT NULL,
    competencia_ano integer,
    competencia_mes integer,
    escopo_tipo character varying(20) NOT NULL,
    ativo boolean NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    min_total double precision
);


--
-- Name: campanhas_ranking_marca_emps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_ranking_marca_emps (
    id integer NOT NULL,
    campanha_id integer NOT NULL,
    emp character varying(30) NOT NULL
);


--
-- Name: campanhas_ranking_marca_emps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_ranking_marca_emps_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_ranking_marca_emps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_ranking_marca_emps_id_seq OWNED BY public.campanhas_ranking_marca_emps.id;


--
-- Name: campanhas_ranking_marca_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_ranking_marca_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_ranking_marca_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_ranking_marca_id_seq OWNED BY public.campanhas_ranking_marca.id;


--
-- Name: campanhas_ranking_marca_premios; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_ranking_marca_premios (
    id integer NOT NULL,
    campanha_id integer NOT NULL,
    posicao integer NOT NULL,
    valor_premio double precision NOT NULL
);


--
-- Name: campanhas_ranking_marca_premios_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_ranking_marca_premios_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_ranking_marca_premios_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_ranking_marca_premios_id_seq OWNED BY public.campanhas_ranking_marca_premios.id;


--
-- Name: campanhas_ranking_marca_resultados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_ranking_marca_resultados (
    id integer NOT NULL,
    campanha_id integer NOT NULL,
    competencia_ano integer NOT NULL,
    competencia_mes integer NOT NULL,
    emp character varying(30),
    vendedor character varying(80) NOT NULL,
    valor_vendido double precision NOT NULL,
    posicao integer,
    valor_premio double precision NOT NULL,
    status_pagamento character varying(20) NOT NULL,
    pago_em timestamp without time zone,
    atualizado_em timestamp without time zone NOT NULL
);


--
-- Name: campanhas_ranking_marca_resultados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_ranking_marca_resultados_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_ranking_marca_resultados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_ranking_marca_resultados_id_seq OWNED BY public.campanhas_ranking_marca_resultados.id;


--
-- Name: campanhas_resultados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_resultados (
    id bigint NOT NULL,
    campanha_id bigint NOT NULL,
    competencia_ano integer NOT NULL,
    competencia_mes integer NOT NULL,
    emp integer NOT NULL,
    vendedor text NOT NULL,
    valor_base numeric(14,2),
    qtd_base numeric(14,2),
    mix_base integer,
    margem_base numeric(14,2),
    percent_base numeric(7,4),
    atingiu boolean DEFAULT false NOT NULL,
    posicao integer,
    premio_valor numeric(14,2) DEFAULT 0 NOT NULL,
    detalhes_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: campanhas_resultados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_resultados_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_resultados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_resultados_id_seq OWNED BY public.campanhas_resultados.id;


--
-- Name: campanhas_resultados_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_resultados_v2 (
    id bigint NOT NULL,
    campanha_id bigint NOT NULL,
    competencia_ano integer NOT NULL,
    competencia_mes integer NOT NULL,
    emp integer NOT NULL,
    vendedor character varying(80) NOT NULL,
    tipo character varying(40) NOT NULL,
    base_num double precision DEFAULT 0 NOT NULL,
    atingiu boolean DEFAULT false NOT NULL,
    valor_recompensa double precision DEFAULT 0 NOT NULL,
    detalhes_json text,
    vigencia_ini date,
    vigencia_fim date,
    status_pagamento character varying(20) DEFAULT 'PENDENTE'::character varying NOT NULL,
    pago_em timestamp with time zone,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: campanhas_resultados_v2_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_resultados_v2_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_resultados_v2_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_resultados_v2_id_seq OWNED BY public.campanhas_resultados_v2.id;


--
-- Name: campanhas_scope_emp_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_scope_emp_v2 (
    id bigint NOT NULL,
    campanha_id integer NOT NULL,
    emp integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: campanhas_scope_emp_v2_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_scope_emp_v2_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_scope_emp_v2_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_scope_emp_v2_id_seq OWNED BY public.campanhas_scope_emp_v2.id;


--
-- Name: campanhas_v2_master; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_v2_master (
    id bigint NOT NULL,
    nome text NOT NULL,
    tipo text NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    vigencia_inicio date,
    vigencia_fim date,
    scope_mode text DEFAULT 'GLOBAL'::text NOT NULL,
    marca_alvo text,
    meta_valor numeric(14,2),
    meta_percentual numeric(8,4),
    mix_qtd_min integer,
    janela_meses integer DEFAULT 1 NOT NULL,
    premio_tipo text DEFAULT 'FIXO'::text NOT NULL,
    premio_top1 numeric(14,2),
    premio_top2 numeric(14,2),
    premio_top3 numeric(14,2),
    premio_percentual numeric(8,4),
    base_minima_valor numeric(14,2) DEFAULT 0 NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: campanhas_v2_master_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_v2_master_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_v2_master_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_v2_master_id_seq OWNED BY public.campanhas_v2_master.id;


--
-- Name: campanhas_v2_resultados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campanhas_v2_resultados (
    id bigint NOT NULL,
    campanha_id bigint NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    emp integer,
    vendedor text NOT NULL,
    valor_base numeric(14,2),
    valor_atual numeric(14,2),
    pct numeric(10,4),
    mix integer,
    posicao integer,
    atingiu boolean DEFAULT false NOT NULL,
    premio numeric(14,2) DEFAULT 0 NOT NULL,
    detalhes_json jsonb,
    calculado_em timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: campanhas_v2_resultados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.campanhas_v2_resultados_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: campanhas_v2_resultados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.campanhas_v2_resultados_id_seq OWNED BY public.campanhas_v2_resultados.id;


--
-- Name: dashboard_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dashboard_cache (
    emp text NOT NULL,
    vendedor text NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    valor_bruto numeric(18,2) DEFAULT 0 NOT NULL,
    valor_liquido numeric(18,2) DEFAULT 0 NOT NULL,
    devolucoes numeric(18,2) DEFAULT 0 NOT NULL,
    cancelamentos numeric(18,2) DEFAULT 0 NOT NULL,
    pct_devolucao numeric(10,4) DEFAULT 0 NOT NULL,
    mix_produtos integer DEFAULT 0 NOT NULL,
    mix_marcas integer DEFAULT 0 NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL,
    id bigint NOT NULL,
    ranking_json text DEFAULT '[]'::text NOT NULL,
    ranking_top15_json text DEFAULT '[]'::text NOT NULL,
    total_liquido_periodo numeric(18,2) DEFAULT 0 NOT NULL,
    emp_scope character varying(30),
    vendedor_alvo character varying(80),
    tipo character varying(60),
    payload_json text
);


--
-- Name: dashboard_cache_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dashboard_cache_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dashboard_cache_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dashboard_cache_id_seq OWNED BY public.dashboard_cache.id;


--
-- Name: emps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.emps (
    id integer NOT NULL,
    codigo character varying(30) NOT NULL,
    nome character varying(120) NOT NULL,
    cidade character varying(120),
    uf character varying(2),
    ativo boolean NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: emps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.emps_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: emps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.emps_id_seq OWNED BY public.emps.id;


--
-- Name: fechamento_mensal; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fechamento_mensal (
    id bigint NOT NULL,
    emp text DEFAULT ''::text NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    fechado boolean DEFAULT false NOT NULL,
    fechado_em timestamp with time zone,
    status character varying(20) DEFAULT 'aberto'::character varying
);


--
-- Name: fechamento_mensal_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fechamento_mensal_audit (
    id integer NOT NULL,
    emp character varying(30) NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    acao character varying(30) NOT NULL,
    fechado_de boolean,
    fechado_para boolean,
    status_de character varying(20),
    status_para character varying(20),
    actor character varying(120),
    created_at timestamp without time zone NOT NULL
);


--
-- Name: fechamento_mensal_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.fechamento_mensal_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fechamento_mensal_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.fechamento_mensal_audit_id_seq OWNED BY public.fechamento_mensal_audit.id;


--
-- Name: fechamento_mensal_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.fechamento_mensal_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fechamento_mensal_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.fechamento_mensal_id_seq OWNED BY public.fechamento_mensal.id;


--
-- Name: financeiro_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.financeiro_audit (
    id bigint NOT NULL,
    pagamento_id bigint NOT NULL,
    acao text NOT NULL,
    de_status text,
    para_status text,
    usuario text,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    meta jsonb
);


--
-- Name: financeiro_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.financeiro_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: financeiro_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.financeiro_audit_id_seq OWNED BY public.financeiro_audit.id;


--
-- Name: financeiro_pagamentos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.financeiro_pagamentos (
    id bigint NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    origem_tipo text NOT NULL,
    origem_id bigint NOT NULL,
    campanha_nome text,
    emp integer,
    vendedor text NOT NULL,
    valor_premio numeric(14,2) DEFAULT 0 NOT NULL,
    status text DEFAULT 'PENDENTE'::text NOT NULL,
    atualizado_por text,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: financeiro_pagamentos_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.financeiro_pagamentos_audit (
    id integer NOT NULL,
    pagamento_id integer NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    origem_tipo character varying(20) NOT NULL,
    origem_id integer NOT NULL,
    emp character varying(30),
    vendedor character varying(80),
    status_de character varying(20),
    status_para character varying(20) NOT NULL,
    alterado_por character varying(80),
    alterado_em timestamp without time zone NOT NULL,
    motivo text
);


--
-- Name: financeiro_pagamentos_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.financeiro_pagamentos_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: financeiro_pagamentos_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.financeiro_pagamentos_audit_id_seq OWNED BY public.financeiro_pagamentos_audit.id;


--
-- Name: financeiro_pagamentos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.financeiro_pagamentos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: financeiro_pagamentos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.financeiro_pagamentos_id_seq OWNED BY public.financeiro_pagamentos.id;


--
-- Name: importacoes_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.importacoes_log (
    id integer NOT NULL,
    usuario character varying(80),
    arquivo_nome character varying(255),
    criado_em timestamp without time zone NOT NULL,
    emps_json text,
    periodos_json text,
    resumo_json text,
    total_linhas integer,
    validas integer,
    inseridas integer,
    ignoradas integer,
    erros_linha integer,
    total_bruto double precision,
    total_ca double precision,
    total_liquido double precision,
    ca_linhas integer,
    duracao_s double precision
);


--
-- Name: importacoes_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.importacoes_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: importacoes_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.importacoes_log_id_seq OWNED BY public.importacoes_log.id;


--
-- Name: insights_fechamento; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.insights_fechamento (
    emp integer NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    cidade_norm text NOT NULL,
    total_vendido numeric(14,2) NOT NULL,
    clientes_unicos integer NOT NULL,
    clientes_novos integer NOT NULL,
    clientes_recorrentes integer NOT NULL,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: insights_parciais; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.insights_parciais (
    emp integer NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    cidade_norm text NOT NULL,
    total_vendido numeric(14,2) DEFAULT 0 NOT NULL,
    clientes_unicos integer DEFAULT 0 NOT NULL,
    clientes_novos integer DEFAULT 0 NOT NULL,
    clientes_recorrentes integer DEFAULT 0 NOT NULL,
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: itens_parados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itens_parados (
    id bigint NOT NULL,
    emp text NOT NULL,
    codigo text NOT NULL,
    descricao text,
    quantidade integer,
    recompensa_pct double precision DEFAULT 0 NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL,
    percentual numeric(10,4),
    modo character varying(20) DEFAULT 'PONTOS'::character varying NOT NULL,
    data_inicio date,
    data_fim date,
    multiplicador_pontos numeric(10,4) DEFAULT 1 NOT NULL
);


--
-- Name: itens_parados_fechamentos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itens_parados_fechamentos (
    id bigint NOT NULL,
    emp integer NOT NULL,
    data_inicio date NOT NULL,
    data_fim date NOT NULL,
    fechado_por integer,
    observacao text,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: itens_parados_fechamentos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.itens_parados_fechamentos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: itens_parados_fechamentos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.itens_parados_fechamentos_id_seq OWNED BY public.itens_parados_fechamentos.id;


--
-- Name: itens_parados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.itens_parados_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: itens_parados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.itens_parados_id_seq OWNED BY public.itens_parados.id;


--
-- Name: itens_parados_pontos_bonus; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itens_parados_pontos_bonus (
    id bigint NOT NULL,
    emp character varying(50),
    min_pontos double precision NOT NULL,
    bonus_valor numeric(10,2) DEFAULT 0 NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: itens_parados_pontos_bonus_faixas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itens_parados_pontos_bonus_faixas (
    id bigint NOT NULL,
    emp character varying(50),
    pontos_min integer NOT NULL,
    bonus_valor numeric(10,2) DEFAULT 0 NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: itens_parados_pontos_bonus_faixas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.itens_parados_pontos_bonus_faixas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: itens_parados_pontos_bonus_faixas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.itens_parados_pontos_bonus_faixas_id_seq OWNED BY public.itens_parados_pontos_bonus_faixas.id;


--
-- Name: itens_parados_pontos_bonus_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.itens_parados_pontos_bonus_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: itens_parados_pontos_bonus_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.itens_parados_pontos_bonus_id_seq OWNED BY public.itens_parados_pontos_bonus.id;


--
-- Name: itens_parados_pontos_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itens_parados_pontos_config (
    id bigint NOT NULL,
    emp character varying(50),
    base_reais double precision DEFAULT 100 NOT NULL,
    valor_por_ponto numeric(10,2) DEFAULT 10 NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: itens_parados_pontos_config_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.itens_parados_pontos_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: itens_parados_pontos_config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.itens_parados_pontos_config_id_seq OWNED BY public.itens_parados_pontos_config.id;


--
-- Name: itens_parados_pontos_fechamentos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itens_parados_pontos_fechamentos (
    id bigint NOT NULL,
    emp character varying(50),
    periodo_inicio date NOT NULL,
    periodo_fim date NOT NULL,
    criado_por integer,
    status character varying(20) DEFAULT 'PENDENTE'::character varying NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL,
    data_inicio date,
    data_fim date
);


--
-- Name: itens_parados_pontos_fechamentos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.itens_parados_pontos_fechamentos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: itens_parados_pontos_fechamentos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.itens_parados_pontos_fechamentos_id_seq OWNED BY public.itens_parados_pontos_fechamentos.id;


--
-- Name: itens_parados_pontos_resultados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itens_parados_pontos_resultados (
    id bigint NOT NULL,
    fechamento_id bigint NOT NULL,
    emp character varying(50) NOT NULL,
    vendedor character varying(120) NOT NULL,
    valor_vendido numeric(14,2) DEFAULT 0 NOT NULL,
    pontos double precision DEFAULT 0 NOT NULL,
    premio_base numeric(14,2) DEFAULT 0 NOT NULL,
    bonus_extra numeric(14,2) DEFAULT 0 NOT NULL,
    premio_total numeric(14,2) DEFAULT 0 NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL,
    vendedor_id integer,
    bonus_base double precision DEFAULT 0.0 NOT NULL,
    total double precision DEFAULT 0.0 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: itens_parados_pontos_resultados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.itens_parados_pontos_resultados_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: itens_parados_pontos_resultados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.itens_parados_pontos_resultados_id_seq OWNED BY public.itens_parados_pontos_resultados.id;


--
-- Name: itens_parados_resultados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itens_parados_resultados (
    id integer NOT NULL,
    item_parado_id integer NOT NULL,
    competencia_ano integer NOT NULL,
    competencia_mes integer NOT NULL,
    emp character varying(30) NOT NULL,
    vendedor character varying(80) NOT NULL,
    titulo character varying(255) NOT NULL,
    base_valor_vendido double precision NOT NULL,
    recompensa_pct double precision NOT NULL,
    valor_recompensa double precision NOT NULL,
    status_pagamento character varying(20) NOT NULL,
    pago_em timestamp without time zone,
    atualizado_em timestamp without time zone NOT NULL,
    qtd_base double precision,
    recompensa_unit double precision
);


--
-- Name: itens_parados_resultados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.itens_parados_resultados_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: itens_parados_resultados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.itens_parados_resultados_id_seq OWNED BY public.itens_parados_resultados.id;


--
-- Name: margem_vendedor_periodo; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.margem_vendedor_periodo (
    id bigint NOT NULL,
    competencia_ano integer NOT NULL,
    competencia_mes integer NOT NULL,
    emp integer NOT NULL,
    vendedor text NOT NULL,
    faturamento numeric(14,2) DEFAULT 0 NOT NULL,
    custo_total numeric(14,2) DEFAULT 0 NOT NULL,
    margem_real_valor numeric(14,2) DEFAULT 0 NOT NULL,
    margem_padrao_valor numeric(14,2) DEFAULT 0 NOT NULL,
    saldo_valor numeric(14,2) DEFAULT 0 NOT NULL,
    saldo_pontos numeric(14,3) DEFAULT 0 NOT NULL,
    margem_real_pct_pond numeric(7,3) DEFAULT 0 NOT NULL,
    margem_padrao_pct_pond numeric(7,3) DEFAULT 0 NOT NULL,
    saldo_pct_pond numeric(7,3) DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: margem_vendedor_periodo_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.margem_vendedor_periodo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: margem_vendedor_periodo_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.margem_vendedor_periodo_id_seq OWNED BY public.margem_vendedor_periodo.id;


--
-- Name: mensagem_empresas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mensagem_empresas (
    id integer NOT NULL,
    mensagem_id integer NOT NULL,
    emp character varying(30) NOT NULL
);


--
-- Name: mensagem_empresas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mensagem_empresas_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mensagem_empresas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mensagem_empresas_id_seq OWNED BY public.mensagem_empresas.id;


--
-- Name: mensagem_lidas_diarias; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mensagem_lidas_diarias (
    id integer NOT NULL,
    mensagem_id integer NOT NULL,
    usuario_id integer NOT NULL,
    data date NOT NULL,
    lida_em timestamp without time zone NOT NULL
);


--
-- Name: mensagem_lidas_diarias_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mensagem_lidas_diarias_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mensagem_lidas_diarias_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mensagem_lidas_diarias_id_seq OWNED BY public.mensagem_lidas_diarias.id;


--
-- Name: mensagem_usuarios; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mensagem_usuarios (
    id integer NOT NULL,
    mensagem_id integer NOT NULL,
    usuario_id integer NOT NULL
);


--
-- Name: mensagem_usuarios_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mensagem_usuarios_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mensagem_usuarios_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mensagem_usuarios_id_seq OWNED BY public.mensagem_usuarios.id;


--
-- Name: mensagens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mensagens (
    id integer NOT NULL,
    titulo character varying(180) NOT NULL,
    conteudo text NOT NULL,
    bloqueante boolean DEFAULT false NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    inicio_em date,
    fim_em date,
    created_by_user_id integer,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: mensagens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mensagens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mensagens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mensagens_id_seq OWNED BY public.mensagens.id;


--
-- Name: metas_bases_manuais; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_bases_manuais (
    id bigint NOT NULL,
    meta_id bigint NOT NULL,
    emp character varying(30) NOT NULL,
    vendedor character varying(80) NOT NULL,
    base_valor numeric(18,2) DEFAULT 0 NOT NULL,
    observacao character varying(200),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    margem_percentual double precision,
    bonus_extra_percentual double precision
);


--
-- Name: metas_bases_manuais_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_bases_manuais_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_bases_manuais_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_bases_manuais_id_seq OWNED BY public.metas_bases_manuais.id;


--
-- Name: metas_escalas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_escalas (
    id bigint NOT NULL,
    meta_id bigint NOT NULL,
    ordem integer DEFAULT 0 NOT NULL,
    limite_min double precision NOT NULL,
    bonus_percentual double precision NOT NULL
);


--
-- Name: metas_escalas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_escalas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_escalas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_escalas_id_seq OWNED BY public.metas_escalas.id;


--
-- Name: metas_gate_vendedor_emp; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_gate_vendedor_emp (
    id integer NOT NULL,
    emp character varying(30) NOT NULL,
    vendedor character varying(80) NOT NULL,
    periodo_tipo character varying(20) DEFAULT 'MENSAL'::character varying NOT NULL,
    ano integer,
    mes integer,
    data_ini date,
    data_fim date,
    gate_valor double precision DEFAULT 0 NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    created_by_user_id integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    usuario_id integer
);


--
-- Name: metas_gate_vendedor_emp_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_gate_vendedor_emp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_gate_vendedor_emp_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_gate_vendedor_emp_id_seq OWNED BY public.metas_gate_vendedor_emp.id;


--
-- Name: metas_marcas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_marcas (
    id bigint NOT NULL,
    meta_id bigint NOT NULL,
    marca character varying(120) NOT NULL
);


--
-- Name: metas_marcas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_marcas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_marcas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_marcas_id_seq OWNED BY public.metas_marcas.id;


--
-- Name: metas_margens_vendedores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_margens_vendedores (
    id integer NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    emp character varying(30) NOT NULL,
    vendedor character varying(80) NOT NULL,
    margem_percentual double precision DEFAULT 0 NOT NULL,
    observacao character varying(240),
    arquivo_origem character varying(255),
    importado_por character varying(80),
    importado_em timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: metas_margens_vendedores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_margens_vendedores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_margens_vendedores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_margens_vendedores_id_seq OWNED BY public.metas_margens_vendedores.id;


--
-- Name: metas_programas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_programas (
    id bigint NOT NULL,
    nome character varying(180) NOT NULL,
    tipo character varying(30) NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    created_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    periodo_tipo character varying(20) DEFAULT 'MENSAL'::character varying NOT NULL,
    data_ini date,
    data_fim date,
    gate_valor_meta double precision,
    escopo character varying(20) DEFAULT 'VENDEDOR'::character varying NOT NULL,
    faturamento_minimo double precision DEFAULT 70000,
    margem_minima double precision,
    teto_faturamento double precision,
    teto_bonus_percentual double precision
);


--
-- Name: metas_programas_emps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_programas_emps (
    id bigint NOT NULL,
    meta_id bigint NOT NULL,
    emp character varying(30) NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    criado_em timestamp without time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp without time zone,
    removido_em timestamp without time zone
);


--
-- Name: metas_programas_emps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_programas_emps_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_programas_emps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_programas_emps_id_seq OWNED BY public.metas_programas_emps.id;


--
-- Name: metas_programas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_programas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_programas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_programas_id_seq OWNED BY public.metas_programas.id;


--
-- Name: metas_recompensas_itens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_recompensas_itens (
    id integer NOT NULL,
    meta_id integer NOT NULL,
    ordem integer DEFAULT 0 NOT NULL,
    mestre character varying(60),
    marca character varying(120),
    produto_like character varying(200),
    recompensa_por_un double precision DEFAULT 0 NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: metas_recompensas_itens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_recompensas_itens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_recompensas_itens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_recompensas_itens_id_seq OWNED BY public.metas_recompensas_itens.id;


--
-- Name: metas_recompensas_loja_itens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_recompensas_loja_itens (
    id integer NOT NULL,
    emp character varying(30) NOT NULL,
    ordem integer DEFAULT 0 NOT NULL,
    mestre character varying(60),
    marca character varying(120),
    produto_like character varying(200),
    recompensa_por_un double precision DEFAULT 0 NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    produto_terms character varying(200),
    recompensa_un numeric(14,4) DEFAULT 0 NOT NULL
);


--
-- Name: metas_recompensas_loja_itens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_recompensas_loja_itens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_recompensas_loja_itens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_recompensas_loja_itens_id_seq OWNED BY public.metas_recompensas_loja_itens.id;


--
-- Name: metas_resultados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_resultados (
    id bigint NOT NULL,
    meta_id bigint NOT NULL,
    emp character varying(30) NOT NULL,
    vendedor character varying(80) NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    valor_mes numeric(18,2) DEFAULT 0 NOT NULL,
    base_valor numeric(18,2),
    crescimento_pct double precision,
    mix_itens_unicos double precision,
    share_pct double precision,
    valor_marcas numeric(18,2),
    bonus_percentual double precision DEFAULT 0 NOT NULL,
    premio numeric(18,2) DEFAULT 0 NOT NULL,
    calculado_em timestamp with time zone DEFAULT now() NOT NULL,
    detalhes_json text,
    margem_percentual double precision,
    margem_minima double precision,
    margem_atingida boolean,
    bloqueado_margem boolean DEFAULT false NOT NULL
);


--
-- Name: metas_resultados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_resultados_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_resultados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_resultados_id_seq OWNED BY public.metas_resultados.id;


--
-- Name: metas_v2_criterios; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_v2_criterios (
    id bigint NOT NULL,
    programa_id bigint NOT NULL,
    tipo text NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    params jsonb DEFAULT '{}'::jsonb NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: metas_v2_criterios_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_v2_criterios_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_v2_criterios_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_v2_criterios_id_seq OWNED BY public.metas_v2_criterios.id;


--
-- Name: metas_v2_faixas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_v2_faixas (
    id bigint NOT NULL,
    criterio_id bigint NOT NULL,
    limite numeric(14,4) NOT NULL,
    recompensa_pct numeric(10,4) NOT NULL,
    ordem integer DEFAULT 0 NOT NULL
);


--
-- Name: metas_v2_faixas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_v2_faixas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_v2_faixas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_v2_faixas_id_seq OWNED BY public.metas_v2_faixas.id;


--
-- Name: metas_v2_programa_emps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_v2_programa_emps (
    programa_id bigint NOT NULL,
    emp text NOT NULL
);


--
-- Name: metas_v2_programas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_v2_programas (
    id bigint NOT NULL,
    nome text NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    baseline_tipo text DEFAULT 'ano_passado'::text NOT NULL,
    baseline_janela_meses integer DEFAULT 3 NOT NULL,
    gate_itens_parados_enabled boolean DEFAULT false NOT NULL,
    gate_itens_parados_min_valor numeric(14,2) DEFAULT 0 NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    atualizado_em timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: metas_v2_programas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_v2_programas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_v2_programas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_v2_programas_id_seq OWNED BY public.metas_v2_programas.id;


--
-- Name: metas_v2_resultados; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metas_v2_resultados (
    id bigint NOT NULL,
    programa_id bigint NOT NULL,
    emp text NOT NULL,
    vendedor text NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    valor_liquido numeric(14,2) DEFAULT 0 NOT NULL,
    itens_parados_valor numeric(14,2) DEFAULT 0 NOT NULL,
    crescimento_base numeric(14,2),
    crescimento_atual_ref numeric(14,2),
    crescimento_pct numeric(10,4),
    mix_produtos integer,
    pct_total numeric(10,4) DEFAULT 0 NOT NULL,
    valor_premio numeric(14,2) DEFAULT 0 NOT NULL,
    breakdown jsonb DEFAULT '{}'::jsonb NOT NULL,
    criado_em timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: metas_v2_resultados_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.metas_v2_resultados_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metas_v2_resultados_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.metas_v2_resultados_id_seq OWNED BY public.metas_v2_resultados.id;


--
-- Name: pagamentos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pagamentos (
    id bigint NOT NULL,
    origem text DEFAULT 'CAMPANHA'::text NOT NULL,
    campanha_id bigint,
    competencia_ano integer NOT NULL,
    competencia_mes integer NOT NULL,
    emp integer NOT NULL,
    vendedor text NOT NULL,
    valor numeric(14,2) NOT NULL,
    status text DEFAULT 'PENDENTE'::text NOT NULL,
    pago_em timestamp with time zone,
    comprovante_url text,
    observacao text,
    alterado_por_usuario_id bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: pagamentos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.pagamentos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: pagamentos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.pagamentos_id_seq OWNED BY public.pagamentos.id;


--
-- Name: produto_custo; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.produto_custo (
    id bigint NOT NULL,
    mestre text NOT NULL,
    custo_unit numeric(14,4) NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: produto_custo_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.produto_custo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: produto_custo_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.produto_custo_id_seq OWNED BY public.produto_custo.id;


--
-- Name: produto_margem_padrao; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.produto_margem_padrao (
    id bigint NOT NULL,
    mestre text NOT NULL,
    margem_padrao_pct numeric(7,3) NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: produto_margem_padrao_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.produto_margem_padrao_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: produto_margem_padrao_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.produto_margem_padrao_id_seq OWNED BY public.produto_margem_padrao.id;


--
-- Name: produtos_custos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.produtos_custos (
    id bigint NOT NULL,
    emp integer,
    mestre text NOT NULL,
    custo_unitario numeric(14,4) NOT NULL,
    vigencia_inicio date,
    vigencia_fim date,
    ativo boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: produtos_custos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.produtos_custos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: produtos_custos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.produtos_custos_id_seq OWNED BY public.produtos_custos.id;


--
-- Name: usuario_emp_backup; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usuario_emp_backup (
    id integer,
    usuario_id integer,
    emp character varying(30),
    ativo boolean,
    criado_em timestamp without time zone
);


--
-- Name: usuario_emps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usuario_emps (
    id bigint NOT NULL,
    usuario_id bigint NOT NULL,
    emp text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ativo boolean DEFAULT true
);


--
-- Name: usuario_emps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.usuario_emps_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: usuario_emps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.usuario_emps_id_seq OWNED BY public.usuario_emps.id;


--
-- Name: usuarios; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usuarios (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    senha_hash character varying(255) NOT NULL,
    role character varying(20) DEFAULT 'vendedor'::character varying NOT NULL,
    emp text
);


--
-- Name: usuarios_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.usuarios_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: usuarios_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.usuarios_id_seq OWNED BY public.usuarios.id;


--
-- Name: vendas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vendas (
    id integer NOT NULL,
    mestre character varying(120),
    marca character varying(120),
    vendedor character varying(80) NOT NULL,
    movimento date NOT NULL,
    mov_tipo_movto character varying(5) NOT NULL,
    qtdade_vendida numeric(18,3),
    valor_total numeric(18,2) NOT NULL,
    nota text,
    emp text,
    unit numeric(18,4),
    des numeric(18,4),
    descricao text,
    razao text,
    cidade text,
    cnpj_cpf text,
    descricao_norm text,
    razao_norm text,
    cidade_norm text,
    cliente_id_norm text,
    ano integer GENERATED ALWAYS AS ((EXTRACT(year FROM movimento))::integer) STORED,
    mes integer GENERATED ALWAYS AS ((EXTRACT(month FROM movimento))::integer) STORED
);


--
-- Name: vendas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vendas_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vendas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vendas_id_seq OWNED BY public.vendas.id;


--
-- Name: vendas_resumo_periodo; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vendas_resumo_periodo (
    id bigint NOT NULL,
    emp text DEFAULT ''::text NOT NULL,
    vendedor character varying NOT NULL,
    ano integer NOT NULL,
    mes integer NOT NULL,
    valor_venda numeric(18,2) DEFAULT 0 NOT NULL,
    mix_produtos integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone
);


--
-- Name: vendas_resumo_periodo_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vendas_resumo_periodo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vendas_resumo_periodo_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vendas_resumo_periodo_id_seq OWNED BY public.vendas_resumo_periodo.id;


--
-- Name: messages; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    binary_payload bytea
)
PARTITION BY RANGE (inserted_at);


--
-- Name: schema_migrations; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.schema_migrations (
    version bigint NOT NULL,
    inserted_at timestamp(0) without time zone
);


--
-- Name: subscription; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.subscription (
    id bigint NOT NULL,
    subscription_id uuid NOT NULL,
    entity regclass NOT NULL,
    filters realtime.user_defined_filter[] DEFAULT '{}'::realtime.user_defined_filter[] NOT NULL,
    claims jsonb NOT NULL,
    claims_role regrole GENERATED ALWAYS AS (realtime.to_regrole((claims ->> 'role'::text))) STORED NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    action_filter text DEFAULT '*'::text,
    selected_columns text[],
    CONSTRAINT subscription_action_filter_check CHECK ((action_filter = ANY (ARRAY['*'::text, 'INSERT'::text, 'UPDATE'::text, 'DELETE'::text])))
);


--
-- Name: subscription_id_seq; Type: SEQUENCE; Schema: realtime; Owner: -
--

ALTER TABLE realtime.subscription ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME realtime.subscription_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: buckets; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.buckets (
    id text NOT NULL,
    name text NOT NULL,
    owner uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    public boolean DEFAULT false,
    avif_autodetection boolean DEFAULT false,
    file_size_limit bigint,
    allowed_mime_types text[],
    owner_id text,
    type storage.buckettype DEFAULT 'STANDARD'::storage.buckettype NOT NULL
);


--
-- Name: COLUMN buckets.owner; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN storage.buckets.owner IS 'Field is deprecated, use owner_id instead';


--
-- Name: buckets_analytics; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.buckets_analytics (
    name text NOT NULL,
    type storage.buckettype DEFAULT 'ANALYTICS'::storage.buckettype NOT NULL,
    format text DEFAULT 'ICEBERG'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: buckets_vectors; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.buckets_vectors (
    id text NOT NULL,
    type storage.buckettype DEFAULT 'VECTOR'::storage.buckettype NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: migrations; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.migrations (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    hash character varying(40) NOT NULL,
    executed_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: objects; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.objects (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    bucket_id text,
    name text,
    owner uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_accessed_at timestamp with time zone DEFAULT now(),
    metadata jsonb,
    path_tokens text[] GENERATED ALWAYS AS (string_to_array(name, '/'::text)) STORED,
    version text,
    owner_id text,
    user_metadata jsonb
);


--
-- Name: COLUMN objects.owner; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN storage.objects.owner IS 'Field is deprecated, use owner_id instead';


--
-- Name: s3_multipart_uploads; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.s3_multipart_uploads (
    id text NOT NULL,
    in_progress_size bigint DEFAULT 0 NOT NULL,
    upload_signature text NOT NULL,
    bucket_id text NOT NULL,
    key text NOT NULL COLLATE pg_catalog."C",
    version text NOT NULL,
    owner_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_metadata jsonb,
    metadata jsonb
);


--
-- Name: s3_multipart_uploads_parts; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.s3_multipart_uploads_parts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    upload_id text NOT NULL,
    size bigint DEFAULT 0 NOT NULL,
    part_number integer NOT NULL,
    bucket_id text NOT NULL,
    key text NOT NULL COLLATE pg_catalog."C",
    etag text NOT NULL,
    owner_id text,
    version text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vector_indexes; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.vector_indexes (
    id text DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL COLLATE pg_catalog."C",
    bucket_id text NOT NULL,
    data_type text NOT NULL,
    dimension integer NOT NULL,
    distance_metric text NOT NULL,
    metadata_configuration jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: refresh_tokens id; Type: DEFAULT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens ALTER COLUMN id SET DEFAULT nextval('auth.refresh_tokens_id_seq'::regclass);


--
-- Name: app_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_settings ALTER COLUMN id SET DEFAULT nextval('public.app_settings_id_seq'::regclass);


--
-- Name: branding_themes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.branding_themes ALTER COLUMN id SET DEFAULT nextval('public.branding_themes_id_seq'::regclass);


--
-- Name: cache_cidades_emp id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cache_cidades_emp ALTER COLUMN id SET DEFAULT nextval('public.cache_cidades_emp_id_seq'::regclass);


--
-- Name: cache_cliente_marcas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cache_cliente_marcas ALTER COLUMN id SET DEFAULT nextval('public.cache_cliente_marcas_id_seq'::regclass);


--
-- Name: cache_clientes_emp id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cache_clientes_emp ALTER COLUMN id SET DEFAULT nextval('public.cache_clientes_emp_id_seq'::regclass);


--
-- Name: campanhas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas ALTER COLUMN id SET DEFAULT nextval('public.campanhas_id_seq'::regclass);


--
-- Name: campanhas_audit_v2 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_audit_v2 ALTER COLUMN id SET DEFAULT nextval('public.campanhas_audit_v2_id_seq'::regclass);


--
-- Name: campanhas_combo id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_combo ALTER COLUMN id SET DEFAULT nextval('public.campanhas_combo_id_seq'::regclass);


--
-- Name: campanhas_combo_itens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_combo_itens ALTER COLUMN id SET DEFAULT nextval('public.campanhas_combo_itens_id_seq'::regclass);


--
-- Name: campanhas_combo_resultados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_combo_resultados ALTER COLUMN id SET DEFAULT nextval('public.campanhas_combo_resultados_id_seq'::regclass);


--
-- Name: campanhas_emps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_emps ALTER COLUMN id SET DEFAULT nextval('public.campanhas_emps_id_seq'::regclass);


--
-- Name: campanhas_master_v2 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_master_v2 ALTER COLUMN id SET DEFAULT nextval('public.campanhas_master_v2_id_seq'::regclass);


--
-- Name: campanhas_qtd id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_qtd ALTER COLUMN id SET DEFAULT nextval('public.campanhas_qtd_id_seq'::regclass);


--
-- Name: campanhas_qtd_resultados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_qtd_resultados ALTER COLUMN id SET DEFAULT nextval('public.campanhas_qtd_resultados_id_seq'::regclass);


--
-- Name: campanhas_ranking_marca id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca ALTER COLUMN id SET DEFAULT nextval('public.campanhas_ranking_marca_id_seq'::regclass);


--
-- Name: campanhas_ranking_marca_emps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca_emps ALTER COLUMN id SET DEFAULT nextval('public.campanhas_ranking_marca_emps_id_seq'::regclass);


--
-- Name: campanhas_ranking_marca_premios id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca_premios ALTER COLUMN id SET DEFAULT nextval('public.campanhas_ranking_marca_premios_id_seq'::regclass);


--
-- Name: campanhas_ranking_marca_resultados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca_resultados ALTER COLUMN id SET DEFAULT nextval('public.campanhas_ranking_marca_resultados_id_seq'::regclass);


--
-- Name: campanhas_resultados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_resultados ALTER COLUMN id SET DEFAULT nextval('public.campanhas_resultados_id_seq'::regclass);


--
-- Name: campanhas_resultados_v2 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_resultados_v2 ALTER COLUMN id SET DEFAULT nextval('public.campanhas_resultados_v2_id_seq'::regclass);


--
-- Name: campanhas_scope_emp_v2 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_scope_emp_v2 ALTER COLUMN id SET DEFAULT nextval('public.campanhas_scope_emp_v2_id_seq'::regclass);


--
-- Name: campanhas_v2_master id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_v2_master ALTER COLUMN id SET DEFAULT nextval('public.campanhas_v2_master_id_seq'::regclass);


--
-- Name: campanhas_v2_resultados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_v2_resultados ALTER COLUMN id SET DEFAULT nextval('public.campanhas_v2_resultados_id_seq'::regclass);


--
-- Name: dashboard_cache id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dashboard_cache ALTER COLUMN id SET DEFAULT nextval('public.dashboard_cache_id_seq'::regclass);


--
-- Name: emps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.emps ALTER COLUMN id SET DEFAULT nextval('public.emps_id_seq'::regclass);


--
-- Name: fechamento_mensal id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fechamento_mensal ALTER COLUMN id SET DEFAULT nextval('public.fechamento_mensal_id_seq'::regclass);


--
-- Name: fechamento_mensal_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fechamento_mensal_audit ALTER COLUMN id SET DEFAULT nextval('public.fechamento_mensal_audit_id_seq'::regclass);


--
-- Name: financeiro_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.financeiro_audit ALTER COLUMN id SET DEFAULT nextval('public.financeiro_audit_id_seq'::regclass);


--
-- Name: financeiro_pagamentos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.financeiro_pagamentos ALTER COLUMN id SET DEFAULT nextval('public.financeiro_pagamentos_id_seq'::regclass);


--
-- Name: financeiro_pagamentos_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.financeiro_pagamentos_audit ALTER COLUMN id SET DEFAULT nextval('public.financeiro_pagamentos_audit_id_seq'::regclass);


--
-- Name: importacoes_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.importacoes_log ALTER COLUMN id SET DEFAULT nextval('public.importacoes_log_id_seq'::regclass);


--
-- Name: itens_parados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados ALTER COLUMN id SET DEFAULT nextval('public.itens_parados_id_seq'::regclass);


--
-- Name: itens_parados_fechamentos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_fechamentos ALTER COLUMN id SET DEFAULT nextval('public.itens_parados_fechamentos_id_seq'::regclass);


--
-- Name: itens_parados_pontos_bonus id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_bonus ALTER COLUMN id SET DEFAULT nextval('public.itens_parados_pontos_bonus_id_seq'::regclass);


--
-- Name: itens_parados_pontos_bonus_faixas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_bonus_faixas ALTER COLUMN id SET DEFAULT nextval('public.itens_parados_pontos_bonus_faixas_id_seq'::regclass);


--
-- Name: itens_parados_pontos_config id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_config ALTER COLUMN id SET DEFAULT nextval('public.itens_parados_pontos_config_id_seq'::regclass);


--
-- Name: itens_parados_pontos_fechamentos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_fechamentos ALTER COLUMN id SET DEFAULT nextval('public.itens_parados_pontos_fechamentos_id_seq'::regclass);


--
-- Name: itens_parados_pontos_resultados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_resultados ALTER COLUMN id SET DEFAULT nextval('public.itens_parados_pontos_resultados_id_seq'::regclass);


--
-- Name: itens_parados_resultados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_resultados ALTER COLUMN id SET DEFAULT nextval('public.itens_parados_resultados_id_seq'::regclass);


--
-- Name: margem_vendedor_periodo id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.margem_vendedor_periodo ALTER COLUMN id SET DEFAULT nextval('public.margem_vendedor_periodo_id_seq'::regclass);


--
-- Name: mensagem_empresas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_empresas ALTER COLUMN id SET DEFAULT nextval('public.mensagem_empresas_id_seq'::regclass);


--
-- Name: mensagem_lidas_diarias id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_lidas_diarias ALTER COLUMN id SET DEFAULT nextval('public.mensagem_lidas_diarias_id_seq'::regclass);


--
-- Name: mensagem_usuarios id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_usuarios ALTER COLUMN id SET DEFAULT nextval('public.mensagem_usuarios_id_seq'::regclass);


--
-- Name: mensagens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagens ALTER COLUMN id SET DEFAULT nextval('public.mensagens_id_seq'::regclass);


--
-- Name: metas_bases_manuais id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_bases_manuais ALTER COLUMN id SET DEFAULT nextval('public.metas_bases_manuais_id_seq'::regclass);


--
-- Name: metas_escalas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_escalas ALTER COLUMN id SET DEFAULT nextval('public.metas_escalas_id_seq'::regclass);


--
-- Name: metas_gate_vendedor_emp id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_gate_vendedor_emp ALTER COLUMN id SET DEFAULT nextval('public.metas_gate_vendedor_emp_id_seq'::regclass);


--
-- Name: metas_marcas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_marcas ALTER COLUMN id SET DEFAULT nextval('public.metas_marcas_id_seq'::regclass);


--
-- Name: metas_margens_vendedores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_margens_vendedores ALTER COLUMN id SET DEFAULT nextval('public.metas_margens_vendedores_id_seq'::regclass);


--
-- Name: metas_programas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_programas ALTER COLUMN id SET DEFAULT nextval('public.metas_programas_id_seq'::regclass);


--
-- Name: metas_programas_emps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_programas_emps ALTER COLUMN id SET DEFAULT nextval('public.metas_programas_emps_id_seq'::regclass);


--
-- Name: metas_recompensas_itens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_recompensas_itens ALTER COLUMN id SET DEFAULT nextval('public.metas_recompensas_itens_id_seq'::regclass);


--
-- Name: metas_recompensas_loja_itens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_recompensas_loja_itens ALTER COLUMN id SET DEFAULT nextval('public.metas_recompensas_loja_itens_id_seq'::regclass);


--
-- Name: metas_resultados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_resultados ALTER COLUMN id SET DEFAULT nextval('public.metas_resultados_id_seq'::regclass);


--
-- Name: metas_v2_criterios id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_criterios ALTER COLUMN id SET DEFAULT nextval('public.metas_v2_criterios_id_seq'::regclass);


--
-- Name: metas_v2_faixas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_faixas ALTER COLUMN id SET DEFAULT nextval('public.metas_v2_faixas_id_seq'::regclass);


--
-- Name: metas_v2_programas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_programas ALTER COLUMN id SET DEFAULT nextval('public.metas_v2_programas_id_seq'::regclass);


--
-- Name: metas_v2_resultados id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_resultados ALTER COLUMN id SET DEFAULT nextval('public.metas_v2_resultados_id_seq'::regclass);


--
-- Name: pagamentos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pagamentos ALTER COLUMN id SET DEFAULT nextval('public.pagamentos_id_seq'::regclass);


--
-- Name: produto_custo id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.produto_custo ALTER COLUMN id SET DEFAULT nextval('public.produto_custo_id_seq'::regclass);


--
-- Name: produto_margem_padrao id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.produto_margem_padrao ALTER COLUMN id SET DEFAULT nextval('public.produto_margem_padrao_id_seq'::regclass);


--
-- Name: produtos_custos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.produtos_custos ALTER COLUMN id SET DEFAULT nextval('public.produtos_custos_id_seq'::regclass);


--
-- Name: usuario_emps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuario_emps ALTER COLUMN id SET DEFAULT nextval('public.usuario_emps_id_seq'::regclass);


--
-- Name: usuarios id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuarios ALTER COLUMN id SET DEFAULT nextval('public.usuarios_id_seq'::regclass);


--
-- Name: vendas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vendas ALTER COLUMN id SET DEFAULT nextval('public.vendas_id_seq'::regclass);


--
-- Name: vendas_resumo_periodo id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vendas_resumo_periodo ALTER COLUMN id SET DEFAULT nextval('public.vendas_resumo_periodo_id_seq'::regclass);


--
-- Name: mfa_amr_claims amr_id_pk; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT amr_id_pk PRIMARY KEY (id);


--
-- Name: audit_log_entries audit_log_entries_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.audit_log_entries
    ADD CONSTRAINT audit_log_entries_pkey PRIMARY KEY (id);


--
-- Name: custom_oauth_providers custom_oauth_providers_identifier_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.custom_oauth_providers
    ADD CONSTRAINT custom_oauth_providers_identifier_key UNIQUE (identifier);


--
-- Name: custom_oauth_providers custom_oauth_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.custom_oauth_providers
    ADD CONSTRAINT custom_oauth_providers_pkey PRIMARY KEY (id);


--
-- Name: flow_state flow_state_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.flow_state
    ADD CONSTRAINT flow_state_pkey PRIMARY KEY (id);


--
-- Name: identities identities_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_pkey PRIMARY KEY (id);


--
-- Name: identities identities_provider_id_provider_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_provider_id_provider_unique UNIQUE (provider_id, provider);


--
-- Name: instances instances_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.instances
    ADD CONSTRAINT instances_pkey PRIMARY KEY (id);


--
-- Name: mfa_amr_claims mfa_amr_claims_session_id_authentication_method_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT mfa_amr_claims_session_id_authentication_method_pkey UNIQUE (session_id, authentication_method);


--
-- Name: mfa_challenges mfa_challenges_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_challenges
    ADD CONSTRAINT mfa_challenges_pkey PRIMARY KEY (id);


--
-- Name: mfa_factors mfa_factors_last_challenged_at_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT mfa_factors_last_challenged_at_key UNIQUE (last_challenged_at);


--
-- Name: mfa_factors mfa_factors_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT mfa_factors_pkey PRIMARY KEY (id);


--
-- Name: oauth_authorizations oauth_authorizations_authorization_code_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_authorization_code_key UNIQUE (authorization_code);


--
-- Name: oauth_authorizations oauth_authorizations_authorization_id_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_authorization_id_key UNIQUE (authorization_id);


--
-- Name: oauth_authorizations oauth_authorizations_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_pkey PRIMARY KEY (id);


--
-- Name: oauth_client_states oauth_client_states_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_client_states
    ADD CONSTRAINT oauth_client_states_pkey PRIMARY KEY (id);


--
-- Name: oauth_clients oauth_clients_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (id);


--
-- Name: oauth_consents oauth_consents_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_consents
    ADD CONSTRAINT oauth_consents_pkey PRIMARY KEY (id);


--
-- Name: oauth_consents oauth_consents_user_client_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_consents
    ADD CONSTRAINT oauth_consents_user_client_unique UNIQUE (user_id, client_id);


--
-- Name: one_time_tokens one_time_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.one_time_tokens
    ADD CONSTRAINT one_time_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_token_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_unique UNIQUE (token);


--
-- Name: saml_providers saml_providers_entity_id_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_entity_id_key UNIQUE (entity_id);


--
-- Name: saml_providers saml_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_pkey PRIMARY KEY (id);


--
-- Name: saml_relay_states saml_relay_states_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sso_domains sso_domains_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_domains
    ADD CONSTRAINT sso_domains_pkey PRIMARY KEY (id);


--
-- Name: sso_providers sso_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_providers
    ADD CONSTRAINT sso_providers_pkey PRIMARY KEY (id);


--
-- Name: users users_phone_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.users
    ADD CONSTRAINT users_phone_key UNIQUE (phone);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: webauthn_challenges webauthn_challenges_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.webauthn_challenges
    ADD CONSTRAINT webauthn_challenges_pkey PRIMARY KEY (id);


--
-- Name: webauthn_credentials webauthn_credentials_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (id);


--
-- Name: app_settings app_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_settings
    ADD CONSTRAINT app_settings_pkey PRIMARY KEY (id);


--
-- Name: branding_themes branding_themes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.branding_themes
    ADD CONSTRAINT branding_themes_pkey PRIMARY KEY (id);


--
-- Name: cache_cidades_emp cache_cidades_emp_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cache_cidades_emp
    ADD CONSTRAINT cache_cidades_emp_pkey PRIMARY KEY (id);


--
-- Name: cache_cliente_marcas cache_cliente_marcas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cache_cliente_marcas
    ADD CONSTRAINT cache_cliente_marcas_pkey PRIMARY KEY (id);


--
-- Name: cache_clientes_emp cache_clientes_emp_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cache_clientes_emp
    ADD CONSTRAINT cache_clientes_emp_pkey PRIMARY KEY (id);


--
-- Name: campanhas_audit_v2 campanhas_audit_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_audit_v2
    ADD CONSTRAINT campanhas_audit_v2_pkey PRIMARY KEY (id);


--
-- Name: campanhas_combo_itens campanhas_combo_itens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_combo_itens
    ADD CONSTRAINT campanhas_combo_itens_pkey PRIMARY KEY (id);


--
-- Name: campanhas_combo campanhas_combo_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_combo
    ADD CONSTRAINT campanhas_combo_pkey PRIMARY KEY (id);


--
-- Name: campanhas_combo_resultados campanhas_combo_resultados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_combo_resultados
    ADD CONSTRAINT campanhas_combo_resultados_pkey PRIMARY KEY (id);


--
-- Name: campanhas_emps campanhas_emps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_emps
    ADD CONSTRAINT campanhas_emps_pkey PRIMARY KEY (id);


--
-- Name: campanhas_master_v2 campanhas_master_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_master_v2
    ADD CONSTRAINT campanhas_master_v2_pkey PRIMARY KEY (id);


--
-- Name: campanhas campanhas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas
    ADD CONSTRAINT campanhas_pkey PRIMARY KEY (id);


--
-- Name: campanhas_qtd campanhas_qtd_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_qtd
    ADD CONSTRAINT campanhas_qtd_pkey PRIMARY KEY (id);


--
-- Name: campanhas_qtd_resultados campanhas_qtd_resultados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_qtd_resultados
    ADD CONSTRAINT campanhas_qtd_resultados_pkey PRIMARY KEY (id);


--
-- Name: campanhas_ranking_marca_emps campanhas_ranking_marca_emps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca_emps
    ADD CONSTRAINT campanhas_ranking_marca_emps_pkey PRIMARY KEY (id);


--
-- Name: campanhas_ranking_marca campanhas_ranking_marca_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca
    ADD CONSTRAINT campanhas_ranking_marca_pkey PRIMARY KEY (id);


--
-- Name: campanhas_ranking_marca_premios campanhas_ranking_marca_premios_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca_premios
    ADD CONSTRAINT campanhas_ranking_marca_premios_pkey PRIMARY KEY (id);


--
-- Name: campanhas_ranking_marca_resultados campanhas_ranking_marca_resultados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca_resultados
    ADD CONSTRAINT campanhas_ranking_marca_resultados_pkey PRIMARY KEY (id);


--
-- Name: campanhas_resultados campanhas_resultados_campanha_id_competencia_ano_competenci_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_resultados
    ADD CONSTRAINT campanhas_resultados_campanha_id_competencia_ano_competenci_key UNIQUE (campanha_id, competencia_ano, competencia_mes, emp, vendedor);


--
-- Name: campanhas_resultados campanhas_resultados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_resultados
    ADD CONSTRAINT campanhas_resultados_pkey PRIMARY KEY (id);


--
-- Name: campanhas_resultados_v2 campanhas_resultados_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_resultados_v2
    ADD CONSTRAINT campanhas_resultados_v2_pkey PRIMARY KEY (id);


--
-- Name: campanhas_scope_emp_v2 campanhas_scope_emp_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_scope_emp_v2
    ADD CONSTRAINT campanhas_scope_emp_v2_pkey PRIMARY KEY (id);


--
-- Name: campanhas_v2_master campanhas_v2_master_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_v2_master
    ADD CONSTRAINT campanhas_v2_master_pkey PRIMARY KEY (id);


--
-- Name: campanhas_v2_resultados campanhas_v2_resultados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_v2_resultados
    ADD CONSTRAINT campanhas_v2_resultados_pkey PRIMARY KEY (id);


--
-- Name: dashboard_cache dashboard_cache_pk; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dashboard_cache
    ADD CONSTRAINT dashboard_cache_pk PRIMARY KEY (emp, vendedor, ano, mes);


--
-- Name: emps emps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.emps
    ADD CONSTRAINT emps_pkey PRIMARY KEY (id);


--
-- Name: fechamento_mensal_audit fechamento_mensal_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fechamento_mensal_audit
    ADD CONSTRAINT fechamento_mensal_audit_pkey PRIMARY KEY (id);


--
-- Name: fechamento_mensal fechamento_mensal_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fechamento_mensal
    ADD CONSTRAINT fechamento_mensal_pkey PRIMARY KEY (id);


--
-- Name: financeiro_audit financeiro_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.financeiro_audit
    ADD CONSTRAINT financeiro_audit_pkey PRIMARY KEY (id);


--
-- Name: financeiro_pagamentos_audit financeiro_pagamentos_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.financeiro_pagamentos_audit
    ADD CONSTRAINT financeiro_pagamentos_audit_pkey PRIMARY KEY (id);


--
-- Name: financeiro_pagamentos financeiro_pagamentos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.financeiro_pagamentos
    ADD CONSTRAINT financeiro_pagamentos_pkey PRIMARY KEY (id);


--
-- Name: importacoes_log importacoes_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.importacoes_log
    ADD CONSTRAINT importacoes_log_pkey PRIMARY KEY (id);


--
-- Name: insights_fechamento insights_fechamento_pk; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.insights_fechamento
    ADD CONSTRAINT insights_fechamento_pk PRIMARY KEY (emp, ano, mes, cidade_norm);


--
-- Name: insights_parciais insights_parciais_pk; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.insights_parciais
    ADD CONSTRAINT insights_parciais_pk PRIMARY KEY (emp, ano, mes, cidade_norm);


--
-- Name: itens_parados_fechamentos itens_parados_fechamentos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_fechamentos
    ADD CONSTRAINT itens_parados_fechamentos_pkey PRIMARY KEY (id);


--
-- Name: itens_parados itens_parados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados
    ADD CONSTRAINT itens_parados_pkey PRIMARY KEY (id);


--
-- Name: itens_parados_pontos_bonus_faixas itens_parados_pontos_bonus_faixas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_bonus_faixas
    ADD CONSTRAINT itens_parados_pontos_bonus_faixas_pkey PRIMARY KEY (id);


--
-- Name: itens_parados_pontos_bonus itens_parados_pontos_bonus_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_bonus
    ADD CONSTRAINT itens_parados_pontos_bonus_pkey PRIMARY KEY (id);


--
-- Name: itens_parados_pontos_config itens_parados_pontos_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_config
    ADD CONSTRAINT itens_parados_pontos_config_pkey PRIMARY KEY (id);


--
-- Name: itens_parados_pontos_fechamentos itens_parados_pontos_fechamentos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_fechamentos
    ADD CONSTRAINT itens_parados_pontos_fechamentos_pkey PRIMARY KEY (id);


--
-- Name: itens_parados_pontos_resultados itens_parados_pontos_resultados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_resultados
    ADD CONSTRAINT itens_parados_pontos_resultados_pkey PRIMARY KEY (id);


--
-- Name: itens_parados_resultados itens_parados_resultados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_resultados
    ADD CONSTRAINT itens_parados_resultados_pkey PRIMARY KEY (id);


--
-- Name: margem_vendedor_periodo margem_vendedor_periodo_competencia_ano_competencia_mes_emp_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.margem_vendedor_periodo
    ADD CONSTRAINT margem_vendedor_periodo_competencia_ano_competencia_mes_emp_key UNIQUE (competencia_ano, competencia_mes, emp, vendedor);


--
-- Name: margem_vendedor_periodo margem_vendedor_periodo_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.margem_vendedor_periodo
    ADD CONSTRAINT margem_vendedor_periodo_pkey PRIMARY KEY (id);


--
-- Name: mensagem_empresas mensagem_empresas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_empresas
    ADD CONSTRAINT mensagem_empresas_pkey PRIMARY KEY (id);


--
-- Name: mensagem_lidas_diarias mensagem_lidas_diarias_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_lidas_diarias
    ADD CONSTRAINT mensagem_lidas_diarias_pkey PRIMARY KEY (id);


--
-- Name: mensagem_usuarios mensagem_usuarios_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_usuarios
    ADD CONSTRAINT mensagem_usuarios_pkey PRIMARY KEY (id);


--
-- Name: mensagens mensagens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagens
    ADD CONSTRAINT mensagens_pkey PRIMARY KEY (id);


--
-- Name: metas_bases_manuais metas_bases_manuais_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_bases_manuais
    ADD CONSTRAINT metas_bases_manuais_pkey PRIMARY KEY (id);


--
-- Name: metas_escalas metas_escalas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_escalas
    ADD CONSTRAINT metas_escalas_pkey PRIMARY KEY (id);


--
-- Name: metas_gate_vendedor_emp metas_gate_vendedor_emp_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_gate_vendedor_emp
    ADD CONSTRAINT metas_gate_vendedor_emp_pkey PRIMARY KEY (id);


--
-- Name: metas_marcas metas_marcas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_marcas
    ADD CONSTRAINT metas_marcas_pkey PRIMARY KEY (id);


--
-- Name: metas_margens_vendedores metas_margens_vendedores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_margens_vendedores
    ADD CONSTRAINT metas_margens_vendedores_pkey PRIMARY KEY (id);


--
-- Name: metas_programas_emps metas_programas_emps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_programas_emps
    ADD CONSTRAINT metas_programas_emps_pkey PRIMARY KEY (id);


--
-- Name: metas_programas metas_programas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_programas
    ADD CONSTRAINT metas_programas_pkey PRIMARY KEY (id);


--
-- Name: metas_recompensas_itens metas_recompensas_itens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_recompensas_itens
    ADD CONSTRAINT metas_recompensas_itens_pkey PRIMARY KEY (id);


--
-- Name: metas_recompensas_loja_itens metas_recompensas_loja_itens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_recompensas_loja_itens
    ADD CONSTRAINT metas_recompensas_loja_itens_pkey PRIMARY KEY (id);


--
-- Name: metas_resultados metas_resultados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_resultados
    ADD CONSTRAINT metas_resultados_pkey PRIMARY KEY (id);


--
-- Name: metas_v2_criterios metas_v2_criterios_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_criterios
    ADD CONSTRAINT metas_v2_criterios_pkey PRIMARY KEY (id);


--
-- Name: metas_v2_faixas metas_v2_faixas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_faixas
    ADD CONSTRAINT metas_v2_faixas_pkey PRIMARY KEY (id);


--
-- Name: metas_v2_programa_emps metas_v2_programa_emps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_programa_emps
    ADD CONSTRAINT metas_v2_programa_emps_pkey PRIMARY KEY (programa_id, emp);


--
-- Name: metas_v2_programas metas_v2_programas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_programas
    ADD CONSTRAINT metas_v2_programas_pkey PRIMARY KEY (id);


--
-- Name: metas_v2_resultados metas_v2_resultados_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_resultados
    ADD CONSTRAINT metas_v2_resultados_pkey PRIMARY KEY (id);


--
-- Name: metas_v2_resultados metas_v2_resultados_programa_id_emp_vendedor_ano_mes_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_resultados
    ADD CONSTRAINT metas_v2_resultados_programa_id_emp_vendedor_ano_mes_key UNIQUE (programa_id, emp, vendedor, ano, mes);


--
-- Name: pagamentos pagamentos_origem_campanha_id_competencia_ano_competencia_m_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pagamentos
    ADD CONSTRAINT pagamentos_origem_campanha_id_competencia_ano_competencia_m_key UNIQUE (origem, campanha_id, competencia_ano, competencia_mes, emp, vendedor);


--
-- Name: pagamentos pagamentos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pagamentos
    ADD CONSTRAINT pagamentos_pkey PRIMARY KEY (id);


--
-- Name: produto_custo produto_custo_mestre_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.produto_custo
    ADD CONSTRAINT produto_custo_mestre_key UNIQUE (mestre);


--
-- Name: produto_custo produto_custo_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.produto_custo
    ADD CONSTRAINT produto_custo_pkey PRIMARY KEY (id);


--
-- Name: produto_margem_padrao produto_margem_padrao_mestre_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.produto_margem_padrao
    ADD CONSTRAINT produto_margem_padrao_mestre_key UNIQUE (mestre);


--
-- Name: produto_margem_padrao produto_margem_padrao_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.produto_margem_padrao
    ADD CONSTRAINT produto_margem_padrao_pkey PRIMARY KEY (id);


--
-- Name: produtos_custos produtos_custos_emp_mestre_vigencia_inicio_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.produtos_custos
    ADD CONSTRAINT produtos_custos_emp_mestre_vigencia_inicio_key UNIQUE (emp, mestre, vigencia_inicio);


--
-- Name: produtos_custos produtos_custos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.produtos_custos
    ADD CONSTRAINT produtos_custos_pkey PRIMARY KEY (id);


--
-- Name: campanhas_resultados_v2 uq_camp_v2_res; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_resultados_v2
    ADD CONSTRAINT uq_camp_v2_res UNIQUE (campanha_id, competencia_ano, competencia_mes, emp, vendedor);


--
-- Name: campanhas_qtd_resultados uq_campanha_qtd_resultado; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_qtd_resultados
    ADD CONSTRAINT uq_campanha_qtd_resultado UNIQUE (campanha_id, emp, vendedor, competencia_ano, competencia_mes);


--
-- Name: itens_parados_resultados uq_itens_parados_resultado; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_resultados
    ADD CONSTRAINT uq_itens_parados_resultado UNIQUE (item_parado_id, emp, vendedor, competencia_ano, competencia_mes);


--
-- Name: metas_margens_vendedores uq_meta_margem_vendedor_periodo; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_margens_vendedores
    ADD CONSTRAINT uq_meta_margem_vendedor_periodo UNIQUE (ano, mes, emp, vendedor);


--
-- Name: mensagem_empresas uq_msg_empresa; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_empresas
    ADD CONSTRAINT uq_msg_empresa UNIQUE (mensagem_id, emp);


--
-- Name: mensagem_lidas_diarias uq_msg_lida_dia; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_lidas_diarias
    ADD CONSTRAINT uq_msg_lida_dia UNIQUE (mensagem_id, usuario_id, data);


--
-- Name: mensagem_usuarios uq_msg_usuario; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_usuarios
    ADD CONSTRAINT uq_msg_usuario UNIQUE (mensagem_id, usuario_id);


--
-- Name: campanhas_ranking_marca_emps uq_rank_marca_emp; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca_emps
    ADD CONSTRAINT uq_rank_marca_emp UNIQUE (campanha_id, emp);


--
-- Name: campanhas_ranking_marca_premios uq_rank_marca_premio; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca_premios
    ADD CONSTRAINT uq_rank_marca_premio UNIQUE (campanha_id, posicao);


--
-- Name: campanhas_ranking_marca_resultados uq_rank_marca_resultado; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_ranking_marca_resultados
    ADD CONSTRAINT uq_rank_marca_resultado UNIQUE (campanha_id, competencia_ano, competencia_mes, emp, vendedor);


--
-- Name: usuario_emps usuario_emps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuario_emps
    ADD CONSTRAINT usuario_emps_pkey PRIMARY KEY (id);


--
-- Name: usuario_emps usuario_emps_usuario_id_emp_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuario_emps
    ADD CONSTRAINT usuario_emps_usuario_id_emp_key UNIQUE (usuario_id, emp);


--
-- Name: usuarios usuarios_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuarios
    ADD CONSTRAINT usuarios_pkey PRIMARY KEY (id);


--
-- Name: usuarios usuarios_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuarios
    ADD CONSTRAINT usuarios_username_key UNIQUE (username);


--
-- Name: vendas vendas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vendas
    ADD CONSTRAINT vendas_pkey PRIMARY KEY (id);


--
-- Name: vendas_resumo_periodo vendas_resumo_periodo_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vendas_resumo_periodo
    ADD CONSTRAINT vendas_resumo_periodo_pkey PRIMARY KEY (id);


--
-- Name: vendas vendas_unique_import; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vendas
    ADD CONSTRAINT vendas_unique_import UNIQUE (mestre, marca, vendedor, movimento, mov_tipo_movto, nota, emp);


--
-- Name: messages messages_payload_exclusive; Type: CHECK CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE realtime.messages
    ADD CONSTRAINT messages_payload_exclusive CHECK (((payload IS NULL) OR (binary_payload IS NULL))) NOT VALID;


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: subscription pk_subscription; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.subscription
    ADD CONSTRAINT pk_subscription PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: buckets_analytics buckets_analytics_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.buckets_analytics
    ADD CONSTRAINT buckets_analytics_pkey PRIMARY KEY (id);


--
-- Name: buckets buckets_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.buckets
    ADD CONSTRAINT buckets_pkey PRIMARY KEY (id);


--
-- Name: buckets_vectors buckets_vectors_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.buckets_vectors
    ADD CONSTRAINT buckets_vectors_pkey PRIMARY KEY (id);


--
-- Name: migrations migrations_name_key; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.migrations
    ADD CONSTRAINT migrations_name_key UNIQUE (name);


--
-- Name: migrations migrations_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.migrations
    ADD CONSTRAINT migrations_pkey PRIMARY KEY (id);


--
-- Name: objects objects_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.objects
    ADD CONSTRAINT objects_pkey PRIMARY KEY (id);


--
-- Name: s3_multipart_uploads_parts s3_multipart_uploads_parts_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads_parts
    ADD CONSTRAINT s3_multipart_uploads_parts_pkey PRIMARY KEY (id);


--
-- Name: s3_multipart_uploads s3_multipart_uploads_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads
    ADD CONSTRAINT s3_multipart_uploads_pkey PRIMARY KEY (id);


--
-- Name: vector_indexes vector_indexes_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.vector_indexes
    ADD CONSTRAINT vector_indexes_pkey PRIMARY KEY (id);


--
-- Name: audit_logs_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX audit_logs_instance_id_idx ON auth.audit_log_entries USING btree (instance_id);


--
-- Name: confirmation_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX confirmation_token_idx ON auth.users USING btree (confirmation_token) WHERE ((confirmation_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: custom_oauth_providers_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX custom_oauth_providers_created_at_idx ON auth.custom_oauth_providers USING btree (created_at);


--
-- Name: custom_oauth_providers_enabled_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX custom_oauth_providers_enabled_idx ON auth.custom_oauth_providers USING btree (enabled);


--
-- Name: custom_oauth_providers_identifier_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX custom_oauth_providers_identifier_idx ON auth.custom_oauth_providers USING btree (identifier);


--
-- Name: custom_oauth_providers_provider_type_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX custom_oauth_providers_provider_type_idx ON auth.custom_oauth_providers USING btree (provider_type);


--
-- Name: email_change_token_current_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX email_change_token_current_idx ON auth.users USING btree (email_change_token_current) WHERE ((email_change_token_current)::text !~ '^[0-9 ]*$'::text);


--
-- Name: email_change_token_new_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX email_change_token_new_idx ON auth.users USING btree (email_change_token_new) WHERE ((email_change_token_new)::text !~ '^[0-9 ]*$'::text);


--
-- Name: factor_id_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX factor_id_created_at_idx ON auth.mfa_factors USING btree (user_id, created_at);


--
-- Name: flow_state_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX flow_state_created_at_idx ON auth.flow_state USING btree (created_at DESC);


--
-- Name: identities_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX identities_email_idx ON auth.identities USING btree (email text_pattern_ops);


--
-- Name: INDEX identities_email_idx; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX auth.identities_email_idx IS 'Auth: Ensures indexed queries on the email column';


--
-- Name: identities_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX identities_user_id_idx ON auth.identities USING btree (user_id);


--
-- Name: idx_auth_code; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_auth_code ON auth.flow_state USING btree (auth_code);


--
-- Name: idx_oauth_client_states_created_at; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_oauth_client_states_created_at ON auth.oauth_client_states USING btree (created_at);


--
-- Name: idx_user_id_auth_method; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_user_id_auth_method ON auth.flow_state USING btree (user_id, authentication_method);


--
-- Name: mfa_challenge_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX mfa_challenge_created_at_idx ON auth.mfa_challenges USING btree (created_at DESC);


--
-- Name: mfa_factors_user_friendly_name_unique; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX mfa_factors_user_friendly_name_unique ON auth.mfa_factors USING btree (friendly_name, user_id) WHERE (TRIM(BOTH FROM friendly_name) <> ''::text);


--
-- Name: mfa_factors_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX mfa_factors_user_id_idx ON auth.mfa_factors USING btree (user_id);


--
-- Name: oauth_auth_pending_exp_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_auth_pending_exp_idx ON auth.oauth_authorizations USING btree (expires_at) WHERE (status = 'pending'::auth.oauth_authorization_status);


--
-- Name: oauth_clients_deleted_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_clients_deleted_at_idx ON auth.oauth_clients USING btree (deleted_at);


--
-- Name: oauth_consents_active_client_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_consents_active_client_idx ON auth.oauth_consents USING btree (client_id) WHERE (revoked_at IS NULL);


--
-- Name: oauth_consents_active_user_client_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_consents_active_user_client_idx ON auth.oauth_consents USING btree (user_id, client_id) WHERE (revoked_at IS NULL);


--
-- Name: oauth_consents_user_order_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_consents_user_order_idx ON auth.oauth_consents USING btree (user_id, granted_at DESC);


--
-- Name: one_time_tokens_relates_to_hash_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX one_time_tokens_relates_to_hash_idx ON auth.one_time_tokens USING hash (relates_to);


--
-- Name: one_time_tokens_token_hash_hash_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX one_time_tokens_token_hash_hash_idx ON auth.one_time_tokens USING hash (token_hash);


--
-- Name: one_time_tokens_user_id_token_type_key; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX one_time_tokens_user_id_token_type_key ON auth.one_time_tokens USING btree (user_id, token_type);


--
-- Name: reauthentication_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX reauthentication_token_idx ON auth.users USING btree (reauthentication_token) WHERE ((reauthentication_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: recovery_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX recovery_token_idx ON auth.users USING btree (recovery_token) WHERE ((recovery_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: refresh_tokens_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_instance_id_idx ON auth.refresh_tokens USING btree (instance_id);


--
-- Name: refresh_tokens_instance_id_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_instance_id_user_id_idx ON auth.refresh_tokens USING btree (instance_id, user_id);


--
-- Name: refresh_tokens_parent_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_parent_idx ON auth.refresh_tokens USING btree (parent);


--
-- Name: refresh_tokens_session_id_revoked_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_session_id_revoked_idx ON auth.refresh_tokens USING btree (session_id, revoked);


--
-- Name: refresh_tokens_updated_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_updated_at_idx ON auth.refresh_tokens USING btree (updated_at DESC);


--
-- Name: saml_providers_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_providers_sso_provider_id_idx ON auth.saml_providers USING btree (sso_provider_id);


--
-- Name: saml_relay_states_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_relay_states_created_at_idx ON auth.saml_relay_states USING btree (created_at DESC);


--
-- Name: saml_relay_states_for_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_relay_states_for_email_idx ON auth.saml_relay_states USING btree (for_email);


--
-- Name: saml_relay_states_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_relay_states_sso_provider_id_idx ON auth.saml_relay_states USING btree (sso_provider_id);


--
-- Name: sessions_not_after_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_not_after_idx ON auth.sessions USING btree (not_after DESC);


--
-- Name: sessions_oauth_client_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_oauth_client_id_idx ON auth.sessions USING btree (oauth_client_id);


--
-- Name: sessions_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_user_id_idx ON auth.sessions USING btree (user_id);


--
-- Name: sso_domains_domain_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX sso_domains_domain_idx ON auth.sso_domains USING btree (lower(domain));


--
-- Name: sso_domains_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sso_domains_sso_provider_id_idx ON auth.sso_domains USING btree (sso_provider_id);


--
-- Name: sso_providers_resource_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX sso_providers_resource_id_idx ON auth.sso_providers USING btree (lower(resource_id));


--
-- Name: sso_providers_resource_id_pattern_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sso_providers_resource_id_pattern_idx ON auth.sso_providers USING btree (resource_id text_pattern_ops);


--
-- Name: unique_phone_factor_per_user; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX unique_phone_factor_per_user ON auth.mfa_factors USING btree (user_id, phone);


--
-- Name: user_id_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX user_id_created_at_idx ON auth.sessions USING btree (user_id, created_at);


--
-- Name: users_email_partial_key; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX users_email_partial_key ON auth.users USING btree (email) WHERE (is_sso_user = false);


--
-- Name: INDEX users_email_partial_key; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX auth.users_email_partial_key IS 'Auth: A partial unique index that applies only when is_sso_user is false';


--
-- Name: users_instance_id_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_instance_id_email_idx ON auth.users USING btree (instance_id, lower((email)::text));


--
-- Name: users_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_instance_id_idx ON auth.users USING btree (instance_id);


--
-- Name: users_is_anonymous_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_is_anonymous_idx ON auth.users USING btree (is_anonymous);


--
-- Name: webauthn_challenges_expires_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX webauthn_challenges_expires_at_idx ON auth.webauthn_challenges USING btree (expires_at);


--
-- Name: webauthn_challenges_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX webauthn_challenges_user_id_idx ON auth.webauthn_challenges USING btree (user_id);


--
-- Name: webauthn_credentials_credential_id_key; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX webauthn_credentials_credential_id_key ON auth.webauthn_credentials USING btree (credential_id);


--
-- Name: webauthn_credentials_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX webauthn_credentials_user_id_idx ON auth.webauthn_credentials USING btree (user_id);


--
-- Name: idx_camp_res_comp_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_camp_res_comp_emp ON public.campanhas_resultados USING btree (competencia_ano, competencia_mes, emp);


--
-- Name: idx_camp_res_vend_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_camp_res_vend_comp ON public.campanhas_resultados USING btree (vendedor, competencia_ano, competencia_mes);


--
-- Name: idx_campanhas_emps_campanha; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campanhas_emps_campanha ON public.campanhas_emps USING btree (campanha_id);


--
-- Name: idx_campanhas_emps_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campanhas_emps_emp ON public.campanhas_emps USING btree (emp);


--
-- Name: idx_combo_res_emp_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_combo_res_emp_comp ON public.campanhas_combo_resultados USING btree (emp, competencia_ano, competencia_mes);


--
-- Name: idx_combo_res_vend_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_combo_res_vend_comp ON public.campanhas_combo_resultados USING btree (vendedor, competencia_ano, competencia_mes);


--
-- Name: idx_dashboard_cache_v2_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dashboard_cache_v2_lookup ON public.dashboard_cache USING btree (ano, mes, emp_scope, vendedor_alvo, tipo);


--
-- Name: idx_itens_parados_bonus_emp_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_bonus_emp_ativo ON public.itens_parados_pontos_bonus_faixas USING btree (emp, ativo);


--
-- Name: idx_itens_parados_emp_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_emp_ativo ON public.itens_parados USING btree (emp, ativo);


--
-- Name: idx_itens_parados_fech_emp_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_fech_emp_data ON public.itens_parados_pontos_fechamentos USING btree (emp, data_inicio, data_fim);


--
-- Name: idx_itens_parados_fech_emp_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_fech_emp_periodo ON public.itens_parados_pontos_fechamentos USING btree (emp, periodo_inicio, periodo_fim);


--
-- Name: idx_itens_parados_fechamentos_emp_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_fechamentos_emp_periodo ON public.itens_parados_fechamentos USING btree (emp, data_inicio, data_fim);


--
-- Name: idx_itens_parados_modo_emp_codigo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_modo_emp_codigo ON public.itens_parados USING btree (modo, emp, codigo);


--
-- Name: idx_itens_parados_pontos_bonus_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_pontos_bonus_emp ON public.itens_parados_pontos_bonus USING btree (emp);


--
-- Name: idx_itens_parados_pontos_bonus_emp_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_pontos_bonus_emp_ativo ON public.itens_parados_pontos_bonus USING btree (emp, ativo);


--
-- Name: idx_itens_parados_pontos_config_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_pontos_config_emp ON public.itens_parados_pontos_config USING btree (emp);


--
-- Name: idx_itens_parados_pontos_config_emp_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_pontos_config_emp_ativo ON public.itens_parados_pontos_config USING btree (emp, ativo);


--
-- Name: idx_itens_parados_result_fech_vend; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_result_fech_vend ON public.itens_parados_pontos_resultados USING btree (fechamento_id, vendedor);


--
-- Name: idx_itens_parados_resultados_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itens_parados_resultados_emp ON public.itens_parados_pontos_resultados USING btree (emp);


--
-- Name: idx_margem_vend_comp_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_margem_vend_comp_emp ON public.margem_vendedor_periodo USING btree (competencia_ano, competencia_mes, emp);


--
-- Name: idx_margem_vend_comp_vend; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_margem_vend_comp_vend ON public.margem_vendedor_periodo USING btree (competencia_ano, competencia_mes, vendedor);


--
-- Name: idx_metas_v2_criterios_programa; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_metas_v2_criterios_programa ON public.metas_v2_criterios USING btree (programa_id, tipo);


--
-- Name: idx_metas_v2_resultados_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_metas_v2_resultados_periodo ON public.metas_v2_resultados USING btree (ano, mes, emp);


--
-- Name: idx_pagamentos_comp_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pagamentos_comp_emp ON public.pagamentos USING btree (competencia_ano, competencia_mes, emp);


--
-- Name: idx_pagamentos_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pagamentos_status ON public.pagamentos USING btree (status);


--
-- Name: idx_prod_custos_emp_mestre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_prod_custos_emp_mestre ON public.produtos_custos USING btree (emp, mestre);


--
-- Name: idx_prod_custos_mestre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_prod_custos_mestre ON public.produtos_custos USING btree (mestre);


--
-- Name: idx_produto_custo_mestre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_produto_custo_mestre ON public.produto_custo USING btree (mestre);


--
-- Name: idx_produto_margem_padrao_mestre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_produto_margem_padrao_mestre ON public.produto_margem_padrao USING btree (mestre);


--
-- Name: idx_qtd_res_emp_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_qtd_res_emp_comp ON public.campanhas_qtd_resultados USING btree (emp, competencia_ano, competencia_mes);


--
-- Name: idx_qtd_res_vend_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_qtd_res_vend_comp ON public.campanhas_qtd_resultados USING btree (vendedor, competencia_ano, competencia_mes);


--
-- Name: idx_usuario_emps_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_usuario_emps_emp ON public.usuario_emps USING btree (emp);


--
-- Name: idx_usuario_emps_usuario; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_usuario_emps_usuario ON public.usuario_emps USING btree (usuario_id);


--
-- Name: idx_vendas_ano_mes_emp_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_ano_mes_emp_marca ON public.vendas USING btree (ano, mes, emp, marca);


--
-- Name: idx_vendas_ano_mes_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_ano_mes_marca ON public.vendas USING btree (ano, mes, marca);


--
-- Name: idx_vendas_cidade_norm_movimento; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_cidade_norm_movimento ON public.vendas USING btree (cidade_norm, movimento);


--
-- Name: idx_vendas_cliente_id_norm_movimento; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_cliente_id_norm_movimento ON public.vendas USING btree (cliente_id_norm, movimento);


--
-- Name: idx_vendas_descricao_norm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_descricao_norm ON public.vendas USING btree (descricao_norm);


--
-- Name: idx_vendas_emp_ano_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_emp_ano_mes ON public.vendas USING btree (emp, ano, mes);


--
-- Name: idx_vendas_emp_ano_mes_cidade; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_emp_ano_mes_cidade ON public.vendas USING btree (emp, ano, mes, cidade_norm);


--
-- Name: idx_vendas_emp_ano_mes_cliente; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_emp_ano_mes_cliente ON public.vendas USING btree (emp, ano, mes, cliente_id_norm);


--
-- Name: idx_vendas_emp_ano_mes_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_emp_ano_mes_marca ON public.vendas USING btree (emp, ano, mes, marca);


--
-- Name: idx_vendas_emp_ano_mes_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_emp_ano_mes_vendedor ON public.vendas USING btree (emp, ano, mes, vendedor);


--
-- Name: idx_vendas_emp_movimento; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_emp_movimento ON public.vendas USING btree (emp, movimento);


--
-- Name: idx_vendas_emp_vendedor_movimento; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_emp_vendedor_movimento ON public.vendas USING btree (emp, vendedor, movimento);


--
-- Name: idx_vendas_mestre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_mestre ON public.vendas USING btree (mestre);


--
-- Name: idx_vendas_mov_tipo_movto; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vendas_mov_tipo_movto ON public.vendas USING btree (mov_tipo_movto);


--
-- Name: ix_app_settings_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_app_settings_key ON public.app_settings USING btree (key);


--
-- Name: ix_branding_themes_active_dates; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_branding_themes_active_dates ON public.branding_themes USING btree (is_active, start_date, end_date);


--
-- Name: ix_camp_qtd_res_comp_emp_vend_camp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_qtd_res_comp_emp_vend_camp ON public.campanhas_qtd_resultados USING btree (competencia_ano, competencia_mes, emp, vendedor, campanha_id);


--
-- Name: ix_camp_qtd_res_periodo_emp_vendedor_campanha; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_qtd_res_periodo_emp_vendedor_campanha ON public.campanhas_qtd_resultados USING btree (competencia_ano, competencia_mes, emp, vendedor, campanha_id);


--
-- Name: ix_camp_v2_audit_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_audit_comp ON public.campanhas_audit_v2 USING btree (competencia_ano, competencia_mes);


--
-- Name: ix_camp_v2_audit_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_audit_emp ON public.campanhas_audit_v2 USING btree (emp);


--
-- Name: ix_camp_v2_escopo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_escopo ON public.campanhas_master_v2 USING btree (escopo);


--
-- Name: ix_camp_v2_master_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_master_ativo ON public.campanhas_v2_master USING btree (ativo);


--
-- Name: ix_camp_v2_master_tipo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_master_tipo ON public.campanhas_v2_master USING btree (tipo);


--
-- Name: ix_camp_v2_master_vigencia; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_master_vigencia ON public.campanhas_v2_master USING btree (vigencia_inicio, vigencia_fim);


--
-- Name: ix_camp_v2_res_comp_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_res_comp_emp ON public.campanhas_resultados_v2 USING btree (competencia_ano, competencia_mes, emp);


--
-- Name: ix_camp_v2_res_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_res_status ON public.campanhas_resultados_v2 USING btree (status_pagamento);


--
-- Name: ix_camp_v2_res_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_res_vendedor ON public.campanhas_resultados_v2 USING btree (vendedor);


--
-- Name: ix_camp_v2_result_campanha_competencia; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_result_campanha_competencia ON public.campanhas_v2_resultados USING btree (campanha_id, ano, mes);


--
-- Name: ix_camp_v2_result_competencia; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_result_competencia ON public.campanhas_v2_resultados USING btree (ano, mes);


--
-- Name: ix_camp_v2_result_emp_competencia; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_result_emp_competencia ON public.campanhas_v2_resultados USING btree (emp, ano, mes);


--
-- Name: ix_camp_v2_result_periodo_emp_vendedor_campanha; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_result_periodo_emp_vendedor_campanha ON public.campanhas_v2_resultados USING btree (ano, mes, emp, vendedor, campanha_id);


--
-- Name: ix_camp_v2_result_vendedor_competencia; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_result_vendedor_competencia ON public.campanhas_v2_resultados USING btree (vendedor, ano, mes);


--
-- Name: ix_camp_v2_scope_emp_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_scope_emp_emp ON public.campanhas_scope_emp_v2 USING btree (emp);


--
-- Name: ix_camp_v2_scope_emp_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_scope_emp_lookup ON public.campanhas_scope_emp_v2 USING btree (emp, campanha_id);


--
-- Name: ix_camp_v2_tipo_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_camp_v2_tipo_ativo ON public.campanhas_master_v2 USING btree (tipo, ativo);


--
-- Name: ix_campanha_qtd_resultados_emp_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanha_qtd_resultados_emp_comp ON public.campanhas_qtd_resultados USING btree (emp, competencia_ano, competencia_mes);


--
-- Name: ix_campanhas_combo_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_emp ON public.campanhas_combo USING btree (emp);


--
-- Name: ix_campanhas_combo_filtro_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_filtro_marca ON public.campanhas_combo USING btree (filtro_marca);


--
-- Name: ix_campanhas_combo_itens_combo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_itens_combo ON public.campanhas_combo_itens USING btree (combo_id);


--
-- Name: ix_campanhas_combo_itens_combo_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_itens_combo_id ON public.campanhas_combo_itens USING btree (combo_id);


--
-- Name: ix_campanhas_combo_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_marca ON public.campanhas_combo USING btree (marca);


--
-- Name: ix_campanhas_combo_modelo_pagamento; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_modelo_pagamento ON public.campanhas_combo USING btree (modelo_pagamento);


--
-- Name: ix_campanhas_combo_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_periodo ON public.campanhas_combo USING btree (ano, mes);


--
-- Name: ix_campanhas_combo_resultados_combo_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_resultados_combo_id ON public.campanhas_combo_resultados USING btree (combo_id);


--
-- Name: ix_campanhas_combo_resultados_competencia_ano; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_resultados_competencia_ano ON public.campanhas_combo_resultados USING btree (competencia_ano);


--
-- Name: ix_campanhas_combo_resultados_competencia_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_resultados_competencia_mes ON public.campanhas_combo_resultados USING btree (competencia_mes);


--
-- Name: ix_campanhas_combo_resultados_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_resultados_emp ON public.campanhas_combo_resultados USING btree (emp);


--
-- Name: ix_campanhas_combo_resultados_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_combo_resultados_vendedor ON public.campanhas_combo_resultados USING btree (vendedor);


--
-- Name: ix_campanhas_qtd_data_fim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_data_fim ON public.campanhas_qtd USING btree (data_fim);


--
-- Name: ix_campanhas_qtd_data_inicio; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_data_inicio ON public.campanhas_qtd USING btree (data_inicio);


--
-- Name: ix_campanhas_qtd_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_emp ON public.campanhas_qtd USING btree (emp);


--
-- Name: ix_campanhas_qtd_emp_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_emp_periodo ON public.campanhas_qtd USING btree (emp, data_inicio, data_fim);


--
-- Name: ix_campanhas_qtd_resultados_bloq_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_resultados_bloq_emp ON public.campanhas_qtd_resultados USING btree (competencia_ano, competencia_mes, emp, bloqueado_faturamento_emp);


--
-- Name: ix_campanhas_qtd_resultados_campanha_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_resultados_campanha_id ON public.campanhas_qtd_resultados USING btree (campanha_id);


--
-- Name: ix_campanhas_qtd_resultados_competencia_ano; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_resultados_competencia_ano ON public.campanhas_qtd_resultados USING btree (competencia_ano);


--
-- Name: ix_campanhas_qtd_resultados_competencia_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_resultados_competencia_mes ON public.campanhas_qtd_resultados USING btree (competencia_mes);


--
-- Name: ix_campanhas_qtd_resultados_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_resultados_emp ON public.campanhas_qtd_resultados USING btree (emp);


--
-- Name: ix_campanhas_qtd_resultados_tipo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_resultados_tipo ON public.campanhas_qtd_resultados USING btree (campanha_tipo);


--
-- Name: ix_campanhas_qtd_resultados_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_resultados_vendedor ON public.campanhas_qtd_resultados USING btree (vendedor);


--
-- Name: ix_campanhas_qtd_tipo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_tipo ON public.campanhas_qtd USING btree (campanha_tipo);


--
-- Name: ix_campanhas_qtd_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_qtd_vendedor ON public.campanhas_qtd USING btree (vendedor);


--
-- Name: ix_campanhas_ranking_marca_competencia_ano; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_competencia_ano ON public.campanhas_ranking_marca USING btree (competencia_ano);


--
-- Name: ix_campanhas_ranking_marca_competencia_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_competencia_mes ON public.campanhas_ranking_marca USING btree (competencia_mes);


--
-- Name: ix_campanhas_ranking_marca_data_fim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_data_fim ON public.campanhas_ranking_marca USING btree (data_fim);


--
-- Name: ix_campanhas_ranking_marca_data_inicio; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_data_inicio ON public.campanhas_ranking_marca USING btree (data_inicio);


--
-- Name: ix_campanhas_ranking_marca_emps_campanha_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_emps_campanha_id ON public.campanhas_ranking_marca_emps USING btree (campanha_id);


--
-- Name: ix_campanhas_ranking_marca_emps_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_emps_emp ON public.campanhas_ranking_marca_emps USING btree (emp);


--
-- Name: ix_campanhas_ranking_marca_escopo_tipo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_escopo_tipo ON public.campanhas_ranking_marca USING btree (escopo_tipo);


--
-- Name: ix_campanhas_ranking_marca_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_marca ON public.campanhas_ranking_marca USING btree (marca);


--
-- Name: ix_campanhas_ranking_marca_premios_campanha_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_premios_campanha_id ON public.campanhas_ranking_marca_premios USING btree (campanha_id);


--
-- Name: ix_campanhas_ranking_marca_resultados_campanha_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_resultados_campanha_id ON public.campanhas_ranking_marca_resultados USING btree (campanha_id);


--
-- Name: ix_campanhas_ranking_marca_resultados_competencia_ano; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_resultados_competencia_ano ON public.campanhas_ranking_marca_resultados USING btree (competencia_ano);


--
-- Name: ix_campanhas_ranking_marca_resultados_competencia_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_resultados_competencia_mes ON public.campanhas_ranking_marca_resultados USING btree (competencia_mes);


--
-- Name: ix_campanhas_ranking_marca_resultados_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_resultados_emp ON public.campanhas_ranking_marca_resultados USING btree (emp);


--
-- Name: ix_campanhas_ranking_marca_resultados_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campanhas_ranking_marca_resultados_vendedor ON public.campanhas_ranking_marca_resultados USING btree (vendedor);


--
-- Name: ix_combo_ativo_ano_mes_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_combo_ativo_ano_mes_emp ON public.campanhas_combo USING btree (ano, mes, emp) WHERE (ativo IS TRUE);


--
-- Name: ix_combo_ativo_periodo_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_combo_ativo_periodo_emp ON public.campanhas_combo USING btree (ano, mes, emp) WHERE (ativo IS TRUE);


--
-- Name: ix_combo_ativo_periodo_global; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_combo_ativo_periodo_global ON public.campanhas_combo USING btree (ano, mes) WHERE ((ativo IS TRUE) AND ((emp IS NULL) OR ((emp)::text = ''::text)));


--
-- Name: ix_combo_itens_combo_ordem_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_combo_itens_combo_ordem_id ON public.campanhas_combo_itens USING btree (combo_id, ordem, id);


--
-- Name: ix_combo_itens_combo_ordem_id_turbo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_combo_itens_combo_ordem_id_turbo ON public.campanhas_combo_itens USING btree (combo_id, ordem, id);


--
-- Name: ix_combo_res_comp_emp_vend_combo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_combo_res_comp_emp_vend_combo ON public.campanhas_combo_resultados USING btree (competencia_ano, competencia_mes, emp, vendedor, combo_id);


--
-- Name: ix_combo_res_emp_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_combo_res_emp_comp ON public.campanhas_combo_resultados USING btree (emp, competencia_ano, competencia_mes);


--
-- Name: ix_combo_res_periodo_emp_vendedor_combo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_combo_res_periodo_emp_vendedor_combo ON public.campanhas_combo_resultados USING btree (competencia_ano, competencia_mes, emp, vendedor, combo_id);


--
-- Name: ix_combo_res_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_combo_res_vendedor ON public.campanhas_combo_resultados USING btree (vendedor);


--
-- Name: ix_dashboard_cache_emp_ano_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_dashboard_cache_emp_ano_mes ON public.dashboard_cache USING btree (emp, ano, mes);


--
-- Name: ix_dashboard_cache_vendedor_ano_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_dashboard_cache_vendedor_ano_mes ON public.dashboard_cache USING btree (vendedor, ano, mes);


--
-- Name: ix_emps_cidade; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_emps_cidade ON public.emps USING btree (cidade);


--
-- Name: ix_emps_codigo; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_emps_codigo ON public.emps USING btree (codigo);


--
-- Name: ix_emps_uf; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_emps_uf ON public.emps USING btree (uf);


--
-- Name: ix_fech_audit_emp_ano_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fech_audit_emp_ano_mes ON public.fechamento_mensal_audit USING btree (emp, ano, mes);


--
-- Name: ix_fechamento_mensal_audit_acao; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fechamento_mensal_audit_acao ON public.fechamento_mensal_audit USING btree (acao);


--
-- Name: ix_fechamento_mensal_audit_ano; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fechamento_mensal_audit_ano ON public.fechamento_mensal_audit USING btree (ano);


--
-- Name: ix_fechamento_mensal_audit_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fechamento_mensal_audit_emp ON public.fechamento_mensal_audit USING btree (emp);


--
-- Name: ix_fechamento_mensal_audit_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fechamento_mensal_audit_mes ON public.fechamento_mensal_audit USING btree (mes);


--
-- Name: ix_fechamento_mensal_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fechamento_mensal_status ON public.fechamento_mensal USING btree (status);


--
-- Name: ix_fin_audit_criado_em; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fin_audit_criado_em ON public.financeiro_audit USING btree (criado_em);


--
-- Name: ix_fin_audit_pagamento; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fin_audit_pagamento ON public.financeiro_audit USING btree (pagamento_id);


--
-- Name: ix_fin_pag_competencia; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fin_pag_competencia ON public.financeiro_pagamentos USING btree (ano, mes);


--
-- Name: ix_fin_pag_emp_competencia; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fin_pag_emp_competencia ON public.financeiro_pagamentos USING btree (emp, ano, mes);


--
-- Name: ix_fin_pag_origem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fin_pag_origem ON public.financeiro_pagamentos USING btree (origem_tipo, origem_id);


--
-- Name: ix_fin_pag_periodo_origem_emp_vendedor_origemid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fin_pag_periodo_origem_emp_vendedor_origemid ON public.financeiro_pagamentos USING btree (ano, mes, origem_tipo, emp, vendedor, origem_id);


--
-- Name: ix_fin_pag_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fin_pag_status ON public.financeiro_pagamentos USING btree (status);


--
-- Name: ix_fin_pag_vendedor_competencia; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fin_pag_vendedor_competencia ON public.financeiro_pagamentos USING btree (vendedor, ano, mes);


--
-- Name: ix_financeiro_pagamentos_audit_ano; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_financeiro_pagamentos_audit_ano ON public.financeiro_pagamentos_audit USING btree (ano);


--
-- Name: ix_financeiro_pagamentos_audit_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_financeiro_pagamentos_audit_emp ON public.financeiro_pagamentos_audit USING btree (emp);


--
-- Name: ix_financeiro_pagamentos_audit_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_financeiro_pagamentos_audit_mes ON public.financeiro_pagamentos_audit USING btree (mes);


--
-- Name: ix_financeiro_pagamentos_audit_origem_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_financeiro_pagamentos_audit_origem_id ON public.financeiro_pagamentos_audit USING btree (origem_id);


--
-- Name: ix_financeiro_pagamentos_audit_origem_tipo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_financeiro_pagamentos_audit_origem_tipo ON public.financeiro_pagamentos_audit USING btree (origem_tipo);


--
-- Name: ix_financeiro_pagamentos_audit_pagamento_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_financeiro_pagamentos_audit_pagamento_id ON public.financeiro_pagamentos_audit USING btree (pagamento_id);


--
-- Name: ix_financeiro_pagamentos_audit_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_financeiro_pagamentos_audit_vendedor ON public.financeiro_pagamentos_audit USING btree (vendedor);


--
-- Name: ix_importacoes_log_criado_em; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_importacoes_log_criado_em ON public.importacoes_log USING btree (criado_em);


--
-- Name: ix_itens_parados_bonus_emp_ativo_min; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_bonus_emp_ativo_min ON public.itens_parados_pontos_bonus USING btree (emp, ativo, min_pontos);


--
-- Name: ix_itens_parados_cfg_emp_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_cfg_emp_ativo ON public.itens_parados_pontos_config USING btree (emp, ativo);


--
-- Name: ix_itens_parados_codigo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_codigo ON public.itens_parados USING btree (codigo);


--
-- Name: ix_itens_parados_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_emp ON public.itens_parados USING btree (emp);


--
-- Name: ix_itens_parados_emp_ativo_codigo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_emp_ativo_codigo ON public.itens_parados USING btree (emp, ativo, codigo);


--
-- Name: ix_itens_parados_emp_ativo_codigo_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_emp_ativo_codigo_periodo ON public.itens_parados USING btree (emp, ativo, codigo, data_inicio, data_fim);


--
-- Name: ix_itens_parados_emp_ativo_datas; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_emp_ativo_datas ON public.itens_parados USING btree (emp, ativo, data_inicio, data_fim);


--
-- Name: ix_itens_parados_emp_ativo_vigencia_codigo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_emp_ativo_vigencia_codigo ON public.itens_parados USING btree (emp, data_inicio, data_fim, codigo) WHERE (ativo IS TRUE);


--
-- Name: ix_itens_parados_emp_ativo_vigencia_codigo_turbo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_emp_ativo_vigencia_codigo_turbo ON public.itens_parados USING btree (emp, data_inicio, data_fim, codigo) WHERE (ativo IS TRUE);


--
-- Name: ix_itens_parados_emp_codigo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_emp_codigo ON public.itens_parados USING btree (emp, codigo);


--
-- Name: ix_itens_parados_pontos_bonus_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_pontos_bonus_emp ON public.itens_parados_pontos_bonus USING btree (emp);


--
-- Name: ix_itens_parados_pontos_bonus_min; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_pontos_bonus_min ON public.itens_parados_pontos_bonus USING btree (min_pontos);


--
-- Name: ix_itens_parados_pontos_cfg_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_pontos_cfg_emp ON public.itens_parados_pontos_config USING btree (emp);


--
-- Name: ix_itens_parados_pontos_fech_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_pontos_fech_emp ON public.itens_parados_pontos_fechamentos USING btree (emp);


--
-- Name: ix_itens_parados_pontos_fech_fim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_pontos_fech_fim ON public.itens_parados_pontos_fechamentos USING btree (data_fim);


--
-- Name: ix_itens_parados_pontos_fech_ini; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_pontos_fech_ini ON public.itens_parados_pontos_fechamentos USING btree (data_inicio);


--
-- Name: ix_itens_parados_pontos_res_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_pontos_res_emp ON public.itens_parados_pontos_resultados USING btree (emp);


--
-- Name: ix_itens_parados_pontos_res_fech; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_pontos_res_fech ON public.itens_parados_pontos_resultados USING btree (fechamento_id);


--
-- Name: ix_itens_parados_pontos_res_vend; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_pontos_res_vend ON public.itens_parados_pontos_resultados USING btree (vendedor);


--
-- Name: ix_itens_parados_res_comp_emp_vend; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_res_comp_emp_vend ON public.itens_parados_resultados USING btree (competencia_ano, competencia_mes, emp, vendedor);


--
-- Name: ix_itens_parados_res_comp_emp_vend_turbo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_res_comp_emp_vend_turbo ON public.itens_parados_resultados USING btree (competencia_ano, competencia_mes, emp, vendedor);


--
-- Name: ix_itens_parados_res_emp_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_res_emp_comp ON public.itens_parados_resultados USING btree (emp, competencia_ano, competencia_mes);


--
-- Name: ix_itens_parados_res_vend; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_res_vend ON public.itens_parados_resultados USING btree (vendedor);


--
-- Name: ix_itens_parados_resultados_competencia_ano; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_resultados_competencia_ano ON public.itens_parados_resultados USING btree (competencia_ano);


--
-- Name: ix_itens_parados_resultados_competencia_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_resultados_competencia_mes ON public.itens_parados_resultados USING btree (competencia_mes);


--
-- Name: ix_itens_parados_resultados_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_resultados_emp ON public.itens_parados_resultados USING btree (emp);


--
-- Name: ix_itens_parados_resultados_item_parado_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_resultados_item_parado_id ON public.itens_parados_resultados USING btree (item_parado_id);


--
-- Name: ix_itens_parados_resultados_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_itens_parados_resultados_vendedor ON public.itens_parados_resultados USING btree (vendedor);


--
-- Name: ix_mensagem_empresas_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagem_empresas_emp ON public.mensagem_empresas USING btree (emp);


--
-- Name: ix_mensagem_empresas_mensagem_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagem_empresas_mensagem_id ON public.mensagem_empresas USING btree (mensagem_id);


--
-- Name: ix_mensagem_lidas_diarias_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagem_lidas_diarias_data ON public.mensagem_lidas_diarias USING btree (data);


--
-- Name: ix_mensagem_lidas_diarias_mensagem_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagem_lidas_diarias_mensagem_id ON public.mensagem_lidas_diarias USING btree (mensagem_id);


--
-- Name: ix_mensagem_lidas_diarias_usuario_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagem_lidas_diarias_usuario_id ON public.mensagem_lidas_diarias USING btree (usuario_id);


--
-- Name: ix_mensagem_usuarios_mensagem_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagem_usuarios_mensagem_id ON public.mensagem_usuarios USING btree (mensagem_id);


--
-- Name: ix_mensagem_usuarios_usuario; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagem_usuarios_usuario ON public.mensagem_usuarios USING btree (usuario_id);


--
-- Name: ix_mensagem_usuarios_usuario_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagem_usuarios_usuario_id ON public.mensagem_usuarios USING btree (usuario_id);


--
-- Name: ix_mensagens_ativo_bloqueante; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagens_ativo_bloqueante ON public.mensagens USING btree (ativo, bloqueante);


--
-- Name: ix_mensagens_created_by_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagens_created_by_user_id ON public.mensagens USING btree (created_by_user_id);


--
-- Name: ix_mensagens_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mensagens_periodo ON public.mensagens USING btree (inicio_em, fim_em);


--
-- Name: ix_meta_base_manual_emp_vend; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_base_manual_emp_vend ON public.metas_bases_manuais USING btree (emp, vendedor);


--
-- Name: ix_meta_emp_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_emp_emp ON public.metas_programas_emps USING btree (emp);


--
-- Name: ix_meta_escala_meta; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_escala_meta ON public.metas_escalas USING btree (meta_id);


--
-- Name: ix_meta_marca_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_marca_marca ON public.metas_marcas USING btree (marca);


--
-- Name: ix_meta_margem_emp_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_margem_emp_periodo ON public.metas_margens_vendedores USING btree (emp, ano, mes);


--
-- Name: ix_meta_margem_periodo_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_margem_periodo_vendedor ON public.metas_margens_vendedores USING btree (ano, mes, vendedor);


--
-- Name: ix_meta_margem_vendedor_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_margem_vendedor_periodo ON public.metas_margens_vendedores USING btree (vendedor, ano, mes);


--
-- Name: ix_meta_recomp_loja_emp_ordem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_recomp_loja_emp_ordem ON public.metas_recompensas_loja_itens USING btree (emp, ordem);


--
-- Name: ix_meta_recomp_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_recomp_marca ON public.metas_recompensas_itens USING btree (marca);


--
-- Name: ix_meta_recomp_mestre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_recomp_mestre ON public.metas_recompensas_itens USING btree (mestre);


--
-- Name: ix_meta_recomp_meta; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_recomp_meta ON public.metas_recompensas_itens USING btree (meta_id);


--
-- Name: ix_meta_recomp_meta_ordem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_recomp_meta_ordem ON public.metas_recompensas_itens USING btree (meta_id, ordem);


--
-- Name: ix_meta_resultados_comp_emp_vend_meta_turbo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_resultados_comp_emp_vend_meta_turbo ON public.metas_resultados USING btree (ano, mes, emp, vendedor, meta_id);


--
-- Name: ix_meta_resultados_emp_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_resultados_emp_periodo ON public.metas_resultados USING btree (emp, ano, mes);


--
-- Name: ix_meta_resultados_meta_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_resultados_meta_periodo ON public.metas_resultados USING btree (meta_id, ano, mes);


--
-- Name: ix_meta_resultados_periodo_emp_vendedor_meta; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_meta_resultados_periodo_emp_vendedor_meta ON public.metas_resultados USING btree (ano, mes, emp, vendedor, meta_id);


--
-- Name: ix_metas_bases_meta_emp_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_bases_meta_emp_vendedor ON public.metas_bases_manuais USING btree (meta_id, emp, vendedor);


--
-- Name: ix_metas_escalas_meta; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_escalas_meta ON public.metas_escalas USING btree (meta_id);


--
-- Name: ix_metas_gate_emp_vend_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_gate_emp_vend_periodo ON public.metas_gate_vendedor_emp USING btree (emp, vendedor, periodo_tipo, ano, mes);


--
-- Name: ix_metas_gate_emp_vend_range; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_gate_emp_vend_range ON public.metas_gate_vendedor_emp USING btree (emp, vendedor, data_ini, data_fim);


--
-- Name: ix_metas_gate_vend_emp_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_gate_vend_emp_emp ON public.metas_gate_vendedor_emp USING btree (emp);


--
-- Name: ix_metas_gate_vend_emp_usuario; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_gate_vend_emp_usuario ON public.metas_gate_vendedor_emp USING btree (usuario_id);


--
-- Name: ix_metas_gate_vendedor_emp_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_gate_vendedor_emp_emp ON public.metas_gate_vendedor_emp USING btree (emp);


--
-- Name: ix_metas_gate_vendedor_emp_usuario; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_gate_vendedor_emp_usuario ON public.metas_gate_vendedor_emp USING btree (usuario_id);


--
-- Name: ix_metas_marcas_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_marcas_marca ON public.metas_marcas USING btree (marca);


--
-- Name: ix_metas_marcas_meta; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_marcas_meta ON public.metas_marcas USING btree (meta_id);


--
-- Name: ix_metas_programas_emps_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_programas_emps_ativo ON public.metas_programas_emps USING btree (meta_id, ativo, emp);


--
-- Name: ix_metas_programas_emps_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_programas_emps_emp ON public.metas_programas_emps USING btree (emp);


--
-- Name: ix_metas_programas_emps_meta; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_programas_emps_meta ON public.metas_programas_emps USING btree (meta_id);


--
-- Name: ix_metas_programas_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_programas_periodo ON public.metas_programas USING btree (ano, mes);


--
-- Name: ix_metas_programas_tipo_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_programas_tipo_periodo ON public.metas_programas USING btree (tipo, ano, mes);


--
-- Name: ix_metas_recomp_loja_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_recomp_loja_emp ON public.metas_recompensas_loja_itens USING btree (emp);


--
-- Name: ix_metas_recomp_loja_emp_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_recomp_loja_emp_ativo ON public.metas_recompensas_loja_itens USING btree (emp, ativo);


--
-- Name: ix_metas_recompensas_loja_itens_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_recompensas_loja_itens_emp ON public.metas_recompensas_loja_itens USING btree (emp);


--
-- Name: ix_metas_recompensas_loja_itens_mestre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_recompensas_loja_itens_mestre ON public.metas_recompensas_loja_itens USING btree (mestre);


--
-- Name: ix_metas_resultados_emp_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_resultados_emp_periodo ON public.metas_resultados USING btree (emp, ano, mes);


--
-- Name: ix_metas_resultados_meta_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_metas_resultados_meta_periodo ON public.metas_resultados USING btree (meta_id, ano, mes);


--
-- Name: ix_mld_usuario_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mld_usuario_data ON public.mensagem_lidas_diarias USING btree (usuario_id, data);


--
-- Name: ix_msg_emp_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_msg_emp_emp ON public.mensagem_empresas USING btree (emp);


--
-- Name: ix_msg_emp_mensagem_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_msg_emp_mensagem_id ON public.mensagem_empresas USING btree (mensagem_id);


--
-- Name: ix_msg_lidas_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_msg_lidas_data ON public.mensagem_lidas_diarias USING btree (data);


--
-- Name: ix_msg_lidas_usuario_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_msg_lidas_usuario_data ON public.mensagem_lidas_diarias USING btree (usuario_id, data);


--
-- Name: ix_msg_usr_mensagem_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_msg_usr_mensagem_id ON public.mensagem_usuarios USING btree (mensagem_id);


--
-- Name: ix_msg_usr_usuario_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_msg_usr_usuario_id ON public.mensagem_usuarios USING btree (usuario_id);


--
-- Name: ix_rank_marca_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_comp ON public.campanhas_ranking_marca USING btree (competencia_ano, competencia_mes);


--
-- Name: ix_rank_marca_emps_campanha; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_emps_campanha ON public.campanhas_ranking_marca_emps USING btree (campanha_id);


--
-- Name: ix_rank_marca_emps_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_emps_emp ON public.campanhas_ranking_marca_emps USING btree (emp);


--
-- Name: ix_rank_marca_escopo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_escopo ON public.campanhas_ranking_marca USING btree (escopo_tipo);


--
-- Name: ix_rank_marca_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_marca ON public.campanhas_ranking_marca USING btree (marca);


--
-- Name: ix_rank_marca_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_periodo ON public.campanhas_ranking_marca USING btree (marca, data_inicio, data_fim);


--
-- Name: ix_rank_marca_premios_campanha; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_premios_campanha ON public.campanhas_ranking_marca_premios USING btree (campanha_id);


--
-- Name: ix_rank_marca_res_emp_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_res_emp_comp ON public.campanhas_ranking_marca_resultados USING btree (emp, competencia_ano, competencia_mes);


--
-- Name: ix_rank_marca_res_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_res_status ON public.campanhas_ranking_marca_resultados USING btree (status_pagamento);


--
-- Name: ix_rank_marca_res_vendedor_comp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rank_marca_res_vendedor_comp ON public.campanhas_ranking_marca_resultados USING btree (vendedor, competencia_ano, competencia_mes);


--
-- Name: ix_usuario_emps_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usuario_emps_ativo ON public.usuario_emps USING btree (ativo);


--
-- Name: ix_usuario_emps_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usuario_emps_emp ON public.usuario_emps USING btree (emp);


--
-- Name: ix_usuario_emps_usuario_ativo_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usuario_emps_usuario_ativo_emp ON public.usuario_emps USING btree (usuario_id, ativo, emp);


--
-- Name: ix_usuario_emps_usuario_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usuario_emps_usuario_id ON public.usuario_emps USING btree (usuario_id);


--
-- Name: ix_usuarios_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usuarios_role ON public.usuarios USING btree (role);


--
-- Name: ix_vendas_ano_mes_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_ano_mes_emp ON public.vendas USING btree (ano, mes, emp);


--
-- Name: ix_vendas_cidade_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_cidade_data ON public.vendas USING btree (cidade_norm, movimento);


--
-- Name: ix_vendas_cliente_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_cliente_data ON public.vendas USING btree (cliente_id_norm, movimento);


--
-- Name: ix_vendas_emp_cidade; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_emp_cidade ON public.vendas USING btree (emp, cidade);


--
-- Name: ix_vendas_emp_cliente; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_emp_cliente ON public.vendas USING btree (emp, cnpj_cpf);


--
-- Name: ix_vendas_emp_cliente_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_emp_cliente_mes ON public.vendas USING btree (ano, mes, emp, cnpj_cpf);


--
-- Name: ix_vendas_emp_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_emp_data ON public.vendas USING btree (emp, movimento);


--
-- Name: ix_vendas_emp_movimento_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_emp_movimento_vendedor ON public.vendas USING btree (emp, movimento, vendedor);


--
-- Name: ix_vendas_emp_vendedor_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_emp_vendedor_mes ON public.vendas USING btree (ano, mes, emp, vendedor);


--
-- Name: ix_vendas_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_marca ON public.vendas USING btree (marca);


--
-- Name: ix_vendas_marca_data_emp_vend; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_marca_data_emp_vend ON public.vendas USING btree (marca, movimento, emp, vendedor);


--
-- Name: ix_vendas_movimento_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_movimento_emp ON public.vendas USING btree (movimento, emp);


--
-- Name: ix_vendas_oa_emp_mestre_movimento_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_oa_emp_mestre_movimento_vendedor ON public.vendas USING btree (emp, mestre, movimento, vendedor) WHERE ((mov_tipo_movto)::text = 'OA'::text);


--
-- Name: ix_vendas_relatorio_ativos_emp_vendedor_mov_mestre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_relatorio_ativos_emp_vendedor_mov_mestre ON public.vendas USING btree (emp, vendedor, movimento, mestre) WHERE (((mov_tipo_movto)::text <> 'DS'::text) AND ((mov_tipo_movto)::text <> 'CA'::text));


--
-- Name: ix_vendas_relatorio_oa_emp_mestre_mov_vendedor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_relatorio_oa_emp_mestre_mov_vendedor ON public.vendas USING btree (emp, mestre, movimento, vendedor) WHERE ((mov_tipo_movto)::text = 'OA'::text);


--
-- Name: ix_vendas_relatorio_validas_emp_mov_mestre_vend; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_relatorio_validas_emp_mov_mestre_vend ON public.vendas USING btree (emp, movimento, mestre, vendedor) WHERE (((mov_tipo_movto)::text <> 'DS'::text) AND ((mov_tipo_movto)::text <> 'CA'::text));


--
-- Name: ix_vendas_relatorio_venda_emp_mestre_mov_vend; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_relatorio_venda_emp_mestre_mov_vend ON public.vendas USING btree (emp, mestre, movimento, vendedor) WHERE (upper((COALESCE(mov_tipo_movto, ''::character varying))::text) = ANY (ARRAY['OA'::text, 'VV'::text, 'SV'::text]));


--
-- Name: ix_vendas_vendedor_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vendas_vendedor_data ON public.vendas USING btree (vendedor, movimento);


--
-- Name: uq_camp_v2_result_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_camp_v2_result_key ON public.campanhas_v2_resultados USING btree (campanha_id, ano, mes, emp, vendedor);


--
-- Name: uq_camp_v2_scope_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_camp_v2_scope_emp ON public.campanhas_scope_emp_v2 USING btree (campanha_id, emp);


--
-- Name: uq_fechamento_mensal; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_fechamento_mensal ON public.fechamento_mensal USING btree (emp, ano, mes);


--
-- Name: uq_fin_pag_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_fin_pag_key ON public.financeiro_pagamentos USING btree (ano, mes, origem_tipo, origem_id, emp, vendedor);


--
-- Name: uq_meta_base_manual; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_meta_base_manual ON public.metas_bases_manuais USING btree (meta_id, emp, vendedor);


--
-- Name: uq_meta_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_meta_emp ON public.metas_programas_emps USING btree (meta_id, emp);


--
-- Name: uq_meta_escala_ordem; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_meta_escala_ordem ON public.metas_escalas USING btree (meta_id, ordem);


--
-- Name: uq_meta_marca; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_meta_marca ON public.metas_marcas USING btree (meta_id, marca);


--
-- Name: uq_meta_resultado; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_meta_resultado ON public.metas_resultados USING btree (meta_id, emp, vendedor, ano, mes);


--
-- Name: uq_metas_gate_vend_emp_v2; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_metas_gate_vend_emp_v2 ON public.metas_gate_vendedor_emp USING btree (emp, usuario_id, ano, mes);


--
-- Name: uq_metas_gate_vendedor_emp_emp_usuario_ano_mes; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_metas_gate_vendedor_emp_emp_usuario_ano_mes ON public.metas_gate_vendedor_emp USING btree (emp, usuario_id, ano, mes);


--
-- Name: uq_vendas_resumo_periodo; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_vendas_resumo_periodo ON public.vendas_resumo_periodo USING btree (COALESCE(emp, ''::text), vendedor, ano, mes);


--
-- Name: ux_cache_cidades_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_cache_cidades_emp ON public.cache_cidades_emp USING btree (ano, mes, emp, COALESCE(vendedor, ''::text));


--
-- Name: ux_cache_cliente_marcas; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_cache_cliente_marcas ON public.cache_cliente_marcas USING btree (ano, mes, emp, COALESCE(vendedor, ''::text), cliente_id);


--
-- Name: ux_cache_clientes_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_cache_clientes_emp ON public.cache_clientes_emp USING btree (ano, mes, emp, COALESCE(vendedor, ''::text));


--
-- Name: ux_me_mensagem_emp; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_me_mensagem_emp ON public.mensagem_empresas USING btree (mensagem_id, emp);


--
-- Name: ux_mld_mensagem_usuario_data; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_mld_mensagem_usuario_data ON public.mensagem_lidas_diarias USING btree (mensagem_id, usuario_id, data);


--
-- Name: ux_mu_mensagem_usuario; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_mu_mensagem_usuario ON public.mensagem_usuarios USING btree (mensagem_id, usuario_id);


--
-- Name: ix_realtime_subscription_entity; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX ix_realtime_subscription_entity ON realtime.subscription USING btree (entity);


--
-- Name: messages_inserted_at_topic_index; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_inserted_at_topic_index ON ONLY realtime.messages USING btree (inserted_at DESC, topic) WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));


--
-- Name: subscription_subscription_id_entity_filters_action_filter_selec; Type: INDEX; Schema: realtime; Owner: -
--

CREATE UNIQUE INDEX subscription_subscription_id_entity_filters_action_filter_selec ON realtime.subscription USING btree (subscription_id, entity, filters, action_filter, COALESCE(selected_columns, '{}'::text[]));


--
-- Name: bname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX bname ON storage.buckets USING btree (name);


--
-- Name: bucketid_objname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX bucketid_objname ON storage.objects USING btree (bucket_id, name);


--
-- Name: buckets_analytics_unique_name_idx; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX buckets_analytics_unique_name_idx ON storage.buckets_analytics USING btree (name) WHERE (deleted_at IS NULL);


--
-- Name: idx_multipart_uploads_list; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX idx_multipart_uploads_list ON storage.s3_multipart_uploads USING btree (bucket_id, key, created_at);


--
-- Name: idx_objects_bucket_id_name; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX idx_objects_bucket_id_name ON storage.objects USING btree (bucket_id, name COLLATE "C");


--
-- Name: idx_objects_bucket_id_name_lower; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX idx_objects_bucket_id_name_lower ON storage.objects USING btree (bucket_id, lower(name) COLLATE "C");


--
-- Name: name_prefix_search; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX name_prefix_search ON storage.objects USING btree (name text_pattern_ops);


--
-- Name: vector_indexes_name_bucket_id_idx; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX vector_indexes_name_bucket_id_idx ON storage.vector_indexes USING btree (name, bucket_id);


--
-- Name: campanhas_v2_master trg_camp_v2_master_touch; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_camp_v2_master_touch BEFORE UPDATE ON public.campanhas_v2_master FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();


--
-- Name: financeiro_pagamentos trg_fin_pag_touch; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_fin_pag_touch BEFORE UPDATE ON public.financeiro_pagamentos FOR EACH ROW EXECUTE FUNCTION public._touch_financeiro_updated_at();


--
-- Name: subscription tr_check_filters; Type: TRIGGER; Schema: realtime; Owner: -
--

CREATE TRIGGER tr_check_filters BEFORE INSERT OR UPDATE ON realtime.subscription FOR EACH ROW EXECUTE FUNCTION realtime.subscription_check_filters();


--
-- Name: buckets enforce_bucket_name_length_trigger; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER enforce_bucket_name_length_trigger BEFORE INSERT OR UPDATE OF name ON storage.buckets FOR EACH ROW EXECUTE FUNCTION storage.enforce_bucket_name_length();


--
-- Name: buckets protect_buckets_delete; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER protect_buckets_delete BEFORE DELETE ON storage.buckets FOR EACH STATEMENT EXECUTE FUNCTION storage.protect_delete();


--
-- Name: objects protect_objects_delete; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER protect_objects_delete BEFORE DELETE ON storage.objects FOR EACH STATEMENT EXECUTE FUNCTION storage.protect_delete();


--
-- Name: objects update_objects_updated_at; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER update_objects_updated_at BEFORE UPDATE ON storage.objects FOR EACH ROW EXECUTE FUNCTION storage.update_updated_at_column();


--
-- Name: identities identities_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: mfa_amr_claims mfa_amr_claims_session_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT mfa_amr_claims_session_id_fkey FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE;


--
-- Name: mfa_challenges mfa_challenges_auth_factor_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_challenges
    ADD CONSTRAINT mfa_challenges_auth_factor_id_fkey FOREIGN KEY (factor_id) REFERENCES auth.mfa_factors(id) ON DELETE CASCADE;


--
-- Name: mfa_factors mfa_factors_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT mfa_factors_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: oauth_authorizations oauth_authorizations_client_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_client_id_fkey FOREIGN KEY (client_id) REFERENCES auth.oauth_clients(id) ON DELETE CASCADE;


--
-- Name: oauth_authorizations oauth_authorizations_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: oauth_consents oauth_consents_client_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_consents
    ADD CONSTRAINT oauth_consents_client_id_fkey FOREIGN KEY (client_id) REFERENCES auth.oauth_clients(id) ON DELETE CASCADE;


--
-- Name: oauth_consents oauth_consents_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_consents
    ADD CONSTRAINT oauth_consents_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: one_time_tokens one_time_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.one_time_tokens
    ADD CONSTRAINT one_time_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_session_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_session_id_fkey FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE;


--
-- Name: saml_providers saml_providers_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: saml_relay_states saml_relay_states_flow_state_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_flow_state_id_fkey FOREIGN KEY (flow_state_id) REFERENCES auth.flow_state(id) ON DELETE CASCADE;


--
-- Name: saml_relay_states saml_relay_states_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_oauth_client_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_oauth_client_id_fkey FOREIGN KEY (oauth_client_id) REFERENCES auth.oauth_clients(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: sso_domains sso_domains_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_domains
    ADD CONSTRAINT sso_domains_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: webauthn_challenges webauthn_challenges_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.webauthn_challenges
    ADD CONSTRAINT webauthn_challenges_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: webauthn_credentials webauthn_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: campanhas_emps campanhas_emps_campanha_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_emps
    ADD CONSTRAINT campanhas_emps_campanha_id_fkey FOREIGN KEY (campanha_id) REFERENCES public.campanhas(id) ON DELETE CASCADE;


--
-- Name: campanhas_resultados campanhas_resultados_campanha_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_resultados
    ADD CONSTRAINT campanhas_resultados_campanha_id_fkey FOREIGN KEY (campanha_id) REFERENCES public.campanhas(id) ON DELETE CASCADE;


--
-- Name: campanhas_v2_resultados campanhas_v2_resultados_campanha_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_v2_resultados
    ADD CONSTRAINT campanhas_v2_resultados_campanha_id_fkey FOREIGN KEY (campanha_id) REFERENCES public.campanhas_v2_master(id) ON DELETE CASCADE;


--
-- Name: financeiro_audit financeiro_audit_pagamento_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.financeiro_audit
    ADD CONSTRAINT financeiro_audit_pagamento_id_fkey FOREIGN KEY (pagamento_id) REFERENCES public.financeiro_pagamentos(id) ON DELETE CASCADE;


--
-- Name: campanhas_qtd_resultados fk_campanha_qtd_resultados_campanha_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_qtd_resultados
    ADD CONSTRAINT fk_campanha_qtd_resultados_campanha_id FOREIGN KEY (campanha_id) REFERENCES public.campanhas_qtd(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: campanhas_combo_itens fk_combo_itens_combo_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_combo_itens
    ADD CONSTRAINT fk_combo_itens_combo_id FOREIGN KEY (combo_id) REFERENCES public.campanhas_combo(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: campanhas_combo_resultados fk_combo_resultados_combo_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campanhas_combo_resultados
    ADD CONSTRAINT fk_combo_resultados_combo_id FOREIGN KEY (combo_id) REFERENCES public.campanhas_combo(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: mensagem_empresas fk_mensagem_empresas_emp; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_empresas
    ADD CONSTRAINT fk_mensagem_empresas_emp FOREIGN KEY (emp) REFERENCES public.emps(codigo) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: mensagem_empresas fk_mensagem_empresas_mensagem_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_empresas
    ADD CONSTRAINT fk_mensagem_empresas_mensagem_id FOREIGN KEY (mensagem_id) REFERENCES public.mensagens(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: mensagem_lidas_diarias fk_mensagem_lidas_diarias_mensagem_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_lidas_diarias
    ADD CONSTRAINT fk_mensagem_lidas_diarias_mensagem_id FOREIGN KEY (mensagem_id) REFERENCES public.mensagens(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: mensagem_lidas_diarias fk_mensagem_lidas_diarias_usuario_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_lidas_diarias
    ADD CONSTRAINT fk_mensagem_lidas_diarias_usuario_id FOREIGN KEY (usuario_id) REFERENCES public.usuarios(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: mensagem_usuarios fk_mensagem_usuarios_mensagem_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_usuarios
    ADD CONSTRAINT fk_mensagem_usuarios_mensagem_id FOREIGN KEY (mensagem_id) REFERENCES public.mensagens(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: mensagem_usuarios fk_mensagem_usuarios_usuario_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mensagem_usuarios
    ADD CONSTRAINT fk_mensagem_usuarios_usuario_id FOREIGN KEY (usuario_id) REFERENCES public.usuarios(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: usuario_emps fk_usuario_emps_emp; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuario_emps
    ADD CONSTRAINT fk_usuario_emps_emp FOREIGN KEY (emp) REFERENCES public.emps(codigo) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: usuario_emps fk_usuario_emps_usuario_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuario_emps
    ADD CONSTRAINT fk_usuario_emps_usuario_id FOREIGN KEY (usuario_id) REFERENCES public.usuarios(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: itens_parados_pontos_resultados itens_parados_pontos_resultados_fechamento_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itens_parados_pontos_resultados
    ADD CONSTRAINT itens_parados_pontos_resultados_fechamento_id_fkey FOREIGN KEY (fechamento_id) REFERENCES public.itens_parados_pontos_fechamentos(id) ON DELETE CASCADE;


--
-- Name: metas_bases_manuais metas_bases_manuais_meta_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_bases_manuais
    ADD CONSTRAINT metas_bases_manuais_meta_id_fkey FOREIGN KEY (meta_id) REFERENCES public.metas_programas(id) ON DELETE CASCADE;


--
-- Name: metas_escalas metas_escalas_meta_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_escalas
    ADD CONSTRAINT metas_escalas_meta_id_fkey FOREIGN KEY (meta_id) REFERENCES public.metas_programas(id) ON DELETE CASCADE;


--
-- Name: metas_marcas metas_marcas_meta_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_marcas
    ADD CONSTRAINT metas_marcas_meta_id_fkey FOREIGN KEY (meta_id) REFERENCES public.metas_programas(id) ON DELETE CASCADE;


--
-- Name: metas_programas_emps metas_programas_emps_meta_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_programas_emps
    ADD CONSTRAINT metas_programas_emps_meta_id_fkey FOREIGN KEY (meta_id) REFERENCES public.metas_programas(id) ON DELETE CASCADE;


--
-- Name: metas_resultados metas_resultados_meta_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_resultados
    ADD CONSTRAINT metas_resultados_meta_id_fkey FOREIGN KEY (meta_id) REFERENCES public.metas_programas(id) ON DELETE CASCADE;


--
-- Name: metas_v2_criterios metas_v2_criterios_programa_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_criterios
    ADD CONSTRAINT metas_v2_criterios_programa_id_fkey FOREIGN KEY (programa_id) REFERENCES public.metas_v2_programas(id) ON DELETE CASCADE;


--
-- Name: metas_v2_faixas metas_v2_faixas_criterio_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_faixas
    ADD CONSTRAINT metas_v2_faixas_criterio_id_fkey FOREIGN KEY (criterio_id) REFERENCES public.metas_v2_criterios(id) ON DELETE CASCADE;


--
-- Name: metas_v2_programa_emps metas_v2_programa_emps_programa_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_programa_emps
    ADD CONSTRAINT metas_v2_programa_emps_programa_id_fkey FOREIGN KEY (programa_id) REFERENCES public.metas_v2_programas(id) ON DELETE CASCADE;


--
-- Name: metas_v2_resultados metas_v2_resultados_programa_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metas_v2_resultados
    ADD CONSTRAINT metas_v2_resultados_programa_id_fkey FOREIGN KEY (programa_id) REFERENCES public.metas_v2_programas(id) ON DELETE CASCADE;


--
-- Name: pagamentos pagamentos_campanha_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pagamentos
    ADD CONSTRAINT pagamentos_campanha_id_fkey FOREIGN KEY (campanha_id) REFERENCES public.campanhas(id) ON DELETE SET NULL;


--
-- Name: objects objects_bucketId_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.objects
    ADD CONSTRAINT "objects_bucketId_fkey" FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: s3_multipart_uploads s3_multipart_uploads_bucket_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads
    ADD CONSTRAINT s3_multipart_uploads_bucket_id_fkey FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: s3_multipart_uploads_parts s3_multipart_uploads_parts_bucket_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads_parts
    ADD CONSTRAINT s3_multipart_uploads_parts_bucket_id_fkey FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: s3_multipart_uploads_parts s3_multipart_uploads_parts_upload_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads_parts
    ADD CONSTRAINT s3_multipart_uploads_parts_upload_id_fkey FOREIGN KEY (upload_id) REFERENCES storage.s3_multipart_uploads(id) ON DELETE CASCADE;


--
-- Name: vector_indexes vector_indexes_bucket_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.vector_indexes
    ADD CONSTRAINT vector_indexes_bucket_id_fkey FOREIGN KEY (bucket_id) REFERENCES storage.buckets_vectors(id);


--
-- Name: audit_log_entries; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.audit_log_entries ENABLE ROW LEVEL SECURITY;

--
-- Name: flow_state; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.flow_state ENABLE ROW LEVEL SECURITY;

--
-- Name: identities; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.identities ENABLE ROW LEVEL SECURITY;

--
-- Name: instances; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.instances ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_amr_claims; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.mfa_amr_claims ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_challenges; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.mfa_challenges ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_factors; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.mfa_factors ENABLE ROW LEVEL SECURITY;

--
-- Name: one_time_tokens; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.one_time_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: refresh_tokens; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.refresh_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: saml_providers; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.saml_providers ENABLE ROW LEVEL SECURITY;

--
-- Name: saml_relay_states; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.saml_relay_states ENABLE ROW LEVEL SECURITY;

--
-- Name: schema_migrations; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.schema_migrations ENABLE ROW LEVEL SECURITY;

--
-- Name: sessions; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: sso_domains; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.sso_domains ENABLE ROW LEVEL SECURITY;

--
-- Name: sso_providers; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.sso_providers ENABLE ROW LEVEL SECURITY;

--
-- Name: users; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;

--
-- Name: messages; Type: ROW SECURITY; Schema: realtime; Owner: -
--

ALTER TABLE realtime.messages ENABLE ROW LEVEL SECURITY;

--
-- Name: objects Public read branding; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Public read branding" ON storage.objects FOR SELECT USING ((bucket_id = 'branding'::text));


--
-- Name: objects Service role delete branding; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Service role delete branding" ON storage.objects FOR DELETE TO service_role USING ((bucket_id = 'branding'::text));


--
-- Name: objects Service role insert branding; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Service role insert branding" ON storage.objects FOR INSERT TO service_role WITH CHECK ((bucket_id = 'branding'::text));


--
-- Name: objects Service role update branding; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Service role update branding" ON storage.objects FOR UPDATE TO service_role USING ((bucket_id = 'branding'::text)) WITH CHECK ((bucket_id = 'branding'::text));


--
-- Name: buckets; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY;

--
-- Name: buckets_analytics; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.buckets_analytics ENABLE ROW LEVEL SECURITY;

--
-- Name: buckets_vectors; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.buckets_vectors ENABLE ROW LEVEL SECURITY;

--
-- Name: migrations; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.migrations ENABLE ROW LEVEL SECURITY;

--
-- Name: objects; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;

--
-- Name: s3_multipart_uploads; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.s3_multipart_uploads ENABLE ROW LEVEL SECURITY;

--
-- Name: s3_multipart_uploads_parts; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.s3_multipart_uploads_parts ENABLE ROW LEVEL SECURITY;

--
-- Name: vector_indexes; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.vector_indexes ENABLE ROW LEVEL SECURITY;

--
-- Name: supabase_realtime; Type: PUBLICATION; Schema: -; Owner: -
--

CREATE PUBLICATION supabase_realtime WITH (publish = 'insert, update, delete, truncate');


--
-- Name: issue_graphql_placeholder; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_graphql_placeholder ON sql_drop
         WHEN TAG IN ('DROP EXTENSION')
   EXECUTE FUNCTION extensions.set_graphql_placeholder();


--
-- Name: issue_pg_cron_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_cron_access ON ddl_command_end
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION extensions.grant_pg_cron_access();


--
-- Name: issue_pg_graphql_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_graphql_access ON ddl_command_end
         WHEN TAG IN ('CREATE FUNCTION')
   EXECUTE FUNCTION extensions.grant_pg_graphql_access();


--
-- Name: issue_pg_net_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_net_access ON ddl_command_end
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION extensions.grant_pg_net_access();


--
-- Name: pgrst_ddl_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER pgrst_ddl_watch ON ddl_command_end
   EXECUTE FUNCTION extensions.pgrst_ddl_watch();


--
-- Name: pgrst_drop_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER pgrst_drop_watch ON sql_drop
   EXECUTE FUNCTION extensions.pgrst_drop_watch();


--
-- PostgreSQL database dump complete
--

\unrestrict HzXpOAQF3dfFDGmBlhiHKQudfRvyu5FHutkvuVEV2gQqcSPOabMEZOcM9WqyBbE

