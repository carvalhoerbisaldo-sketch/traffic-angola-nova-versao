-- Traffic Angola: base de dados para autenticação e gestão segura dos parceiros.
-- Executar no SQL Editor do Supabase.

create extension if not exists pgcrypto;

create table if not exists public.partners (
  id integer primary key check (id between 1 and 4),
  display_name text not null,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

insert into public.partners (id, display_name)
values
  (1, 'Gestor 1'),
  (2, 'Gestor 2'),
  (3, 'Gestor 3'),
  (4, 'Gestor 4')
on conflict (id) do nothing;

create table if not exists public.partner_access_codes (
  id uuid primary key default gen_random_uuid(),
  partner_id integer not null references public.partners(id),
  code_hash text not null unique,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  created_by uuid
);

create unique index if not exists one_active_code_per_partner
  on public.partner_access_codes(partner_id) where active = true;

create table if not exists public.partner_sessions (
  id uuid primary key default gen_random_uuid(),
  partner_id integer not null references public.partners(id),
  token_hash text not null unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz
);

create index if not exists partner_sessions_partner_active_idx
  on public.partner_sessions(partner_id, expires_at) where revoked_at is null;

create table if not exists public.traffic_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Compatibilidade: a tabela traffic_admins pode já ter sido criada
-- manualmente antes desta migração, sem a coluna active.
alter table public.traffic_admins
  add column if not exists active boolean not null default true;

create table if not exists public.partner_login_limits (
  ip_hash text primary key,
  window_started_at timestamptz not null,
  attempts integer not null default 0,
  blocked_until timestamptz
);

-- Limite atómico: máximo de 10 tentativas por IP em 15 minutos.
create or replace function public.consume_partner_login_attempt(p_ip_hash text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row public.partner_login_limits%rowtype;
  v_now timestamptz := now();
begin
  insert into public.partner_login_limits(ip_hash, window_started_at, attempts)
  values (p_ip_hash, v_now, 1)
  on conflict (ip_hash) do nothing;

  select * into v_row
  from public.partner_login_limits
  where ip_hash = p_ip_hash
  for update;

  if v_row.blocked_until is not null and v_row.blocked_until > v_now then
    return false;
  end if;

  if v_row.window_started_at < v_now - interval '15 minutes' then
    update public.partner_login_limits
      set window_started_at = v_now, attempts = 1, blocked_until = null
      where ip_hash = p_ip_hash;
    return true;
  end if;

  if v_row.attempts >= 10 then
    update public.partner_login_limits
      set blocked_until = v_now + interval '15 minutes'
      where ip_hash = p_ip_hash;
    return false;
  end if;

  update public.partner_login_limits
    set attempts = attempts + 1
    where ip_hash = p_ip_hash;
  return true;
end;
$$;

revoke all on function public.consume_partner_login_attempt(text) from public, anon, authenticated;
grant execute on function public.consume_partner_login_attempt(text) to service_role;

-- As tabelas não são acessíveis directamente pelo browser. Apenas a Edge Function,
-- usando a service-role key guardada no servidor, pode consultá-las ou alterá-las.
alter table public.partners enable row level security;
alter table public.partner_access_codes enable row level security;
alter table public.partner_sessions enable row level security;
alter table public.traffic_admins enable row level security;
alter table public.partner_login_limits enable row level security;

revoke all on public.partners from anon, authenticated;
revoke all on public.partner_access_codes from anon, authenticated;
revoke all on public.partner_sessions from anon, authenticated;
revoke all on public.traffic_admins from anon, authenticated;
revoke all on public.partner_login_limits from anon, authenticated;

-- Após criar o utilizador administrador em Authentication > Users,
-- executar esta instrução substituindo o UUID pelo ID desse utilizador:
-- insert into public.traffic_admins(user_id) values ('UUID-DO-UTILIZADOR-AQUI');
