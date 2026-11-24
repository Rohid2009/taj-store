-- TAJ STORE: schema, helpers, triggers, RLS
create sequence if not exists public.uid_seq start 1000;

create table public.profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  uid bigint unique not null default nextval('public.uid_seq'),
  role text not null default 'buyer' check (role in ('buyer','seller','admin')),
  sid bigint,
  blocked boolean not null default false,
  d jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  del boolean not null default false);

create table public.stores  (id bigint primary key, uid bigint, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.products(id bigint primary key, sid bigint not null, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.cats    (id text primary key, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.orders  (id text primary key, buyer bigint not null, sids bigint[] not null default '{}', d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.chats   (id bigint primary key, buyer bigint not null, sid bigint not null default 0, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false, unique(buyer,sid));
create table public.msgs    (id text primary key, chat bigint not null references public.chats(id) on delete cascade, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.reviews (id bigint primary key, uid bigint, pid bigint, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.qa      (id bigint primary key, uid bigint, pid bigint, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.banners (id bigint primary key, sid bigint not null default 0, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.coupons (id text primary key, sid bigint, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.settings(id text primary key, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.notes   (id text primary key, to_uid bigint not null, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.used    (id text primary key, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.cu      (id text primary key, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.pts     (id bigint primary key, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.po      (id bigint primary key, sid bigint not null, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);
create table public.prefs   (id bigint primary key, d jsonb not null, updated_at timestamptz not null default now(), del boolean not null default false);

create index on public.products(updated_at); create index on public.products(sid);
create index on public.orders(updated_at); create index on public.orders(buyer); create index on public.orders using gin(sids);
create index on public.chats(updated_at); create index on public.chats(sid);
create index on public.msgs(updated_at); create index on public.msgs(chat);
create index on public.notes(to_uid, updated_at);
create index on public.stores(updated_at); create index on public.reviews(updated_at); create index on public.qa(updated_at);
create index on public.banners(updated_at); create index on public.coupons(updated_at); create index on public.cats(updated_at);
create index on public.profiles(updated_at); create index on public.po(sid); create index on public.pts(updated_at); create index on public.cu(updated_at); create index on public.used(updated_at); create index on public.prefs(updated_at);

-- helpers (security definer: they read profiles without RLS recursion)
create or replace function public.my_uid() returns bigint language sql stable security definer set search_path=public as
$$ select uid from public.profiles where id = auth.uid() and not blocked $$;
create or replace function public.my_sid() returns bigint language sql stable security definer set search_path=public as
$$ select sid from public.profiles where id = auth.uid() and role = 'seller' and not blocked $$;
create or replace function public.is_admin() returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from public.profiles where id = auth.uid() and role = 'admin' and not blocked) $$;
-- true for SQL editor / service role (no end-user JWT) and for admins
create or replace function public.priv() returns boolean language sql stable security definer set search_path=public as
$$ select coalesce(auth.role(),'service_role') = 'service_role' or public.is_admin() $$;

-- updated_at
create or replace function public.touch() returns trigger language plpgsql set search_path=public as
$$ begin new.updated_at := clock_timestamp(); return new; end $$;
do $$ declare t text; begin
  foreach t in array array['profiles','stores','products','cats','orders','chats','msgs','reviews','qa','banners','coupons','settings','notes','used','cu','pts','po','prefs'] loop
    execute format('create trigger touch before insert or update on public.%I for each row execute function public.touch()', t);
    execute format('alter table public.%I enable row level security', t);
  end loop; end $$;

-- product fields that a buyer's order may change: stock, popularity, flash quantity left, waitlist
create or replace function public.prod_core(d jsonb) returns jsonb language sql immutable set search_path=public as
$$ select (d - 'pop' - 'wait' - 'vs' - 'flash')
   || jsonb_build_object('vs', coalesce((select jsonb_agg(v - 'st' order by o) from jsonb_array_elements(case when jsonb_typeof(d->'vs')='array' then d->'vs' else '[]'::jsonb end) with ordinality x(v,o)),'[]'::jsonb))
   || jsonb_build_object('flash', case when jsonb_typeof(d->'flash')='object' then (d->'flash') - 'left' else d->'flash' end) $$;

-- guards
create or replace function public.g_profiles() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if public.priv() then return new; end if;
  new.id := old.id; new.uid := old.uid; new.blocked := old.blocked; new.del := old.del;
  if new.role is distinct from old.role or new.sid is distinct from old.sid then
    if not (old.role = 'buyer' and new.role = 'seller' and exists(select 1 from public.stores s where s.id = new.sid and s.uid = old.uid)) then
      new.role := old.role; new.sid := old.sid;
    end if;
  end if;
  return new; end $$;
create trigger guard before update on public.profiles for each row execute function public.g_profiles();

create or replace function public.g_stores() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if public.priv() then return new; end if;
  if tg_op = 'INSERT' then new.d := new.d || '{"ver":"pending","blocked":false}'::jsonb; new.del := false; return new; end if;
  new.uid := old.uid; new.del := old.del;
  new.d := jsonb_set(jsonb_set(new.d,'{ver}',coalesce(old.d->'ver','"pending"'::jsonb)),'{blocked}',coalesce(old.d->'blocked','false'::jsonb));
  return new; end $$;
create trigger guard before insert or update on public.stores for each row execute function public.g_stores();

create or replace function public.g_products() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if public.priv() then return new; end if;
  if tg_op = 'INSERT' then
    if coalesce(new.d->>'ap','') = 'approved' then new.d := jsonb_set(new.d,'{ap}','"pending"'); end if;
    return new; end if;
  if new.sid <> old.sid then raise exception 'sid is read-only'; end if;
  if old.sid = public.my_sid() then
    if coalesce(new.d->>'ap','') = 'approved' and coalesce(old.d->>'ap','') <> 'approved' then new.d := jsonb_set(new.d,'{ap}',coalesce(old.d->'ap','"pending"')); end if;
    return new; end if;
  if public.prod_core(new.d) is distinct from public.prod_core(old.d) or new.del <> old.del then raise exception 'not allowed'; end if;
  return new; end $$;
create trigger guard before insert or update on public.products for each row execute function public.g_products();

create or replace function public.g_cats() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if public.priv() or tg_op = 'INSERT' then return new; end if;
  if (new.d - 'subs') is distinct from (old.d - 'subs') or not (coalesce(old.d->'subs','[]') <@ coalesce(new.d->'subs','[]')) or new.del <> old.del then raise exception 'not allowed'; end if;
  return new; end $$;
create trigger guard before insert or update on public.cats for each row execute function public.g_cats();

create or replace function public.g_orders() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if public.priv() or tg_op = 'INSERT' then return new; end if;
  new.buyer := old.buyer; new.sids := old.sids; new.del := old.del; return new; end $$;
create trigger guard before insert or update on public.orders for each row execute function public.g_orders();

create or replace function public.g_reviews() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if public.priv() or tg_op = 'INSERT' then return new; end if;
  new.uid := old.uid; new.pid := old.pid;
  if old.uid = public.my_uid() then return new; end if;
  if (new.d - 'hp') is distinct from (old.d - 'hp') or new.del <> old.del then raise exception 'not allowed'; end if;
  return new; end $$;
create trigger guard before insert or update on public.reviews for each row execute function public.g_reviews();

create or replace function public.g_qa() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if public.priv() or tg_op = 'INSERT' then return new; end if;
  new.uid := old.uid; new.pid := old.pid;
  if exists(select 1 from public.products p where p.id = old.pid and p.sid = public.my_sid()) then
    if (new.d - 'a' - 'ats') is distinct from (old.d - 'a' - 'ats') or new.del <> old.del then raise exception 'not allowed'; end if;
    return new; end if;
  if old.uid = public.my_uid() then
    if (new.d - 'q') is distinct from (old.d - 'q') then raise exception 'not allowed'; end if;
    return new; end if;
  raise exception 'not allowed'; end $$;
create trigger guard before insert or update on public.qa for each row execute function public.g_qa();

create or replace function public.g_chats() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if public.priv() or tg_op = 'INSERT' then return new; end if;
  new.buyer := old.buyer; new.sid := old.sid; new.del := old.del; return new; end $$;
create trigger guard before insert or update on public.chats for each row execute function public.g_chats();

-- policies
create policy r on public.profiles for select to authenticated using (id = auth.uid() or public.is_admin());
create policy u on public.profiles for update to authenticated using (id = auth.uid() or public.is_admin()) with check (id = auth.uid() or public.is_admin());

create policy r on public.stores for select to anon, authenticated using (true);
create policy i on public.stores for insert to authenticated with check (uid = public.my_uid() or public.is_admin());
create policy u on public.stores for update to authenticated using (public.is_admin() or id = public.my_sid()) with check (public.is_admin() or id = public.my_sid());

create policy r on public.products for select to anon, authenticated using (true);
create policy i on public.products for insert to authenticated with check (public.is_admin() or sid = public.my_sid());
create policy u on public.products for update to authenticated using (public.my_uid() is not null) with check (public.my_uid() is not null);

create policy r on public.cats for select to anon, authenticated using (true);
create policy i on public.cats for insert to authenticated with check (public.is_admin() or public.my_sid() is not null);
create policy u on public.cats for update to authenticated using (public.is_admin() or public.my_sid() is not null) with check (public.is_admin() or public.my_sid() is not null);

create policy r on public.orders for select to authenticated using (buyer = public.my_uid() or public.my_sid() = any(sids) or public.is_admin());
create policy i on public.orders for insert to authenticated with check (buyer = public.my_uid());
create policy u on public.orders for update to authenticated using (buyer = public.my_uid() or public.my_sid() = any(sids) or public.is_admin()) with check (buyer = public.my_uid() or public.my_sid() = any(sids) or public.is_admin());

create policy r on public.chats for select to authenticated using (buyer = public.my_uid() or (sid > 0 and sid = public.my_sid()) or public.is_admin());
create policy i on public.chats for insert to authenticated with check (buyer = public.my_uid());
create policy u on public.chats for update to authenticated using (buyer = public.my_uid() or (sid > 0 and sid = public.my_sid()) or public.is_admin()) with check (true);

create policy r on public.msgs for select to authenticated using (exists(select 1 from public.chats c where c.id = msgs.chat));
create policy i on public.msgs for insert to authenticated with check (exists(select 1 from public.chats c where c.id = msgs.chat));
create policy u on public.msgs for update to authenticated using (exists(select 1 from public.chats c where c.id = msgs.chat)) with check (exists(select 1 from public.chats c where c.id = msgs.chat));

create policy r on public.reviews for select to anon, authenticated using (true);
create policy i on public.reviews for insert to authenticated with check (uid = public.my_uid());
create policy u on public.reviews for update to authenticated using (public.my_uid() is not null) with check (public.my_uid() is not null);

create policy r on public.qa for select to anon, authenticated using (true);
create policy i on public.qa for insert to authenticated with check (uid = public.my_uid());
create policy u on public.qa for update to authenticated using (public.my_uid() is not null) with check (public.my_uid() is not null);

create policy r on public.banners for select to anon, authenticated using (true);
create policy i on public.banners for insert to authenticated with check (public.is_admin() or (sid > 0 and sid = public.my_sid()));
create policy u on public.banners for update to authenticated using (public.is_admin() or (sid > 0 and sid = public.my_sid())) with check (public.is_admin() or (sid > 0 and sid = public.my_sid()));

create policy r on public.coupons for select to anon, authenticated using (true);
create policy i on public.coupons for insert to authenticated with check (public.is_admin() or (sid is not null and sid = public.my_sid()));
create policy u on public.coupons for update to authenticated using (public.is_admin() or (sid is not null and sid = public.my_sid())) with check (public.is_admin() or (sid is not null and sid = public.my_sid()));

create policy r on public.settings for select to anon, authenticated using (true);
create policy i on public.settings for insert to authenticated with check (public.is_admin());
create policy u on public.settings for update to authenticated using (public.is_admin()) with check (public.is_admin());

create policy r on public.notes for select to authenticated using (to_uid = public.my_uid());
create policy i on public.notes for insert to authenticated with check (public.my_uid() is not null);
create policy u on public.notes for update to authenticated using (to_uid = public.my_uid()) with check (to_uid = public.my_uid());

create policy r on public.used for select to authenticated using (true);
create policy i on public.used for insert to authenticated with check (public.my_uid() is not null);

create policy r on public.cu for select to authenticated using (true);
create policy i on public.cu for insert to authenticated with check (public.my_uid() is not null);
create policy u on public.cu for update to authenticated using (public.my_uid() is not null) with check (public.my_uid() is not null);

create policy r on public.pts for select to authenticated using (id = public.my_uid() or public.is_admin() or public.my_sid() is not null);
create policy i on public.pts for insert to authenticated with check (public.is_admin() or public.my_sid() is not null);
create policy u on public.pts for update to authenticated using (public.is_admin() or public.my_sid() is not null) with check (public.is_admin() or public.my_sid() is not null);

create policy r on public.po for select to authenticated using (sid = public.my_sid() or public.is_admin());
create policy i on public.po for insert to authenticated with check (sid = public.my_sid());
create policy u on public.po for update to authenticated using (public.is_admin()) with check (public.is_admin());

create policy a on public.prefs for all to authenticated using (id = public.my_uid()) with check (id = public.my_uid());

-- privileges: no DELETE for app users (deletion is a soft "del" flag)
revoke all on all tables in schema public from anon, authenticated;
grant select on all tables in schema public to anon; -- rows are still filtered by RLS (anon only sees the public catalog)
grant select, insert, update on all tables in schema public to authenticated;
revoke insert on public.profiles from authenticated;

-- one call returns everything changed since a moment, filtered by RLS
create or replace function public.pull(since timestamptz) returns jsonb language sql stable security invoker set search_path=public as $$
select jsonb_build_object('now', now(),
 'profiles', coalesce((select jsonb_agg(jsonb_build_object('id',uid,'role',role,'sid',sid,'blocked',blocked,'d',d,'del',del)) from public.profiles where updated_at > since),'[]'),
 'settings', coalesce((select jsonb_agg(jsonb_build_object('id',id,'d',d,'del',del)) from public.settings where updated_at > since),'[]'),
 'cats',     coalesce((select jsonb_agg(jsonb_build_object('id',id,'d',d,'del',del)) from public.cats where updated_at > since),'[]'),
 'stores',   coalesce((select jsonb_agg(jsonb_build_object('id',id,'uid',uid,'d',d,'del',del)) from public.stores where updated_at > since),'[]'),
 'products', coalesce((select jsonb_agg(jsonb_build_object('id',id,'sid',sid,'d',d,'del',del)) from public.products where updated_at > since),'[]'),
 'banners',  coalesce((select jsonb_agg(jsonb_build_object('id',id,'sid',sid,'d',d,'del',del)) from public.banners where updated_at > since),'[]'),
 'coupons',  coalesce((select jsonb_agg(jsonb_build_object('id',id,'sid',sid,'d',d,'del',del)) from public.coupons where updated_at > since),'[]'),
 'reviews',  coalesce((select jsonb_agg(jsonb_build_object('id',id,'uid',uid,'pid',pid,'d',d,'del',del)) from public.reviews where updated_at > since),'[]'),
 'qa',       coalesce((select jsonb_agg(jsonb_build_object('id',id,'uid',uid,'pid',pid,'d',d,'del',del)) from public.qa where updated_at > since),'[]'),
 'orders',   coalesce((select jsonb_agg(jsonb_build_object('id',id,'buyer',buyer,'sids',sids,'d',d,'del',del)) from public.orders where updated_at > since),'[]'),
 'chats',    coalesce((select jsonb_agg(jsonb_build_object('id',id,'buyer',buyer,'sid',sid,'d',d,'del',del)) from public.chats where updated_at > since),'[]'),
 'msgs',     coalesce((select jsonb_agg(jsonb_build_object('id',id,'chat',chat,'d',d,'del',del)) from public.msgs where updated_at > since),'[]'),
 'notes',    coalesce((select jsonb_agg(jsonb_build_object('id',id,'to_uid',to_uid,'d',d,'del',del)) from public.notes where updated_at > since and not del),'[]'),
 'used',     coalesce((select jsonb_agg(jsonb_build_object('id',id,'d',d,'del',del)) from public.used where updated_at > since),'[]'),
 'cu',       coalesce((select jsonb_agg(jsonb_build_object('id',id,'d',d,'del',del)) from public.cu where updated_at > since),'[]'),
 'pts',      coalesce((select jsonb_agg(jsonb_build_object('id',id,'d',d,'del',del)) from public.pts where updated_at > since),'[]'),
 'po',       coalesce((select jsonb_agg(jsonb_build_object('id',id,'sid',sid,'d',d,'del',del)) from public.po where updated_at > since),'[]'),
 'prefs',    coalesce((select jsonb_agg(jsonb_build_object('id',id,'d',d,'del',del)) from public.prefs where updated_at > since),'[]'))
$$;
grant execute on function public.pull(timestamptz) to anon, authenticated;

-- public directory of sellers and admins (names only) so notifications can reach them
create or replace function public.directory() returns table(uid bigint, role text, sid bigint, name text) language sql stable security definer set search_path=public as
$$ select p.uid, p.role, p.sid, coalesce(p.d->>'name','') from public.profiles p where p.role in ('seller','admin') and not p.blocked and auth.uid() is not null $$;
revoke execute on function public.directory() from public, anon;
grant execute on function public.directory() to authenticated;

-- called only by the register edge function (service role): first account becomes admin
create or replace function public.register_profile(p_id uuid, p_name text, p_phone text) returns jsonb language plpgsql security definer set search_path=public as
$$ declare r text; u bigint; begin
  select case when exists(select 1 from public.profiles where role='admin') then 'buyer' else 'admin' end into r;
  insert into public.profiles(id, role, d) values (p_id, r, jsonb_build_object('name', p_name, 'phone', p_phone)) returning uid into u;
  update public.profiles set d = d || jsonb_build_object('id', u) where uid = u;
  return jsonb_build_object('uid', u, 'role', r); end $$;
revoke execute on function public.register_profile(uuid,text,text) from public, anon, authenticated;

revoke execute on function public.my_uid(), public.my_sid(), public.is_admin(), public.priv() from public, anon;
grant execute on function public.my_uid(), public.my_sid(), public.is_admin(), public.priv() to authenticated;

-- images
insert into storage.buckets(id, name, public, file_size_limit, allowed_mime_types)
values ('img','img',true,2097152,array['image/webp','image/jpeg','image/png']) on conflict (id) do nothing;
create policy "img upload" on storage.objects for insert to authenticated with check (bucket_id = 'img' and public.my_uid() is not null);
