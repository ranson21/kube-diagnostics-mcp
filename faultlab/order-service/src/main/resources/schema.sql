create table if not exists orders (
  id          bigserial primary key,
  total_cents integer not null,
  status      varchar(32) not null,
  created_at  timestamptz not null default now()
);
