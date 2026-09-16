create table if not exists products (
  id          bigserial primary key,
  name        varchar(120) not null,
  description text,
  price_cents integer not null
);
create table if not exists authors (
  id    bigserial primary key,
  name  varchar(120) not null,
  email varchar(200) not null
);
create table if not exists reviews (
  id         bigserial primary key,
  product_id bigint not null references products(id),
  author_id  bigint not null references authors(id),
  rating     integer not null,
  body       text
);
create index if not exists reviews_product_id_idx on reviews(product_id);
