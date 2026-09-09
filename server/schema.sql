-- מבנה מסד הנתונים. מורץ אוטומטית בכל עלייה של השרת.

create table if not exists pricebooks (
    id                  text primary key,
    kind                text        not null default 'implementer',
    label               text,
    implementer_name    text,
    auth_salt           text,
    auth_hash           text,
    password_changed_at timestamptz,
    last_login_at       timestamptz,
    disabled            boolean     not null default false,
    config              jsonb       not null default '{}'::jsonb,
    master_version      integer,
    version             integer     not null default 1,
    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now()
);

create table if not exists pricebook_versions (
    id               text primary key,
    pricebook_id     text        not null references pricebooks(id) on delete cascade,
    at               timestamptz not null default now(),
    note             text,
    version          integer,
    label            text,
    implementer_name text,
    config           jsonb       not null default '{}'::jsonb
);
create index if not exists pricebook_versions_book_idx on pricebook_versions (pricebook_id, at desc);

-- אומדנים שהמיישם שמר על שם לקוח
create table if not exists quotes (
    id               text primary key,
    pricebook_id     text        not null references pricebooks(id) on delete cascade,
    implementer_name text,
    client_name      text        not null,
    note             text,
    selection        jsonb       not null default '{}'::jsonb,
    totals           jsonb       not null default '{}'::jsonb,
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now()
);
create index if not exists quotes_book_idx   on quotes (pricebook_id, updated_at desc);
create index if not exists quotes_client_idx on quotes (lower(client_name));

-- אסימוני כניסה של מיישמים, נוצרים אחרי אימות סיסמה
create table if not exists sessions (
    token        text primary key,
    pricebook_id text        not null references pricebooks(id) on delete cascade,
    created_at   timestamptz not null default now(),
    expires_at   timestamptz not null
);
create index if not exists sessions_expiry_idx on sessions (expires_at);
