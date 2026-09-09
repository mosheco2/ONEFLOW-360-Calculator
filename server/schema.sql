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


-- ============================================================
--  כניסת מנהל בסיסמה - שכבה נוספת מעל מפתח הגישה הגולמי (ADMIN_TOKEN),
--  כדי שהמנהל יוכל להתחבר עם סיסמה פשוטה מכל מכשיר, במקום להעתיק
--  את המפתח הארוך בכל פעם. המפתח הגולמי נשאר ככלי גיבוי/איפוס בלבד.
-- ============================================================
create table if not exists admin_credentials (
    id                   text primary key default 'admin',
    salt                 text,
    hash                 text,
    password_changed_at  timestamptz
);
insert into admin_credentials (id) values ('admin') on conflict (id) do nothing;

-- אסימוני כניסת מנהל - טבלה נפרדת מ-sessions כי אינם משויכים למחירון מסוים
create table if not exists admin_sessions (
    token      text primary key,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);
create index if not exists admin_sessions_expiry_idx on admin_sessions (expires_at);


-- ============================================================
--  פרופיל מיישם (חובה) והצעות מחיר
-- ============================================================

-- פרטי הפרופיל שהמיישם ממלא בכניסה הראשונה. נפרדים משם המחירון
-- ומשם המיישם שהמנהל בחר בעת היצירה, כדי לא לדרוס אותם.
alter table pricebooks add column if not exists profile_business_name text;
alter table pricebooks add column if not exists profile_business_id   text;
alter table pricebooks add column if not exists profile_contact_name text;
alter table pricebooks add column if not exists profile_phone        text;
alter table pricebooks add column if not exists profile_email        text;
alter table pricebooks add column if not exists profile_address      text;
alter table pricebooks add column if not exists profile_completed_at timestamptz;

-- הצעות מחיר - מסמך רשמי הנוצר מתוך אומדן, עם פרטי לקוח מלאים,
-- שלושה בלוקי טקסט, וסטטוס. האומדן המקורי (בטבלת quotes) אינו
-- נמחק ואינו משתנה בעת ההמרה.
create table if not exists proposals (
    id                  text primary key,
    pricebook_id        text        not null references pricebooks(id) on delete cascade,
    source_quote_id     text,
    created_by          text        not null default 'implementer', -- 'admin' | 'implementer'
    client_name         text        not null,
    client_business_id  text,
    client_contact_name text,
    client_phone        text,
    client_email        text,
    client_address      text,
    intro_text          text,
    terms_text          text,
    closing_text        text,
    selection           jsonb       not null default '{}'::jsonb,
    totals              jsonb       not null default '{}'::jsonb,
    status              text        not null default 'open'
                             check (status in ('open','approved','won','lost','expired')),
    retention_days       integer    not null default 14,
    retention_expires_at timestamptz not null default (now() + interval '14 days'),
    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now()
);
create index if not exists proposals_book_idx   on proposals (pricebook_id, updated_at desc);
create index if not exists proposals_client_idx on proposals (lower(trim(client_name)));
create index if not exists proposals_status_idx on proposals (status);
