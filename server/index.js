// שרת ה-API של מחשבון ONEFLOW PRO.
// ללא תלויות מלבד pg: הניתוב, ה-CORS וההרשאות ממומשים ישירות מעל http.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT           = process.env.PORT || 10000;
const ORG_SLUG       = process.env.ORG_SLUG || 'onebtn_team';
const ADMIN_TOKEN    = process.env.ADMIN_TOKEN || '';
// אפשר יותר ממקור מותר אחד (למשל דומיין מותאם אישית + כתובת ה-onrender.com),
// מופרדים בפסיקים - כדי שלא כל שינוי דומיין ידרוש בחירה בין הישן לחדש
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || '*').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
const resolveOrigin = (req) => {
    if (ALLOWED_ORIGINS.includes('*')) return '*';
    const reqOrigin = ((req && req.headers && req.headers.origin) || '').replace(/\/+$/, '');
    if (reqOrigin && ALLOWED_ORIGINS.includes(reqOrigin)) return reqOrigin;
    return ALLOWED_ORIGINS[0] || '*';
};
const SESSION_DAYS   = Number(process.env.SESSION_DAYS || 30);

if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is required'); process.exit(1); }
if (!ADMIN_TOKEN) console.warn('WARNING: ADMIN_TOKEN is empty — admin actions are disabled.');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: /localhost|127\.0\.0\.1|\/tmp/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false }
});

// אותו גיבוב שהדפדפן מייצר בעת קביעת סיסמה, כדי ששני המצבים יהיו תואמים
const hashPassword = (password, salt) =>
    crypto.createHash('sha256').update(salt + '|' + password).digest('hex');
const newToken = () => crypto.randomBytes(32).toString('hex');
const newId = (p) => p + '_' + Date.now().toString(36) + crypto.randomBytes(4).toString('hex');

// ---------- תשתית בקשה ותשובה ----------
const send = (res, code, body) => {
    const payload = body === undefined || body === null ? '' : JSON.stringify(body);
    res.writeHead(code, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': resolveOrigin(res.req),
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-org-slug',
        'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
        'Access-Control-Max-Age': '86400',
        'Vary': 'Origin',
        'Content-Length': Buffer.byteLength(payload)
    });
    res.end(payload);
};
const readBody = (req) => new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => {
        data += c;
        if (data.length > 5e6) { reject(new Error('payload too large')); req.destroy(); }
    });
    req.on('end', () => {
        if (!data) return resolve({});
        try { resolve(JSON.parse(data)); } catch { reject(new Error('invalid json')); }
    });
    req.on('error', reject);
});

// ---------- זיהוי מבצע הבקשה ----------
// admin      - נושא את ADMIN_TOKEN, גישה מלאה
// implementer- נושא אסימון כניסה, מוגבל למחירון שלו
// anon       - ללא אסימון, קריאת master ואימות סיסמה בלבד
async function identify(req) {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    if (!token) return { role: 'anon' };
    if (ADMIN_TOKEN && crypto.timingSafeEqual(
            Buffer.from(token.padEnd(128).slice(0, 128)),
            Buffer.from(ADMIN_TOKEN.padEnd(128).slice(0, 128)))) {
        return { role: 'admin' };
    }
    // אסימון כניסת מנהל בסיסמה (POST /admin/login) - מעניק אותה הרשאה מלאה כמו המפתח הגולמי
    const adminSess = await pool.query(
        'select 1 from admin_sessions where token=$1 and expires_at > now()', [token]);
    if (adminSess.rows.length) return { role: 'admin' };
    const { rows } = await pool.query(
        'select pricebook_id from sessions where token=$1 and expires_at > now()', [token]);
    if (rows.length) return { role: 'implementer', pricebookId: rows[0].pricebook_id };
    return { role: 'anon' };
}

// ---------- המרות ----------
const profileOut = (r) => ({
    businessName: r.profile_business_name, businessId: r.profile_business_id,
    contactName: r.profile_contact_name, phone: r.profile_phone,
    email: r.profile_email, address: r.profile_address,
    completedAt: r.profile_completed_at
});
// כל שדות הפרופיל נדרשים - הפרופיל נחשב הושלם רק כששישתם מלאים
const PROFILE_FIELDS = ['profile_business_name','profile_business_id','profile_contact_name','profile_phone','profile_email','profile_address'];
const isProfileComplete = (r) => PROFILE_FIELDS.every(k => String(r[k] || '').trim());

const bookOut = (r) => r && ({
    id: r.id, kind: r.kind, label: r.label, implementerName: r.implementer_name,
    auth: r.auth_hash ? { salt: r.auth_salt, hash: r.auth_hash } : null,
    config: r.config, masterVersion: r.master_version, version: r.version,
    disabled: r.disabled, updatedAt: r.updated_at, createdAt: r.created_at,
    passwordChangedAt: r.password_changed_at, lastLoginAt: r.last_login_at,
    profile: profileOut(r), profileCompleted: isProfileComplete(r)
});
const bookSummary = (r) => ({
    id: r.id, label: r.label, kind: r.kind, implementerName: r.implementer_name,
    updatedAt: r.updated_at, version: r.version, hasPassword: !!r.auth_hash,
    disabled: r.disabled, passwordChangedAt: r.password_changed_at,
    lastLoginAt: r.last_login_at, quoteCount: Number(r.quote_count || 0),
    profile: profileOut(r), profileCompleted: isProfileComplete(r),
    openProposalCount: Number(r.open_proposal_count || 0),
    openProposalSum: Number(r.open_proposal_sum || 0)
});
const quoteOut = (r) => ({
    id: r.id, pricebookId: r.pricebook_id, implementerName: r.implementer_name,
    clientName: r.client_name, note: r.note, selection: r.selection, totals: r.totals,
    createdAt: r.created_at, updatedAt: r.updated_at,
    pricebookLabel: r.pricebook_label
});
const proposalOut = (r) => ({
    id: r.id, pricebookId: r.pricebook_id, sourceQuoteId: r.source_quote_id,
    createdBy: r.created_by,
    clientName: r.client_name, clientBusinessId: r.client_business_id,
    clientContactName: r.client_contact_name, clientPhone: r.client_phone,
    clientEmail: r.client_email, clientAddress: r.client_address,
    introText: r.intro_text, termsText: r.terms_text, closingText: r.closing_text,
    selection: r.selection, totals: r.totals, status: r.status,
    retentionDays: r.retention_days, retentionExpiresAt: r.retention_expires_at,
    createdAt: r.created_at, updatedAt: r.updated_at,
    pricebookLabel: r.pricebook_label, implementerName: r.implementer_name,
    // האומדן שממנו הצעה זו הומרה - נשלף מטבלת quotes אם עדיין קיים (ה-JOIN חיצוני, לכן ייתכן null)
    sourceQuote: r.source_quote_id ? {
        id: r.source_quote_id, clientName: r.sq_client_name, note: r.sq_note,
        totals: r.sq_totals, createdAt: r.sq_created_at, updatedAt: r.sq_updated_at
    } : null
});

// ---------- הניתוב ----------
async function route(req, res, url, who) {
    const seg = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    const m = req.method;

    if (seg[0] === 'health') return send(res, 200, { ok: true, org: ORG_SLUG });

    // ===== כניסת מנהל בסיסמה =====
    // שכבה נוחה מעל מפתח הגישה הגולמי: אחרי שמוגדרת סיסמה, המנהל יכול
    // להתחבר איתה מכל מכשיר, בלי להעתיק את המפתח הארוך בכל פעם. המפתח
    // הגולמי (ADMIN_TOKEN) עדיין עובד תמיד, כערוץ גיבוי/איפוס.
    if (seg[0] === 'admin' && seg[1] === 'status' && seg.length === 2 && m === 'GET') {
        const { rows } = await pool.query('select hash from admin_credentials where id=$1', ['admin']);
        return send(res, 200, { hasPassword: !!(rows.length && rows[0].hash) });
    }
    if (seg[0] === 'admin' && seg[1] === 'login' && seg.length === 2 && m === 'POST') {
        const body = await readBody(req);
        const { rows } = await pool.query('select * from admin_credentials where id=$1', ['admin']);
        const cred = rows[0];
        if (!cred || !cred.hash) return send(res, 400, { ok: false, error: 'no_password_set' });
        const ok = hashPassword(body.password || '', cred.salt) === cred.hash;
        if (!ok) return send(res, 401, { ok: false, error: 'bad password' });
        const token = newToken();
        const expiresAt = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
        await pool.query('insert into admin_sessions (token, expires_at) values ($1,$2)', [token, expiresAt]);
        return send(res, 200, { ok: true, token, expiresAt });
    }
    if (seg[0] === 'admin' && seg[1] === 'password' && seg.length === 2 && m === 'PUT') {
        if (who.role !== 'admin') return send(res, 403, { error: 'forbidden' });
        const body = await readBody(req);
        if (!body.password || String(body.password).length < 4) {
            return send(res, 400, { error: 'password must be at least 4 characters' });
        }
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = hashPassword(body.password, salt);
        await pool.query(`
            insert into admin_credentials (id, salt, hash, password_changed_at)
            values ('admin', $1, $2, now())
            on conflict (id) do update set salt=excluded.salt, hash=excluded.hash, password_changed_at=now()`,
            [salt, hash]);
        return send(res, 200, { ok: true });
    }

    // ===== אימות סיסמה =====
    // תמיד מנפיק אסימון כניסה בהצלחה, גם כאשר לא הוגדרה סיסמה למחירון -
    // כדי שהמיישם יהפוך למזוהה ויוכל לקרוא את המחירון שלו בבקשה הבאה.
    if (seg[0] === 'pricebooks' && seg[2] === 'auth' && m === 'POST') {
        const id = seg[1];
        const body = await readBody(req);
        const { rows } = await pool.query('select * from pricebooks where id=$1', [id]);
        if (!rows.length) return send(res, 404, { ok: false, error: 'not found' });
        const b = rows[0];
        if (b.disabled) return send(res, 403, { ok: false, error: 'disabled' });
        if (b.auth_hash && hashPassword(String(body.password || ''), b.auth_salt) !== b.auth_hash) {
            return send(res, 401, { ok: false, error: 'bad password' });
        }
        const token = newToken();
        const expires = new Date(Date.now() + SESSION_DAYS * 864e5);
        await pool.query('insert into sessions (token, pricebook_id, expires_at) values ($1,$2,$3)',
            [token, id, expires]);
        await pool.query('update pricebooks set last_login_at=now() where id=$1', [id]);
        await pool.query('delete from sessions where expires_at < now()');
        return send(res, 200, { ok: true, token, expiresAt: expires.toISOString() });
    }

    // ===== תקציר פומבי, בלי צורך באימות =====
    // מאפשר לממשק להציג את שם המחירון במסך הכניסה לפני שהמשתמש הזין סיסמה.
    if (seg[0] === 'pricebooks' && seg[2] === 'summary' && seg.length === 3 && m === 'GET') {
        const { rows } = await pool.query(
            'select id, label, kind, disabled, auth_hash from pricebooks where id=$1', [seg[1]]);
        if (!rows.length) return send(res, 404);
        const b = rows[0];
        return send(res, 200, { id: b.id, label: b.label, kind: b.kind,
                                disabled: b.disabled, hasPassword: !!b.auth_hash });
    }

    // ===== מחירונים =====
    const BOOK_LIST_SQL = `
        select p.*,
               (select count(*) from quotes q where q.pricebook_id = p.id) as quote_count,
               (select count(*) from proposals pr where pr.pricebook_id = p.id
                   and pr.status in ('open','approved')) as open_proposal_count,
               (select coalesce(sum((pr.totals->>'totalMRR')::numeric), 0) from proposals pr
                   where pr.pricebook_id = p.id and pr.status in ('open','approved')) as open_proposal_sum
        from pricebooks p`;
    if (seg[0] === 'pricebooks' && seg.length === 1 && m === 'GET') {
        if (who.role === 'admin') {
            const { rows } = await pool.query(
                BOOK_LIST_SQL + ` order by (p.kind='master') desc, p.label nulls last, p.id`);
            return send(res, 200, rows.map(bookSummary));
        }
        if (who.role === 'implementer') {
            const { rows } = await pool.query(BOOK_LIST_SQL + ` where p.id=$1`, [who.pricebookId]);
            return send(res, 200, rows.map(bookSummary));
        }
        return send(res, 200, []);
    }

    if (seg[0] === 'pricebooks' && seg.length === 2) {
        const id = seg[1];
        // אסימון שהתקבל מכניסה למאסטר עצמו אינו מקנה כתיבה - רק מפתח הניהול מקנה אותה.
        const mayWrite = who.role === 'admin' ||
                         (who.role === 'implementer' && who.pricebookId === id && id !== 'master');

        if (m === 'GET') {
            const { rows } = await pool.query('select * from pricebooks where id=$1', [id]);
            if (!rows.length) return send(res, 404);
            const row = rows[0];
            // המאסטר פתוח לקריאה לכל מיישם מחובר (דרוש לטאב הסנכרון), וגם ללא אסימון
            // כלל, כל עוד לא הוגדרה לו סיסמה משלו. ברגע שהוגדרה, אנונימי נחסם.
            const mayRead = who.role === 'admin' ||
                            (who.role === 'implementer' && who.pricebookId === id) ||
                            (id === 'master' && (who.role === 'implementer' || !row.auth_hash));
            if (!mayRead) return send(res, 403, { error: 'forbidden' });
            const out = bookOut(row);
            // פרטי ההצפנה נחשפים למנהל בלבד
            if (who.role !== 'admin') out.auth = out.auth ? { salt: '', hash: '' } : null;
            return send(res, 200, out);
        }

        if (m === 'PUT') {
            if (!mayWrite) return send(res, 403, { error: 'forbidden' });
            const d = await readBody(req);
            const existing = (await pool.query('select * from pricebooks where id=$1', [id])).rows[0];
            // מיישם אינו יכול לשנות סיסמה, שיוך או השבתה של עצמו
            const auth = (who.role === 'admin' && d.auth && d.auth.hash)
                ? d.auth
                : (existing ? { salt: existing.auth_salt, hash: existing.auth_hash } : null);
            const pwChanged = who.role === 'admin' && d.auth && d.auth.hash &&
                              existing && d.auth.hash !== existing.auth_hash;
            const { rows } = await pool.query(`
                insert into pricebooks
                    (id, kind, label, implementer_name, auth_salt, auth_hash, config,
                     master_version, version, updated_at, password_changed_at)
                values ($1,$2,$3,$4,$5,$6,$7,$8,$9, now(), case when $10 then now() else null end)
                on conflict (id) do update set
                    kind=excluded.kind, label=excluded.label,
                    implementer_name=excluded.implementer_name,
                    auth_salt=excluded.auth_salt, auth_hash=excluded.auth_hash,
                    config=excluded.config, master_version=excluded.master_version,
                    version=excluded.version, updated_at=now(),
                    password_changed_at=case when $10 then now()
                                             else pricebooks.password_changed_at end
                returning *`,
                [id, d.kind || 'implementer', d.label || null, d.implementerName || null,
                 auth ? auth.salt : null, auth ? auth.hash : null,
                 d.config || {}, d.masterVersion || null, d.version || 1,
                 !!pwChanged || (!existing && !!(auth && auth.hash))]);
            return send(res, 200, bookOut(rows[0]));
        }

        if (m === 'DELETE') {
            if (who.role !== 'admin') return send(res, 403, { error: 'forbidden' });
            if (id === 'master') return send(res, 400, { error: 'cannot delete master' });
            await pool.query('delete from pricebooks where id=$1', [id]);
            return send(res, 204);
        }
    }

    // ===== פרופיל מיישם (חובה) =====
    if (seg[0] === 'pricebooks' && seg[2] === 'profile' && seg.length === 3 && m === 'PUT') {
        const id = seg[1];
        const mayWrite = who.role === 'admin' || (who.role === 'implementer' && who.pricebookId === id);
        if (!mayWrite) return send(res, 403, { error: 'forbidden' });
        const d = await readBody(req);
        const { rows } = await pool.query(`
            update pricebooks set
                profile_business_name=$2, profile_business_id=$3, profile_contact_name=$4,
                profile_phone=$5, profile_email=$6, profile_address=$7,
                profile_completed_at = case
                    when $2<>'' and $3<>'' and $4<>'' and $5<>'' and $6<>'' and $7<>''
                    then now() else profile_completed_at end,
                updated_at = now()
            where id=$1 returning *`,
            [id, String(d.businessName || '').trim(), String(d.businessId || '').trim(),
             String(d.contactName || '').trim(), String(d.phone || '').trim(),
             String(d.email || '').trim(), String(d.address || '').trim()]);
        if (!rows.length) return send(res, 404);
        return send(res, 200, bookOut(rows[0]));
    }

    // ===== השבתה והפעלה של מיישם =====
    if (seg[0] === 'pricebooks' && seg[2] === 'disabled' && m === 'PUT') {
        if (who.role !== 'admin') return send(res, 403, { error: 'forbidden' });
        const d = await readBody(req);
        const { rows } = await pool.query(
            'update pricebooks set disabled=$2, updated_at=now() where id=$1 returning *',
            [seg[1], !!d.disabled]);
        if (!rows.length) return send(res, 404);
        if (d.disabled) await pool.query('delete from sessions where pricebook_id=$1', [seg[1]]);
        const cnt = await pool.query('select count(*) from quotes where pricebook_id=$1', [seg[1]]);
        return send(res, 200, bookSummary({ ...rows[0], quote_count: cnt.rows[0].count }));
    }

    // ===== גרסאות =====
    if (seg[0] === 'pricebooks' && seg[2] === 'versions') {
        const id = seg[1];
        let mayRead = who.role === 'admin' || (who.role === 'implementer' && who.pricebookId === id);
        if (!mayRead && id === 'master') {
            mayRead = who.role === 'implementer';
            if (!mayRead) {
                const { rows } = await pool.query('select auth_hash from pricebooks where id=$1', [id]);
                mayRead = rows.length > 0 && !rows[0].auth_hash;
            }
        }
        if (!mayRead) return send(res, 403, { error: 'forbidden' });

        if (seg.length === 3 && m === 'GET') {
            const { rows } = await pool.query(
                'select id, at, note, version from pricebook_versions where pricebook_id=$1 order by at desc limit 100', [id]);
            return send(res, 200, rows);
        }
        if (seg.length === 4 && m === 'GET') {
            const { rows } = await pool.query(
                'select * from pricebook_versions where pricebook_id=$1 and id=$2', [id, seg[3]]);
            if (!rows.length) return send(res, 404);
            const v = rows[0];
            return send(res, 200, { id: v.id, at: v.at, note: v.note, version: v.version,
                                    label: v.label, implementerName: v.implementer_name, config: v.config });
        }
        if (seg.length === 3 && m === 'POST') {
            if (who.role !== 'admin' && !(who.role === 'implementer' && who.pricebookId === id))
                return send(res, 403, { error: 'forbidden' });
            const d = await readBody(req);
            const { rows } = await pool.query(`
                insert into pricebook_versions (id, pricebook_id, at, note, version, label, implementer_name, config)
                values ($1,$2, coalesce($3::timestamptz, now()), $4,$5,$6,$7,$8) returning *`,
                [d.id || newId('v'), id, d.at || null, d.note || null, d.version || null,
                 d.label || null, d.implementerName || null, d.config || {}]);
            const v = rows[0];
            return send(res, 200, { id: v.id, at: v.at, note: v.note, version: v.version });
        }
    }

    // ===== אומדנים =====
    if (seg[0] === 'quotes' && seg.length === 1 && m === 'GET') {
        const filter = url.searchParams.get('pricebookId');
        let rows;
        if (who.role === 'admin') {
            rows = (await pool.query(`
                select q.*, p.label as pricebook_label from quotes q
                join pricebooks p on p.id=q.pricebook_id
                ${filter ? 'where q.pricebook_id=$1' : ''}
                order by q.updated_at desc limit 1000`, filter ? [filter] : [])).rows;
        } else if (who.role === 'implementer') {
            rows = (await pool.query(`
                select q.*, p.label as pricebook_label from quotes q
                join pricebooks p on p.id=q.pricebook_id
                where q.pricebook_id=$1 order by q.updated_at desc limit 1000`, [who.pricebookId])).rows;
        } else return send(res, 403, { error: 'forbidden' });
        return send(res, 200, rows.map(quoteOut));
    }

    if (seg[0] === 'quotes' && seg.length === 2) {
        const id = seg[1];
        const owned = async () => {
            const { rows } = await pool.query('select pricebook_id from quotes where id=$1', [id]);
            return rows.length ? rows[0].pricebook_id : null;
        };
        if (m === 'GET') {
            const { rows } = await pool.query(`
                select q.*, p.label as pricebook_label from quotes q
                join pricebooks p on p.id=q.pricebook_id where q.id=$1`, [id]);
            if (!rows.length) return send(res, 404);
            if (who.role !== 'admin' && !(who.role === 'implementer' && who.pricebookId === rows[0].pricebook_id))
                return send(res, 403, { error: 'forbidden' });
            return send(res, 200, quoteOut(rows[0]));
        }
        if (m === 'PUT') {
            const d = await readBody(req);
            const target = d.pricebookId || (await owned());
            if (who.role !== 'admin' && !(who.role === 'implementer' && who.pricebookId === target))
                return send(res, 403, { error: 'forbidden' });
            if (!d.clientName) return send(res, 400, { error: 'clientName is required' });
            const { rows } = await pool.query(`
                insert into quotes (id, pricebook_id, implementer_name, client_name, note, selection, totals, updated_at)
                values ($1,$2,$3,$4,$5,$6,$7, now())
                on conflict (id) do update set
                    implementer_name=excluded.implementer_name, client_name=excluded.client_name,
                    note=excluded.note, selection=excluded.selection, totals=excluded.totals,
                    updated_at=now()
                returning *`,
                [d.id || newId('q'), target, d.implementerName || null, d.clientName,
                 d.note || null, d.selection || {}, d.totals || {}]);
            return send(res, 200, quoteOut(rows[0]));
        }
        if (m === 'DELETE') {
            const target = await owned();
            if (!target) return send(res, 404);
            if (who.role !== 'admin' && !(who.role === 'implementer' && who.pricebookId === target))
                return send(res, 403, { error: 'forbidden' });
            await pool.query('delete from quotes where id=$1', [id]);
            return send(res, 204);
        }
    }

    // ===== הצעות מחיר =====
    const PROPOSAL_STATUSES = ['open','approved','won','lost','expired'];

    // שאילתת בסיס משותפת לכל שליפת הצעות מחיר, כולל האומדן שממנו הן הומרו (אם יש)
    const PROPOSAL_SELECT_SQL = `
        select pr.*, p.label as pricebook_label, p.implementer_name,
               q.client_name as sq_client_name, q.note as sq_note,
               q.totals as sq_totals, q.created_at as sq_created_at, q.updated_at as sq_updated_at
        from proposals pr
        join pricebooks p on p.id = pr.pricebook_id
        left join quotes q on q.id = pr.source_quote_id`;

    // בודק אם ליד תפוס: הצעה פתוחה/מאושרת של מיישם אחר, בתוך חלון השמירה, לאותו שם לקוח
    const findLeadConflict = async (proposalId, pricebookId, clientName) => {
        const { rows } = await pool.query(`
            select pr.id, pr.pricebook_id, pr.retention_expires_at, p.label, p.implementer_name
            from proposals pr join pricebooks p on p.id = pr.pricebook_id
            where pr.id <> $1 and pr.pricebook_id <> $2
              and lower(trim(pr.client_name)) = lower(trim($3))
              and pr.status in ('open','approved')
              and pr.retention_expires_at > now()
            order by pr.created_at asc limit 1`,
            [proposalId || '', pricebookId, clientName]);
        if (!rows.length) return null;
        const r = rows[0];
        return { pricebookId: r.pricebook_id, pricebookLabel: r.label,
                 implementerName: r.implementer_name, retentionExpiresAt: r.retention_expires_at };
    };

    if (seg[0] === 'proposals' && seg.length === 1 && m === 'GET') {
        const filter = url.searchParams.get('pricebookId');
        let rows;
        if (who.role === 'admin') {
            rows = (await pool.query(`
                ${PROPOSAL_SELECT_SQL}
                ${filter ? 'where pr.pricebook_id=$1' : ''}
                order by pr.updated_at desc limit 1000`, filter ? [filter] : [])).rows;
        } else if (who.role === 'implementer') {
            rows = (await pool.query(`
                ${PROPOSAL_SELECT_SQL}
                where pr.pricebook_id=$1 order by pr.updated_at desc limit 1000`, [who.pricebookId])).rows;
        } else return send(res, 403, { error: 'forbidden' });
        return send(res, 200, rows.map(proposalOut));
    }

    if (seg[0] === 'proposals' && seg[2] === 'reassign' && seg.length === 3 && m === 'PUT') {
        if (who.role !== 'admin') return send(res, 403, { error: 'forbidden' });
        const d = await readBody(req);
        if (!d.pricebookId) return send(res, 400, { error: 'pricebookId is required' });
        const target = await pool.query('select id from pricebooks where id=$1', [d.pricebookId]);
        if (!target.rows.length) return send(res, 400, { error: 'target pricebook not found' });
        const { rows } = await pool.query(`
            update proposals set pricebook_id=$2, updated_at=now() where id=$1
            returning *`, [seg[1], d.pricebookId]);
        if (!rows.length) return send(res, 404);
        const full = await pool.query(`
            ${PROPOSAL_SELECT_SQL}
            where pr.id=$1`, [seg[1]]);
        return send(res, 200, proposalOut(full.rows[0]));
    }

    if (seg[0] === 'proposals' && seg[2] === 'retention' && seg.length === 3 && m === 'PUT') {
        if (who.role !== 'admin') return send(res, 403, { error: 'forbidden' });
        const d = await readBody(req);
        const days = Number(d.extendByDays);
        if (!Number.isFinite(days) || days <= 0) return send(res, 400, { error: 'extendByDays must be a positive number' });
        const { rows } = await pool.query(`
            update proposals set
                retention_expires_at = greatest(retention_expires_at, now()) + make_interval(days => $2::int),
                updated_at = now()
            where id=$1 returning *`, [seg[1], days]);
        if (!rows.length) return send(res, 404);
        const full = await pool.query(`
            ${PROPOSAL_SELECT_SQL}
            where pr.id=$1`, [seg[1]]);
        return send(res, 200, proposalOut(full.rows[0]));
    }

    if (seg[0] === 'proposals' && seg.length === 2) {
        const id = seg[1];
        const owned = async () => {
            const { rows } = await pool.query('select pricebook_id from proposals where id=$1', [id]);
            return rows.length ? rows[0].pricebook_id : null;
        };
        if (m === 'GET') {
            const { rows } = await pool.query(`
                ${PROPOSAL_SELECT_SQL}
                where pr.id=$1`, [id]);
            if (!rows.length) return send(res, 404);
            if (who.role !== 'admin' && !(who.role === 'implementer' && who.pricebookId === rows[0].pricebook_id))
                return send(res, 403, { error: 'forbidden' });
            return send(res, 200, proposalOut(rows[0]));
        }
        if (m === 'PUT') {
            const d = await readBody(req);
            const target = d.pricebookId || (await owned());
            if (who.role !== 'admin' && !(who.role === 'implementer' && who.pricebookId === target))
                return send(res, 403, { error: 'forbidden' });
            if (!d.clientName) return send(res, 400, { error: 'clientName is required' });
            const status = PROPOSAL_STATUSES.includes(d.status) ? d.status : 'open';
            const isNew = !(await owned());
            const proposalId = d.id || newId('pr');
            const retentionDays = Number(d.retentionDays) > 0 ? Number(d.retentionDays) : 14;
            // מיישם (לא מנהל) אינו יכול לייצר הצעת מחיר ללקוח שיש עליו הגנה אצל מיישם אחר - חוסם לפני השמירה
            if (who.role === 'implementer') {
                const blocking = await findLeadConflict(proposalId, target, d.clientName);
                if (blocking) {
                    return send(res, 409, { error: 'lead_protected', retentionExpiresAt: blocking.retentionExpiresAt });
                }
            }
            const { rows } = await pool.query(`
                insert into proposals
                    (id, pricebook_id, source_quote_id, created_by, client_name, client_business_id,
                     client_contact_name, client_phone, client_email, client_address,
                     intro_text, terms_text, closing_text, selection, totals, status,
                     retention_days, retention_expires_at, updated_at)
                values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
                        now() + make_interval(days => $17::int), now())
                on conflict (id) do update set
                    pricebook_id=excluded.pricebook_id, client_name=excluded.client_name,
                    client_business_id=excluded.client_business_id,
                    client_contact_name=excluded.client_contact_name,
                    client_phone=excluded.client_phone, client_email=excluded.client_email,
                    client_address=excluded.client_address,
                    intro_text=excluded.intro_text, terms_text=excluded.terms_text,
                    closing_text=excluded.closing_text, selection=excluded.selection,
                    totals=excluded.totals, status=excluded.status, updated_at=now()
                returning *`,
                [proposalId, target, d.sourceQuoteId || null,
                 who.role === 'admin' ? 'admin' : 'implementer',
                 d.clientName, d.clientBusinessId || null, d.clientContactName || null,
                 d.clientPhone || null, d.clientEmail || null, d.clientAddress || null,
                 d.introText || null, d.termsText || null, d.closingText || null,
                 d.selection || {}, d.totals || {}, status, retentionDays]);
            const full = await pool.query(`
                ${PROPOSAL_SELECT_SQL}
                where pr.id=$1`, [rows[0].id]);
            const out = proposalOut(full.rows[0]);
            // מתריע על התנגשות ליד רק לאחר שהשמירה כבר הצליחה, לא חוסם אותה
            if (isNew) {
                const conflict = await findLeadConflict(rows[0].id, target, d.clientName);
                if (conflict) out.leadWarning = conflict;
            }
            return send(res, 200, out);
        }
        if (m === 'DELETE') {
            const target = await owned();
            if (!target) return send(res, 404);
            if (who.role !== 'admin' && !(who.role === 'implementer' && who.pricebookId === target))
                return send(res, 403, { error: 'forbidden' });
            await pool.query('delete from proposals where id=$1', [id]);
            return send(res, 204);
        }
    }

    // ===== לידים: כל האומדנים, עם סימון לקוחות שנתפסו על ידי יותר ממיישם אחד =====
    if (seg[0] === 'leads' && m === 'GET') {
        if (who.role !== 'admin') return send(res, 403, { error: 'forbidden' });
        const { rows } = await pool.query(`
            with agg as (
                select lower(trim(client_name)) as key,
                       count(*) as client_rows,
                       count(distinct pricebook_id) as client_books,
                       min(created_at) as client_first_at
                from quotes group by lower(trim(client_name))
            ),
            prop as (
                select distinct on (source_quote_id)
                       source_quote_id, id as proposal_id, status as proposal_status, retention_expires_at
                from proposals
                where source_quote_id is not null
                order by source_quote_id, created_at desc
            )
            select q.*, p.label as pricebook_label,
                   a.client_rows, a.client_books, a.client_first_at,
                   pr.proposal_id, pr.proposal_status, pr.retention_expires_at
            from quotes q
            join pricebooks p on p.id=q.pricebook_id
            join agg a on a.key = lower(trim(q.client_name))
            left join prop pr on pr.source_quote_id = q.id
            order by q.created_at desc limit 2000`);
        return send(res, 200, rows.map(r => ({
            ...quoteOut(r),
            contested: Number(r.client_books) > 1,
            clientQuoteCount: Number(r.client_rows),
            clientImplementerCount: Number(r.client_books),
            clientFirstAt: r.client_first_at,
            isFirstForClient: new Date(r.created_at).getTime() === new Date(r.client_first_at).getTime(),
            proposal: r.proposal_id ? { id: r.proposal_id, status: r.proposal_status, retentionExpiresAt: r.retention_expires_at } : null
        })));
    }

    // ===== פניות "צור קשר מול ONEBTN" כשמיישם נחסם מלפתוח הצעה ללקוח מוגן =====
    const contactRequestOut = (r) => ({
        id: r.id, pricebookId: r.pricebook_id, pricebookLabel: r.pricebook_label, implementerName: r.implementer_name,
        contactName: r.contact_name, contactPhone: r.contact_phone, contactEmail: r.contact_email,
        clientName: r.client_name, clientBusinessId: r.client_business_id, clientContactName: r.client_contact_name,
        clientPhone: r.client_phone, clientEmail: r.client_email, clientAddress: r.client_address,
        message: r.message,
        protectingPricebookId: r.protecting_pricebook_id, protectingPricebookLabel: r.protecting_pricebook_label,
        protectingRetentionExpiresAt: r.protecting_retention_expires_at,
        status: r.status, createdAt: r.created_at, handledAt: r.handled_at
    });
    const CONTACT_REQUEST_SELECT_SQL = `
        select lcr.*, p.label as pricebook_label, p.implementer_name, pp.label as protecting_pricebook_label
        from lead_contact_requests lcr
        join pricebooks p on p.id = lcr.pricebook_id
        left join pricebooks pp on pp.id = lcr.protecting_pricebook_id`;

    if (seg[0] === 'lead-contact-requests' && seg.length === 1 && m === 'POST') {
        if (who.role !== 'implementer') return send(res, 403, { error: 'forbidden' });
        const d = await readBody(req);
        if (!d.clientName) return send(res, 400, { error: 'clientName is required' });
        const conflict = await findLeadConflict('', who.pricebookId, d.clientName);
        const id = newId('lcr');
        const { rows } = await pool.query(`
            insert into lead_contact_requests
                (id, pricebook_id, contact_name, contact_phone, contact_email,
                 client_name, client_business_id, client_contact_name, client_phone, client_email, client_address,
                 message, protecting_pricebook_id, protecting_retention_expires_at)
            values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            returning *`,
            [id, who.pricebookId, d.contactName || null, d.contactPhone || null, d.contactEmail || null,
             d.clientName, d.clientBusinessId || null, d.clientContactName || null, d.clientPhone || null,
             d.clientEmail || null, d.clientAddress || null, d.message || null,
             conflict ? conflict.pricebookId : null, conflict ? conflict.retentionExpiresAt : null]);
        const full = await pool.query(`${CONTACT_REQUEST_SELECT_SQL} where lcr.id=$1`, [rows[0].id]);
        return send(res, 200, contactRequestOut(full.rows[0]));
    }
    if (seg[0] === 'lead-contact-requests' && seg.length === 1 && m === 'GET') {
        if (who.role !== 'admin') return send(res, 403, { error: 'forbidden' });
        const { rows } = await pool.query(`${CONTACT_REQUEST_SELECT_SQL} order by lcr.created_at desc limit 500`);
        return send(res, 200, rows.map(contactRequestOut));
    }
    if (seg[0] === 'lead-contact-requests' && seg.length === 2 && m === 'PUT') {
        if (who.role !== 'admin') return send(res, 403, { error: 'forbidden' });
        const d = await readBody(req);
        const status = d.status === 'handled' ? 'handled' : 'open';
        const { rows } = await pool.query(`
            update lead_contact_requests set status=$2, handled_at=case when $2='handled' then now() else null end
            where id=$1 returning *`, [seg[1], status]);
        if (!rows.length) return send(res, 404);
        const full = await pool.query(`${CONTACT_REQUEST_SELECT_SQL} where lcr.id=$1`, [seg[1]]);
        return send(res, 200, contactRequestOut(full.rows[0]));
    }

    return send(res, 404, { error: 'unknown endpoint' });
}

// ---------- שרת ----------
const server = http.createServer(async (req, res) => {
    try {
        if (req.method === 'OPTIONS') return send(res, 204);
        const url = new URL(req.url, 'http://x');

        if (url.pathname === '/health' || url.pathname === '/') {
            return send(res, 200, { ok: true, service: 'oneflow-api' });
        }
        // כל בקשה חייבת לשאת את מזהה הארגון
        if ((req.headers['x-org-slug'] || '') !== ORG_SLUG) {
            return send(res, 403, { error: 'missing or wrong x-org-slug' });
        }
        const who = await identify(req);
        await route(req, res, url, who);
    } catch (e) {
        console.error('request failed:', e.message);
        if (res.headersSent) return;
        // גוף בקשה שגוי הוא טעות קלט, לא תקלת שרת
        if (e.message === 'invalid json' || e.message === 'payload too large') {
            return send(res, 400, { error: e.message });
        }
        send(res, 500, { error: 'server error' });
    }
});

(async () => {
    const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    await pool.query(sql);
    console.log('schema ready');
    server.listen(PORT, () => console.log('oneflow-api listening on ' + PORT + ' (org: ' + ORG_SLUG + ')'));
})().catch(e => { console.error('startup failed:', e.message); process.exit(1); });
