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
const ALLOWED_ORIGIN = (process.env.ALLOWED_ORIGIN || '*').replace(/\/+$/, '');
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
        'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
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
    const { rows } = await pool.query(
        'select pricebook_id from sessions where token=$1 and expires_at > now()', [token]);
    if (rows.length) return { role: 'implementer', pricebookId: rows[0].pricebook_id };
    return { role: 'anon' };
}

// ---------- המרות ----------
const bookOut = (r) => r && ({
    id: r.id, kind: r.kind, label: r.label, implementerName: r.implementer_name,
    auth: r.auth_hash ? { salt: r.auth_salt, hash: r.auth_hash } : null,
    config: r.config, masterVersion: r.master_version, version: r.version,
    disabled: r.disabled, updatedAt: r.updated_at, createdAt: r.created_at,
    passwordChangedAt: r.password_changed_at, lastLoginAt: r.last_login_at
});
const bookSummary = (r) => ({
    id: r.id, label: r.label, kind: r.kind, implementerName: r.implementer_name,
    updatedAt: r.updated_at, version: r.version, hasPassword: !!r.auth_hash,
    disabled: r.disabled, passwordChangedAt: r.password_changed_at,
    lastLoginAt: r.last_login_at, quoteCount: Number(r.quote_count || 0)
});
const quoteOut = (r) => ({
    id: r.id, pricebookId: r.pricebook_id, implementerName: r.implementer_name,
    clientName: r.client_name, note: r.note, selection: r.selection, totals: r.totals,
    createdAt: r.created_at, updatedAt: r.updated_at,
    pricebookLabel: r.pricebook_label
});

// ---------- הניתוב ----------
async function route(req, res, url, who) {
    const seg = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    const m = req.method;

    if (seg[0] === 'health') return send(res, 200, { ok: true, org: ORG_SLUG });

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
    if (seg[0] === 'pricebooks' && seg.length === 1 && m === 'GET') {
        if (who.role === 'admin') {
            const { rows } = await pool.query(`
                select p.*, (select count(*) from quotes q where q.pricebook_id = p.id) as quote_count
                from pricebooks p order by (p.kind='master') desc, p.label nulls last, p.id`);
            return send(res, 200, rows.map(bookSummary));
        }
        if (who.role === 'implementer') {
            const { rows } = await pool.query(`
                select p.*, (select count(*) from quotes q where q.pricebook_id = p.id) as quote_count
                from pricebooks p where p.id=$1`, [who.pricebookId]);
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
            )
            select q.*, p.label as pricebook_label,
                   a.client_rows, a.client_books, a.client_first_at
            from quotes q
            join pricebooks p on p.id=q.pricebook_id
            join agg a on a.key = lower(trim(q.client_name))
            order by q.created_at desc limit 2000`);
        return send(res, 200, rows.map(r => ({
            ...quoteOut(r),
            contested: Number(r.client_books) > 1,
            clientQuoteCount: Number(r.client_rows),
            clientImplementerCount: Number(r.client_books),
            clientFirstAt: r.client_first_at,
            isFirstForClient: new Date(r.created_at).getTime() === new Date(r.client_first_at).getTime()
        })));
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
