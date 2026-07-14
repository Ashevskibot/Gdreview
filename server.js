'use strict';
const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const { buildCodeEmail, buildCodeEmailText } = require('./email-templates');
const { moderateText, moderateImage } = require('./moderation');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';

// Railway (and most PaaS providers) terminate TLS at a reverse proxy and
// forward the real client IP via X-Forwarded-For. Trusting the proxy makes
// req.ip / req.secure resolve correctly instead of always returning the
// proxy's own address.
app.set('trust proxy', 1);

/* ============ SECURITY: HELMET + CORS ============ */
// Helmet sets a sane set of security headers (HSTS, X-Content-Type-Options,
// no-sniff, etc). CSP is left in "report only"-free default mode disabled
// here because the app is a classic server-rendered/static bundle with
// inline scripts (see index.html) — enabling the default CSP would break it.
// If/when inline scripts are moved to external files, re-enable it.
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// Only the production domain (and local dev) may call the API with
// credentials/cookies or custom headers. Requests with no Origin header
// (curl, server-to-server, mobile apps, Postman) are allowed through since
// they can't be spoofed by a browser the way cross-site requests can.
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || 'https://gdreview.com,https://www.gdreview.com,http://localhost:3000,http://localhost:5173')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

const corsOptions = {
    origin(origin, callback) {
        if (!origin) return callback(null, true); // non-browser clients
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        callback(new Error('not_allowed_by_cors'));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
};
app.use(cors(corsOptions));
// Express 5 / recent path-to-regexp reject bare '*' — match all paths via regex instead.
app.options(/.*/, cors(corsOptions));

// Surface CORS rejections as clean 403s instead of a raw Express error page.
app.use((err, req, res, next) => {
    if (err && err.message === 'not_allowed_by_cors') return res.status(403).json({ error: 'origin_not_allowed' });
    next(err);
});

const resend = new Resend(process.env.RESEND_API_KEY);
const EMAIL_FROM = process.env.EMAIL_FROM || 'GD Review <onboarding@resend.dev>';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/* ============ DB INIT ============ */
async function initDb() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                level_id VARCHAR(50) NOT NULL,
                level_name VARCHAR(255),
                level_author VARCHAR(255),
                difficulty VARCHAR(50),
                difficulty_face VARCHAR(100),
                stars INTEGER,
                gameplay INTEGER, flow INTEGER, decoration INTEGER, music INTEGER, originality INTEGER, optimization INTEGER,
                final_score NUMERIC(4,2), review_text TEXT, saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        // Existing databases created before this change still have the old
        // FK without ON DELETE CASCADE. Drop and recreate it so deleting a
        // user (e.g. cleaning up unverified/test accounts) no longer fails
        // with a foreign key constraint violation on their reviews.
        await client.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.table_constraints
                    WHERE table_name = 'reviews' AND constraint_name = 'reviews_user_id_fkey'
                ) THEN
                    ALTER TABLE reviews DROP CONSTRAINT reviews_user_id_fkey;
                END IF;
                ALTER TABLE reviews
                    ADD CONSTRAINT reviews_user_id_fkey
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
            END $$;
        `).catch(err => console.error('⚠️  Could not migrate reviews FK to ON DELETE CASCADE:', err.message));
        await client.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS avatar TEXT,
            ADD COLUMN IF NOT EXISTS banner TEXT,
            ADD COLUMN IF NOT EXISTS frame VARCHAR(50) DEFAULT 'frame-default',
            ADD COLUMN IF NOT EXISTS description TEXT,
            ADD COLUMN IF NOT EXISTS socials TEXT,
            ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS verify_code VARCHAR(10),
            ADD COLUMN IF NOT EXISTS reset_code VARCHAR(10),
            ADD COLUMN IF NOT EXISTS reset_expires BIGINT,
            ADD COLUMN IF NOT EXISTS register_ip VARCHAR(45);
        `).catch(() => {});
        await client.query(`ALTER TABLE reviews ADD COLUMN IF NOT EXISTS title VARCHAR(120);`).catch(() => {});
        // New 5-axis scoring system (Gameplay / Sync / Design / Creativity /
        // Optimization). Legacy 6-axis data is backfilled so old reviews keep
        // meaningful values: music -> sync_rhythm, decoration -> design_deco,
        // originality -> creativity. Old columns are kept for history.
        await client.query(`
            ALTER TABLE reviews
            ADD COLUMN IF NOT EXISTS sync_rhythm INTEGER,
            ADD COLUMN IF NOT EXISTS design_deco INTEGER,
            ADD COLUMN IF NOT EXISTS creativity INTEGER;
        `).catch(() => {});
        await client.query(`
            UPDATE reviews SET
                sync_rhythm = COALESCE(sync_rhythm, music),
                design_deco = COALESCE(design_deco, decoration),
                creativity  = COALESCE(creativity, originality)
            WHERE sync_rhythm IS NULL OR design_deco IS NULL OR creativity IS NULL;
        `).catch(err => console.error('⚠️  Could not backfill new rating columns:', err.message));
        await client.query(`
            CREATE TABLE IF NOT EXISTS review_likes (
                id SERIAL PRIMARY KEY,
                review_id INTEGER REFERENCES reviews(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(review_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_reviews_level ON reviews(level_id);
            CREATE INDEX IF NOT EXISTS idx_reviews_saved ON reviews(saved_at DESC);
            CREATE INDEX IF NOT EXISTS idx_likes_review ON review_likes(review_id);
        `);
        // Walkthrough submissions + admin flag.
        await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;`).catch(() => {});
        await client.query(`
            CREATE TABLE IF NOT EXISTS walkthroughs (
                id SERIAL PRIMARY KEY,
                level_id VARCHAR(50) NOT NULL,
                level_name VARCHAR(255),
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                youtube_url TEXT NOT NULL,
                video_id VARCHAR(20) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_walkthroughs_level ON walkthroughs(level_id, status);
            CREATE INDEX IF NOT EXISTS idx_walkthroughs_status ON walkthroughs(status, submitted_at DESC);
        `);
        // Bootstrap admins from ADMIN_EMAILS (comma-separated) so the first
        // moderators can be promoted without manual SQL.
        const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
        if (adminEmails.length) {
            await client.query('UPDATE users SET is_admin = TRUE WHERE LOWER(email) = ANY($1)', [adminEmails])
                .catch(err => console.error('⚠️  Admin bootstrap failed:', err.message));
        }
        console.log('✅ Database ready');
    } finally { client.release(); }
}
initDb().catch(err => console.error('❌ DB init error:', err.stack));

app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ============ HELPERS ============ */
const fail = (res, status, code) => res.status(status).json({ error: code });

// Structured moderation rejection so the client can explain exactly why the
// content was blocked and offer a retry flow.
// 422 = content rejected by moderation, 503 = moderation provider unreachable
// (strict mode: nothing is published while moderation is down; retry later).
const rejectContent = (res, verdict, field) => res.status(verdict.reason === 'unavailable' ? 503 : 422).json({
    error: verdict.reason === 'unavailable' ? 'moderation_unavailable' : 'content_rejected',
    reason: verdict.reason,
    field,
});

// Stricter RFC-5322-ish email check: bounds local/domain part lengths,
// rejects consecutive dots and leading/trailing dots, and requires a
// plausible TLD. This runs before we ever hand the address to Resend, so
// malformed input fails fast with a clean 400 instead of an API error.
const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
const isEmail = v => {
    if (typeof v !== 'string') return false;
    const email = v.trim();
    if (email.length === 0 || email.length > 254) return false;
    if (email.includes('..')) return false;
    if (!EMAIL_RE.test(email)) return false;
    const atIndex = email.lastIndexOf('@');
    const local = email.slice(0, atIndex);
    const domain = email.slice(atIndex + 1);
    if (local.length === 0 || local.length > 64) return false;
    if (domain.length === 0 || domain.length > 253) return false;
    const tld = domain.split('.').pop();
    if (!tld || tld.length < 2) return false;
    return true;
};

const isUsername = v => typeof v === 'string' && /^[a-zA-Z0-9а-яА-ЯёЁ_\-. ]{3,20}$/.test(v.trim());
const isPassword = v => typeof v === 'string' && v.length >= 8 && v.length <= 100;
const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();
const normEmail = v => String(v || '').trim().toLowerCase();

// Railway's edge proxy sets X-Forwarded-For to "client, proxy1, proxy2...".
// With `trust proxy` enabled above, req.ip already resolves this correctly,
// but we read the header directly as a fallback/for explicit logging.
const getClientIp = req => {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
    return req.ip || req.socket?.remoteAddress || 'unknown';
};

const authenticateToken = (req, res, next) => {
    const h = req.headers['authorization'];
    const token = h && h.split(' ')[1];
    if (!token) return fail(res, 401, 'auth_required');
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return fail(res, 403, 'session_expired');
        req.user = user; next();
    });
};
const optionalAuth = (req, res, next) => {
    const h = req.headers['authorization'];
    const token = h && h.split(' ')[1];
    if (!token) return next();
    jwt.verify(token, JWT_SECRET, (err, user) => { if (!err) req.user = user; next(); });
};

// Must run after authenticateToken. Checks the is_admin flag in the DB on
// every request so revoking admin rights takes effect immediately.
const requireAdmin = async (req, res, next) => {
    try {
        const r = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.userId]);
        if (!r.rows.length || !r.rows[0].is_admin) return fail(res, 403, 'admin_only');
        next();
    } catch (err) { fail(res, 500, 'server_error'); }
};

// Accepts youtube.com/watch?v=, youtu.be/, /shorts/, /embed/ and /live/
// URLs; returns the canonical 11-char video id or null.
function parseYouTubeId(raw) {
    if (typeof raw !== 'string') return null;
    let url;
    try { url = new URL(raw.trim()); } catch (e) { return null; }
    if (!/^https?:$/.test(url.protocol)) return null;
    const host = url.hostname.toLowerCase().replace(/^www\.|^m\./, '');
    let id = null;
    if (host === 'youtu.be') id = url.pathname.slice(1).split('/')[0];
    else if (host === 'youtube.com' || host === 'youtube-nocookie.com') {
        if (url.pathname === '/watch') id = url.searchParams.get('v');
        else if (/^\/(shorts|embed|live)\//.test(url.pathname)) id = url.pathname.split('/')[2];
    }
    return (id && /^[A-Za-z0-9_-]{11}$/.test(id)) ? id : null;
}

/* Simple in-memory rate limiter for sensitive endpoints */
const rlStore = new Map();
function rateLimit(max, windowMs) {
    return (req, res, next) => {
        const key = `${req.ip}:${req.path}`;
        const now = Date.now();
        const hits = (rlStore.get(key) || []).filter(t => now - t < windowMs);
        if (hits.length >= max) return fail(res, 429, 'too_many_requests');
        hits.push(now); rlStore.set(key, hits);
        next();
    };
}
setInterval(() => { const now = Date.now(); for (const [k, v] of rlStore) { const f = v.filter(t => now - t < 900000); if (f.length) rlStore.set(k, f); else rlStore.delete(k); } }, 300000).unref();

function sendEmail(to, subject, text, html) {
    const payload = html ? { from: EMAIL_FROM, to, subject, text, html } : { from: EMAIL_FROM, to, subject, text };
    resend.emails.send(payload).then(({ data, error }) => {
        if (error) { console.error(`❌ Email error (${to}):`, error.message || error); return; }
        console.log(`📧 Email sent to ${to} (id: ${data && data.id})`);
    }).catch(err => console.error(`❌ Email error (${to}):`, err.message));
}

/**
 * Sends the GDREVIEW dark-themed code email (verification or password reset).
 */
function sendCodeEmail(to, { subject, code, headline, intro, expiresMinutes, preheader, ip }) {
    const html = buildCodeEmail({ code, headline, intro, expiresMinutes, preheader, ip });
    const text = buildCodeEmailText({ code, headline, intro, expiresMinutes, ip });
    sendEmail(to, subject, text, html);
}

async function uploadToCloud(base64Image) {
    if (!base64Image || !base64Image.startsWith('data:image')) return base64Image;
    const base64Data = base64Image.split(',')[1];
    const params = new URLSearchParams(); params.append('image', base64Data);
    try {
        const response = await fetch(`https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`, { method: 'POST', body: params });
        const result = await response.json();
        if (result.success) return result.data.url;
    } catch (e) { console.error('Cloud upload error:', e); }
    return base64Image;
}

const REVIEW_FIELDS = `
    r.id, r.level_id, r.level_name, r.level_author, r.difficulty, r.difficulty_face, r.stars,
    r.gameplay, r.sync_rhythm AS sync, r.design_deco AS design, r.creativity, r.optimization,
    r.final_score, r.title, r.review_text, r.saved_at`;
const REVIEW_WITH_USER = `
    SELECT ${REVIEW_FIELDS}, u.username, u.avatar, u.frame,
        COUNT(l.id)::int AS likes,
        COALESCE(BOOL_OR(l.user_id = $1), false) AS liked_by_me
    FROM reviews r
    JOIN users u ON u.id = r.user_id
    LEFT JOIN review_likes l ON l.review_id = r.id`;

/* ============ AUTH ============ */
app.post('/api/register', rateLimit(10, 600000), async (req, res) => {
    try {
        const { username, password } = req.body;
        const email = normEmail(req.body.email);
        if (!isUsername(username)) return fail(res, 400, 'invalid_username');
        if (!isEmail(email)) return fail(res, 400, 'invalid_email');
        if (!isPassword(password)) return fail(res, 400, 'weak_password');

        const clientIp = getClientIp(req);

        const existing = await pool.query('SELECT id, is_verified FROM users WHERE email = $1 OR username = $2', [email, username.trim()]);
        if (existing.rows.length > 0) {
            if (existing.rows[0].is_verified) return fail(res, 400, 'user_exists');
            // Reviews cascade-delete automatically now (ON DELETE CASCADE on
            // reviews.user_id), so we no longer need to delete them manually.
            await pool.query('DELETE FROM users WHERE id = $1', [existing.rows[0].id]);
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const code = generateCode();
        await pool.query(
            'INSERT INTO users (username, email, password_hash, verify_code, register_ip) VALUES ($1, $2, $3, $4, $5)',
            [username.trim(), email, passwordHash, code, clientIp]
        );

        console.log(`\n🔑 REGISTRATION CODE for ${email}: [ ${code} ] — IP: ${clientIp}\n`);
        sendCodeEmail(email, {
            subject: 'GDREVIEW — Confirm your email',
            code,
            headline: 'Confirm Your Email',
            intro: "We received a request to verify your email address and complete your GDREVIEW registration. Enter the code below to continue.",
            expiresMinutes: 10,
            preheader: 'Your GDREVIEW verification code is ready — enter it to complete your registration.',
            ip: clientIp,
        });
        res.json({ message: 'code_sent' });
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

app.post('/api/resend-code', rateLimit(5, 600000), async (req, res) => {
    try {
        const email = normEmail(req.body.email);
        if (!isEmail(email)) return fail(res, 400, 'invalid_email');
        const result = await pool.query('SELECT id FROM users WHERE email = $1 AND is_verified = FALSE', [email]);
        if (result.rows.length === 0) return fail(res, 400, 'account_not_found');
        const code = generateCode();
        await pool.query('UPDATE users SET verify_code = $1 WHERE id = $2', [code, result.rows[0].id]);
        console.log(`\n🔑 RESENT CODE for ${email}: [ ${code} ]\n`);
        sendCodeEmail(email, {
            subject: 'GDREVIEW — Confirm your email',
            code,
            headline: 'Confirm Your Email',
            intro: "We received a request to verify your email address and complete your GDREVIEW registration. Enter the code below to continue.",
            expiresMinutes: 10,
            preheader: 'Your GDREVIEW verification code is ready — enter it to complete your registration.',
            ip: getClientIp(req),
        });
        res.json({ message: 'code_sent' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/verify', rateLimit(15, 600000), async (req, res) => {
    try {
        const email = normEmail(req.body.email);
        const code = String(req.body.code || '').trim();
        const result = await pool.query('SELECT * FROM users WHERE email = $1 AND verify_code = $2', [email, code]);
        if (result.rows.length === 0) return fail(res, 400, 'invalid_code');
        const user = result.rows[0];
        await pool.query('UPDATE users SET is_verified = TRUE, verify_code = NULL WHERE id = $1', [user.id]);
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ message: 'verified', token, username: user.username });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/login', rateLimit(15, 600000), async (req, res) => {
    try {
        const email = normEmail(req.body.email);
        const { password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0 || !result.rows[0].is_verified) return fail(res, 400, 'wrong_credentials');
        const user = result.rows[0];
        const isMatch = await bcrypt.compare(String(password || ''), user.password_hash);
        if (!isMatch) return fail(res, 400, 'wrong_credentials');
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ message: 'ok', token, username: user.username });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/forgot-password', rateLimit(5, 600000), async (req, res) => {
    try {
        const email = normEmail(req.body.email);
        if (!isEmail(email)) return fail(res, 400, 'invalid_email');
        const result = await pool.query('SELECT id FROM users WHERE email = $1 AND is_verified = TRUE', [email]);
        if (result.rows.length === 0) return fail(res, 400, 'account_not_found');
        const code = generateCode();
        const expires = Date.now() + 15 * 60 * 1000;
        await pool.query('UPDATE users SET reset_code = $1, reset_expires = $2 WHERE id = $3', [code, expires, result.rows[0].id]);
        console.log(`\n🔑 RESET CODE for ${email}: [ ${code} ]\n`);
        sendCodeEmail(email, {
            subject: 'GDREVIEW — Password reset code',
            code,
            headline: 'Reset Your Password',
            intro: "We received a request to reset your GDREVIEW account password. Enter the code below to continue.",
            expiresMinutes: 15,
            preheader: 'Your GDREVIEW password reset code is ready — enter it to continue.',
            ip: getClientIp(req),
        });
        res.json({ message: 'code_sent' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/reset-password', rateLimit(15, 600000), async (req, res) => {
    try {
        const email = normEmail(req.body.email);
        const code = String(req.body.code || '').trim();
        const { newPassword } = req.body;
        if (!isPassword(newPassword)) return fail(res, 400, 'weak_password');
        const result = await pool.query('SELECT * FROM users WHERE email = $1 AND reset_code = $2', [email, code]);
        if (result.rows.length === 0) return fail(res, 400, 'invalid_code');
        if (Date.now() > Number(result.rows[0].reset_expires)) return fail(res, 400, 'code_expired');
        const passwordHash = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1, reset_code = NULL, reset_expires = NULL WHERE id = $2', [passwordHash, result.rows[0].id]);
        res.json({ message: 'password_changed' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/change-password', authenticateToken, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!isPassword(newPassword)) return fail(res, 400, 'weak_password');
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
        if (result.rows.length === 0) return fail(res, 404, 'not_found');
        const isMatch = await bcrypt.compare(String(oldPassword || ''), result.rows[0].password_hash);
        if (!isMatch) return fail(res, 400, 'wrong_password');
        const hash = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.userId]);
        res.json({ message: 'password_changed' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/change-email', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        const newEmail = normEmail(req.body.newEmail);
        if (!isEmail(newEmail)) return fail(res, 400, 'invalid_email');
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
        if (result.rows.length === 0) return fail(res, 404, 'not_found');
        const isMatch = await bcrypt.compare(String(password || ''), result.rows[0].password_hash);
        if (!isMatch) return fail(res, 400, 'wrong_password');
        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1 AND id <> $2', [newEmail, req.user.userId]);
        if (emailCheck.rows.length > 0) return fail(res, 400, 'email_taken');
        await pool.query('UPDATE users SET email = $1 WHERE id = $2', [newEmail, req.user.userId]);
        res.json({ message: 'email_changed' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.delete('/api/account', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body || {};
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
        if (result.rows.length === 0) return fail(res, 404, 'not_found');
        const isMatch = await bcrypt.compare(String(password || ''), result.rows[0].password_hash);
        if (!isMatch) return fail(res, 400, 'wrong_password');
        await pool.query('DELETE FROM reviews WHERE user_id = $1', [req.user.userId]);
        await pool.query('DELETE FROM users WHERE id = $1', [req.user.userId]);
        res.json({ message: 'account_deleted' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

/* ============ PROFILE ============ */
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.username, u.email, u.avatar, u.banner, u.frame, u.description, u.socials, u.created_at, u.is_admin,
                (SELECT COUNT(*)::int FROM reviews r WHERE r.user_id = u.id) AS review_count,
                (SELECT COUNT(*)::int FROM review_likes l JOIN reviews r ON r.id = l.review_id WHERE r.user_id = u.id) AS likes_received
            FROM users u WHERE u.id = $1`, [req.user.userId]);
        if (result.rows.length === 0) return fail(res, 404, 'not_found');
        res.json(result.rows[0]);
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/profile', authenticateToken, async (req, res) => {
    try {
        let { avatar, banner, frame, description, socials } = req.body;
        if (description && String(description).length > 300) description = String(description).slice(0, 300);
        // Automatic moderation BEFORE anything is stored or uploaded.
        const bioVerdict = await moderateText(description || '');
        if (!bioVerdict.ok) return rejectContent(res, bioVerdict, 'description');
        if (avatar && String(avatar).startsWith('data:image')) {
            const v = await moderateImage(avatar);
            if (!v.ok) return rejectContent(res, v, 'avatar');
        }
        if (banner && String(banner).startsWith('data:image')) {
            const v = await moderateImage(banner);
            if (!v.ok) return rejectContent(res, v, 'banner');
        }
        avatar = await uploadToCloud(avatar);
        banner = await uploadToCloud(banner);
        await pool.query('UPDATE users SET avatar = $1, banner = $2, frame = $3, description = $4, socials = $5 WHERE id = $6',
            [avatar || null, banner || null, frame || 'frame-default', description || null, socials || null, req.user.userId]);
        res.json({ message: 'profile_saved' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.get('/api/users/:username', optionalAuth, async (req, res) => {
    try {
        const uRes = await pool.query(`
            SELECT u.id, u.username, u.avatar, u.banner, u.frame, u.description, u.socials, u.created_at,
                (SELECT COUNT(*)::int FROM review_likes l JOIN reviews r ON r.id = l.review_id WHERE r.user_id = u.id) AS likes_received
            FROM users u WHERE LOWER(u.username) = LOWER($1) AND u.is_verified = TRUE`, [req.params.username]);
        if (uRes.rows.length === 0) return fail(res, 404, 'not_found');
        const user = uRes.rows[0];
        const viewerId = req.user ? req.user.userId : null;
        const rRes = await pool.query(`${REVIEW_WITH_USER} WHERE r.user_id = $2 GROUP BY r.id, u.id ORDER BY r.saved_at DESC`, [viewerId, user.id]);
        const { id, ...publicUser } = user;
        res.json({ user: publicUser, reviews: rRes.rows });
    } catch (err) { fail(res, 500, 'server_error'); }
});

/* ============ REVIEWS (own) ============ */
app.get('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`${REVIEW_WITH_USER} WHERE r.user_id = $1 GROUP BY r.id, u.id ORDER BY r.saved_at DESC`, [req.user.userId]);
        res.json(result.rows);
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { level_id, level_name, level_author, difficulty, difficulty_face, stars, ratings, finalScore, title, text } = req.body;
        if (!level_id || !ratings || typeof ratings !== 'object') return fail(res, 400, 'invalid_payload');
        const keys = ['gameplay', 'sync', 'design', 'creativity', 'optimization'];
        for (const k of keys) {
            const v = Number(ratings[k]);
            if (!Number.isInteger(v) || v < 1 || v > 10) return fail(res, 400, 'invalid_payload');
        }
        const score = Number(finalScore);
        if (!(score >= 0 && score <= 10)) return fail(res, 400, 'invalid_payload');
        const safeTitle = String(title || '').slice(0, 120);
        const safeText = String(text || '').slice(0, 5000);

        // Automatic moderation BEFORE the review is published (or updated).
        const verdict = await moderateText(`${safeTitle}\n${safeText}`);
        if (!verdict.ok) return rejectContent(res, verdict, 'review');

        const existing = await pool.query('SELECT id FROM reviews WHERE user_id = $1 AND level_id = $2', [req.user.userId, String(level_id)]);
        if (existing.rows.length > 0) {
            await pool.query(`UPDATE reviews SET gameplay=$1, sync_rhythm=$2, design_deco=$3, creativity=$4, optimization=$5, final_score=$6, title=$7, review_text=$8, saved_at=CURRENT_TIMESTAMP WHERE id=$9`,
                [ratings.gameplay, ratings.sync, ratings.design, ratings.creativity, ratings.optimization, score, safeTitle, safeText, existing.rows[0].id]);
            return res.json({ message: 'review_updated', id: existing.rows[0].id });
        }
        const ins = await pool.query(`INSERT INTO reviews (user_id, level_id, level_name, level_author, difficulty, difficulty_face, stars, gameplay, sync_rhythm, design_deco, creativity, optimization, final_score, title, review_text)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
            [req.user.userId, String(level_id), level_name, level_author, difficulty, difficulty_face, stars || 0, ratings.gameplay, ratings.sync, ratings.design, ratings.creativity, ratings.optimization, score, safeTitle, safeText]);
        res.json({ message: 'review_saved', id: ins.rows[0].id });
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

app.delete('/api/reviews/:id', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM reviews WHERE id = $1 AND user_id = $2', [req.params.id, req.user.userId]);
        res.json({ message: 'deleted' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

/* ============ LIKES ============ */
app.post('/api/reviews/:id/like', authenticateToken, async (req, res) => {
    try {
        const reviewId = parseInt(req.params.id, 10);
        if (!Number.isInteger(reviewId)) return fail(res, 400, 'invalid_payload');
        const rev = await pool.query('SELECT id FROM reviews WHERE id = $1', [reviewId]);
        if (rev.rows.length === 0) return fail(res, 404, 'not_found');
        const existing = await pool.query('SELECT id FROM review_likes WHERE review_id = $1 AND user_id = $2', [reviewId, req.user.userId]);
        let liked;
        if (existing.rows.length > 0) {
            await pool.query('DELETE FROM review_likes WHERE id = $1', [existing.rows[0].id]);
            liked = false;
        } else {
            await pool.query('INSERT INTO review_likes (review_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [reviewId, req.user.userId]);
            liked = true;
        }
        const count = await pool.query('SELECT COUNT(*)::int AS c FROM review_likes WHERE review_id = $1', [reviewId]);
        res.json({ liked, likes: count.rows[0].c });
    } catch (err) { fail(res, 500, 'server_error'); }
});

/* ============ FEED ============ */
app.get('/api/feed/reviews', optionalAuth, async (req, res) => {
    try {
        const sort = String(req.query.sort || 'recent');
        const viewerId = req.user ? req.user.userId : null;
        let where = '';
        let order = 'r.saved_at DESC';
        if (sort === 'popular') order = 'likes DESC, r.saved_at DESC';
        else if (sort === 'top_today') { where = `WHERE r.saved_at > NOW() - INTERVAL '1 day'`; order = 'r.final_score DESC, likes DESC'; }
        else if (sort === 'top_week') { where = `WHERE r.saved_at > NOW() - INTERVAL '7 days'`; order = 'r.final_score DESC, likes DESC'; }
        else if (sort === 'top_all') order = 'r.final_score DESC, likes DESC';
        const result = await pool.query(`${REVIEW_WITH_USER} ${where} GROUP BY r.id, u.id ORDER BY ${order} LIMIT 40`, [viewerId]);
        res.json(result.rows);
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

app.get('/api/feed/levels', async (req, res) => {
    try {
        const sort = String(req.query.sort || 'discussed');
        const diff = String(req.query.difficulty || '').trim();
        const params = [];
        let where = '';
        if (diff) {
            if (diff.toLowerCase() === 'demon') { where = `WHERE r.difficulty ILIKE '%demon%'`; }
            else { params.push(diff); where = `WHERE LOWER(r.difficulty) = LOWER($${params.length})`; }
        }
        let order = 'review_count DESC, last_at DESC';
        if (sort === 'beautiful') order = 'avg_beauty DESC, review_count DESC';
        else if (sort === 'easiest') order = 'diff_rank ASC, avg_score DESC';
        else if (sort === 'hardest') order = 'diff_rank DESC, avg_score DESC';
        else if (sort === 'top') order = 'avg_score DESC, review_count DESC';
        const result = await pool.query(`
            SELECT r.level_id, MAX(r.level_name) AS level_name, MAX(r.level_author) AS level_author,
                MAX(r.difficulty) AS difficulty, MAX(r.difficulty_face) AS difficulty_face, MAX(r.stars) AS stars,
                COUNT(*)::int AS review_count, ROUND(AVG(r.final_score), 2) AS avg_score,
                ROUND(AVG(r.design_deco), 2) AS avg_beauty, MAX(r.saved_at) AS last_at,
                MIN(CASE LOWER(COALESCE(r.difficulty, ''))
                    WHEN 'auto' THEN 0 WHEN 'easy' THEN 1 WHEN 'normal' THEN 2 WHEN 'hard' THEN 3
                    WHEN 'harder' THEN 4 WHEN 'insane' THEN 5 WHEN 'easy demon' THEN 6 WHEN 'medium demon' THEN 7
                    WHEN 'demon' THEN 8 WHEN 'hard demon' THEN 8 WHEN 'insane demon' THEN 9 WHEN 'extreme demon' THEN 10
                    ELSE 3 END) AS diff_rank
            FROM reviews r ${where} GROUP BY r.level_id ORDER BY ${order} LIMIT 30`, params);
        res.json(result.rows);
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

/* ============ LEVEL PAGE ============ */
app.get('/api/levels/:levelId', optionalAuth, async (req, res) => {
    try {
        const viewerId = req.user ? req.user.userId : null;
        const levelId = String(req.params.levelId);
        const [result, wt] = await Promise.all([
            pool.query(`${REVIEW_WITH_USER} WHERE r.level_id = $2 GROUP BY r.id, u.id ORDER BY r.saved_at DESC LIMIT 200`, [viewerId, levelId]),
            pool.query(`SELECT youtube_url, video_id FROM walkthroughs WHERE level_id = $1 AND status = 'approved' ORDER BY reviewed_at DESC LIMIT 1`, [levelId]),
        ]);
        res.json({ reviews: result.rows, walkthrough: wt.rows[0] || null });
    } catch (err) { fail(res, 500, 'server_error'); }
});

/* ============ WALKTHROUGHS ============ */
app.post('/api/levels/:levelId/walkthroughs', authenticateToken, rateLimit(5, 600000), async (req, res) => {
    try {
        const levelId = String(req.params.levelId);
        // Walkthroughs carry no user text — the only server-side check is
        // that the submitted string is a valid YouTube URL.
        const videoId = parseYouTubeId(req.body.youtube_url);
        if (!videoId) return fail(res, 400, 'invalid_youtube_url');
        const levelName = String(req.body.level_name || '').slice(0, 255);
        const dup = await pool.query(`SELECT id FROM walkthroughs WHERE level_id = $1 AND video_id = $2 AND status IN ('pending','approved')`, [levelId, videoId]);
        if (dup.rows.length) return fail(res, 400, 'walkthrough_exists');
        await pool.query(
            'INSERT INTO walkthroughs (level_id, level_name, user_id, youtube_url, video_id) VALUES ($1,$2,$3,$4,$5)',
            [levelId, levelName || null, req.user.userId, `https://www.youtube.com/watch?v=${videoId}`, videoId]
        );
        res.json({ message: 'walkthrough_submitted' });
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

app.get('/api/admin/walkthroughs', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const status = ['pending', 'approved', 'rejected'].includes(String(req.query.status)) ? String(req.query.status) : 'pending';
        const r = await pool.query(`
            SELECT w.id, w.level_id, w.level_name, w.youtube_url, w.video_id, w.status, w.submitted_at, u.username
            FROM walkthroughs w LEFT JOIN users u ON u.id = w.user_id
            WHERE w.status = $1 ORDER BY w.submitted_at ASC LIMIT 100`, [status]);
        res.json(r.rows);
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/admin/walkthroughs/:id/decision', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        const action = String(req.body.action || '');
        if (!Number.isInteger(id) || !['approve', 'reject'].includes(action)) return fail(res, 400, 'invalid_payload');
        const w = await pool.query('SELECT id, level_id FROM walkthroughs WHERE id = $1', [id]);
        if (!w.rows.length) return fail(res, 404, 'not_found');
        if (action === 'approve') {
            // Only one approved walkthrough per level — demote any previous one.
            await pool.query(`UPDATE walkthroughs SET status = 'rejected' WHERE level_id = $1 AND status = 'approved' AND id <> $2`, [w.rows[0].level_id, id]);
        }
        await pool.query('UPDATE walkthroughs SET status = $1, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = $2 WHERE id = $3',
            [action === 'approve' ? 'approved' : 'rejected', req.user.userId, id]);
        res.json({ message: 'ok' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.listen(PORT, () => { console.log(`🚀 Server running on port ${PORT}`); });
