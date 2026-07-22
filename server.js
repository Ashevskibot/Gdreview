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
if (!process.env.JWT_SECRET) {
    console.error('⚠️  SECURITY: JWT_SECRET is not set — using an insecure fallback. Set JWT_SECRET in production!');
}

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
// Scope CORS enforcement to the API only. Static assets (fonts, images) are
// same-origin, but <link rel="preload" as="font" crossorigin> sends an Origin
// header — running the allowlist on those requests would 403 the site's own
// fonts on any domain not in CORS_ORIGINS.
app.use('/api', cors(corsOptions));
// Express 5 / recent path-to-regexp reject bare '*' — match all paths via regex instead.
app.options(/^\/api\/.*/, cors(corsOptions));

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
            ADD COLUMN IF NOT EXISTS description VARCHAR(150),
            ADD COLUMN IF NOT EXISTS socials TEXT,
            ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS verify_code VARCHAR(10),
            ADD COLUMN IF NOT EXISTS reset_code VARCHAR(10),
            ADD COLUMN IF NOT EXISTS reset_expires BIGINT,
            ADD COLUMN IF NOT EXISTS register_ip VARCHAR(45);
        `).catch(() => {});
        // Google Sign-In support: google_id stores the Google OAuth subject
        // (sub) for linked accounts. password_hash becomes nullable because
        // Google-only accounts have no local password — they can create one
        // later through the password-reset flow.
        await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255);`).catch(() => {});
        await client.query(`ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;`).catch(err => console.error('⚠️  Could not make password_hash nullable:', err.message));
        await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);`).catch(() => {});
        await client.query(`ALTER TABLE reviews ADD COLUMN IF NOT EXISTS title VARCHAR(30);`).catch(() => {});
        // Enforce current public text limits for existing databases. Legacy values
        // are trimmed once before the varchar columns are narrowed.
        await client.query(`
            UPDATE users SET description = LEFT(description, 150) WHERE CHAR_LENGTH(description) > 150;
            ALTER TABLE users ALTER COLUMN description TYPE VARCHAR(150);
            UPDATE reviews SET title = LEFT(title, 30) WHERE CHAR_LENGTH(title) > 30;
            ALTER TABLE reviews ALTER COLUMN title TYPE VARCHAR(30);
        `).catch(err => console.error('⚠️  Could not migrate text limits:', err.message));
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
        // Admin-extensible forbidden-words blacklist (second moderation layer).
        await client.query(`
            CREATE TABLE IF NOT EXISTS forbidden_words (
                id SERIAL PRIMARY KEY,
                word VARCHAR(100) UNIQUE NOT NULL,
                added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        // User verification (blue badge). Separate from is_verified, which is
        // the email-confirmation flag. Only admins can grant/revoke it.
        await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_user_verified BOOLEAN DEFAULT FALSE;`).catch(() => {});
        // Support ticket system: tickets + threaded messages.
        await client.query(`
            CREATE TABLE IF NOT EXISTS support_tickets (
                id SERIAL PRIMARY KEY,
                ref VARCHAR(16) UNIQUE NOT NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                category VARCHAR(30) NOT NULL,
                subject VARCHAR(120) NOT NULL,
                message TEXT NOT NULL,
                extra TEXT,
                status VARCHAR(20) DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS support_messages (
                id SERIAL PRIMARY KEY,
                ticket_id INTEGER REFERENCES support_tickets(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_tickets_status ON support_tickets(status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_tickets_user ON support_tickets(user_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_support_msgs_ticket ON support_messages(ticket_id, created_at);
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
/* ---- Admin-managed forbidden words (kept in memory, reloaded on change) ----
   The list is passed into moderateText() so the blacklist layer always uses
   the latest words without a DB round-trip per moderation call. */
let adminForbiddenWords = [];
async function loadForbiddenWords() {
    try {
        const r = await pool.query('SELECT word FROM forbidden_words ORDER BY word');
        adminForbiddenWords = r.rows.map(row => row.word);
    } catch (err) { console.error('⚠️  Could not load forbidden words:', err.message); }
}

initDb().then(loadForbiddenWords).catch(err => console.error('❌ DB init error:', err.stack));

/* Body parsing: the only endpoint that legitimately receives large payloads
   is POST /api/profile (base64 avatar/banner before cloud upload). Everything
   else is plain JSON and gets a tight 1 MB cap, which shrinks the surface for
   memory-exhaustion attacks. */
const jsonSmall = express.json({ limit: '1mb' });
const jsonLarge = express.json({ limit: '8mb' });
app.use((req, res, next) => {
    if (req.method === 'POST' && req.path === '/api/profile') return jsonLarge(req, res, next);
    return jsonSmall(req, res, next);
});
/* Static assets are immutable between deploys — let browsers cache them.
   index.html itself is always revalidated so releases show up immediately. */
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '7d',
    setHeaders(res, filePath) {
        if (filePath.endsWith('index.html')) res.setHeader('Cache-Control', 'no-cache');
    },
}));

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
const RL_MAX_KEYS = 50000; // hard cap so a spoofed-IP flood cannot exhaust memory
function rateLimit(max, windowMs) {
    return (req, res, next) => {
        const key = `${req.ip}:${req.path}`;
        const now = Date.now();
        const hits = (rlStore.get(key) || []).filter(t => now - t < windowMs);
        if (hits.length >= max) {
            res.setHeader('Retry-After', Math.ceil(windowMs / 1000));
            return fail(res, 429, 'too_many_requests');
        }
        if (!rlStore.has(key) && rlStore.size >= RL_MAX_KEYS) {
            // Evict the oldest entry instead of growing without bound.
            rlStore.delete(rlStore.keys().next().value);
        }
        hits.push(now); rlStore.set(key, hits);
        next();
    };
}
setInterval(() => { const now = Date.now(); for (const [k, v] of rlStore) { const f = v.filter(t => now - t < 900000); if (f.length) rlStore.set(k, f); else rlStore.delete(k); } }, 300000).unref();

/* Global API rate limit: a generous per-IP ceiling (all endpoints combined)
   that normal browsing never reaches but that blunts scripted floods and
   basic DoS attempts. Sensitive endpoints keep their own much stricter
   limits on top of this. */
const GLOBAL_RL_MAX = Math.max(60, parseInt(process.env.GLOBAL_RATE_LIMIT, 10) || 300);
app.use('/api', (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip}:*`;
    const hits = (rlStore.get(key) || []).filter(t => now - t < 60000);
    if (hits.length >= GLOBAL_RL_MAX) {
        res.setHeader('Retry-After', 60);
        return fail(res, 429, 'too_many_requests');
    }
    if (!rlStore.has(key) && rlStore.size >= RL_MAX_KEYS) rlStore.delete(rlStore.keys().next().value);
    hits.push(now); rlStore.set(key, hits);
    next();
});

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
    SELECT ${REVIEW_FIELDS}, u.username, u.avatar, u.frame, u.is_user_verified AS user_verified,
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
        // Google-only accounts have no local password. Point the user at the
        // Google button (or the reset flow, which lets them set a password).
        if (!user.password_hash) return fail(res, 400, 'use_google_signin');
        const isMatch = await bcrypt.compare(String(password || ''), user.password_hash);
        if (!isMatch) return fail(res, 400, 'wrong_credentials');
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ message: 'ok', token, username: user.username });
    } catch (err) { fail(res, 500, 'server_error'); }
});

/* ============ GOOGLE SIGN-IN (OAuth 2.0 authorization-code flow) ============ */
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// The redirect URI must exactly match one registered in the Google Cloud
// console. It can be pinned via GOOGLE_REDIRECT_URI; otherwise it is derived
// from the request host (correct behind the PaaS proxy thanks to trust proxy).
function googleRedirectUri(req) {
    if (process.env.GOOGLE_REDIRECT_URI) return process.env.GOOGLE_REDIRECT_URI;
    return `${req.protocol}://${req.get('host')}/api/auth/google/callback`;
}

// OAuth results are delivered to the SPA through the URL fragment: fragments
// are never sent to the server and never end up in access logs. The client
// reads the value once and strips it from the address bar immediately.
const googleFail = (res, code) => res.redirect('/#gerr=' + encodeURIComponent(code));

app.get('/api/auth/google', rateLimit(20, 600000), (req, res) => {
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return googleFail(res, 'google_not_configured');
    // Signed short-lived state token = stateless CSRF protection on callback.
    const state = jwt.sign({ p: 'google_oauth' }, JWT_SECRET, { expiresIn: '10m' });
    const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        redirect_uri: googleRedirectUri(req),
        response_type: 'code',
        scope: 'openid email profile',
        state,
        prompt: 'select_account',
    });
    res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString());
});

// Google display names may collide or contain characters we do not allow —
// build a valid, unique username from the name / email local part.
async function generateUniqueUsername(base) {
    let name = String(base || '').replace(/[^a-zA-Z0-9а-яА-ЯёЁ_\-. ]/g, '').trim().slice(0, 20).trim();
    if (name.length < 3) name = 'player';
    let candidate = name;
    for (let i = 0; i < 30; i++) {
        const r = await pool.query('SELECT 1 FROM users WHERE LOWER(username) = LOWER($1)', [candidate]);
        if (!r.rows.length) return candidate;
        const suffix = String(Math.floor(100 + Math.random() * 9900));
        candidate = name.slice(0, 20 - suffix.length) + suffix;
    }
    return 'player' + Date.now().toString().slice(-9);
}

app.get('/api/auth/google/callback', rateLimit(30, 600000), async (req, res) => {
    try {
        if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return googleFail(res, 'google_not_configured');
        if (req.query.error) return googleFail(res, 'google_auth_failed');
        try {
            const st = jwt.verify(String(req.query.state || ''), JWT_SECRET);
            if (st.p !== 'google_oauth') throw new Error('bad_state');
        } catch (e) { return googleFail(res, 'google_auth_failed'); }
        const code = String(req.query.code || '');
        if (!code) return googleFail(res, 'google_auth_failed');

        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code,
                client_id: GOOGLE_CLIENT_ID,
                client_secret: GOOGLE_CLIENT_SECRET,
                redirect_uri: googleRedirectUri(req),
                grant_type: 'authorization_code',
            }),
        });
        const tokenData = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok || !tokenData.access_token) {
            console.error('❌ Google token exchange failed:', tokenData.error || tokenRes.status);
            return googleFail(res, 'google_auth_failed');
        }

        const profRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });
        const prof = await profRes.json().catch(() => ({}));
        if (!profRes.ok || !prof.sub) return googleFail(res, 'google_auth_failed');
        const email = normEmail(prof.email);
        // Never link accounts on an email Google itself has not verified.
        if (!email || prof.email_verified !== true) return googleFail(res, 'google_email_unverified');

        let user = (await pool.query('SELECT * FROM users WHERE google_id = $1', [prof.sub])).rows[0] || null;
        if (!user) {
            const byEmail = (await pool.query('SELECT * FROM users WHERE email = $1', [email])).rows[0] || null;
            if (byEmail) {
                // Existing email/password account with the same Google-verified
                // address → link it. Google proved mailbox ownership, so any
                // pending email verification is completed as part of linking.
                await pool.query('UPDATE users SET google_id = $1, is_verified = TRUE, verify_code = NULL WHERE id = $2', [prof.sub, byEmail.id]);
                user = byEmail;
            } else {
                const username = await generateUniqueUsername(prof.name || email.split('@')[0]);
                const ins = await pool.query(
                    `INSERT INTO users (username, email, password_hash, google_id, is_verified, register_ip, avatar)
                     VALUES ($1, $2, NULL, $3, TRUE, $4, $5) RETURNING *`,
                    [username, email, prof.sub, getClientIp(req), prof.picture || null]
                );
                user = ins.rows[0];
            }
        }
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        res.redirect('/#gtoken=' + encodeURIComponent(token));
    } catch (err) {
        console.error('❌ Google OAuth error:', err);
        googleFail(res, 'google_auth_failed');
    }
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
        // Google-only accounts must create a password via the reset flow first.
        if (!result.rows[0].password_hash) return fail(res, 400, 'password_not_set');
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
        // Google-only accounts must create a password via the reset flow first.
        if (!result.rows[0].password_hash) return fail(res, 400, 'password_not_set');
        const isMatch = await bcrypt.compare(String(password || ''), result.rows[0].password_hash);
        if (!isMatch) return fail(res, 400, 'wrong_password');
        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1 AND id <> $2', [newEmail, req.user.userId]);
        if (emailCheck.rows.length > 0) return fail(res, 400, 'email_taken');
        await pool.query('UPDATE users SET email = $1 WHERE id = $2', [newEmail, req.user.userId]);
        res.json({ message: 'email_changed' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

// Username changes are validated (format + uniqueness), pass automatic
// moderation, and take effect immediately: reviews join on user id, so the
// new name shows up everywhere without any data migration.
app.post('/api/change-username', authenticateToken, rateLimit(10, 600000), async (req, res) => {
    try {
        const username = String(req.body.username || '').trim();
        if (!isUsername(username)) return fail(res, 400, 'invalid_username');
        const verdict = await moderateText(username, adminForbiddenWords);
        if (!verdict.ok) return rejectContent(res, verdict, 'username');
        const dup = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1) AND id <> $2', [username, req.user.userId]);
        if (dup.rows.length > 0) return fail(res, 400, 'user_exists');
        await pool.query('UPDATE users SET username = $1 WHERE id = $2', [username, req.user.userId]);
        res.json({ message: 'username_changed', username });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.delete('/api/account', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body || {};
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
        if (result.rows.length === 0) return fail(res, 404, 'not_found');
        // Google-only accounts must create a password via the reset flow first.
        if (!result.rows[0].password_hash) return fail(res, 400, 'password_not_set');
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
            SELECT u.username, u.email, u.avatar, u.banner, u.frame, u.description, u.socials, u.created_at, u.is_admin, u.is_user_verified AS user_verified,
                (SELECT COUNT(*)::int FROM reviews r WHERE r.user_id = u.id AND r.review_text IS NOT NULL) AS review_count,
                (SELECT COUNT(*)::int FROM reviews r WHERE r.user_id = u.id) AS rating_count,
                (SELECT COUNT(*)::int FROM review_likes l JOIN reviews r ON r.id = l.review_id WHERE r.user_id = u.id AND r.review_text IS NOT NULL) AS likes_received
            FROM users u WHERE u.id = $1`, [req.user.userId]);
        if (result.rows.length === 0) return fail(res, 404, 'not_found');
        res.json(result.rows[0]);
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/profile', authenticateToken, async (req, res) => {
    try {
        let { avatar, banner, frame, description, socials } = req.body;
        description = String(description || '').trim();
        if (description.length > 150) return fail(res, 400, 'description_too_long');
        // Automatic moderation BEFORE anything is stored or uploaded.
        const bioVerdict = await moderateText(description, adminForbiddenWords);
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

/* Profile search for the global home search (must be registered before the
   :username route so "search" is not treated as a username). */
app.get('/api/users/search', rateLimit(60, 60000), async (req, res) => {
    try {
        const q = String(req.query.q || '').trim();
        if (q.length < 1 || q.length > 100) return res.json({ users: [] });
        const like = '%' + q.replace(/[\\%_]/g, '\\$&') + '%';
        const result = await pool.query(`
            SELECT u.username, u.avatar, u.is_user_verified AS user_verified,
                (SELECT COUNT(*)::int FROM review_likes l JOIN reviews r ON r.id = l.review_id WHERE r.user_id = u.id AND r.review_text IS NOT NULL) AS likes_received,
                (SELECT COUNT(*)::int FROM reviews r WHERE r.user_id = u.id AND r.review_text IS NOT NULL) AS review_count
            FROM users u
            WHERE u.is_verified = TRUE AND u.username ILIKE $2
            ORDER BY (LOWER(u.username) = LOWER($1)) DESC, POSITION(LOWER($1) IN LOWER(u.username)), u.username
            LIMIT 10`, [q, like]);
        res.json({ users: result.rows });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.get('/api/users/:username', optionalAuth, async (req, res) => {
    try {
        const uRes = await pool.query(`
            SELECT u.id, u.username, u.avatar, u.banner, u.frame, u.description, u.socials, u.created_at, u.is_user_verified AS user_verified,
                (SELECT COUNT(*)::int FROM review_likes l JOIN reviews r ON r.id = l.review_id WHERE r.user_id = u.id AND r.review_text IS NOT NULL) AS likes_received
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
        const safeTitle = String(title || '').trim();
        const safeText = String(text || '').trim();
        /* Rating-only submissions: when neither a title nor a text was written,
           the user is publishing just their category scores. Text validation and
           moderation are skipped and NULLs are stored, so the database cleanly
           distinguishes rating-only entries from full written reviews. */
        const isWritten = !!(safeTitle || safeText);
        if (isWritten) {
            if (!safeTitle) return fail(res, 400, 'review_title_required');
            if (safeTitle.length > 30) return fail(res, 400, 'review_title_too_long');
            if (safeText.length < 50) return fail(res, 400, 'review_text_too_short');
            if (safeText.length > 2000) return fail(res, 400, 'review_text_too_long');

            // Automatic moderation BEFORE the review is published (or updated).
            const verdict = await moderateText(`${safeTitle}\n${safeText}`, adminForbiddenWords);
            if (!verdict.ok) return rejectContent(res, verdict, 'review');
        }
        const dbTitle = isWritten ? safeTitle : null;
        const dbText = isWritten ? safeText : null;

        const existing = await pool.query('SELECT id FROM reviews WHERE user_id = $1 AND level_id = $2', [req.user.userId, String(level_id)]);
        if (existing.rows.length > 0) {
            await pool.query(`UPDATE reviews SET gameplay=$1, sync_rhythm=$2, design_deco=$3, creativity=$4, optimization=$5, final_score=$6, title=$7, review_text=$8, saved_at=CURRENT_TIMESTAMP WHERE id=$9`,
                [ratings.gameplay, ratings.sync, ratings.design, ratings.creativity, ratings.optimization, score, dbTitle, dbText, existing.rows[0].id]);
            return res.json({ message: 'review_updated', id: existing.rows[0].id });
        }
        const ins = await pool.query(`INSERT INTO reviews (user_id, level_id, level_name, level_author, difficulty, difficulty_face, stars, gameplay, sync_rhythm, design_deco, creativity, optimization, final_score, title, review_text)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
            [req.user.userId, String(level_id), level_name, level_author, difficulty, difficulty_face, stars || 0, ratings.gameplay, ratings.sync, ratings.design, ratings.creativity, ratings.optimization, score, dbTitle, dbText]);
        res.json({ message: 'review_saved', id: ins.rows[0].id });
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

/* Owners can delete their own reviews. Administrators can moderate any
   review — the is_admin flag is re-checked in the DB on every call, so a
   revoked admin loses the ability immediately. */
app.delete('/api/reviews/:id', authenticateToken, async (req, res) => {
    try {
        const reviewId = parseInt(req.params.id, 10);
        if (!Number.isInteger(reviewId)) return fail(res, 400, 'invalid_payload');
        const rev = await pool.query('SELECT id, user_id FROM reviews WHERE id = $1', [reviewId]);
        if (!rev.rows.length) return fail(res, 404, 'not_found');
        if (rev.rows[0].user_id !== req.user.userId) {
            const adm = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.userId]);
            if (!adm.rows.length || !adm.rows[0].is_admin) return fail(res, 403, 'admin_only');
            console.log(`🛡️  Admin ${req.user.userId} deleted review ${reviewId} (author ${rev.rows[0].user_id})`);
        }
        await pool.query('DELETE FROM reviews WHERE id = $1', [reviewId]);
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
/* Paginated review feed: 10 reviews per page plus a total count, so the
   client can build real pagination. `page` is 0-based. */
const FEED_PAGE_SIZE = 10;
app.get('/api/feed/reviews', optionalAuth, async (req, res) => {
    try {
        const sort = String(req.query.sort || 'recent');
        const viewerId = req.user ? req.user.userId : null;
        const page = Math.max(0, parseInt(req.query.page, 10) || 0);
        /* The review feed only ever contains WRITTEN reviews — rating-only
           submissions influence level scores but are not reviews. */
        let where = 'WHERE r.review_text IS NOT NULL';
        let order = 'r.saved_at DESC';
        if (sort === 'popular') order = 'likes DESC, r.saved_at DESC';
        else if (sort === 'top_today') { where += ` AND r.saved_at > NOW() - INTERVAL '1 day'`; order = 'r.final_score DESC, likes DESC'; }
        else if (sort === 'top_week') { where += ` AND r.saved_at > NOW() - INTERVAL '7 days'`; order = 'r.final_score DESC, likes DESC'; }
        else if (sort === 'top_all') order = 'r.final_score DESC, likes DESC';
        const [result, count] = await Promise.all([
            pool.query(`${REVIEW_WITH_USER} ${where} GROUP BY r.id, u.id ORDER BY ${order} LIMIT ${FEED_PAGE_SIZE} OFFSET ${page * FEED_PAGE_SIZE}`, [viewerId]),
            pool.query(`SELECT COUNT(*)::int AS c FROM reviews r ${where}`),
        ]);
        res.json({ reviews: result.rows, total: count.rows[0].c, page, per_page: FEED_PAGE_SIZE });
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
                COUNT(*) FILTER (WHERE r.review_text IS NOT NULL)::int AS review_count,
                COUNT(*)::int AS rating_count, ROUND(AVG(r.final_score), 2) AS avg_score,
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

/* ============ HOME DASHBOARD ============ */
// Maps a difficulty filter value from the UI to a SQL WHERE fragment.
// 'na' matches levels without a rating; everything else is an exact match
// against the difficulty stored with the review ('easy demon', 'auto', ...).
function difficultyFilter(diff, params) {
    const d = String(diff || '').trim().toLowerCase();
    if (!d) return '';
    if (d === 'na') return `WHERE (r.difficulty IS NULL OR r.difficulty = '' OR LOWER(r.difficulty) IN ('na', 'n/a', 'unrated'))`;
    params.push(d);
    return `WHERE LOWER(r.difficulty) = $${params.length}`;
}

/* ---- Ranking configuration ----
   POPULARITY SCORE (used by "Most Popular" and "Popular This Week"):
       popularity = 3 × likes + 2 × reviews
   Likes are the strongest endorsement signal (a reader explicitly approved a
   review of the level); each written review counts slightly less but still
   matters, so heavily-reviewed levels cannot be overtaken by a single review
   that picked up a couple of likes.

   TOP RATED uses an IMDb-style Bayesian weighted rating to avoid low-sample
   bias:
       rating = (v × R + m × C) / (v + m)
   where v = number of reviews for the level in the window, R = the level's
   mean score, C = the global mean score across all reviews, and m = the
   prior weight (RANK_BAYES_PRIOR). With few reviews the rating is pulled
   toward the global mean; it converges to the true average as v grows.
   Levels additionally need at least RANK_MIN_REVIEWS reviews in the ranking
   window before they appear in Top Rated at all. */
const RANK_MIN_REVIEWS = Math.max(1, parseInt(process.env.RANK_MIN_REVIEWS, 10) || 2);
const RANK_BAYES_PRIOR = Math.max(1, parseInt(process.env.RANK_BAYES_PRIOR, 10) || 5);

/* Short-lived in-memory cache for homepage responses. The dashboard is the
   most-hit surface and its data changes slowly, so ~45 s of staleness is a
   good trade for eliminating nearly all repeated ranking queries. */
const homeCache = new Map();
const HOME_CACHE_TTL = 45000;
function homeCacheGet(key) {
    const hit = homeCache.get(key);
    if (hit && Date.now() - hit.at < HOME_CACHE_TTL) return hit.payload;
    homeCache.delete(key);
    return null;
}
function homeCacheSet(key, payload) { homeCache.set(key, { at: Date.now(), payload }); }

// Both RANK_BAYES_PRIOR and globalMean are server-derived numbers (never user
// input), so inlining them into the SQL text is safe.
const rankingFields = (globalMean) => `
    SELECT r.level_id, MAX(r.level_name) AS level_name, MAX(r.level_author) AS level_author,
        MAX(r.difficulty) AS difficulty, MAX(r.difficulty_face) AS difficulty_face, MAX(r.stars) AS stars,
        COUNT(DISTINCT r.id) FILTER (WHERE r.review_text IS NOT NULL)::int AS review_count,
        COUNT(DISTINCT r.id)::int AS rating_count,
        ROUND(AVG(r.final_score), 2) AS avg_score,
        COUNT(l.id)::int AS total_likes,
        (COUNT(l.id) * 3 + COUNT(DISTINCT r.id) FILTER (WHERE r.review_text IS NOT NULL) * 2)::int AS popularity,
        ROUND((COUNT(DISTINCT r.id) * AVG(r.final_score) + ${RANK_BAYES_PRIOR} * ${globalMean}) / (COUNT(DISTINCT r.id) + ${RANK_BAYES_PRIOR}), 2) AS rating,
        MAX(r.saved_at) AS last_at
    FROM reviews r LEFT JOIN review_likes l ON l.review_id = r.id`;

// All four homepage ranking sections in a single request so the dashboard
// can update atomically when the difficulty filter changes.
app.get('/api/home/rankings', async (req, res) => {
    try {
        const diffKey = String(req.query.difficulty || '').trim().toLowerCase();
        const cached = homeCacheGet('rankings:' + diffKey);
        if (cached) return res.json(cached);

        const meanRes = await pool.query('SELECT ROUND(COALESCE(AVG(final_score), 5), 3) AS c FROM reviews');
        const globalMean = Number(meanRes.rows[0].c) || 5;
        const FIELDS = rankingFields(globalMean);

        const params = [];
        const where = difficultyFilter(diffKey, params);
        const and = where ? where + ' AND' : 'WHERE';
        const q = (extraWhere, having, order) => pool.query(
            `${FIELDS} ${extraWhere} GROUP BY r.level_id ${having} ORDER BY ${order} LIMIT 8`, params);
        const minHaving = `HAVING COUNT(DISTINCT r.id) >= ${RANK_MIN_REVIEWS}`;
        const [popularAll, topToday, popularWeek, discussed] = await Promise.all([
            q(where, '', 'popularity DESC, total_likes DESC, last_at DESC'),
            // Top Rated Today: Bayesian rating over today's activity + minimum sample size.
            q(`${and} r.saved_at > NOW() - INTERVAL '1 day'`, minHaving, 'rating DESC, popularity DESC'),
            q(`${and} r.saved_at > NOW() - INTERVAL '7 days'`, '', 'popularity DESC, rating DESC'),
            q(where, '', 'review_count DESC, last_at DESC'),
        ]);
        const payload = { popular_all: popularAll.rows, top_today: topToday.rows, popular_week: popularWeek.rows, discussed: discussed.rows };
        homeCacheSet('rankings:' + diffKey, payload);
        res.json(payload);
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

// Top-10 reviewer leaderboard (by total likes received) + global site stats.
app.get('/api/home/community', async (req, res) => {
    try {
        const cached = homeCacheGet('community');
        if (cached) return res.json(cached);
        /* Reviewer leaderboard and review stats count WRITTEN reviews only —
           rating-only submissions never influence reviewer rankings. */
        const [lb, stats] = await Promise.all([
            pool.query(`
                SELECT u.username, u.avatar, u.frame, u.is_user_verified AS user_verified,
                    COUNT(DISTINCT r.id)::int AS review_count,
                    COUNT(l.id)::int AS likes_received
                FROM users u
                JOIN reviews r ON r.user_id = u.id AND r.review_text IS NOT NULL
                LEFT JOIN review_likes l ON l.review_id = r.id
                WHERE u.is_verified = TRUE
                GROUP BY u.id
                ORDER BY likes_received DESC, review_count DESC
                LIMIT 10`),
            pool.query(`
                SELECT (SELECT COUNT(*) FROM reviews WHERE review_text IS NOT NULL)::int AS total_reviews,
                       (SELECT COUNT(*) FROM users WHERE is_verified = TRUE)::int AS total_users`),
        ]);
        const payload = { leaderboard: lb.rows, stats: stats.rows[0] };
        homeCacheSet('community', payload);
        res.json(payload);
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

/* ============ ADMIN: FORBIDDEN WORDS ============ */
/* Admin-maintained blacklist extension. The seed list lives in
   forbidden-words.js; words added here are stored in the DB and applied to
   all future text moderation immediately. */
app.get('/api/admin/forbidden-words', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const r = await pool.query(`
            SELECT f.id, f.word, f.created_at, u.username AS added_by
            FROM forbidden_words f LEFT JOIN users u ON u.id = f.added_by
            ORDER BY f.word ASC LIMIT 500`);
        res.json(r.rows);
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.post('/api/admin/forbidden-words', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const word = String(req.body.word || '').trim().toLowerCase();
        if (word.length < 2 || word.length > 100) return fail(res, 400, 'invalid_payload');
        const ins = await pool.query(
            'INSERT INTO forbidden_words (word, added_by) VALUES ($1, $2) ON CONFLICT (word) DO NOTHING RETURNING id',
            [word, req.user.userId]);
        if (!ins.rows.length) return fail(res, 400, 'word_exists');
        await loadForbiddenWords();
        res.json({ message: 'word_added', id: ins.rows[0].id });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.delete('/api/admin/forbidden-words/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isInteger(id)) return fail(res, 400, 'invalid_payload');
        await pool.query('DELETE FROM forbidden_words WHERE id = $1', [id]);
        await loadForbiddenWords();
        res.json({ message: 'deleted' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

/* ============ SUPPORT TICKETS ============ */
const TICKET_CATEGORIES = ['bug', 'account', 'verification', 'other'];
const TICKET_STATUSES = ['open', 'in_progress', 'completed'];

// Public ticket reference, e.g. GDR-4F7K2Q — retried on the (very unlikely)
// unique-constraint collision.
function makeTicketRef() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let s = '';
    for (let i = 0; i < 6; i++) s += chars[Math.floor(Math.random() * chars.length)];
    return 'GDR-' + s;
}

const ticketRow = `
    st.id, st.ref, st.category, st.subject, st.message, st.extra, st.status,
    st.created_at, st.updated_at, u.username, u.avatar, u.is_user_verified AS user_verified`;

app.post('/api/support/tickets', authenticateToken, rateLimit(8, 600000), async (req, res) => {
    try {
        const category = String(req.body.category || '').trim().toLowerCase();
        const subject = String(req.body.subject || '').trim();
        const message = String(req.body.message || '').trim();
        const extra = String(req.body.extra || '').trim();
        if (!TICKET_CATEGORIES.includes(category)) return fail(res, 400, 'invalid_payload');
        if (subject.length < 3 || subject.length > 120) return fail(res, 400, 'ticket_subject_invalid');
        if (message.length < 10 || message.length > 3000) return fail(res, 400, 'ticket_message_invalid');
        if (extra.length > 1000) return fail(res, 400, 'ticket_message_invalid');
        for (let attempt = 0; attempt < 5; attempt++) {
            const ref = makeTicketRef();
            try {
                const ins = await pool.query(
                    `INSERT INTO support_tickets (ref, user_id, category, subject, message, extra)
                     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, ref, status, created_at`,
                    [ref, req.user.userId, category, subject, message, extra || null]);
                return res.json({ message: 'ticket_created', ticket: ins.rows[0] });
            } catch (err) {
                if (err.code !== '23505') throw err; // retry only on ref collision
            }
        }
        fail(res, 500, 'server_error');
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

// The requester's own tickets, newest activity first.
app.get('/api/support/tickets', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query(`
            SELECT st.id, st.ref, st.category, st.subject, st.status, st.created_at, st.updated_at,
                (SELECT COUNT(*)::int FROM support_messages m WHERE m.ticket_id = st.id) AS reply_count
            FROM support_tickets st WHERE st.user_id = $1
            ORDER BY st.updated_at DESC LIMIT 100`, [req.user.userId]);
        res.json(r.rows);
    } catch (err) { fail(res, 500, 'server_error'); }
});

// Ticket detail + conversation. Owner or admin only.
async function loadTicketFor(req, res) {
    const ref = String(req.params.ref || '').trim().toUpperCase();
    const tr = await pool.query(`
        SELECT ${ticketRow}, st.user_id
        FROM support_tickets st LEFT JOIN users u ON u.id = st.user_id
        WHERE st.ref = $1`, [ref]);
    if (!tr.rows.length) { fail(res, 404, 'not_found'); return null; }
    const ticket = tr.rows[0];
    if (ticket.user_id !== req.user.userId) {
        const adm = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.userId]);
        if (!adm.rows.length || !adm.rows[0].is_admin) { fail(res, 403, 'admin_only'); return null; }
        ticket.viewer_is_admin = true;
    }
    return ticket;
}

app.get('/api/support/tickets/:ref', authenticateToken, async (req, res) => {
    try {
        const ticket = await loadTicketFor(req, res);
        if (!ticket) return;
        const ms = await pool.query(`
            SELECT m.id, m.is_admin, m.message, m.created_at, u.username, u.avatar
            FROM support_messages m LEFT JOIN users u ON u.id = m.user_id
            WHERE m.ticket_id = $1 ORDER BY m.created_at ASC LIMIT 300`, [ticket.id]);
        const { user_id, viewer_is_admin, ...publicTicket } = ticket;
        res.json({ ticket: publicTicket, messages: ms.rows });
    } catch (err) { fail(res, 500, 'server_error'); }
});

// Reply in a ticket thread (owner or admin). An admin reply moves an open
// ticket to in_progress; an owner reply reopens a completed ticket.
app.post('/api/support/tickets/:ref/messages', authenticateToken, rateLimit(20, 600000), async (req, res) => {
    try {
        const ticket = await loadTicketFor(req, res);
        if (!ticket) return;
        const message = String(req.body.message || '').trim();
        if (message.length < 1 || message.length > 3000) return fail(res, 400, 'ticket_message_invalid');
        const asAdmin = !!ticket.viewer_is_admin;
        await pool.query('INSERT INTO support_messages (ticket_id, user_id, is_admin, message) VALUES ($1, $2, $3, $4)',
            [ticket.id, req.user.userId, asAdmin, message]);
        let status = ticket.status;
        if (asAdmin && ticket.status === 'open') status = 'in_progress';
        if (!asAdmin && ticket.status === 'completed') status = 'open';
        await pool.query('UPDATE support_tickets SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [status, ticket.id]);
        res.json({ message: 'reply_sent', status });
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

/* ============ ADMIN: SUPPORT TICKETS ============ */
app.get('/api/admin/tickets', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const rawStatus = String(req.query.status || '');
        const status = TICKET_STATUSES.includes(rawStatus) ? rawStatus : null;
        const q = String(req.query.q || '').trim();
        const params = [];
        const where = [];
        if (status) { params.push(status); where.push(`st.status = $${params.length}`); }
        /* Completed tickets are archived: they only appear when explicitly
           requested (status=completed → the Archive view, or status=all).
           The default view stays clean with active tickets only. */
        else if (rawStatus !== 'all') { where.push(`st.status <> 'completed'`); }
        if (q) {
            params.push('%' + q.replace(/[\\%_]/g, '\\$&') + '%');
            where.push(`(st.ref ILIKE $${params.length} OR st.subject ILIKE $${params.length} OR u.username ILIKE $${params.length})`);
        }
        const r = await pool.query(`
            SELECT st.id, st.ref, st.category, st.subject, st.status, st.created_at, st.updated_at,
                u.username, u.avatar,
                (SELECT COUNT(*)::int FROM support_messages m WHERE m.ticket_id = st.id) AS reply_count
            FROM support_tickets st LEFT JOIN users u ON u.id = st.user_id
            ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
            ORDER BY (st.status = 'open') DESC, st.updated_at DESC LIMIT 200`, params);
        res.json(r.rows);
    } catch (err) { console.error(err); fail(res, 500, 'server_error'); }
});

app.post('/api/admin/tickets/:id/status', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        const status = String(req.body.status || '');
        if (!Number.isInteger(id) || !TICKET_STATUSES.includes(status)) return fail(res, 400, 'invalid_payload');
        const r = await pool.query('UPDATE support_tickets SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id', [status, id]);
        if (!r.rows.length) return fail(res, 404, 'not_found');
        res.json({ message: 'status_changed', status });
    } catch (err) { fail(res, 500, 'server_error'); }
});

/* ============ ADMIN: USER VERIFICATION ============ */
// Grant or revoke the blue verification badge. Admin-only; every user-facing
// query reads users.is_user_verified, so the badge applies instantly everywhere.
app.post('/api/admin/verification', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const username = String(req.body.username || '').trim();
        const action = String(req.body.action || '');
        if (!username || !['grant', 'revoke'].includes(action)) return fail(res, 400, 'invalid_payload');
        const r = await pool.query(
            'UPDATE users SET is_user_verified = $1 WHERE LOWER(username) = LOWER($2) RETURNING id, username',
            [action === 'grant', username]);
        if (!r.rows.length) return fail(res, 404, 'not_found');
        console.log(`🛡️  Admin ${req.user.userId} ${action}ed verification for ${r.rows[0].username}`);
        res.json({ message: 'ok', username: r.rows[0].username, verified: action === 'grant' });
    } catch (err) { fail(res, 500, 'server_error'); }
});

app.get('/api/admin/verified-users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const r = await pool.query(`
            SELECT username, avatar, created_at FROM users
            WHERE is_user_verified = TRUE ORDER BY LOWER(username) LIMIT 500`);
        res.json(r.rows);
    } catch (err) { fail(res, 500, 'server_error'); }
});

/* Unknown API routes return a JSON 404 instead of the SPA shell. */
app.use('/api', (req, res) => fail(res, 404, 'not_found'));
/* ---- SPA fallback (History API routing) ----
   Every unknown non-API GET returns the app shell so clean URLs like
   /level/12345, /profile/Crxz, /settings or /review/10565740 load correctly
   on deep links and refreshes. Requests that look like missing static assets
   (a file extension in the last path segment) get a real 404 instead, so a
   broken image URL never silently receives an HTML document. The shell is
   served with no-cache — deep-linked pages always revalidate after deploys. */
app.get('*', (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return fail(res, 404, 'not_found');
    const lastSegment = req.path.split('/').pop();
    if (lastSegment.includes('.')) return fail(res, 404, 'not_found');
    res.setHeader('Cache-Control', 'no-cache');
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* Final safety net: malformed JSON, oversized payloads and unexpected
   middleware errors become clean JSON responses. No stack traces or
   internal details ever reach the client. */
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err && err.type === 'entity.too.large') return fail(res, 413, 'payload_too_large');
    if (err && err.type === 'entity.parse.failed') return fail(res, 400, 'invalid_payload');
    if (err instanceof SyntaxError) return fail(res, 400, 'invalid_payload');
    console.error('Unhandled error:', err && err.message ? err.message : err);
    fail(res, 500, 'server_error');
});

/* A rejected promise outside a route must never kill the process. */
process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection:', reason && reason.message ? reason.message : reason);
});

app.listen(PORT, () => { console.log(`🚀 Server running on port ${PORT}`); });
