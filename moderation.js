'use strict';
/**
 * Automatic pre-publication content moderation, powered by Sightengine.
 *
 * - Text (reviews, bios):
 *     1. Local rule check: external links / advertising are rejected outright.
 *     2. Sightengine Text Moderation API (standard mode, en + ru) for
 *        insults, profanity, toxicity, extremism, violence and drug refs.
 * - Images (avatars, banners): Sightengine image checks (nudity, gore,
 *   weapons, drugs, offensive symbols), run BEFORE the image is uploaded.
 *
 * Env vars (already configured on Railway):
 *   SIGHTENGINE_API_USER, SIGHTENGINE_API_SECRET
 *
 * Every check resolves to { ok: true } or { ok: false, reason: '<code>' }
 * where reason ∈ links | advertising | forbidden_words | toxicity | image |
 * unavailable. 'unavailable' means Sightengine could not be reached — the
 * platform is strict-by-default, so content is NOT published in that case
 * and the client offers a retry.
 *
 * Text moderation is layered — BOTH layers must pass:
 *   1. Forbidden-words blacklist (./forbidden-words.js) — local, instant,
 *      admin-extensible, catches slurs the AI provider misses.
 *   2. Sightengine AI moderation.
 */

const { checkForbiddenWords } = require('./forbidden-words');

const SE_USER = () => process.env.SIGHTENGINE_API_USER;
const SE_SECRET = () => process.env.SIGHTENGINE_API_SECRET;

// External links: full URLs, www.-prefixed hosts or bare domains with common TLDs.
const LINK_RE = /(https?:\/\/|www\.)\S+|(?:^|[\s(])[a-z0-9-]+\.(?:com|net|org|gg|io|ru|me|tv|link|site|xyz|app|dev|cc|top)(?:[\/\s).,!?:]|$)/i;
// Advertising / self-promotion spam (RU + EN patterns).
const AD_RE = /(discord\.gg|discord\.com\/invite|подпи(шись|сывайтесь)|мой\s+(канал|сервер|дискорд)|sub(scribe)?\s+to\s+my|check\s+out\s+my\s+(channel|server|discord)|free\s+(robux|vbucks)|промокод|promo\s*code)/i;

function localTextCheck(text) {
    if (LINK_RE.test(text)) return { ok: false, reason: 'links' };
    if (AD_RE.test(text)) return { ok: false, reason: 'advertising' };
    return { ok: true };
}

async function sightengineTextCheck(text) {
    if (!SE_USER() || !SE_SECRET()) {
        console.warn('⚠️  Sightengine keys not set — skipping text moderation');
        return { ok: true };
    }
    try {
        const params = new URLSearchParams({
            text: text.slice(0, 6000),
            mode: 'standard',
            lang: 'en,ru',
            categories: 'profanity,personal,link,drug,extremism,violence',
            api_user: SE_USER(),
            api_secret: SE_SECRET(),
        });
        const res = await fetch('https://api.sightengine.com/1.0/text/check.json', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString(),
        });
        if (!res.ok) { console.error('❌ Sightengine text HTTP', res.status); return { ok: false, reason: 'unavailable' }; }
        const d = await res.json();
        if (d.status !== 'success') {
            console.error('❌ Sightengine text error:', d.error && d.error.message);
            return { ok: false, reason: 'unavailable' };
        }
        const matches = c => ((d[c] && d[c].matches) || []);
        if (matches('link').length) return { ok: false, reason: 'links' };
        // Any profanity/insult match, or extremism/violence/drug references,
        // blocks publication outright.
        if (matches('profanity').length || matches('extremism').length || matches('violence').length || matches('drug').length) {
            return { ok: false, reason: 'toxicity' };
        }
        return { ok: true };
    } catch (err) {
        console.error('❌ Sightengine text error:', err.message);
        return { ok: false, reason: 'unavailable' };
    }
}

/**
 * Moderates user-facing text. Resolves to { ok } | { ok:false, reason }.
 * @param {string} text
 * @param {string[]} [extraForbiddenWords] - admin-managed blacklist additions
 */
async function moderateText(text, extraForbiddenWords) {
    const clean = String(text || '').trim();
    if (!clean) return { ok: true };
    const local = localTextCheck(clean);
    if (!local.ok) return local;
    // Layer 1: forbidden-words blacklist (never rely on AI moderation alone).
    const blacklist = checkForbiddenWords(clean, extraForbiddenWords);
    if (!blacklist.ok) return blacklist;
    // Layer 2: AI moderation.
    return sightengineTextCheck(clean);
}

/** Moderates an image (data URL or https URL) via Sightengine. */
async function moderateImage(image) {
    if (!image || typeof image !== 'string') return { ok: true };
    if (!SE_USER() || !SE_SECRET()) {
        console.warn('⚠️  Sightengine keys not set — skipping image moderation');
        return { ok: true };
    }
    const MODELS = 'nudity-2.1,weapon,recreational_drug,gore-2.0,offensive-2.0';
    try {
        let res;
        if (image.startsWith('data:image')) {
            const base64 = image.split(',')[1] || '';
            const buffer = Buffer.from(base64, 'base64');
            const form = new FormData();
            form.append('media', new Blob([buffer]), 'upload.jpg');
            form.append('models', MODELS);
            form.append('api_user', SE_USER());
            form.append('api_secret', SE_SECRET());
            res = await fetch('https://api.sightengine.com/1.0/check.json', { method: 'POST', body: form });
        } else if (/^https?:\/\//.test(image)) {
            const params = new URLSearchParams({ url: image, models: MODELS, api_user: SE_USER(), api_secret: SE_SECRET() });
            res = await fetch('https://api.sightengine.com/1.0/check.json?' + params.toString());
        } else {
            return { ok: true }; // not an image payload we can inspect
        }
        if (!res.ok) { console.error('❌ Sightengine HTTP', res.status); return { ok: false, reason: 'unavailable' }; }
        const d = await res.json();
        if (d.status !== 'success') {
            console.error('❌ Sightengine error:', d.error && d.error.message);
            return { ok: false, reason: 'unavailable' };
        }
        const nudity = d.nudity || {};
        const maxNum = obj => {
            const vals = Object.values(obj || {}).filter(v => typeof v === 'number');
            return vals.length ? Math.max(...vals) : 0;
        };
        const flagged =
            (nudity.sexual_activity || 0) > 0.4 ||
            (nudity.sexual_display || 0) > 0.4 ||
            (nudity.erotica || 0) > 0.6 ||
            maxNum(d.weapon && d.weapon.classes) > 0.7 ||
            ((d.recreational_drug && d.recreational_drug.prob) || 0) > 0.6 ||
            ((d.gore && d.gore.prob) || 0) > 0.5 ||
            maxNum(d.offensive) > 0.5;
        if (flagged) return { ok: false, reason: 'image' };
        return { ok: true };
    } catch (err) {
        console.error('❌ Sightengine error:', err.message);
        return { ok: false, reason: 'unavailable' };
    }
}

module.exports = { moderateText, moderateImage };
