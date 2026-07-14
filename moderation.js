'use strict';
/**
 * Automatic pre-publication content moderation.
 *
 * - Text (reviews, bios, walkthrough descriptions):
 *     1. Local rule check: external links / advertising are rejected outright.
 *     2. OpenAI Moderation API (omni-moderation-latest) for toxicity/insults.
 * - Images (avatars, banners): Sightengine (nudity, gore, weapons, drugs,
 *   offensive symbols), checked BEFORE the image is uploaded anywhere.
 *
 * Env vars (already configured on Railway):
 *   OPENAI_API_KEY, SIGHTENGINE_API_USER, SIGHTENGINE_API_SECRET
 *
 * Every check resolves to { ok: true } or { ok: false, reason: '<code>' }
 * where reason ∈ links | advertising | toxicity | image | unavailable.
 * 'unavailable' means the moderation provider could not be reached — the
 * platform is strict-by-default, so content is NOT published in that case
 * and the client offers a retry.
 */

const OPENAI_KEY = () => process.env.OPENAI_API_KEY;
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

async function openAiTextCheck(text) {
    if (!OPENAI_KEY()) {
        console.warn('⚠️  OPENAI_API_KEY not set — skipping AI text moderation');
        return { ok: true };
    }
    try {
        const res = await fetch('https://api.openai.com/v1/moderations', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_KEY()}` },
            body: JSON.stringify({ model: 'omni-moderation-latest', input: text.slice(0, 8000) }),
        });
        if (!res.ok) { console.error('❌ OpenAI moderation HTTP', res.status); return { ok: false, reason: 'unavailable' }; }
        const data = await res.json();
        const result = data && data.results && data.results[0];
        if (!result) return { ok: false, reason: 'unavailable' };
        if (result.flagged) return { ok: false, reason: 'toxicity' };
        // Extra guard for clearly abusive content just under the API threshold.
        const s = result.category_scores || {};
        const worst = Math.max(
            s.harassment || 0, s['harassment/threatening'] || 0,
            s.hate || 0, s['hate/threatening'] || 0, s.sexual || 0
        );
        if (worst > 0.5) return { ok: false, reason: 'toxicity' };
        return { ok: true };
    } catch (err) {
        console.error('❌ OpenAI moderation error:', err.message);
        return { ok: false, reason: 'unavailable' };
    }
}

/** Moderates user-facing text. Resolves to { ok } | { ok:false, reason }. */
async function moderateText(text) {
    const clean = String(text || '').trim();
    if (!clean) return { ok: true };
    const local = localTextCheck(clean);
    if (!local.ok) return local;
    return openAiTextCheck(clean);
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
