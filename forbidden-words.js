'use strict';
/**
 * Forbidden-words blacklist — the second moderation layer that runs BEFORE
 * (and independently of) the AI moderation provider, so offensive content is
 * blocked even when the AI check misses it or is unreachable.
 *
 * Detection strategy (designed to catch common evasion tricks):
 *   1. Normalize: lowercase, map leetspeak/symbol substitutions (@→a, 1→i…),
 *      strip punctuation, collapse repeated letters ("niiice" → "nice").
 *   2. Token match: every normalized word in the text is compared against the
 *      normalized blacklist (exact word match — safe against the classic
 *      "Scunthorpe" false-positive problem).
 *   3. Joined match: for high-severity terms only, separators are removed
 *      from the whole text ("n i g g e r" → "nigger") and the collapsed text
 *      is searched for the collapsed term as a substring.
 *
 * The built-in seed list covers slurs and hate terms commonly prohibited on
 * platforms like Twitch (EN + RU). Administrators can extend the list at
 * runtime — extra words are stored in the `forbidden_words` table and passed
 * into checkForbiddenWords() by the server.
 */

/* ---- Seed blacklist ----
   severity 'high'  → token match + joined-substring match (evasion-proof).
   severity 'word'  → token match only (avoids false positives inside words). */
const SEED_WORDS = [
    // English slurs / hate speech (Twitch-style zero-tolerance terms)
    { word: 'nigger', severity: 'high' },
    { word: 'nigga', severity: 'high' },
    { word: 'faggot', severity: 'high' },
    { word: 'fag', severity: 'word' },
    { word: 'retard', severity: 'word' },
    { word: 'retarded', severity: 'word' },
    { word: 'tranny', severity: 'high' },
    { word: 'kike', severity: 'word' },
    { word: 'spic', severity: 'word' },
    { word: 'chink', severity: 'word' },
    { word: 'wetback', severity: 'high' },
    { word: 'coon', severity: 'word' },
    { word: 'dyke', severity: 'word' },
    { word: 'raghead', severity: 'high' },
    { word: 'kys', severity: 'word' },
    { word: 'cunt', severity: 'word' },
    { word: 'whore', severity: 'word' },
    { word: 'slut', severity: 'word' },
    { word: 'rape', severity: 'word' },
    { word: 'rapist', severity: 'word' },
    // Russian slurs / hate speech
    { word: 'ниггер', severity: 'high' },
    { word: 'нигер', severity: 'high' },
    { word: 'пидор', severity: 'high' },
    { word: 'пидорас', severity: 'high' },
    { word: 'пидарас', severity: 'high' },
    { word: 'педик', severity: 'word' },
    { word: 'даун', severity: 'word' },
    { word: 'дебил', severity: 'word' },
    { word: 'олигофрен', severity: 'word' },
    { word: 'хач', severity: 'word' },
    { word: 'хачи', severity: 'word' },
    { word: 'жид', severity: 'word' },
    { word: 'чурка', severity: 'word' },
    { word: 'узкоглазый', severity: 'high' },
    { word: 'шлюха', severity: 'word' },
    { word: 'блядь', severity: 'word' },
    { word: 'бля', severity: 'word' },
    { word: 'сука', severity: 'word' },
    { word: 'хуй', severity: 'word' },
    { word: 'хуйня', severity: 'word' },
    { word: 'пизда', severity: 'word' },
    { word: 'пиздец', severity: 'word' },
    { word: 'ебать', severity: 'word' },
    { word: 'ебал', severity: 'word' },
    { word: 'заебал', severity: 'word' },
    { word: 'уебок', severity: 'word' },
    { word: 'мразь', severity: 'word' },
    { word: 'убей себя', severity: 'high' },
];

// Leetspeak / symbol substitutions applied during normalization.
const LEET_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '6': 'b', '7': 't', '8': 'b', '9': 'g',
    '@': 'a', '$': 's', '!': 'i', '|': 'i', '+': 't', '€': 'e', '£': 'l', '¡': 'i',
};

// Cyrillic ↔ Latin homoglyphs are folded into Latin. Applied uniformly to
// both the blacklist and the checked text, so mixed-script evasion like
// "пид0рас" (Latin o) and "cyka" (Latin c/y/k) still matches.
const HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'к': 'k', 'м': 'm', 'т': 't',
};

/** Lowercase, apply leet + homoglyph maps, drop non-letters. */
function normalize(text) {
    let s = String(text || '').toLowerCase();
    s = s.replace(/[013456789@$!|+€£¡]/g, ch => LEET_MAP[ch] || ch);
    s = s.replace(/ё/g, 'е');
    s = s.replace(/[аеорсухкмт]/g, ch => HOMOGLYPH_MAP[ch]);
    s = s.replace(/[^a-zа-я\s]/g, ' ');
    return s.replace(/\s+/g, ' ').trim();
}

/** Collapse runs of the same letter: "niiigger" → "niger". */
function collapseRepeats(s) { return s.replace(/(.)\1+/g, '$1'); }

/** Build the fast lookup structures once per (seed + extra words) set. */
function buildMatcher(extraWords) {
    const tokenSet = new Set();
    const joinedTerms = [];
    const add = (word, severity) => {
        const norm = normalize(word);
        if (!norm) return;
        // Multi-word phrases are matched against the normalized full text.
        if (norm.includes(' ')) { joinedTerms.push(collapseRepeats(norm.replace(/\s+/g, ''))); return; }
        tokenSet.add(norm);
        tokenSet.add(collapseRepeats(norm));
        if (severity === 'high' && collapseRepeats(norm).length >= 4) {
            joinedTerms.push(collapseRepeats(norm));
        }
    };
    SEED_WORDS.forEach(w => add(w.word, w.severity));
    (extraWords || []).forEach(w => add(String(w), 'word'));
    return { tokenSet, joinedTerms };
}

// Cache the matcher for the most recent extra-word list (invalidated by
// reference/length+content change — the server passes a fresh array only
// after admin edits).
let cachedKey = null;
let cachedMatcher = null;
function getMatcher(extraWords) {
    const key = (extraWords || []).join('\u0000');
    if (cachedMatcher && cachedKey === key) return cachedMatcher;
    cachedMatcher = buildMatcher(extraWords);
    cachedKey = key;
    return cachedMatcher;
}

/**
 * Checks text against the forbidden-words blacklist.
 * @param {string} text - raw user text
 * @param {string[]} [extraWords] - additional admin-managed words
 * @returns {{ok: true} | {ok: false, reason: 'forbidden_words'}}
 */
function checkForbiddenWords(text, extraWords) {
    const raw = String(text || '');
    if (!raw.trim()) return { ok: true };
    const { tokenSet, joinedTerms } = getMatcher(extraWords);

    const norm = normalize(raw);
    // 1. Exact token match (normalized + repeat-collapsed forms).
    for (const token of norm.split(' ')) {
        if (!token) continue;
        if (tokenSet.has(token) || tokenSet.has(collapseRepeats(token))) {
            return { ok: false, reason: 'forbidden_words' };
        }
    }
    // 2. Joined-text substring match for high-severity terms — catches
    //    "n i g g e r", "n.i.g.g.e.r", "niiigggeeer" and similar evasions.
    const joined = collapseRepeats(norm.replace(/\s+/g, ''));
    for (const term of joinedTerms) {
        if (term && joined.includes(term)) return { ok: false, reason: 'forbidden_words' };
    }
    return { ok: true };
}

module.exports = { checkForbiddenWords };
