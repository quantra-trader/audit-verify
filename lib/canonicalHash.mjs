/**
 * lib/canonicalHash.mjs — Sealed™ Audit Pack Verifier
 * ============================================================================
 *
 * 1:1 ESM port of `backend/src/lib/canonicalHash.js` (Quantra repo). Pure
 * functions, zero side effects, zero external dependencies (Node `crypto`
 * built-in only).
 *
 * Used by:
 *   - `lib/sealedVerifier.mjs` to recompute payload hashes during chain
 *     verification.
 *
 * Sync policy: this file mirrors the backend source byte-for-byte at the
 * algorithm level. When Quantra backend bumps `lib/canonicalHash.js`, this
 * file MUST bump in lockstep. Version pinned in `package.json` + documented
 * in `CHANGELOG.md`.
 *
 * @module lib/canonicalHash
 */

import { createHash } from 'node:crypto';

const MAX_DEPTH = 64;

/**
 * Throws if any key in `value` (recursive) starts with `$`. Detects MongoDB
 * operator injection attempts.
 *
 * NO recursion over Buffer / Date / null / primitives.
 *
 * @param {*} value
 * @param {string} [path='']
 * @param {number} [depth=0]
 * @throws {Error} code MONGO_OP_INJECTION or PAYLOAD_DEPTH_LIMIT
 */
function assertNoMongoOperators(value, path = '', depth = 0) {
  if (depth > MAX_DEPTH) {
    const err = new Error(`PAYLOAD_DEPTH_LIMIT exceeded at "${path}" (max ${MAX_DEPTH})`);
    err.code = 'PAYLOAD_DEPTH_LIMIT';
    throw err;
  }
  if (value === null || value === undefined) return;
  if (typeof value !== 'object') return;
  if (Buffer.isBuffer(value)) return;
  if (value instanceof Date) return;

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      assertNoMongoOperators(value[i], `${path}[${i}]`, depth + 1);
    }
    return;
  }

  for (const k of Object.keys(value)) {
    if (k.startsWith('$')) {
      const err = new Error(`MONGO_OP_INJECTION at ${path ? path + '.' : ''}${k}`);
      err.code = 'MONGO_OP_INJECTION';
      err.path = path;
      err.key = k;
      throw err;
    }
    assertNoMongoOperators(value[k], `${path ? path + '.' : ''}${k}`, depth + 1);
  }
}

/**
 * Canonical JSON: stable serialization with alphabetically sorted keys
 * (recursive). `{a:1, b:2}` and `{b:2, a:1}` produce identical strings.
 *
 *   - `undefined` → `null` (avoids missing fields in object output).
 *   - Arrays preserve order (semantically meaningful).
 *   - No circular reference handling (would throw RangeError) — caller is
 *     responsible for non-circular payloads.
 *   - Buffer → base64 string. Date → ISO 8601.
 *
 * @param {*} value
 * @returns {string}
 */
function canonicalJson(value) {
  if (value === undefined) return JSON.stringify(null);
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Buffer.isBuffer(value)) return JSON.stringify(value.toString('base64'));
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k]));
  return '{' + parts.join(',') + '}';
}

/**
 * sha256 hex of a canonicalized payload. Deterministic — same input always
 * produces same hash.
 *
 * @param {*} payload
 * @returns {string} 64 chars hex
 */
function payloadHashOf(payload) {
  return createHash('sha256').update(canonicalJson(payload)).digest('hex');
}

export { assertNoMongoOperators, canonicalJson, payloadHashOf, MAX_DEPTH };
