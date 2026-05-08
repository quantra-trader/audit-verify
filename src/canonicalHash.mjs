/**
 * canonicalHash.mjs — Pure deterministic JSON canonicalization + SHA-256 hashing.
 *
 * This file is the cryptographic primitive used by Quantra Sealed verification.
 *
 * Single source of truth — the EXACT same algorithm runs server-side
 * (Quantra backend `lib/canonicalHash.js`) and offline (this `verify.mjs`).
 * Bit-for-bit identical: a chain produced by Quantra's hash chain CAN and MUST
 * be verifiable here without trusting Quantra.
 *
 * Zero dependencies beyond Node `crypto`. Zero side effects. Zero IO.
 *
 * Algorithm:
 *
 *   payloadHash_n = sha256(canonicalJson(canonical_n))
 *
 *   canonicalJson(v):
 *     - undefined           → null
 *     - null / primitive    → JSON.stringify(v)
 *     - Buffer              → JSON.stringify(buffer.toString('base64'))
 *     - Date                → JSON.stringify(date.toISOString())
 *     - Array               → '[' + map(canonicalJson).join(',') + ']'
 *     - Object (plain)      → keys sorted alpha, recurse values
 *
 * Determinism guarantee: `{a:1, b:2}` and `{b:2, a:1}` produce identical output.
 *
 * Mirrors `quantra-api/backend/src/lib/canonicalHash.js` exactly.
 *
 * License: MIT
 */

import crypto from 'node:crypto';

const MAX_DEPTH = 64;

/**
 * Throws if any key starts with `$` (recursive). Defends against Mongo
 * operator injection in attestation payloads.
 *
 * Object/Array recursion only. Primitive/Buffer/Date OK.
 *
 * @param {*} value
 * @param {string} [path='']
 * @param {number} [depth=0]
 * @throws {Error} code MONGO_OP_INJECTION or PAYLOAD_DEPTH_LIMIT
 */
export function assertNoMongoOperators(value, path = '', depth = 0) {
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
 * Stable canonical JSON serialization with sorted keys.
 *
 * @param {*} value
 * @returns {string}
 */
export function canonicalJson(value) {
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
 * sha256 hex digest of canonical JSON form of payload. Deterministic.
 *
 * @param {*} payload
 * @returns {string} 64 chars hex
 */
export function payloadHashOf(payload) {
  return crypto.createHash('sha256').update(canonicalJson(payload)).digest('hex');
}

export { MAX_DEPTH };
