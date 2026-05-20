/**
 * lib/sealedVerifier.mjs — Sealed™ Audit Pack Verifier
 * ============================================================================
 *
 * 1:1 ESM port of `backend/src/lib/sealedVerifier.js` (Quantra repo). Pure
 * cryptographic verification of Quantra HashChain exports. Zero side effects,
 * zero IO, zero external dependencies (Node `crypto` built-in + sibling
 * `lib/canonicalHash.mjs`).
 *
 * Day 1 launch: any allocator, prop firm, regulator, or auditor can verify
 * the output of `hashChain.exportChain()` (E3 Audit Pack) **without trusting
 * Quantra**, with no DB connection, with no Quantra server — just Node
 * `crypto` and this module.
 *
 * Algorithm (replicates `services/hashChain.js` exactly):
 *
 *   genesis(scope, scopeId) = sha256("quantra:hashchain:" + scope + ":"
 *                                     + scopeId + ":genesis")
 *   payloadHash_n           = sha256(canonicalJson(canonical_n))
 *   hash_n                  = sha256(prevHash_n + ":" + payloadHash_n + ":" +
 *                                     attestedAt_n.toISOString())
 *
 *   prevHash_0 = genesis(scope, scopeId)
 *   prevHash_n = hash_{n-1}
 *
 * Sync policy: this file mirrors the backend source byte-for-byte at the
 * algorithm level. When Quantra backend bumps `lib/sealedVerifier.js`, this
 * file MUST bump in lockstep. Version pinned in `package.json` + documented
 * in `CHANGELOG.md`.
 *
 * Output failure shape (canonical, identical for all reasons):
 *
 *   {
 *     ok: false,
 *     totalEntries: <number>,
 *     brokenAtSequence: <number | null>,
 *     expectedHash: <string | null>,
 *     actualHash: <string | null>,
 *     reason: 'PREV_HASH_MISMATCH' | 'PAYLOAD_HASH_MISMATCH' |
 *             'ENTRY_HASH_MISMATCH' | 'GENESIS_MISMATCH' |
 *             'SEQUENCE_GAP' | 'INVALID_EXPORT_SHAPE',
 *     genesis: <string | null>,
 *   }
 *
 * Output success:
 *
 *   { ok: true, totalEntries, head: <last entry hash | null>, genesis }
 *
 * @module lib/sealedVerifier
 */

import { createHash } from 'node:crypto';
import { canonicalJson, payloadHashOf } from './canonicalHash.mjs';

// ── Public constants ───────────────────────────────────────────────────────
// Hardcoded for purity (NO import from Quantra services). If the algorithm
// changes in V2, the only source of truth for verifying v1 chains is this
// module + `lib/canonicalHash.mjs`.

const GENESIS_PREFIX = 'quantra:hashchain:';
// v2.0.0 — F5 PR1 D-J.3 signed Diego 2026-05-17: added 'account-journal' scope
// para dual sealed per-journal sub-chain (mentor Legend tier opt-in granular).
// Backwards-compat: v1.x exports (scope 'account'/'user'/'mentor'/'eventbus'/
// 'tax_report') siguen verificando OK con v2.0 verifier. Cross-version
// fixture test obligatorio (tests/cross-version.test.mjs) + tag git release sync.
const VALID_SCOPES = new Set([
  'account',
  'user',
  'mentor',
  'eventbus',
  'tax_report',
  'account-journal',  // v2.0.0
]);
const HEX24_RE = /^[a-f0-9]{24}$/i;
const HEX64_RE = /^[0-9a-f]{64}$/;

// ── Pure internal helpers ──────────────────────────────────────────────────

function _sha256Hex(s) {
  return createHash('sha256').update(s).digest('hex');
}

/**
 * Compute the genesis hash of a chain (scope + scopeId). Deterministic.
 *
 * @param {string} scope
 * @param {string} scopeId  - hex 24 chars (ObjectId hex string)
 * @returns {string} 64 hex chars
 * @throws {Error} if scope not in VALID_SCOPES or scopeId not hex 24.
 */
function _computeGenesisHash(scope, scopeId) {
  if (typeof scope !== 'string' || !VALID_SCOPES.has(scope)) {
    const e = new Error(`sealedVerifier: invalid scope "${scope}"`);
    e.code = 'INVALID_SCOPE';
    throw e;
  }
  if (typeof scopeId !== 'string' || !HEX24_RE.test(scopeId)) {
    const e = new Error(`sealedVerifier: scopeId must be 24-char hex (got "${scopeId}")`);
    e.code = 'INVALID_SCOPE_ID';
    throw e;
  }
  return _sha256Hex(`${GENESIS_PREFIX}${scope}:${scopeId.toLowerCase()}:genesis`);
}

/**
 * Compute recursive entry hash. Identical to `services/hashChain._computeEntryHash`.
 *
 * @param {string} prevHash       - hex 64 chars
 * @param {string} payloadHash    - hex 64 chars
 * @param {string} attestedAtISO  - ISO 8601 UTC string
 * @returns {string} 64 hex chars
 */
function _computeEntryHash(prevHash, payloadHash, attestedAtISO) {
  return _sha256Hex(`${prevHash}:${payloadHash}:${attestedAtISO}`);
}

/**
 * Compute payloadHash by re-canonicalizing the canonical from scratch.
 * Direct wrapper over `lib/canonicalHash.payloadHashOf`. Explicit identity
 * so tests can validate equivalence.
 *
 * @param {*} canonical
 * @returns {string} 64 hex chars
 */
function _computePayloadHash(canonical) {
  return payloadHashOf(canonical);
}

/**
 * Build canonical failure output with reason + brokenAtSequence + hashes.
 * Ensures all call sites return exactly the same shape.
 *
 * @param {object} params
 * @returns {object}
 */
function _failure({
  reason,
  totalEntries,
  brokenAtSequence = null,
  expectedHash = null,
  actualHash = null,
  genesis = null,
}) {
  return {
    ok: false,
    totalEntries,
    brokenAtSequence,
    expectedHash,
    actualHash,
    reason,
    genesis,
  };
}

/**
 * Validate input shape of `exportData`. Returns `{ valid: true, scope,
 * scopeId, entries, genesis }` if pass, or failure object if not.
 *
 * @param {*} exportData
 * @returns {object}
 */
function _validateExportShape(exportData) {
  if (!exportData || typeof exportData !== 'object' || Array.isArray(exportData)) {
    return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: 0 });
  }

  const { scope, scopeId, entries, genesis } = exportData;

  if (typeof scope !== 'string' || !VALID_SCOPES.has(scope)) {
    return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: 0 });
  }

  if (typeof scopeId !== 'string' || !HEX24_RE.test(scopeId)) {
    return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: 0 });
  }

  if (!Array.isArray(entries)) {
    return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: 0 });
  }

  if (genesis !== undefined && (typeof genesis !== 'string' || !HEX64_RE.test(genesis))) {
    return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
  }

  // Per-entry shape validation.
  for (let i = 0; i < entries.length; i += 1) {
    const e = entries[i];
    if (!e || typeof e !== 'object' || Array.isArray(e)) {
      return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
    }
    if (typeof e.sequence !== 'number') {
      return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
    }
    if (typeof e.hash !== 'string' || !HEX64_RE.test(e.hash)) {
      return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
    }
    if (typeof e.prevHash !== 'string' || !HEX64_RE.test(e.prevHash)) {
      return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
    }
    if (typeof e.payloadHash !== 'string' || !HEX64_RE.test(e.payloadHash)) {
      return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
    }
    if (e.canonical === undefined) {
      return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
    }
    if (e.attestedAt === undefined || e.attestedAt === null) {
      return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
    }
  }

  return { valid: true, scope, scopeId: scopeId.toLowerCase(), entries, genesis };
}

/**
 * Normalize attestedAt to ISO string (exports may carry Date object or ISO
 * string depending on serializer).
 *
 * @param {*} v
 * @returns {string|null}
 */
function _attestedAtToISO(v) {
  if (v instanceof Date) {
    if (Number.isNaN(v.getTime())) return null;
    return v.toISOString();
  }
  if (typeof v === 'string') {
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return null;
    return d.toISOString();
  }
  return null;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Verify a chain segment standalone (without exportData shape). Useful for
 * verifying partial segments or when the caller has parsed genesis separately.
 *
 * Does NOT validate `exportData` shape — assumes entries already validated
 * externally. For end-to-end verification of an E3 Audit Pack export, use
 * `verifySealedExport()`.
 *
 * @param {Array} entries           - entries in chronological order (sequence asc).
 * @param {string} genesis          - hex 64 chars of the chain genesis.
 * @param {object} [opts]           - reserved for extensions.
 * @returns {object} success or failure shape (see module header).
 */
function verifyChainSegment(entries, genesis, _opts = {}) {
  if (!Array.isArray(entries)) {
    return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: 0 });
  }
  if (typeof genesis !== 'string' || !HEX64_RE.test(genesis)) {
    return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
  }

  if (entries.length === 0) {
    return { ok: true, totalEntries: 0, head: null, genesis };
  }

  let expectedPrev = genesis;
  let expectedSequence = entries[0].sequence;

  if (expectedSequence === 0 && entries[0].prevHash !== genesis) {
    return _failure({
      reason: 'PREV_HASH_MISMATCH',
      totalEntries: entries.length,
      brokenAtSequence: 0,
      expectedHash: genesis,
      actualHash: entries[0].prevHash,
      genesis,
    });
  }

  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];

    if (entry.sequence !== expectedSequence) {
      return _failure({
        reason: 'SEQUENCE_GAP',
        totalEntries: entries.length,
        brokenAtSequence: entry.sequence,
        expectedHash: null,
        actualHash: null,
        genesis,
      });
    }

    if (entry.prevHash !== expectedPrev) {
      return _failure({
        reason: 'PREV_HASH_MISMATCH',
        totalEntries: entries.length,
        brokenAtSequence: entry.sequence,
        expectedHash: expectedPrev,
        actualHash: entry.prevHash,
        genesis,
      });
    }

    let recomputedPayloadHash;
    try {
      recomputedPayloadHash = _computePayloadHash(entry.canonical);
    } catch (_) {
      return _failure({
        reason: 'PAYLOAD_HASH_MISMATCH',
        totalEntries: entries.length,
        brokenAtSequence: entry.sequence,
        expectedHash: null,
        actualHash: entry.payloadHash,
        genesis,
      });
    }
    if (recomputedPayloadHash !== entry.payloadHash) {
      return _failure({
        reason: 'PAYLOAD_HASH_MISMATCH',
        totalEntries: entries.length,
        brokenAtSequence: entry.sequence,
        expectedHash: recomputedPayloadHash,
        actualHash: entry.payloadHash,
        genesis,
      });
    }

    const attestedAtISO = _attestedAtToISO(entry.attestedAt);
    if (attestedAtISO === null) {
      return _failure({
        reason: 'ENTRY_HASH_MISMATCH',
        totalEntries: entries.length,
        brokenAtSequence: entry.sequence,
        expectedHash: null,
        actualHash: entry.hash,
        genesis,
      });
    }
    const recomputedHash = _computeEntryHash(
      entry.prevHash,
      entry.payloadHash,
      attestedAtISO,
    );
    if (recomputedHash !== entry.hash) {
      return _failure({
        reason: 'ENTRY_HASH_MISMATCH',
        totalEntries: entries.length,
        brokenAtSequence: entry.sequence,
        expectedHash: recomputedHash,
        actualHash: entry.hash,
        genesis,
      });
    }

    expectedPrev = entry.hash;
    expectedSequence += 1;
  }

  return {
    ok: true,
    totalEntries: entries.length,
    head: entries[entries.length - 1].hash,
    genesis,
  };
}

/**
 * Verify a full export from `hashChain.exportChain()`. Pipeline:
 *
 *   1. Validate `exportData` shape (top-level + per-entry required fields).
 *   2. Recompute genesis from (scope, scopeId). Compare against
 *      exportData.genesis → if mismatch return GENESIS_MISMATCH.
 *   3. If entries empty → return ok (trivial chain).
 *   4. Iterate entries in ascending sequence order from 0:
 *      a) sequence === expectedSequence (else SEQUENCE_GAP).
 *      b) prevHash === expectedPrev (genesis for 0, hash before for >0).
 *      c) payloadHash === sha256(canonicalJson(canonical))
 *         (else PAYLOAD_HASH_MISMATCH).
 *      d) hash === sha256(prevHash + ':' + payloadHash + ':' + attestedAt.iso())
 *         (else ENTRY_HASH_MISMATCH).
 *   5. exportData.head if present must match last entry.hash.
 *
 * @param {object} exportData       - output of hashChain.exportChain()
 * @param {object} [opts]           - reserved.
 * @returns {object} success or failure shape.
 */
function verifySealedExport(exportData, _opts = {}) {
  const shape = _validateExportShape(exportData);
  if (shape.valid !== true) return shape;

  const { scope, scopeId, entries, genesis: declaredGenesis } = shape;

  let expectedGenesis;
  try {
    expectedGenesis = _computeGenesisHash(scope, scopeId);
  } catch (_) {
    return _failure({
      reason: 'INVALID_EXPORT_SHAPE',
      totalEntries: entries.length,
    });
  }

  if (declaredGenesis !== undefined && declaredGenesis !== expectedGenesis) {
    return _failure({
      reason: 'GENESIS_MISMATCH',
      totalEntries: entries.length,
      brokenAtSequence: null,
      expectedHash: expectedGenesis,
      actualHash: declaredGenesis,
      genesis: expectedGenesis,
    });
  }

  if (entries.length === 0) {
    return { ok: true, totalEntries: 0, head: null, genesis: expectedGenesis };
  }

  if (entries[0].sequence !== 0) {
    return _failure({
      reason: 'SEQUENCE_GAP',
      totalEntries: entries.length,
      brokenAtSequence: entries[0].sequence,
      expectedHash: null,
      actualHash: null,
      genesis: expectedGenesis,
    });
  }

  const segmentResult = verifyChainSegment(entries, expectedGenesis);
  if (!segmentResult.ok) {
    return segmentResult;
  }

  if (exportData.head !== undefined && exportData.head !== null) {
    if (exportData.head !== segmentResult.head) {
      return _failure({
        reason: 'ENTRY_HASH_MISMATCH',
        totalEntries: entries.length,
        brokenAtSequence: entries[entries.length - 1].sequence,
        expectedHash: segmentResult.head,
        actualHash: exportData.head,
        genesis: expectedGenesis,
      });
    }
  }

  return segmentResult;
}

// ── Exports ────────────────────────────────────────────────────────────────

export { verifySealedExport, verifyChainSegment };

// `__internal__` exports for isolated tests and fixture generators.
// Public API does NOT expose these — only verifySealedExport / verifyChainSegment.
export const __internal__ = {
  _computeGenesisHash,
  _computeEntryHash,
  _computePayloadHash,
  GENESIS_PREFIX,
  VALID_SCOPES,
  HEX24_RE,
  HEX64_RE,
  canonicalJson,
  payloadHashOf,
};
