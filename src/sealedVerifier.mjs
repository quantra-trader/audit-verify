/**
 * sealedVerifier.mjs — Pure offline verifier for Quantra Sealed™ chain exports.
 *
 * Single source of truth — bit-for-bit identical to Quantra backend
 * `lib/sealedVerifier.js`. Verify Quantra exports without trusting Quantra.
 *
 * Algorithm:
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
 * Output shape (success):
 *   { ok: true, totalEntries, head, genesis }
 *
 * Output shape (failure):
 *   {
 *     ok: false,
 *     totalEntries, brokenAtSequence, expectedHash, actualHash, reason, genesis
 *   }
 *
 *   reason ∈ {
 *     'INVALID_EXPORT_SHAPE',
 *     'GENESIS_MISMATCH',
 *     'SEQUENCE_GAP',
 *     'PREV_HASH_MISMATCH',
 *     'PAYLOAD_HASH_MISMATCH',
 *     'ENTRY_HASH_MISMATCH'
 *   }
 *
 * Zero deps beyond Node `crypto` and the local `canonicalHash.mjs` primitive.
 *
 * License: MIT
 */

import crypto from 'node:crypto';
import { canonicalJson, payloadHashOf } from './canonicalHash.mjs';

const GENESIS_PREFIX = 'quantra:hashchain:';
const VALID_SCOPES = new Set(['account', 'user', 'mentor', 'eventbus', 'tax_report']);
const HEX24_RE = /^[a-f0-9]{24}$/i;
const HEX64_RE = /^[0-9a-f]{64}$/;

function _sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

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

function _computeEntryHash(prevHash, payloadHash, attestedAtISO) {
  return _sha256Hex(`${prevHash}:${payloadHash}:${attestedAtISO}`);
}

function _computePayloadHash(canonical) {
  return payloadHashOf(canonical);
}

function _failure({
  reason,
  totalEntries,
  brokenAtSequence = null,
  expectedHash = null,
  actualHash = null,
  genesis = null,
}) {
  return { ok: false, totalEntries, brokenAtSequence, expectedHash, actualHash, reason, genesis };
}

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

/**
 * Verify a chain segment standalone. Useful for partial segments.
 * For full E3 Audit Pack export verification, use `verifySealedExport()`.
 */
export function verifyChainSegment(entries, genesis) {
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
    const recomputedHash = _computeEntryHash(entry.prevHash, entry.payloadHash, attestedAtISO);
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

  return { ok: true, totalEntries: entries.length, head: entries[entries.length - 1].hash, genesis };
}

/**
 * Verify a full Quantra Audit Pack export from `hashChain.exportChain()` output.
 *
 * Pipeline:
 *   1. Validate exportData shape (top-level + per-entry required fields).
 *   2. Recompute genesis from (scope, scopeId).
 *   3. Iterate entries in sequence-ascending order from 0:
 *      a) sequence contiguous
 *      b) prevHash matches genesis (entry 0) or hash_{n-1} (entry n>0)
 *      c) payloadHash recomputed from canonical
 *      d) hash recomputed from (prevHash, payloadHash, attestedAt)
 *   4. exportData.head must match last entry hash if present.
 */
export function verifySealedExport(exportData) {
  const shape = _validateExportShape(exportData);
  if (shape.valid !== true) return shape;

  const { scope, scopeId, entries, genesis: declaredGenesis } = shape;

  let expectedGenesis;
  try {
    expectedGenesis = _computeGenesisHash(scope, scopeId);
  } catch (_) {
    return _failure({ reason: 'INVALID_EXPORT_SHAPE', totalEntries: entries.length });
  }

  if (declaredGenesis !== undefined && declaredGenesis !== expectedGenesis) {
    return _failure({
      reason: 'GENESIS_MISMATCH',
      totalEntries: entries.length,
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
      genesis: expectedGenesis,
    });
  }

  const segmentResult = verifyChainSegment(entries, expectedGenesis);
  if (!segmentResult.ok) return segmentResult;

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

export const __internal__ = {
  _computeGenesisHash,
  _computeEntryHash,
  _computePayloadHash,
  GENESIS_PREFIX,
  VALID_SCOPES,
  HEX24_RE,
  HEX64_RE,
};
