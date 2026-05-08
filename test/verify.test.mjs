/**
 * Test suite for verify.mjs / sealedVerifier.mjs.
 *
 * Run with: node --test test/
 *
 * License: MIT
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

import {
  verifySealedExport,
  verifyChainSegment,
  __internal__,
} from '../src/sealedVerifier.mjs';
import { canonicalJson, payloadHashOf } from '../src/canonicalHash.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');

// ── Test helpers — build a valid chain for testing ──────────────────────────

function _sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function buildValidChain({ scope = 'account', scopeId, canonicals }) {
  const id = scopeId || crypto.randomBytes(12).toString('hex');
  const genesis = _sha256Hex(`quantra:hashchain:${scope}:${id}:genesis`);

  const entries = [];
  let prevHash = genesis;

  for (let i = 0; i < canonicals.length; i += 1) {
    const canonical = canonicals[i];
    const attestedAt = new Date(2026, 4, 8, 12, 0, i).toISOString();
    const payloadHash = payloadHashOf(canonical);
    const hash = _sha256Hex(`${prevHash}:${payloadHash}:${attestedAt}`);
    entries.push({
      sequence: i,
      hash,
      prevHash,
      payloadHash,
      canonical,
      attestedAt,
      eventType: i === 0 ? 'trade.attested' : 'trade.attested',
      refType: 'TradeAttestation',
      refId: crypto.randomBytes(12).toString('hex'),
      attestedBy: crypto.randomBytes(12).toString('hex'),
      correctsEntryId: null,
      publicId: '01HXXXXXXXXXXXXXXXXXXXXXXX'.slice(0, 26),
    });
    prevHash = hash;
  }

  return {
    scope,
    scopeId: id,
    genesis,
    head: entries.length > 0 ? entries[entries.length - 1].hash : null,
    length: entries.length,
    entries,
  };
}

// ── Tests ────────────────────────────────────────────────────────────────────

test('valid 3-entry chain returns ok', () => {
  const chain = buildValidChain({
    canonicals: [
      { trade: '1', symbol: 'MNQ', side: 'long', size: 1 },
      { trade: '2', symbol: 'ES', side: 'short', size: 2 },
      { trade: '3', symbol: 'EURUSD', side: 'long', size: 0.5 },
    ],
  });

  const result = verifySealedExport(chain);
  assert.equal(result.ok, true);
  assert.equal(result.totalEntries, 3);
  assert.equal(result.head, chain.entries[2].hash);
  assert.equal(result.genesis, chain.genesis);
});

test('empty chain returns ok with head null', () => {
  const chain = buildValidChain({ canonicals: [] });
  const result = verifySealedExport(chain);
  assert.equal(result.ok, true);
  assert.equal(result.totalEntries, 0);
  assert.equal(result.head, null);
});

test('PAYLOAD_HASH_MISMATCH detected when canonical tampered', () => {
  const chain = buildValidChain({
    canonicals: [{ trade: 'A', symbol: 'MNQ' }, { trade: 'B', symbol: 'ES' }],
  });
  // Tamper canonical of entry 1 but keep stored payloadHash.
  chain.entries[1].canonical = { trade: 'B-EVIL', symbol: 'ES' };

  const result = verifySealedExport(chain);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'PAYLOAD_HASH_MISMATCH');
  assert.equal(result.brokenAtSequence, 1);
});

test('PREV_HASH_MISMATCH detected when prevHash mutated', () => {
  const chain = buildValidChain({
    canonicals: [{ trade: 'A' }, { trade: 'B' }, { trade: 'C' }],
  });
  chain.entries[1].prevHash = '0'.repeat(64);

  const result = verifySealedExport(chain);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'PREV_HASH_MISMATCH');
  assert.equal(result.brokenAtSequence, 1);
});

test('ENTRY_HASH_MISMATCH detected when attestedAt mutated', () => {
  const chain = buildValidChain({
    canonicals: [{ trade: 'A' }, { trade: 'B' }],
  });
  chain.entries[1].attestedAt = '2099-01-01T00:00:00.000Z';

  const result = verifySealedExport(chain);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'ENTRY_HASH_MISMATCH');
  assert.equal(result.brokenAtSequence, 1);
});

test('GENESIS_MISMATCH detected when declared genesis tampered', () => {
  const chain = buildValidChain({ canonicals: [{ trade: 'A' }] });
  chain.genesis = '0'.repeat(64);

  const result = verifySealedExport(chain);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'GENESIS_MISMATCH');
});

test('SEQUENCE_GAP detected with skipped entry', () => {
  const chain = buildValidChain({
    canonicals: [{ trade: 'A' }, { trade: 'B' }, { trade: 'C' }],
  });
  chain.entries.splice(1, 1); // remove entry 1, leaving [0, 2]

  const result = verifySealedExport(chain);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'SEQUENCE_GAP');
});

test('INVALID_EXPORT_SHAPE — null exportData', () => {
  const result = verifySealedExport(null);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('INVALID_EXPORT_SHAPE — invalid scope', () => {
  const chain = buildValidChain({ canonicals: [{ trade: 'A' }] });
  chain.scope = 'evil_scope';
  const result = verifySealedExport(chain);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('INVALID_EXPORT_SHAPE — non-hex scopeId', () => {
  const chain = buildValidChain({ canonicals: [{ trade: 'A' }] });
  chain.scopeId = 'not-a-hex-string';
  const result = verifySealedExport(chain);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('INVALID_EXPORT_SHAPE — entries not array', () => {
  const result = verifySealedExport({
    scope: 'account',
    scopeId: '5'.repeat(24),
    entries: 'not-an-array',
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('INVALID_EXPORT_SHAPE — entry missing canonical', () => {
  const chain = buildValidChain({ canonicals: [{ trade: 'A' }] });
  delete chain.entries[0].canonical;
  const result = verifySealedExport(chain);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('verifyChainSegment standalone — valid', () => {
  const chain = buildValidChain({
    canonicals: [{ trade: 'A' }, { trade: 'B' }],
  });
  const result = verifyChainSegment(chain.entries, chain.genesis);
  assert.equal(result.ok, true);
  assert.equal(result.totalEntries, 2);
});

test('verifyChainSegment standalone — empty', () => {
  const result = verifyChainSegment([], '0'.repeat(64));
  assert.equal(result.ok, true);
  assert.equal(result.totalEntries, 0);
});

test('canonicalJson determinism — key order independent', () => {
  const a = canonicalJson({ a: 1, b: 2, nested: { x: 'foo', y: 'bar' } });
  const b = canonicalJson({ nested: { y: 'bar', x: 'foo' }, b: 2, a: 1 });
  assert.equal(a, b);
});

test('payloadHashOf determinism — same input same hash', () => {
  const h1 = payloadHashOf({ a: 1, b: 2 });
  const h2 = payloadHashOf({ b: 2, a: 1 });
  assert.equal(h1, h2);
  assert.match(h1, /^[0-9a-f]{64}$/);
});

test('genesis hash matches Quantra backend algorithm exactly', () => {
  const scope = 'account';
  const scopeId = 'aabbccddeeff001122334455'; // ObjectId hex = exactly 24 chars
  const genesis = __internal__._computeGenesisHash(scope, scopeId);
  const expected = _sha256Hex(`quantra:hashchain:${scope}:${scopeId}:genesis`);
  assert.equal(genesis, expected);
});

test('cross-account isolation — entries from chain A with scope of chain B fails', () => {
  const chainA = buildValidChain({
    canonicals: [{ trade: 'A' }, { trade: 'B' }],
  });
  const chainB = buildValidChain({
    canonicals: [{ trade: 'X' }, { trade: 'Y' }],
  });
  // Frankenstein: A's entries with B's scope/scopeId/genesis.
  const frankenstein = {
    scope: chainB.scope,
    scopeId: chainB.scopeId,
    genesis: chainB.genesis,
    entries: chainA.entries,
  };
  const result = verifySealedExport(frankenstein);
  assert.equal(result.ok, false);
  // Should fail at first entry since A's prevHash != B's genesis.
  assert.equal(result.reason, 'PREV_HASH_MISMATCH');
  assert.equal(result.brokenAtSequence, 0);
});

test('exportData.head consistency check — fails if head tampered', () => {
  const chain = buildValidChain({
    canonicals: [{ trade: 'A' }, { trade: 'B' }],
  });
  chain.head = '0'.repeat(64); // tamper head field
  const result = verifySealedExport(chain);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'ENTRY_HASH_MISMATCH');
});

// ── CLI integration tests ───────────────────────────────────────────────────

test('CLI verify.mjs — valid chain exits 0', () => {
  const chain = buildValidChain({
    canonicals: [{ trade: 'A' }, { trade: 'B' }],
  });
  const tmpFile = join(REPO_ROOT, '.test-tmp-valid.json');
  writeFileSync(tmpFile, JSON.stringify(chain));
  try {
    const result = spawnSync('node', ['verify.mjs', tmpFile], { cwd: REPO_ROOT, encoding: 'utf8' });
    assert.equal(result.status, 0);
    const stdout = JSON.parse(result.stdout);
    assert.equal(stdout.ok, true);
    assert.equal(stdout.totalEntries, 2);
  } finally {
    unlinkSync(tmpFile);
  }
});

test('CLI verify.mjs — tampered chain exits 1', () => {
  const chain = buildValidChain({
    canonicals: [{ trade: 'A' }, { trade: 'B' }],
  });
  chain.entries[1].canonical = { trade: 'TAMPERED' };
  const tmpFile = join(REPO_ROOT, '.test-tmp-tampered.json');
  writeFileSync(tmpFile, JSON.stringify(chain));
  try {
    const result = spawnSync('node', ['verify.mjs', tmpFile], { cwd: REPO_ROOT, encoding: 'utf8' });
    assert.equal(result.status, 1);
    const stdout = JSON.parse(result.stdout);
    assert.equal(stdout.ok, false);
    assert.equal(stdout.reason, 'PAYLOAD_HASH_MISMATCH');
  } finally {
    unlinkSync(tmpFile);
  }
});

test('CLI verify.mjs — accepts Quantra envelope { data: { export } }', () => {
  const chain = buildValidChain({
    canonicals: [{ trade: 'A' }],
  });
  const envelope = {
    data: {
      account: { publicId: 'AAAAA', name: 'Test Account', slug: null },
      export: chain,
      verifierCommand: 'node verify.mjs path/to/this.json',
      auditVerifyRepo: 'https://github.com/quantra-trader/audit-verify',
    },
    meta: { requestId: 'test', timestamp: new Date().toISOString() },
  };
  const tmpFile = join(REPO_ROOT, '.test-tmp-envelope.json');
  writeFileSync(tmpFile, JSON.stringify(envelope));
  try {
    const result = spawnSync('node', ['verify.mjs', tmpFile], { cwd: REPO_ROOT, encoding: 'utf8' });
    assert.equal(result.status, 0);
    const stdout = JSON.parse(result.stdout);
    assert.equal(stdout.ok, true);
  } finally {
    unlinkSync(tmpFile);
  }
});

test('CLI verify.mjs — missing argument exits 2', () => {
  const result = spawnSync('node', ['verify.mjs'], { cwd: REPO_ROOT, encoding: 'utf8' });
  assert.equal(result.status, 2);
});
