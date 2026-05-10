/**
 * tests/verifier.test.mjs — Sealed™ Audit Pack Verifier
 * ============================================================================
 *
 * Test suite for `verify.mjs` + `lib/sealedVerifier.mjs`. Uses Node 20+
 * built-in `node:test` runner. Zero external test framework dependencies.
 *
 * Run:
 *   node --test tests/
 *
 * Covers all acceptance criteria from F2.1 §T-F2.1.4:
 *   - valid-chain-returns-ok
 *   - tampered-canonical-detected (PAYLOAD_HASH_MISMATCH)
 *   - tampered-prevHash-detected
 *   - tampered-attestedAt-detected (ENTRY_HASH_MISMATCH)
 *   - empty-chain-ok
 *   - genesis-mismatch-detected
 *   - sequence-gap-detected
 *   - cross-account-isolation
 *   - malformed-input-rejected
 *   - pure-no-mongoose meta-test
 *   - __internal__ exports present
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  verifySealedExport,
  verifyChainSegment,
  __internal__,
} from '../lib/sealedVerifier.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures');

async function loadFixture(name) {
  const raw = await readFile(join(fixturesDir, name), 'utf-8');
  return JSON.parse(raw);
}

// ─── Happy path ─────────────────────────────────────────────────────────────

test('valid chain returns ok:true with totalEntries + head + genesis', async () => {
  const fixture = await loadFixture('valid-chain.json');
  const result = verifySealedExport(fixture);

  assert.equal(result.ok, true);
  assert.equal(result.totalEntries, 3);
  assert.match(result.head, /^[0-9a-f]{64}$/);
  assert.match(result.genesis, /^[0-9a-f]{64}$/);
});

test('valid chain head matches last entry hash', async () => {
  const fixture = await loadFixture('valid-chain.json');
  const result = verifySealedExport(fixture);

  assert.equal(result.ok, true);
  assert.equal(result.head, fixture.entries[fixture.entries.length - 1].hash);
});

// ─── PAYLOAD_HASH_MISMATCH (canonical tampering) ────────────────────────────

test('tampered canonical payload → PAYLOAD_HASH_MISMATCH', async () => {
  const fixture = await loadFixture('tampered-payload.json');
  const result = verifySealedExport(fixture);

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'PAYLOAD_HASH_MISMATCH');
  assert.equal(result.brokenAtSequence, 1);
  assert.match(result.expectedHash, /^[0-9a-f]{64}$/);
  assert.match(result.actualHash, /^[0-9a-f]{64}$/);
  assert.notEqual(result.expectedHash, result.actualHash);
});

// ─── PREV_HASH_MISMATCH ─────────────────────────────────────────────────────

test('tampered prevHash → PREV_HASH_MISMATCH', async () => {
  const fixture = await loadFixture('tampered-prevhash.json');
  const result = verifySealedExport(fixture);

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'PREV_HASH_MISMATCH');
  assert.equal(result.brokenAtSequence, 2);
});

// ─── ENTRY_HASH_MISMATCH (attestedAt tampering) ─────────────────────────────

test('tampered attestedAt → ENTRY_HASH_MISMATCH or downstream PREV_HASH_MISMATCH', async () => {
  const fixture = await loadFixture('tampered-attestedat.json');
  const result = verifySealedExport(fixture);

  assert.equal(result.ok, false);
  // Tampering attestedAt at entry 1 produces an ENTRY_HASH_MISMATCH at entry 1
  // (the hash was computed with original attestedAt). It does not propagate to
  // entry 2's prevHash because we recompute and detect immediately.
  assert.equal(result.reason, 'ENTRY_HASH_MISMATCH');
  assert.equal(result.brokenAtSequence, 1);
});

// ─── Empty chain ────────────────────────────────────────────────────────────

test('empty chain returns ok:true with totalEntries:0', async () => {
  const fixture = await loadFixture('empty-chain.json');
  const result = verifySealedExport(fixture);

  assert.equal(result.ok, true);
  assert.equal(result.totalEntries, 0);
  assert.equal(result.head, null);
  assert.match(result.genesis, /^[0-9a-f]{64}$/);
});

// ─── GENESIS_MISMATCH ───────────────────────────────────────────────────────

test('genesis from different scopeId → GENESIS_MISMATCH', async () => {
  const fixture = await loadFixture('genesis-mismatch.json');
  const result = verifySealedExport(fixture);

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'GENESIS_MISMATCH');
  assert.equal(result.brokenAtSequence, null);
  assert.match(result.expectedHash, /^[0-9a-f]{64}$/);
  assert.match(result.actualHash, /^[0-9a-f]{64}$/);
  assert.notEqual(result.expectedHash, result.actualHash);
});

// ─── SEQUENCE_GAP ───────────────────────────────────────────────────────────

test('sequence gap (missing entry 1) → SEQUENCE_GAP', async () => {
  const fixture = await loadFixture('sequence-gap.json');
  const result = verifySealedExport(fixture);

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'SEQUENCE_GAP');
  // After entry 0, expectedSequence = 1, but next entry has sequence = 2.
  assert.equal(result.brokenAtSequence, 2);
});

// ─── INVALID_EXPORT_SHAPE ───────────────────────────────────────────────────

test('null exportData → INVALID_EXPORT_SHAPE', () => {
  const result = verifySealedExport(null);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('non-object exportData (string) → INVALID_EXPORT_SHAPE', () => {
  const result = verifySealedExport('not an object');
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('array exportData → INVALID_EXPORT_SHAPE', () => {
  const result = verifySealedExport([]);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('missing scope → INVALID_EXPORT_SHAPE', () => {
  const result = verifySealedExport({ scopeId: '6450a1b2c3d4e5f600000001', entries: [] });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('invalid scope (not in VALID_SCOPES) → INVALID_EXPORT_SHAPE', () => {
  const result = verifySealedExport({
    scope: 'invalid_scope',
    scopeId: '6450a1b2c3d4e5f600000001',
    entries: [],
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('invalid scopeId (not 24-char hex) → INVALID_EXPORT_SHAPE', () => {
  const result = verifySealedExport({
    scope: 'account',
    scopeId: 'not-hex',
    entries: [],
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('entries not an array → INVALID_EXPORT_SHAPE', () => {
  const result = verifySealedExport({
    scope: 'account',
    scopeId: '6450a1b2c3d4e5f600000001',
    entries: 'not an array',
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('entry missing canonical → INVALID_EXPORT_SHAPE', async () => {
  const valid = await loadFixture('valid-chain.json');
  const malformed = JSON.parse(JSON.stringify(valid));
  delete malformed.entries[1].canonical;
  const result = verifySealedExport(malformed);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('entry with invalid hash format → INVALID_EXPORT_SHAPE', async () => {
  const valid = await loadFixture('valid-chain.json');
  const malformed = JSON.parse(JSON.stringify(valid));
  malformed.entries[1].hash = 'not-hex-64';
  const result = verifySealedExport(malformed);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

// ─── Cross-scope isolation ──────────────────────────────────────────────────

test('exports for different scopeIds produce different genesis hashes', () => {
  const { _computeGenesisHash } = __internal__;
  const gA = _computeGenesisHash('account', '6450a1b2c3d4e5f600000001');
  const gB = _computeGenesisHash('account', '6450a1b2c3d4e5f600000002');
  assert.notEqual(gA, gB);
});

test('exports for different scopes produce different genesis hashes', () => {
  const { _computeGenesisHash } = __internal__;
  const gAccount = _computeGenesisHash('account', '6450a1b2c3d4e5f600000001');
  const gUser = _computeGenesisHash('user', '6450a1b2c3d4e5f600000001');
  assert.notEqual(gAccount, gUser);
});

// ─── __internal__ exports ──────────────────────────────────────────────────

test('__internal__ exports required helpers', () => {
  assert.equal(typeof __internal__._computeGenesisHash, 'function');
  assert.equal(typeof __internal__._computeEntryHash, 'function');
  assert.equal(typeof __internal__._computePayloadHash, 'function');
  assert.equal(typeof __internal__.canonicalJson, 'function');
  assert.equal(typeof __internal__.payloadHashOf, 'function');
  assert.equal(__internal__.GENESIS_PREFIX, 'quantra:hashchain:');
  assert.ok(__internal__.VALID_SCOPES instanceof Set);
  assert.ok(__internal__.VALID_SCOPES.has('account'));
});

// ─── verifyChainSegment (lower-level API) ──────────────────────────────────

test('verifyChainSegment with empty entries + valid genesis → ok', () => {
  const { _computeGenesisHash } = __internal__;
  const genesis = _computeGenesisHash('account', '6450a1b2c3d4e5f600000001');
  const result = verifyChainSegment([], genesis);
  assert.equal(result.ok, true);
  assert.equal(result.totalEntries, 0);
  assert.equal(result.head, null);
});

test('verifyChainSegment with malformed genesis → INVALID_EXPORT_SHAPE', () => {
  const result = verifyChainSegment([], 'not-hex-64');
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

test('verifyChainSegment with non-array entries → INVALID_EXPORT_SHAPE', () => {
  const result = verifyChainSegment('not-array', 'a'.repeat(64));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
});

// ─── Pure: no external deps meta-test ───────────────────────────────────────

test('PURE: lib/sealedVerifier.mjs has zero external dependencies', async () => {
  const src = await readFile(join(__dirname, '..', 'lib', 'sealedVerifier.mjs'), 'utf-8');
  const importRegex = /^\s*import\s+(?:.+?\s+from\s+)?['"]([^'"]+)['"]/gm;
  const matches = [...src.matchAll(importRegex)];
  assert.ok(matches.length > 0, 'expected some imports');
  for (const m of matches) {
    const dep = m[1];
    const isBuiltin = dep.startsWith('node:');
    const isRelative = dep.startsWith('./') || dep.startsWith('../');
    assert.ok(
      isBuiltin || isRelative,
      `External dep detected in sealedVerifier.mjs: "${dep}" — verifier MUST be 0-dep`,
    );
  }
});

test('PURE: lib/canonicalHash.mjs has zero external dependencies', async () => {
  const src = await readFile(join(__dirname, '..', 'lib', 'canonicalHash.mjs'), 'utf-8');
  const importRegex = /^\s*import\s+(?:.+?\s+from\s+)?['"]([^'"]+)['"]/gm;
  const matches = [...src.matchAll(importRegex)];
  for (const m of matches) {
    const dep = m[1];
    const isBuiltin = dep.startsWith('node:');
    const isRelative = dep.startsWith('./') || dep.startsWith('../');
    assert.ok(
      isBuiltin || isRelative,
      `External dep detected in canonicalHash.mjs: "${dep}" — verifier MUST be 0-dep`,
    );
  }
});

test('PURE: verify.mjs has zero external dependencies', async () => {
  const src = await readFile(join(__dirname, '..', 'verify.mjs'), 'utf-8');
  const importRegex = /^\s*import\s+(?:.+?\s+from\s+)?['"]([^'"]+)['"]/gm;
  const matches = [...src.matchAll(importRegex)];
  assert.ok(matches.length > 0, 'expected some imports');
  for (const m of matches) {
    const dep = m[1];
    const isBuiltin = dep.startsWith('node:');
    const isRelative = dep.startsWith('./') || dep.startsWith('../');
    assert.ok(
      isBuiltin || isRelative,
      `External dep detected in verify.mjs: "${dep}" — verifier MUST be 0-dep`,
    );
  }
});

test('PURE: package.json has empty dependencies and devDependencies', async () => {
  const pkgPath = join(__dirname, '..', 'package.json');
  const pkg = JSON.parse(await readFile(pkgPath, 'utf-8'));
  const deps = pkg.dependencies || {};
  const devDeps = pkg.devDependencies || {};
  assert.equal(
    Object.keys(deps).length,
    0,
    `package.json must have ZERO dependencies (found: ${Object.keys(deps).join(', ')})`,
  );
  assert.equal(
    Object.keys(devDeps).length,
    0,
    `package.json must have ZERO devDependencies (found: ${Object.keys(devDeps).join(', ')})`,
  );
});
