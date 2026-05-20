/**
 * tests/cross-version.test.mjs — v2.0.0 backwards compatibility check.
 *
 * Validates that v1.x-generated audit pack exports (scopes 'account', 'user',
 * 'mentor', 'eventbus', 'tax_report') verify OK under v2.0.0 verifier without
 * modification. This is the contract guarantee that releases new scopes
 * additively without breaking existing v1.x fixtures.
 *
 * Pattern: load v1.x fixtures from tests/fixtures/ + run verifier + assert
 * ok=true for valid exports, ok=false with expected reason for tampered.
 *
 * Cross-version sync gate: when backend bumps sealedVerifier algorithm (NOT
 * just scope additions), this test fails — forcing the maintainer to write
 * migration shim before merging.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { verifySealedExport } from '../lib/sealedVerifier.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures');

async function loadFixture(name) {
  const raw = await readFile(join(fixturesDir, name), 'utf-8');
  return JSON.parse(raw);
}

describe('v2.0.0 backwards compatibility with v1.x fixtures', () => {
  it('v1.x valid-chain (scope account) still verifies OK', async () => {
    const data = await loadFixture('valid-chain.json');
    const result = verifySealedExport(data);
    assert.equal(result.ok, true);
    assert.equal(result.totalEntries, 3);
    assert.equal(data.scope, 'account'); // confirm legacy scope
  });

  it('v1.x empty-chain still verifies OK', async () => {
    const data = await loadFixture('empty-chain.json');
    const result = verifySealedExport(data);
    assert.equal(result.ok, true);
    assert.equal(result.totalEntries, 0);
  });

  it('v1.x tampered-payload still detected', async () => {
    const data = await loadFixture('tampered-payload.json');
    const result = verifySealedExport(data);
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'PAYLOAD_HASH_MISMATCH');
  });

  it('v1.x tampered-prevhash still detected', async () => {
    const data = await loadFixture('tampered-prevhash.json');
    const result = verifySealedExport(data);
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'PREV_HASH_MISMATCH');
  });

  it('v1.x genesis-mismatch still detected', async () => {
    const data = await loadFixture('genesis-mismatch.json');
    const result = verifySealedExport(data);
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'GENESIS_MISMATCH');
  });
});

describe('v2.0.0 new scope account-journal', () => {
  it('valid-chain-account-journal verifies OK', async () => {
    const data = await loadFixture('valid-chain-account-journal.json');
    const result = verifySealedExport(data);
    assert.equal(result.ok, true);
    assert.equal(result.totalEntries, 3);
    assert.equal(data.scope, 'account-journal');
  });

  it('rejects exports with unknown scope (defense vs v3+ retroactive)', () => {
    const fakeFutureExport = {
      scope: 'allocator-introduction', // hypothetical v3+ scope
      scopeId: '6450a1b2c3d4e5f600000099',
      genesis: '0'.repeat(64),
      entries: [],
    };
    const result = verifySealedExport(fakeFutureExport);
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'INVALID_EXPORT_SHAPE');
  });
});
