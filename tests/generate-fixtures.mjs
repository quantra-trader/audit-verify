/**
 * tests/generate-fixtures.mjs — Sealed™ Audit Pack Verifier
 * ============================================================================
 *
 * Generates synthetic test fixtures by hand-crafting valid HashChain exports
 * + tampered variants. All fixtures are deterministic (no random data) so
 * tests are reproducible.
 *
 * Run with:
 *   node tests/generate-fixtures.mjs
 *
 * Output: 7 JSON files in tests/fixtures/.
 *
 * Provenance: synthetic data only. No real PII, no real broker payloads.
 * Scope IDs are deterministic 24-char hex strings. Trade canonicals contain
 * fake symbols (TEST-A, TEST-B, TEST-C) and round numbers.
 *
 * The fixtures mirror the shape of `hashChain.exportChain()` output from the
 * Quantra backend (lib/sealedVerifier.mjs is a 1:1 port).
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { __internal__ } from '../lib/sealedVerifier.mjs';

const { _computeGenesisHash, _computeEntryHash, _computePayloadHash } = __internal__;

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures');

// Deterministic scope IDs for reproducibility.
const SCOPE_ID_A = '6450a1b2c3d4e5f600000001';
const SCOPE_ID_B = '6450a1b2c3d4e5f600000002';

/**
 * Build a valid 3-entry chain for a given scope/scopeId. Returns the export
 * shape produced by `hashChain.exportChain()`.
 */
function buildValidExport({ scope = 'account', scopeId = SCOPE_ID_A, count = 3 } = {}) {
  const genesis = _computeGenesisHash(scope, scopeId);
  const entries = [];
  let prevHash = genesis;

  for (let i = 0; i < count; i += 1) {
    const canonical = {
      tradeId: `TEST-${String.fromCharCode(65 + i)}`,
      symbol: 'MNQ',
      side: i % 2 === 0 ? 'long' : 'short',
      pnl: 100 + i * 25,
      sequenceMarker: i,
    };
    const payloadHash = _computePayloadHash(canonical);
    const attestedAt = new Date(Date.UTC(2026, 4, 8, 14, i * 5, 0)).toISOString();
    const hash = _computeEntryHash(prevHash, payloadHash, attestedAt);

    entries.push({
      publicId: `01HXXXXXXXXXXXXXXXXXXXXX0${i}`.slice(0, 26).toUpperCase(),
      sequence: i,
      hash,
      prevHash,
      payloadHash,
      canonical,
      eventType: 'trade.attested',
      refType: 'Trade',
      refId: `64aabbccddeeff000000000${i}`.padEnd(24, '0').slice(0, 24),
      attestedAt,
      attestedBy: null,
      correctsEntryId: null,
    });
    prevHash = hash;
  }

  return {
    scope,
    scopeId,
    genesis,
    head: entries.length > 0 ? entries[entries.length - 1].hash : null,
    length: entries.length,
    entries,
  };
}

function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

async function writeFixture(name, data) {
  const filePath = join(fixturesDir, name);
  await writeFile(filePath, JSON.stringify(data, null, 2) + '\n', 'utf-8');
  console.log(`  wrote ${name}`);
}

async function main() {
  await mkdir(fixturesDir, { recursive: true });

  console.log('Generating Sealed™ Audit Pack test fixtures...');
  console.log('');

  // 1. valid-chain.json — baseline 3-entry valid chain.
  const valid = buildValidExport({ count: 3 });
  await writeFixture('valid-chain.json', valid);

  // 2. tampered-payload.json — corrupt entry 1 canonical.pnl, leave hashes.
  const tamperedPayload = deepClone(valid);
  tamperedPayload.entries[1].canonical.pnl = 999999;
  await writeFixture('tampered-payload.json', tamperedPayload);

  // 3. tampered-prevhash.json — corrupt entry 2 prevHash.
  const tamperedPrevHash = deepClone(valid);
  tamperedPrevHash.entries[2].prevHash =
    '0000000000000000000000000000000000000000000000000000000000000000';
  await writeFixture('tampered-prevhash.json', tamperedPrevHash);

  // 4. tampered-attestedat.json — corrupt entry 1 attestedAt (move forward 1 hour).
  // The entry hash will no longer match because hash includes attestedAt ISO.
  const tamperedAttestedAt = deepClone(valid);
  tamperedAttestedAt.entries[1].attestedAt = new Date(Date.UTC(2026, 4, 8, 15, 5, 0)).toISOString();
  await writeFixture('tampered-attestedat.json', tamperedAttestedAt);

  // 5. genesis-mismatch.json — replace genesis with a sha256 from a different scopeId.
  const genesisMismatch = deepClone(valid);
  genesisMismatch.genesis = _computeGenesisHash('account', SCOPE_ID_B);
  await writeFixture('genesis-mismatch.json', genesisMismatch);

  // 6. empty-chain.json — valid empty chain (no entries).
  const empty = buildValidExport({ count: 0 });
  await writeFixture('empty-chain.json', empty);

  // 7. sequence-gap.json — drop entry 1 (sequences 0, 2 — missing 1).
  const sequenceGap = deepClone(valid);
  sequenceGap.entries.splice(1, 1);
  // Recompute length but leave head/genesis as-is (the gap is the failure mode).
  sequenceGap.length = sequenceGap.entries.length;
  await writeFixture('sequence-gap.json', sequenceGap);

  console.log('');
  console.log(`Done. 7 fixtures written to ${fixturesDir}`);
}

main().catch((err) => {
  console.error(`Fixture generation failed: ${err.message}`);
  console.error(err.stack);
  process.exit(1);
});
