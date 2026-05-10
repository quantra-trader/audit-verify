#!/usr/bin/env node
/**
 * verify.mjs — CLI for offline Quantra Sealed™ chain verification.
 *
 * Usage:
 *   node verify.mjs <path/to/audit-pack.json>
 *   node verify.mjs --stdin < audit-pack.json
 *
 * Exit codes:
 *   0  → chain valid (ok: true)
 *   1  → chain tampered or invalid (ok: false, reason printed)
 *   2  → file/argument error
 *
 * Output: JSON to stdout. Human-readable summary to stderr.
 *
 * License: MIT
 */

import { readFileSync } from 'node:fs';
import { argv, exit, stdin } from 'node:process';
import { verifySealedExport } from './lib/sealedVerifier.mjs';

const REASON_LABELS = {
  GENESIS_MISMATCH:
    'Chain genesis hash does not match (scope, scopeId). Audit pack tampered or scopeId rewritten.',
  SEQUENCE_GAP:
    'Sequence numbers not contiguous. Audit pack truncated, reordered, or entries removed.',
  PREV_HASH_MISMATCH:
    'Entry.prevHash does not match previous entry hash. Chain link broken — middle entry tampered or removed.',
  PAYLOAD_HASH_MISMATCH:
    'Canonical payload tampered. The data inside an entry was modified after sealing.',
  ENTRY_HASH_MISMATCH:
    'Entry hash mismatch. attestedAt timestamp or hash field tampered.',
  INVALID_EXPORT_SHAPE:
    'Audit pack shape malformed. Not a valid Quantra Sealed export.',
};

async function readInput() {
  const args = argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    process.stderr.write(
      'Usage: node verify.mjs <path/to/audit-pack.json>\n' +
      '       node verify.mjs --stdin < audit-pack.json\n\n' +
      'Verifies a Quantra Sealed™ Audit Pack export offline.\n' +
      'Exit code 0 = valid, 1 = tampered, 2 = error.\n',
    );
    exit(0);
  }

  if (args[0] === '--stdin' || args[0] === '-') {
    const chunks = [];
    for await (const chunk of stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
  }

  if (!args[0]) {
    process.stderr.write('Error: missing file argument. Run with --help for usage.\n');
    exit(2);
  }

  try {
    return readFileSync(args[0], 'utf8');
  } catch (err) {
    process.stderr.write(`Error reading file "${args[0]}": ${err.message}\n`);
    exit(2);
  }
}

function unwrapEnvelope(parsed) {
  // Quantra API response envelope wraps the export under data.export
  // (see /api/sealed/account/:publicId/export endpoint shape).
  // We accept either:
  //   - The envelope directly: { data: { account, export, verifierCommand, ... } }
  //   - The bare exportData:   { scope, scopeId, genesis, head, length, entries }
  if (parsed && typeof parsed === 'object' && parsed.data && parsed.data.export) {
    return parsed.data.export;
  }
  return parsed;
}

(async () => {
  const raw = await readInput();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    process.stderr.write(`Error: invalid JSON input — ${err.message}\n`);
    exit(2);
  }

  const exportData = unwrapEnvelope(parsed);
  const result = verifySealedExport(exportData);

  process.stdout.write(JSON.stringify(result, null, 2) + '\n');

  if (result.ok) {
    process.stderr.write(
      `\n✓ Chain valid.  Total entries: ${result.totalEntries}.  Head: ${result.head ?? '(empty)'}.\n` +
      `  Genesis: ${result.genesis}\n`,
    );
    exit(0);
  } else {
    const label = REASON_LABELS[result.reason] || 'Unknown failure reason.';
    process.stderr.write(
      `\n✗ Chain INVALID — ${result.reason}\n` +
      `  ${label}\n` +
      `  Broken at sequence: ${result.brokenAtSequence ?? '(top-level)'}\n` +
      (result.expectedHash ? `  Expected: ${result.expectedHash}\n` : '') +
      (result.actualHash ? `  Actual:   ${result.actualHash}\n` : '') +
      `  Total entries seen: ${result.totalEntries}\n`,
    );
    exit(1);
  }
})();
