# Test Fixtures

These JSON files are generated synthetically by `tests/generate-fixtures.mjs`.

## Provenance

- **Synthetic data only.** No real broker payloads, no real PII, no real
  user identifiers.
- Scope IDs are deterministic 24-character hex strings
  (`6450a1b2c3d4e5f600000001`, `6450a1b2c3d4e5f600000002`).
- Trade canonicals contain fake symbols (`TEST-A`, `TEST-B`, `TEST-C`) and
  round numbers.
- Timestamps are deterministic UTC dates in May 2026.
- The `publicId` fields are placeholder ULID-shaped strings — they do NOT
  correspond to any real Quantra object.

## Regeneration

If you modify `tests/generate-fixtures.mjs`, regenerate fixtures with:

```bash
node tests/generate-fixtures.mjs
```

This is also run automatically by the GitHub Actions CI workflow before
test execution.

## Files

| File | Purpose | Expected verifier output |
|------|---------|--------------------------|
| `valid-chain.json` | Baseline 3-entry valid chain. | `ok: true`, exit 0. |
| `tampered-payload.json` | Entry 1 `canonical.pnl` mutated. | `PAYLOAD_HASH_MISMATCH` at sequence 1, exit 1. |
| `tampered-prevhash.json` | Entry 2 `prevHash` zeroed. | `PREV_HASH_MISMATCH` at sequence 2, exit 1. |
| `tampered-attestedat.json` | Entry 1 `attestedAt` shifted +1 hour. | `ENTRY_HASH_MISMATCH` at sequence 1, exit 1. |
| `genesis-mismatch.json` | Genesis recomputed for a different `scopeId`. | `GENESIS_MISMATCH`, exit 1. |
| `empty-chain.json` | Valid empty chain (zero entries). | `ok: true`, `totalEntries: 0`, exit 0. |
| `sequence-gap.json` | Entry 1 removed, leaving sequences 0 and 2. | `SEQUENCE_GAP` at sequence 2, exit 1. |

## What these fixtures do NOT cover

- Real Quantra production exports (those are user-private — the public
  audit pack format is identical at the algorithm level, but contains real
  redacted broker payloads).
- ZIP archive format (out of scope V1 — see `verify.mjs` header).
- Performance benchmarks (synthetic 3-entry chains; production chains
  may have 10⁴–10⁶ entries — verifier is O(n) and benchmark stays fast).
