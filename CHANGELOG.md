# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-10

Initial public release.

### Added

- `verify.mjs` — CLI entry point for verifying Sealed™ Audit Pack JSON exports.
- `lib/sealedVerifier.mjs` — pure cryptographic verification primitive
  (`verifySealedExport` + `verifyChainSegment`).
- `lib/canonicalHash.mjs` — stable JSON canonicalization (`canonicalJson` +
  `payloadHashOf` + `assertNoMongoOperators`).
- `tests/generate-fixtures.mjs` — deterministic synthetic fixture generator.
- 7 test fixtures covering valid + 6 tampered scenarios:
  `valid-chain.json`, `tampered-payload.json`, `tampered-prevhash.json`,
  `tampered-attestedat.json`, `genesis-mismatch.json`, `empty-chain.json`,
  `sequence-gap.json`.
- 50-test suite using Node 20+ built-in `node:test` runner. Zero test
  framework dependencies.
- GitHub Actions CI matrix on Node 20.x and Node 22.x.
- MIT license.

### Sync

- Mirrors Quantra backend `lib/sealedVerifier.js` + `lib/canonicalHash.js`
  v1.0 byte-for-byte at the algorithm level. When the backend bumps the
  verifier algorithm, this repo bumps in lockstep.

### Algorithm

- Hash function: SHA-256.
- Genesis: `sha256("quantra:hashchain:" + scope + ":" + scopeId + ":genesis")`.
- Per-entry: `sha256(prevHash + ":" + payloadHash + ":" + attestedAt.toISOString())`.
- Payload hash: `sha256(canonicalJson(payload))` with alphabetically sorted
  keys, recursive.
- Append-only chain — corrections are new entries, original entries never
  mutate.

### Constraints

- Zero external dependencies. Uses only Node built-ins (`crypto`, `fs`,
  `path`).
- ESM only (`type: "module"`). Requires Node 20+.
- No ZIP unpacking — users unzip `audit-pack-public.zip` first, then run
  `node verify.mjs <unzipped.json>`. This keeps the supply chain footprint
  minimal.
