# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-05-10

### Fixed

- CI test script: `node --test "tests/**/*.test.mjs"` glob pattern is only
  supported in Node 22.x+; switched to explicit file list
  `node --test tests/canonicalHash.test.mjs tests/verifier.test.mjs` for
  Node 20.x + 22.x compatibility (matches `engines.node >=20.0.0`).

## [1.1.0] - 2026-05-10

### Changed

- Restructured `src/` → `lib/` (standard library layout).
- Renamed `test/` → `tests/` (matches Node convention + glob pattern).
- `engines.node`: `>=18` → `>=20.0.0`.
- `package.json`: added `scripts.generate-fixtures` for reproducible chain regen.
- `package.json`: updated `main` + `exports` + `files` to `lib/` paths.

### Added

- `tests/canonicalHash.test.mjs` — 13 dedicated canonical JSON tests.
- `tests/fixtures/` — 7 deterministic synthetic chains shipped for reproducible CI.
- `.github/workflows/ci.yml` — matrix Node 20.x + 22.x × ubuntu/macos/windows.
- 4 pure-grep tests asserting `lib/` + `verify.mjs` + `package.json` zero deps.

### Notes

- Test suite expanded 23 → 50.
- API + CLI behavior unchanged. Compatible with v1.0.0 consumers.

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
