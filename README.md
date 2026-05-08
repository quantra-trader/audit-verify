# `@quantra/audit-verify`

**The cryptographic primitive Quantra cannot lie about.**

A 200-line offline verifier for Quantra Sealed™ Audit Pack exports. Zero
dependencies. Node 18+. Run it on any machine, on any continent, against any
audit pack — and prove for yourself whether the chain holds.

You don't need to trust Quantra. You need to trust SHA-256.

---

## What this is

A pure-Node CLI and library that verifies a Quantra Sealed™ Audit Pack export
is internally consistent and tamper-evident. Given a JSON file produced by
Quantra's `/api/sealed/account/:publicId/export` endpoint, this tool answers
one question:

> *Has any byte of this trade record been altered since the broker attested it?*

If the answer is no, you get `ok: true` and exit 0. If anything moved — a
canonical payload edited, an entry removed, a timestamp rewritten, the chain
genesis substituted — you get a precise failure code and the exact sequence
where the chain broke.

## What this is NOT

- **Not trading advice.** This tool says nothing about whether a trader is
  good, profitable, or worth following. It only verifies the record is
  unaltered.
- **Not a performance claim.** Sealed records can show losing trades just as
  truthfully as winning ones. The point is provenance, not outcome.
- **Not broker authentication.** This verifier confirms cryptographic
  integrity of the chain. It does **not** prove which broker originally
  attested a trade — that requires the broker's own attestation receipt,
  which Quantra preserves separately in the Audit Pack metadata.
- **Not a Quantra dependency.** This package never calls home. It never
  touches the network. Once installed, you can run it air-gapped, forever.

---

## Why this exists

Every trading journal in the market today asks you to take screenshots on
faith. TradeZella, TraderVue, Edgewonk — none of them prove a trade ever
happened. Darwinex hides the verification inside a black box only Darwinex
can open.

Quantra took the opposite path. Every trade that arrives from an authenticated
broker (Tradovate, Rithmic, MT4/5, Interactive Brokers, FTMO, Topstep, Apex,
and the long tail) is sealed into a per-account append-only chain at the
moment of import. The chain is signed with the broker's own attestation and
linked into a SHA-256 hash chain that grows one entry at a time, forever.

The day a trader wants to prove their record — to a prop firm, an allocator,
a regulator, a journalist, a mentor's prospective client, a fund — Quantra
generates an Audit Pack. The pack contains the canonical trade data, the
chain entries, the genesis hash, and a pointer to this repository.

The recipient runs:

```bash
npx @quantra/audit-verify ./audit-pack.json
```

If the verifier exits 0, the record is intact. If Quantra ever modified a
sealed trade, edited a timestamp, or quietly swapped an entry, this verifier
would find the broken link in milliseconds — and produce evidence in JSON
that anyone can reproduce.

That is the meaning of *verifiable without trusting Quantra*. This repository
is the proof.

---

## Quick start

```bash
# As a one-off CLI (no install)
npx @quantra/audit-verify ./audit-pack.json

# As a global CLI
npm install -g @quantra/audit-verify
quantra-audit-verify ./audit-pack.json

# As a library
npm install @quantra/audit-verify
```

```js
import { verifySealedExport } from '@quantra/audit-verify';
import { readFileSync } from 'node:fs';

const pack = JSON.parse(readFileSync('./audit-pack.json', 'utf8'));
const result = verifySealedExport(pack.data?.export ?? pack);

if (result.ok) {
  console.log(`Chain valid. ${result.totalEntries} entries. Head ${result.head}.`);
} else {
  console.log(`Chain INVALID. Reason: ${result.reason}. Broken at sequence ${result.brokenAtSequence}.`);
}
```

---

## What gets verified

The verifier walks the chain entry by entry, recomputing every hash from
scratch and comparing it against what the export claims. Six failure modes
are detected, each with a distinct reason code:

| Reason | Meaning |
| :--- | :--- |
| `INVALID_EXPORT_SHAPE` | The audit pack is malformed. Required fields are missing, scope is unrecognised, scopeId is not a 24-character hex ObjectId, or an entry is structurally invalid. |
| `GENESIS_MISMATCH` | The declared genesis hash does not match `sha256("quantra:hashchain:" + scope + ":" + scopeId + ":genesis")`. The export was generated against a different scope, or the genesis was rewritten. |
| `SEQUENCE_GAP` | Sequence numbers are not contiguous starting from 0. Entries were removed, reordered, or the export was truncated. |
| `PREV_HASH_MISMATCH` | Entry `n` claims a `prevHash` that does not match `hash_{n-1}`. The chain link is broken — a middle entry was tampered with or removed. |
| `PAYLOAD_HASH_MISMATCH` | The recomputed `sha256(canonicalJson(canonical))` of an entry does not match its stored `payloadHash`. The trade data inside an entry was altered after sealing. |
| `ENTRY_HASH_MISMATCH` | The recomputed entry hash does not match its stored `hash`. The `attestedAt` timestamp was rewritten, or the export's declared `head` does not match the last entry's hash. |

Each failure response includes `brokenAtSequence`, `expectedHash`, and
`actualHash` so the discrepancy can be reproduced byte-for-byte.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUDIT PACK                                                         │
│                                                                     │
│   genesis = sha256("quantra:hashchain:account:<id>:genesis")        │
│      │                                                              │
│      ▼                                                              │
│   entry_0 ── prevHash = genesis                                     │
│      │       payloadHash = sha256(canonicalJson(trade_0))           │
│      │       hash = sha256(prevHash : payloadHash : attestedAt)     │
│      ▼                                                              │
│   entry_1 ── prevHash = hash_0                                      │
│      │       payloadHash = sha256(canonicalJson(trade_1))           │
│      │       hash = sha256(prevHash : payloadHash : attestedAt)     │
│      ▼                                                              │
│   entry_n ── prevHash = hash_{n-1}                                  │
│              ...                                                    │
│      │                                                              │
│      ▼                                                              │
│   head = hash_n                                                     │
└─────────────────────────────────────────────────────────────────────┘

  Tamper any byte at any layer → recomputed hash diverges → verifier
  pinpoints the broken sequence → exits 1.
```

---

## The algorithm

Three lines, no ceremony.

```
genesis(scope, scopeId) = sha256("quantra:hashchain:" + scope + ":" + scopeId + ":genesis")
payloadHash_n           = sha256(canonicalJson(canonical_n))
hash_n                  = sha256(prevHash_n + ":" + payloadHash_n + ":" + attestedAt_n.toISOString())
```

Where `prevHash_0 = genesis(scope, scopeId)` and `prevHash_n = hash_{n-1}` for
all `n > 0`.

**Hash function.** SHA-256 (FIPS 180-4). No exotic primitives, no novel
constructions. Hardware-accelerated on every platform shipped in the last
decade.

**Canonical JSON.** A deterministic serialization where object keys are
sorted alphabetically at every depth, recursively. `{a:1, b:2}` and
`{b:2, a:1}` produce byte-identical output. The implementation is inline in
[`src/canonicalHash.mjs`](./src/canonicalHash.mjs) — under 70 lines, no
dependencies. Semantically equivalent to `safe-stable-stringify` but vendored
to keep the supply chain at zero.

**Valid scopes.** `account`, `user`, `mentor`, `eventbus`, `tax_report`. An
export under any other scope is rejected as `INVALID_EXPORT_SHAPE`.

**Single source of truth.** This file is bit-for-bit identical to the
algorithm running inside the Quantra backend (`backend/src/lib/canonicalHash.js`
and `backend/src/lib/sealedVerifier.js`). They are kept in lockstep by tagged
releases — see [Versioning](#versioning) below.

---

## CLI usage

```bash
# Verify a file argument
node verify.mjs ./audit-pack.json

# Verify from stdin
cat ./audit-pack.json | node verify.mjs --stdin

# Help
node verify.mjs --help
```

**Exit codes.**

| Code | Meaning |
| :--- | :--- |
| `0` | Chain valid. The record is internally consistent and tamper-evident. |
| `1` | Chain invalid. A specific failure reason is printed; the JSON result is on stdout, the human summary on stderr. |
| `2` | Argument or file error (missing path, unreadable file, malformed JSON). |

**Output.** A JSON `result` object is always written to stdout. A human
summary is written to stderr — designed to be piped, grepped, or ignored
without losing the machine-readable output.

### Real CLI output, valid chain

```
$ node verify.mjs ./audit-pack-account.json
{
  "ok": true,
  "totalEntries": 247,
  "head": "5e2a8b4c3f9d1e7a6b2c8f5d3a1e9b7c4d6e8f2a5b1c3d7e9f4a6b8c2d5e7f1a",
  "genesis": "9b1c3d7e5a4b8c2d5e7f1a3b6c9d4e8f2a5b1c3d7e9f4a6b8c2d5e7f1a3b6c9d"
}

✓ Chain valid.  Total entries: 247.  Head: 5e2a8b4c3f9d...e7f1a.
  Genesis: 9b1c3d7e5a4b...3b6c9d
```

### Real CLI output, tampered chain

```
$ node verify.mjs ./audit-pack-tampered.json
{
  "ok": false,
  "totalEntries": 247,
  "brokenAtSequence": 142,
  "expectedHash": "a3f8c1d6e2b9...74e5d2a1",
  "actualHash":   "0000000000000000000000000000000000000000000000000000000000000000",
  "reason": "PREV_HASH_MISMATCH",
  "genesis": "9b1c3d7e5a4b...3b6c9d"
}

✗ Chain INVALID — PREV_HASH_MISMATCH
  Entry.prevHash does not match previous entry hash. Chain link broken — middle entry tampered or removed.
  Broken at sequence: 142
  Expected: a3f8c1d6e2b9...74e5d2a1
  Actual:   0000000000000000000000000000000000000000000000000000000000000000
  Total entries seen: 247
```

---

## Programmatic API

```js
import {
  verifySealedExport,
  verifyChainSegment,
} from '@quantra/audit-verify';
```

### `verifySealedExport(exportData)`

Verify a full Audit Pack export object. This is the entry point you want.

**Input.** Either the bare export shape `{ scope, scopeId, genesis, head, entries }`
or the Quantra API envelope `{ data: { export: {...} } }` — both are accepted.

**Output.**

```ts
type Success = {
  ok: true;
  totalEntries: number;
  head: string | null;     // null if entries is empty
  genesis: string;         // 64-char hex
};

type Failure = {
  ok: false;
  totalEntries: number;
  brokenAtSequence: number | null;
  expectedHash: string | null;
  actualHash: string | null;
  reason:
    | 'INVALID_EXPORT_SHAPE'
    | 'GENESIS_MISMATCH'
    | 'SEQUENCE_GAP'
    | 'PREV_HASH_MISMATCH'
    | 'PAYLOAD_HASH_MISMATCH'
    | 'ENTRY_HASH_MISMATCH';
  genesis: string | null;
};
```

### `verifyChainSegment(entries, genesis)`

Lower-level primitive. Verify a contiguous segment of entries against a
known genesis hash. Use this only if you are reconstructing partial chains
or implementing custom audit tooling. For Audit Pack files,
`verifySealedExport` is what you want.

### `canonicalJson(value)` and `payloadHashOf(value)`

```js
import { canonicalJson, payloadHashOf } from '@quantra/audit-verify/canonical';

canonicalJson({ b: 2, a: 1 });       // → '{"a":1,"b":2}'
payloadHashOf({ symbol: 'MNQ' });    // → 'a1b2c3...' (64-char hex)
```

The deterministic serialization and hashing primitives, exposed for anyone
implementing a verifier in another language (Python, Go, Rust) and
cross-checking the bytes match.

---

## Trust model — what this guarantees, and what it doesn't

**This verifier guarantees.**

- Every entry in the audit pack is cryptographically linked to its
  predecessor via SHA-256.
- The trade data (`canonical`) inside each entry is unaltered since the
  entry was sealed.
- The chain's genesis hash is consistent with the declared `(scope, scopeId)`.
- No entry has been removed, reordered, or inserted without breaking the
  chain.
- If `head` is declared, it matches the hash of the last entry.

**This verifier does not guarantee.**

- *That the broker really attested the trade.* That is a separate proof —
  the broker's signed attestation receipt — which Quantra preserves in the
  Audit Pack metadata. Verifying a broker signature requires the broker's
  public key. Out of scope for this primitive.
- *That a trade actually executed in the market.* Even a broker-attested
  trade only proves the broker recorded it. Market execution proof requires
  exchange-level data, which retail brokers do not generally expose.
- *That the trader is honest about anything outside the chain.* Notes,
  voice memos, screenshots, psychology tags — these are intentionally
  excluded from the canonical payload precisely because they are
  user-mutable and would constantly break the chain. The chain protects
  the numbers, not the narrative.

**Threat model.** A verifier exit code of 0 means: *the holder of this
audit pack — including Quantra itself — has not modified the cryptographic
record since the broker attested it*. Combined with the broker's separate
attestation receipt, this is the strongest provenance signal a retail
trading record has ever offered.

---

## Versioning

This verifier is published in lockstep with the Quantra backend. Each
release carries a semantic version that maps directly to a backend git tag.

| `audit-verify` version | Quantra backend tag | Algorithm version |
| :--- | :--- | :--- |
| `1.x` | `audit-verify-v1.x` | SHA-256 + canonicalJson v1 |

A backend release that changes the chain algorithm (e.g. migrating to a new
hash function, adding new canonical fields, bumping the genesis prefix) will
be paired with a major version bump here. Existing audit packs remain
verifiable by the matching prior version forever — older releases of this
package never disappear from npm.

If you depend on this package in production audit infrastructure, pin the
exact version. Bytes do not negotiate.

---

## Reference: tested behaviour

The verifier ships with a comprehensive Node `--test` suite covering every
failure mode, the canonical JSON determinism contract, the genesis algorithm,
cross-account isolation, and CLI integration including stdin and the
Quantra API envelope. Run:

```bash
npm test
```

Highlights:

- 22 tests covering valid chains, every failure mode, shape validation,
  determinism, and cross-account isolation.
- A *cross-account Frankenstein* test that grafts entries from one chain
  onto another's scope — and confirms the verifier rejects it at the first
  entry.
- CLI integration tests that exec the actual `verify.mjs` script with
  temp files and validate exit codes plus JSON output shape.

---

## Contributing

Contributions are welcome on three dimensions:

1. **Correctness.** If you find a way to construct a tampered audit pack
   that the verifier accepts, open an issue immediately. We treat any
   false-positive `ok: true` as a security incident.
2. **Ports.** Verifier implementations in Python, Go, Rust, or any language
   with a SHA-256 standard library are welcome as separate repositories
   under `github.com/quantra-trader`. They must be byte-for-byte compatible
   with this reference.
3. **Documentation.** If a section above was unclear when you first read
   it, fix it. The audience for this README includes allocators, regulators,
   and journalists — not just engineers.

Pull requests must include test coverage for any algorithm change.
Algorithm changes themselves require a major version bump and a
coordinated backend release.

---

## License

MIT — see [LICENSE](./LICENSE).

You may use this verifier in commercial audit workflows, regulatory
filings, due diligence reports, or anywhere else, without asking
permission.

---

## Further reading

- Quantra Sealed™ — the product: <https://quantratrader.com/sealed>
- Algorithm reference (this repository): [`src/sealedVerifier.mjs`](./src/sealedVerifier.mjs)
- Canonical JSON primitive: [`src/canonicalHash.mjs`](./src/canonicalHash.mjs)
- CLI source: [`verify.mjs`](./verify.mjs)

---

<sub>Built by Quantra Tech, S.L.U. · Licensed MIT · <https://github.com/quantra-trader></sub>
