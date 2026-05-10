/**
 * tests/canonicalHash.test.mjs — Sealed™ Audit Pack Verifier
 * ============================================================================
 *
 * Tests for `lib/canonicalHash.mjs`. Pure functions, no IO, no DB.
 *
 * Covers:
 *   - canonicalJson key ordering deterministic
 *   - canonicalJson handles primitives / arrays / nested / Date / null / undefined
 *   - payloadHashOf deterministic (same input → same hash)
 *   - assertNoMongoOperators throws on $-prefixed keys
 *   - assertNoMongoOperators recurses into nested objects + arrays
 *   - assertNoMongoOperators MAX_DEPTH protection
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalJson,
  payloadHashOf,
  assertNoMongoOperators,
  MAX_DEPTH,
} from '../lib/canonicalHash.mjs';

// ─── canonicalJson ──────────────────────────────────────────────────────────

test('canonicalJson: sorts object keys alphabetically', () => {
  const a = canonicalJson({ b: 2, a: 1, c: 3 });
  const b = canonicalJson({ c: 3, a: 1, b: 2 });
  assert.equal(a, b);
  assert.equal(a, '{"a":1,"b":2,"c":3}');
});

test('canonicalJson: nested objects recurse and sort', () => {
  const a = canonicalJson({ x: { z: 9, y: 8 }, w: 1 });
  const b = canonicalJson({ w: 1, x: { y: 8, z: 9 } });
  assert.equal(a, b);
});

test('canonicalJson: arrays preserve order', () => {
  const a = canonicalJson([3, 1, 2]);
  assert.equal(a, '[3,1,2]');
});

test('canonicalJson: undefined → null (avoids missing fields)', () => {
  const a = canonicalJson({ x: undefined, y: 1 });
  assert.equal(a, '{"x":null,"y":1}');
});

test('canonicalJson: top-level undefined → "null"', () => {
  assert.equal(canonicalJson(undefined), 'null');
});

test('canonicalJson: null → "null"', () => {
  assert.equal(canonicalJson(null), 'null');
});

test('canonicalJson: string primitive', () => {
  assert.equal(canonicalJson('hello'), '"hello"');
});

test('canonicalJson: number primitive', () => {
  assert.equal(canonicalJson(42), '42');
});

test('canonicalJson: boolean primitive', () => {
  assert.equal(canonicalJson(true), 'true');
  assert.equal(canonicalJson(false), 'false');
});

test('canonicalJson: Date → ISO string', () => {
  const d = new Date(Date.UTC(2026, 4, 8, 14, 0, 0));
  assert.equal(canonicalJson(d), '"2026-05-08T14:00:00.000Z"');
});

test('canonicalJson: Buffer → base64 string', () => {
  const buf = Buffer.from('hello', 'utf-8');
  assert.equal(canonicalJson(buf), '"aGVsbG8="');
});

// ─── payloadHashOf ──────────────────────────────────────────────────────────

test('payloadHashOf: deterministic same input → same hash', () => {
  const a = payloadHashOf({ a: 1, b: 2 });
  const b = payloadHashOf({ a: 1, b: 2 });
  assert.equal(a, b);
});

test('payloadHashOf: order-insensitive (canonical keys)', () => {
  const a = payloadHashOf({ a: 1, b: 2 });
  const b = payloadHashOf({ b: 2, a: 1 });
  assert.equal(a, b);
});

test('payloadHashOf: different payloads → different hashes', () => {
  const a = payloadHashOf({ a: 1 });
  const b = payloadHashOf({ a: 2 });
  assert.notEqual(a, b);
});

test('payloadHashOf: returns 64-char hex string', () => {
  const h = payloadHashOf({ test: 'value' });
  assert.match(h, /^[0-9a-f]{64}$/);
});

// ─── assertNoMongoOperators ─────────────────────────────────────────────────

test('assertNoMongoOperators: passes on plain object', () => {
  assert.doesNotThrow(() => {
    assertNoMongoOperators({ a: 1, b: 'two', c: [1, 2, 3] });
  });
});

test('assertNoMongoOperators: passes on nested objects', () => {
  assert.doesNotThrow(() => {
    assertNoMongoOperators({ x: { y: { z: 'deep' } } });
  });
});

test('assertNoMongoOperators: throws on $-prefixed top-level key', () => {
  assert.throws(
    () => assertNoMongoOperators({ $set: { role: 'admin' } }),
    (err) => err.code === 'MONGO_OP_INJECTION',
  );
});

test('assertNoMongoOperators: throws on $-prefixed nested key', () => {
  assert.throws(
    () => assertNoMongoOperators({ data: { user: { $where: 'evil' } } }),
    (err) => err.code === 'MONGO_OP_INJECTION',
  );
});

test('assertNoMongoOperators: throws on $-prefixed key in array element', () => {
  assert.throws(
    () => assertNoMongoOperators({ items: [{ $inc: 1 }] }),
    (err) => err.code === 'MONGO_OP_INJECTION',
  );
});

test('assertNoMongoOperators: passes on null / undefined / primitives', () => {
  assert.doesNotThrow(() => assertNoMongoOperators(null));
  assert.doesNotThrow(() => assertNoMongoOperators(undefined));
  assert.doesNotThrow(() => assertNoMongoOperators(42));
  assert.doesNotThrow(() => assertNoMongoOperators('string'));
  assert.doesNotThrow(() => assertNoMongoOperators(true));
});

test('assertNoMongoOperators: passes on Date and Buffer', () => {
  assert.doesNotThrow(() => assertNoMongoOperators(new Date()));
  assert.doesNotThrow(() => assertNoMongoOperators(Buffer.from('test')));
});

test('assertNoMongoOperators: MAX_DEPTH protection', () => {
  // Build a deeply nested object beyond MAX_DEPTH.
  let nested = { v: 1 };
  for (let i = 0; i < MAX_DEPTH + 5; i += 1) {
    nested = { child: nested };
  }
  assert.throws(
    () => assertNoMongoOperators(nested),
    (err) => err.code === 'PAYLOAD_DEPTH_LIMIT',
  );
});
