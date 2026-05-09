import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import { findPii, mask } from '../src/masker.js';

test('email redacted', () => {
  const r = mask('hi alice@example.com bye');
  assert.equal(r.masked, 'hi <EMAIL> bye');
  assert.equal(r.matches.length, 1);
  assert.equal(r.matches[0].kind, 'EMAIL');
  assert.equal(r.matches[0].value, 'alice@example.com');
});

test('credit card with Luhn redacted', () => {
  const r = mask('paid 4111-1111-1111-1111 today');
  assert.equal(r.masked, 'paid <CREDIT_CARD> today');
});

test('credit-card-shaped string failing Luhn passes through', () => {
  const r = mask('order 1234-5678-1234-5678');
  assert.equal(r.masked, 'order 1234-5678-1234-5678');
});

test('ssn redacted', () => {
  const r = mask('ssn 123-45-6789 ok');
  assert.equal(r.masked, 'ssn <US_SSN> ok');
});

test('ipv4 redacted', () => {
  const r = mask('client 192.168.1.42');
  assert.equal(r.masked, 'client <IPV4>');
});

test('aws key redacted', () => {
  const r = mask('key AKIAIOSFODNN7EXAMPLE leaked');
  assert.equal(r.masked, 'key <AWS_ACCESS_KEY> leaked');
});

test('github token redacted', () => {
  const t = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';
  const r = mask(`token ${t} bad`);
  assert.equal(r.masked, 'token <GITHUB_TOKEN> bad');
});

test('jwt redacted', () => {
  const j = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.signature_part_long_enough';
  const r = mask(`auth: ${j} ok`);
  assert.equal(r.masked, 'auth: <JWT> ok');
});

test('multiple kinds resolved left to right', () => {
  const r = mask('email a@b.com card 4111-1111-1111-1111 done');
  assert.equal(r.masked, 'email <EMAIL> card <CREDIT_CARD> done');
  assert.equal(r.matches.length, 2);
});

test('hash strategy stable across calls', () => {
  const a = mask('a@b.com', 'hash').masked;
  const b = mask('a@b.com', 'hash').masked;
  const c = mask('c@d.com', 'hash').masked;
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.ok(a.startsWith('<EMAIL:'));
});

test('fixed strategy preserves length', () => {
  const r = mask('hi a@b.com bye', 'fixed');
  assert.ok(r.masked.includes('█'));
  assert.ok(r.masked.startsWith('hi '));
  assert.ok(r.masked.endsWith(' bye'));
});

test('remove strategy strips match', () => {
  const r = mask('hi a@b.com bye', 'remove');
  assert.equal(r.masked, 'hi  bye');
});

test('match offsets are correct', () => {
  const text = 'hi alice@example.com bye';
  const r = mask(text);
  const m = r.matches[0];
  assert.equal(text.slice(m.start, m.end), m.value);
});

test('find_pii returns matches without rewriting', () => {
  const ms = findPii('email a@b.com card 4111-1111-1111-1111 done');
  assert.equal(ms.length, 2);
  assert.equal(ms[0].kind, 'EMAIL');
  assert.equal(ms[1].kind, 'CREDIT_CARD');
});

test('clean string yields empty matches', () => {
  const r = mask('nothing here');
  assert.equal(r.masked, 'nothing here');
  assert.equal(r.matches.length, 0);
});

test('luhn known-valid card passes', () => {
  // Visa test number.
  const r = mask('4111111111111111');
  assert.equal(r.masked, '<CREDIT_CARD>');
});
