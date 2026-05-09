/**
 * Pure masker: regex detectors + four strategies. Mirrors the rust
 * `maskprompt-core` semantics so output is consistent across ports.
 */

import { createHash } from 'node:crypto';

export type Strategy = 'tag' | 'hash' | 'fixed' | 'remove';

export interface MaskMatch {
  kind: string;
  start: number;
  end: number;
  value: string;
}

export interface MaskResult {
  masked: string;
  matches: MaskMatch[];
}

const RULES: ReadonlyArray<readonly [string, RegExp]> = [
  ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  // US phone: optional +1, optional area-code parens, optional separators.
  [
    'US_PHONE',
    /\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  ],
  ['US_SSN', /\b\d{3}-\d{2}-\d{4}\b/g],
  ['IPV4', /\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b/g],
  ['AWS_ACCESS_KEY', /\bAKIA[0-9A-Z]{16}\b/g],
  ['GITHUB_TOKEN', /\bgh[pours]_[A-Za-z0-9]{36,}\b/g],
  ['JWT', /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g],
  // Credit card: 13–19 digits with optional space/dash separators.
  // Luhn check filters false positives downstream.
  ['CREDIT_CARD', /\b(?:\d[\s-]?){12,18}\d\b/g],
];

export function mask(text: string, strategy: Strategy = 'tag'): MaskResult {
  const raw: MaskMatch[] = [];

  for (const [kind, regex] of RULES) {
    const re = new RegExp(regex.source, regex.flags);
    for (const m of text.matchAll(re)) {
      const start = m.index ?? 0;
      const end = start + m[0].length;
      const value = m[0];
      if (kind === 'CREDIT_CARD' && !luhnValid(value)) continue;
      raw.push({ kind, start, end, value });
    }
  }

  // Resolve overlaps: earliest start wins, longer span wins ties.
  raw.sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: MaskMatch[] = [];
  let cursor = 0;
  for (const m of raw) {
    if (m.start < cursor) continue;
    cursor = m.end;
    kept.push(m);
  }

  // Build output by walking matches.
  let out = '';
  let last = 0;
  for (const m of kept) {
    out += text.slice(last, m.start);
    out += render(m.kind, m.value, strategy);
    last = m.end;
  }
  out += text.slice(last);
  return { masked: out, matches: kept };
}

export function findPii(text: string): MaskMatch[] {
  return mask(text, 'tag').matches;
}

// --- helpers --------------------------------------------------------------

function render(kind: string, value: string, strategy: Strategy): string {
  switch (strategy) {
    case 'tag':
      return `<${kind}>`;
    case 'hash': {
      const h = createHash('sha256').update(value).digest('hex').slice(0, 8);
      return `<${kind}:${h}>`;
    }
    case 'fixed':
      return '█'.repeat(charCount(value));
    case 'remove':
      return '';
    default: {
      const _exhaustive: never = strategy;
      void _exhaustive;
      return value;
    }
  }
}

function charCount(s: string): number {
  // Count Unicode code points, not UTF-16 code units.
  return [...s].length;
}

function luhnValid(s: string): boolean {
  const digits: number[] = [];
  for (const ch of s) {
    if (ch >= '0' && ch <= '9') digits.push(ch.charCodeAt(0) - 48);
  }
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i];
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}
