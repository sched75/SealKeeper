// =============================================================================
// SealKeeper — Transform catalogue (T01..T09)
// =============================================================================
// PRD A §3.4. T10 (synonym substitution) is reported to 0.2.0 and intentionally
// absent from this catalogue.
// =============================================================================

import { cryptoCoin, cryptoRandomChoice, cryptoRandomInt } from "./crypto.js";

const DEFAULT_SYMBOLS = ["!", "@", "#", "$", "%", "&", "*", "+", "=", "?"];

/**
 * T01 — Case randomization (lowercase / UPPERCASE / camelCase / PascalCase /
 * SCREAMING_SNAKE).
 */
export function t01CaseRandom(input, options = {}) {
  const candidates = options.candidates ?? [
    "lowercase",
    "uppercase",
    "camelCase",
    "PascalCase",
    "SCREAMING_SNAKE",
  ];
  const pick = cryptoRandomChoice(candidates);
  return applyCase(input, pick);
}

export function applyCase(input, mode) {
  switch (mode) {
    case "lowercase":
      return input.toLowerCase();
    case "uppercase":
      return input.toUpperCase();
    case "camelCase":
      return toCamelOrPascal(input, false);
    case "PascalCase":
      return toCamelOrPascal(input, true);
    case "SCREAMING_SNAKE":
      return input
        .trim()
        .split(/\s+/u)
        .map((w) => w.toUpperCase())
        .join("_");
    default:
      return input;
  }
}

function toCamelOrPascal(input, startWithUpper) {
  const words = input.trim().split(/\s+/u);
  return words
    .map((w, i) => {
      if (w.length === 0) return w;
      const head = w[0];
      const tail = w.slice(1).toLowerCase();
      const upper = i === 0 ? startWithUpper : true;
      return (upper ? head.toUpperCase() : head.toLowerCase()) + tail;
    })
    .join("");
}

/**
 * T02 — Leet light: a/e/i/o swap, each occurrence independently with prob p.
 */
export function t02LeetLight(input, options = {}) {
  const p = options.probability ?? 0.5;
  return leetMap(input, { a: "@", e: "3", i: "!", o: "0" }, p);
}

/**
 * T03 — Leet heavy: T02 plus s/t/l/g/b/z.
 */
export function t03LeetHeavy(input, options = {}) {
  const p = options.probability ?? 0.5;
  return leetMap(
    input,
    { a: "@", e: "3", i: "!", o: "0", s: "$", t: "+", l: "1", g: "9", b: "8", z: "2" },
    p,
  );
}

function leetMap(input, table, p) {
  let out = "";
  for (const ch of input) {
    const lower = ch.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(table, lower) && cryptoCoin(p)) {
      out += table[lower];
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * T04 — Inversion: reverse string, reverse word order or bypass.
 */
export function t04Inversion(input) {
  const choice = cryptoRandomInt(3); // 0 = bypass, 1 = reverse string, 2 = reverse word order
  if (choice === 1) return Array.from(input).reverse().join("");
  if (choice === 2) return input.trim().split(/\s+/u).reverse().join(" ");
  return input;
}

/**
 * T05 — Truncation: first N chars of each word OR initials.
 */
export function t05Truncate(input, options = {}) {
  const choice = cryptoRandomInt(3); // 0 = bypass, 1 = first N chars, 2 = initials
  if (choice === 0) return input;
  const words = input.trim().split(/\s+/u);
  if (choice === 1) {
    const n = options.firstN ?? 3;
    return words.map((w) => w.slice(0, n)).join("");
  }
  return words.map((w) => (w.length > 0 ? w[0] : "")).join("");
}

/**
 * T06 — Diacritics: keep or strip.
 */
export function t06Diacritics(input) {
  if (cryptoCoin(0.5)) return input;
  return stripDiacritics(input);
}

export function stripDiacritics(input) {
  return input.normalize("NFD").replace(/[\u0300-\u036f]/gu, "");
}

/**
 * T07 — Alternating case: starts upper or starts lower.
 */
export function t07AlternatingCase(input) {
  const startUpper = cryptoCoin(0.5);
  let out = "";
  let idx = 0;
  for (const ch of input) {
    const isLetter = /\p{L}/u.test(ch);
    if (!isLetter) {
      out += ch;
      continue;
    }
    const upper = idx % 2 === 0 ? startUpper : !startUpper;
    out += upper ? ch.toUpperCase() : ch.toLowerCase();
    idx++;
  }
  return out;
}

/**
 * T08 — Symbolic insertion between words (1 in 10 symbols).
 */
export function t08SymbolInsert(input, options = {}) {
  const symbols = options.symbols ?? DEFAULT_SYMBOLS;
  const sym = cryptoRandomChoice(symbols);
  return input.trim().split(/\s+/u).join(sym);
}

/**
 * T09 — Visible truncated hash: 3-4 chars of a timestamp hash appended.
 * The hash material itself draws from the system clock + a fresh nonce so the
 * suffix is non-deterministic even when called twice in the same millisecond.
 */
export async function t09HashTrunc(input, options = {}) {
  const n = options.length ?? 4;
  const seed = `${Date.now()}-${cryptoRandomInt(0xffffffff)}-${input}`;
  const data = new TextEncoder().encode(seed);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return input + hex.slice(0, n);
}

export const TRANSFORMS = {
  T01: t01CaseRandom,
  T02: t02LeetLight,
  T03: t03LeetHeavy,
  T04: t04Inversion,
  T05: t05Truncate,
  T06: t06Diacritics,
  T07: t07AlternatingCase,
  T08: t08SymbolInsert,
  T09: t09HashTrunc,
};

/**
 * Apply the requested transform descriptors in order. Each item shape:
 *   { code: "T0N", active: true, mode: "random"|"deterministic", parameters: {...} }
 *
 * @param {string} input
 * @param {Array<{code:string, active:boolean, mode?:string, parameters?:object}>} descriptors
 * @returns {Promise<string>}
 */
export async function applyTransforms(input, descriptors) {
  let current = input;
  for (const d of descriptors ?? []) {
    if (!d || !d.active) continue;
    const fn = TRANSFORMS[d.code];
    if (!fn) continue;
    const result = fn(current, d.parameters ?? {});
    current = result instanceof Promise ? await result : result;
  }
  return current;
}
