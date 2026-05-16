import { describe, expect, it } from "vitest";
import {
  TRANSFORMS,
  applyCase,
  applyTransforms,
  stripDiacritics,
  t01CaseRandom,
  t02LeetLight,
  t03LeetHeavy,
  t04Inversion,
  t05Truncate,
  t06Diacritics,
  t07AlternatingCase,
  t08SymbolInsert,
  t09HashTrunc,
} from "../src/transforms.js";

describe("transforms catalogue", () => {
  it("TRANSFORMS table exposes all 9 codes (T10 omitted)", () => {
    const keys = Object.keys(TRANSFORMS).sort();
    expect(keys).toEqual(["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"]);
  });

  it("T01 — applyCase covers each branch", () => {
    expect(applyCase("hello world", "lowercase")).toBe("hello world");
    expect(applyCase("hello world", "uppercase")).toBe("HELLO WORLD");
    expect(applyCase("hello world", "camelCase")).toBe("helloWorld");
    expect(applyCase("hello world", "PascalCase")).toBe("HelloWorld");
    expect(applyCase("hello world", "SCREAMING_SNAKE")).toBe("HELLO_WORLD");
    expect(applyCase("hello", "unknown-mode")).toBe("hello");
  });

  it("T01 — random pick falls into one of the candidates", () => {
    const out = t01CaseRandom("hello world");
    expect(["hello world", "HELLO WORLD", "helloWorld", "HelloWorld", "HELLO_WORLD"]).toContain(
      out,
    );
  });

  it("T02 — leet light substitutes at least once with high probability", () => {
    let substitutions = 0;
    for (let i = 0; i < 100; i++) {
      const out = t02LeetLight("eaiouEAIOU");
      if (/@|3|!|0/.test(out)) substitutions++;
    }
    expect(substitutions).toBeGreaterThan(50);
  });

  it("T03 — leet heavy extends the substitution table", () => {
    let extended = 0;
    for (let i = 0; i < 200; i++) {
      const out = t03LeetHeavy("eslbtgz");
      if (/\$|\+|1|9|8|2/.test(out)) extended++;
    }
    expect(extended).toBeGreaterThan(50);
  });

  it("T04 — inversion produces one of three outcomes", () => {
    const outcomes = new Set();
    for (let i = 0; i < 200; i++) outcomes.add(t04Inversion("hello world from sealkeeper"));
    // Original + reversed string + reversed word order = 3 distinct outputs
    expect(outcomes.size).toBeGreaterThanOrEqual(2);
  });

  it("T05 — truncation produces one of three outcomes", () => {
    const outcomes = new Set();
    for (let i = 0; i < 100; i++) outcomes.add(t05Truncate("alpha beta gamma", { firstN: 2 }));
    expect(outcomes.size).toBeGreaterThanOrEqual(2);
  });

  it("T06 — diacritics either keep or strip", () => {
    const seen = new Set();
    for (let i = 0; i < 50; i++) seen.add(t06Diacritics("résumé naïve"));
    expect(seen.has("résumé naïve") || seen.has("resume naive")).toBe(true);
  });

  it("stripDiacritics removes combining marks", () => {
    expect(stripDiacritics("éàçñü")).toBe("eacnu");
  });

  it("T07 — alternating case produces predictable parity", () => {
    const out = t07AlternatingCase("hello world");
    // Letters alternate in case; non-letters pass through
    const letters = out.replace(/[^a-zA-Z]/g, "");
    for (let i = 1; i < letters.length; i++) {
      const a = letters[i - 1];
      const b = letters[i];
      const aUpper = a === a.toUpperCase();
      const bUpper = b === b.toUpperCase();
      expect(aUpper).not.toBe(bUpper);
    }
  });

  it("T08 — symbol insertion replaces inter-word whitespace", () => {
    const out = t08SymbolInsert("alpha beta gamma");
    expect(out).not.toMatch(/\s/);
    expect(out).toMatch(/[!@#$%&*+=?]/);
  });

  it("T09 — hash truncation appends 4 hex chars", async () => {
    const out = await t09HashTrunc("seal");
    expect(out.startsWith("seal")).toBe(true);
    expect(out.length).toBe(8);
    expect(out.slice(4)).toMatch(/^[0-9a-f]{4}$/);
  });

  it("applyTransforms chains async + sync transforms", async () => {
    const out = await applyTransforms("hello world", [
      { code: "T01", active: true, parameters: { candidates: ["uppercase"] } },
      { code: "T09", active: true, parameters: { length: 3 } },
      { code: "T99", active: true }, // unknown — should be ignored
      { code: "T01", active: false }, // inactive — ignored
      null, // sparse — ignored
    ]);
    expect(out.startsWith("HELLO WORLD")).toBe(true);
    expect(out.length).toBe("HELLO WORLD".length + 3);
  });
});
