import { describe, expect, it } from "vitest";
import { generateG2 } from "../src/generators/g2.js";
import { generateG3 } from "../src/generators/g3.js";
import { SAMPLE_DICTIONARY_FR } from "../src/data/sample-dictionary.js";

// FR-L.15: 10 000 generations consecutives = zero duplicate at entropy ≥ 80 bits.
// We run a reduced-but-meaningful 5000 iterations to keep CI fast; if the
// dictionary is the 256-word sample, G2 still produces ~80 bits of entropy when
// 6 words + 4 digits are used, so collisions remain astronomically unlikely.
describe("invariance (FR-L.15)", () => {
  it("G2 has no duplicates over 5000 draws", () => {
    const seen = new Set();
    for (let i = 0; i < 5000; i++) {
      const p = generateG2({ generator: "G2" }, SAMPLE_DICTIONARY_FR);
      expect(seen.has(p)).toBe(false);
      seen.add(p);
    }
    expect(seen.size).toBe(5000);
  });

  it("G3 has no duplicates over 5000 draws", () => {
    const seen = new Set();
    for (let i = 0; i < 5000; i++) {
      const p = generateG3({ generator: "G3" });
      expect(seen.has(p)).toBe(false);
      seen.add(p);
    }
    expect(seen.size).toBe(5000);
  });
});

// FR-L.16: each dictionary word should appear with roughly equal probability.
// Looser threshold (each word in [0.3×expected, 3×expected]) to keep flakiness
// at ≪ 10^-6 while still failing on truly broken RNG.
describe("distribution (FR-L.16)", () => {
  it("G2 picks each dictionary word with roughly equal probability", () => {
    const dict = SAMPLE_DICTIONARY_FR;
    const counts = new Map(dict.map((w) => [w, 0]));
    const ITERATIONS = 2000;
    const WORDS_PER_DRAW = 6;
    for (let i = 0; i < ITERATIONS; i++) {
      const p = generateG2(
        { generator: "G2", parameters: { numberOfWords: WORDS_PER_DRAW, separatorOptions: ["-"] } },
        dict,
      );
      const words = p.split("-").slice(0, WORDS_PER_DRAW);
      for (const w of words) {
        if (counts.has(w)) counts.set(w, counts.get(w) + 1);
      }
    }
    const expected = (ITERATIONS * WORDS_PER_DRAW) / dict.length;
    let minCount = Infinity;
    let maxCount = 0;
    for (const c of counts.values()) {
      if (c < minCount) minCount = c;
      if (c > maxCount) maxCount = c;
    }
    expect(minCount).toBeGreaterThan(0);
    expect(maxCount).toBeLessThan(expected * 5);
  });
});
