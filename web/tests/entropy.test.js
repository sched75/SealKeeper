import { describe, expect, it } from "vitest";
import { anssiLevel, calculateEntropy } from "../src/entropy.js";

describe("calculateEntropy", () => {
  it("anssiLevel maps thresholds correctly", () => {
    expect(anssiLevel(49)).toBeNull();
    expect(anssiLevel(50)).toBe("B1");
    expect(anssiLevel(79)).toBe("B1");
    expect(anssiLevel(80)).toBe("B2");
    expect(anssiLevel(99)).toBe("B2");
    expect(anssiLevel(100)).toBe("B3");
    expect(anssiLevel(200)).toBe("B3");
  });

  it("rejects non-objects", () => {
    expect(() => calculateEntropy(null)).toThrow(TypeError);
    expect(() => calculateEntropy(42)).toThrow(TypeError);
  });

  it("rejects unknown generators", () => {
    expect(() => calculateEntropy({ generator: "GZ" })).toThrow(/unknown generator/);
  });

  it("G1 baseline (5000 corpus, 10 separators, 3×3 digits) ≥ 30 bits", () => {
    const r = calculateEntropy({ generator: "G1" });
    expect(r.expectedBits).toBeGreaterThanOrEqual(30);
    expect(r.anssiLevels.B1).toBe(false); // baseline alone is below B1
  });

  it("G1 with all transforms active reaches B1", () => {
    const r = calculateEntropy({
      generator: "G1",
      parameters: {
        corpusSize: 5000,
        transforms: ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"].map((code) => ({
          code,
          active: true,
          mode: "random",
        })),
      },
    });
    expect(r.expectedBits).toBeGreaterThanOrEqual(50);
    expect(r.anssiLevels.B1).toBe(true);
  });

  it("G2 default policy (6 words × 7776) reaches B2", () => {
    const r = calculateEntropy({ generator: "G2" });
    expect(r.expectedBits).toBeGreaterThanOrEqual(80);
    expect(r.anssiLevels.B2).toBe(true);
  });

  it("G3 default policy (20 chars × 62) reaches B3", () => {
    const r = calculateEntropy({ generator: "G3" });
    expect(r.expectedBits).toBeGreaterThanOrEqual(100);
    expect(r.anssiLevels.B3).toBe(true);
  });

  it("deterministic transforms add 0 bits", () => {
    const without = calculateEntropy({ generator: "G1", parameters: { transforms: [] } });
    const withDet = calculateEntropy({
      generator: "G1",
      parameters: {
        transforms: [{ code: "T01", active: true, mode: "deterministic" }],
      },
    });
    expect(withDet.expectedBits).toBeCloseTo(without.expectedBits, 1);
  });

  it("transform bits cover the catalogue", () => {
    const codes = ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"];
    for (const code of codes) {
      const r = calculateEntropy({
        generator: "G2",
        parameters: { transforms: [{ code, active: true, mode: "random" }] },
      });
      expect(r.expectedBits).toBeGreaterThan(80); // G2 baseline already ≥ 80
    }
  });
});
