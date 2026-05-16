import { describe, expect, it } from "vitest";
import { generateG1 } from "../src/generators/g1.js";
import { generateG2 } from "../src/generators/g2.js";
import { generateG3 } from "../src/generators/g3.js";
import { SAMPLE_CORPUS_FR } from "../src/data/sample-corpus.js";
import { SAMPLE_DICTIONARY_FR } from "../src/data/sample-dictionary.js";

describe("G1 — citation generator", () => {
  it("rejects empty corpus", async () => {
    await expect(generateG1({ generator: "G1" }, [])).rejects.toThrow(/LibraryNotFound/);
  });

  it("emits a non-empty password using default policy", async () => {
    const p = await generateG1({ generator: "G1" }, SAMPLE_CORPUS_FR);
    expect(typeof p).toBe("string");
    expect(p.length).toBeGreaterThan(0);
    expect(p).toMatch(/[0-9]/);
  });

  it("respects custom digit groups + separators", async () => {
    const p = await generateG1(
      {
        generator: "G1",
        parameters: {
          separatorOptions: ["-"],
          numericGroups: [
            { position: "prefix", digitsCount: 2 },
            { position: "suffix", digitsCount: 2 },
          ],
        },
      },
      SAMPLE_CORPUS_FR,
    );
    expect(p).toMatch(/^\d{2}-/);
    expect(p).toMatch(/-\d{2}$/);
  });

  it("applies transforms", async () => {
    const p = await generateG1(
      {
        generator: "G1",
        parameters: {
          transforms: [{ code: "T01", active: true, parameters: { candidates: ["uppercase"] } }],
        },
      },
      SAMPLE_CORPUS_FR,
    );
    // After uppercase T01 the only lowercase letters should be in digits/separators.
    expect(p).toMatch(/[A-Z]/);
  });
});

describe("G2 — Diceware generator", () => {
  it("rejects empty dictionary", () => {
    expect(() => generateG2({ generator: "G2" }, [])).toThrow(/LibraryNotFound/);
  });

  it("default policy emits 6 words + 4 digits joined by a separator", () => {
    const p = generateG2({ generator: "G2" }, SAMPLE_DICTIONARY_FR);
    const parts = p.split(/[-_./+:|;,~]/);
    // 6 words + 1 trailing digit group = 7 parts
    expect(parts.length).toBe(7);
    expect(parts[6]).toMatch(/^\d{4}$/);
  });

  it("supports custom word count and attached digits", () => {
    const p = generateG2(
      {
        generator: "G2",
        parameters: {
          numberOfWords: 4,
          separatorOptions: ["-"],
          numericGroups: [{ digitsCount: 3, separator: "" }],
        },
      },
      SAMPLE_DICTIONARY_FR,
    );
    const parts = p.split("-");
    expect(parts.length).toBe(4);
    expect(parts[3]).toMatch(/\d{3}$/);
  });
});

describe("G3 — random alphanumeric", () => {
  it("default policy emits 20 chars in 4 blocks of 5", () => {
    const p = generateG3({ generator: "G3" });
    expect(p).toMatch(/^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$/);
  });

  it("excludeAmbiguous removes l/I/1/0/O", () => {
    for (let i = 0; i < 50; i++) {
      const p = generateG3({ generator: "G3", parameters: { excludeAmbiguous: true } });
      expect(p).not.toMatch(/[lI10O]/);
    }
  });

  it("custom length and blockSize controls work", () => {
    const p = generateG3({
      generator: "G3",
      parameters: { length: 12, blockSize: 4, blockSeparator: "." },
    });
    expect(p).toMatch(/^[A-Za-z0-9]{4}\.[A-Za-z0-9]{4}\.[A-Za-z0-9]{4}$/);
  });

  it("blockSize ≥ length returns flat string", () => {
    const p = generateG3({
      generator: "G3",
      parameters: { length: 8, blockSize: 8 },
    });
    expect(p).toMatch(/^[A-Za-z0-9]{8}$/);
  });
});
