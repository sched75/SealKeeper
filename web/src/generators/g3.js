// =============================================================================
// G3 — Random alphanumeric blocks
// =============================================================================
// PRD A §3.3 (FR-A.G3.1..5):
//   - 20 chars from a 62-character alphabet (a-z, A-Z, 0-9)
//   - Grouped in 4 blocks of 5 separated by hyphens
//   - Effective entropy ≥ 100 bits (B3 target)
//   - Policy MAY exclude ambiguous chars (l/I/1, 0/O)
//   - Stateless: no library required
// =============================================================================

import { cryptoRandomChoice } from "../crypto.js";

const ALPHABET_FULL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const AMBIGUOUS = ["l", "I", "1", "0", "O"];

/**
 * @param {object} policy
 * @returns {string}
 */
export function generateG3(policy) {
  const params = (policy && policy.parameters) || {};
  const length = params.length ?? 20;
  const blockSize = params.blockSize ?? 5;
  const blockSeparator = params.blockSeparator ?? "-";
  const excludeAmbiguous = params.excludeAmbiguous ?? false;

  const alphabet = excludeAmbiguous
    ? Array.from(ALPHABET_FULL)
        .filter((c) => !AMBIGUOUS.includes(c))
        .join("")
    : ALPHABET_FULL;
  const alphabetChars = Array.from(alphabet);

  let chars = "";
  for (let i = 0; i < length; i++) {
    chars += cryptoRandomChoice(alphabetChars);
  }

  if (blockSize <= 0 || blockSize >= length) return chars;
  const blocks = [];
  for (let i = 0; i < chars.length; i += blockSize) {
    blocks.push(chars.slice(i, i + blockSize));
  }
  return blocks.join(blockSeparator);
}
