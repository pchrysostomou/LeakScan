// Shannon entropy — measures how "random" a string is.
// Real API keys have high entropy (> 4.5). Placeholders have low entropy (< 3.5).
//
// Example:
//   shannonEntropy("your-api-key-here")         → ~3.1  (LOW — false positive)
//   shannonEntropy("gsk_a8Kj2mNpQrStUvWx...")   → ~5.2  (HIGH — real secret)

/**
 * Calculates the Shannon entropy of a string.
 * Returns a value in bits per character (0 = all same chars, ~5-6 = random).
 */
export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0

  // Count character frequencies
  const freq: Record<string, number> = {}
  for (const char of str) {
    freq[char] = (freq[char] ?? 0) + 1
  }

  // H = -Σ p(x) * log₂(p(x))
  return Object.values(freq).reduce((entropy, count) => {
    const p = count / str.length
    return entropy - p * Math.log2(p)
  }, 0)
}
