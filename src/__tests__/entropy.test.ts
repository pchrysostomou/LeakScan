import { describe, it, expect } from 'vitest'
import { shannonEntropy } from '../engine/entropy'

// ─── Known values ─────────────────────────────────────────────────────────────

describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0)
  })

  it('returns 0 for single character string', () => {
    expect(shannonEntropy('a')).toBe(0)
    expect(shannonEntropy('aaaaaaa')).toBe(0)
  })

  it('returns low entropy for repeated characters', () => {
    expect(shannonEntropy('aabbcc')).toBeLessThan(2)
  })

  it('returns low entropy for placeholder text', () => {
    // These should NOT be flagged as secrets
    const placeholders = [
      'your-api-key-here',
      'insert-secret-here',
      'REPLACE_ME',
      'xxxxxxxxxxxxxxxx',
    ]
    for (const p of placeholders) {
      expect(shannonEntropy(p)).toBeLessThan(3.5)
    }
  })

  it('returns high entropy for real-looking API keys', () => {
    // These should pass the entropy gate
    const realKeys = [
      'gsk_AbCdEfGh1234567890IjKlMnOpQrStUvWxYz12345678',
      'sk-AbCdEfGh1234567890IjKlMnOpQrStUvWxYz1234567890',
      'AKIAIOSFODNN7EXAMPLE',    // AWS access key format
    ]
    for (const k of realKeys) {
      expect(shannonEntropy(k)).toBeGreaterThan(3.5)
    }
  })

  it('returns maximum entropy for perfectly random string', () => {
    // A string where every character is unique has the highest possible entropy
    const allUnique = 'abcdefghijklmnopqrstuvwxyz' // 26 unique chars
    expect(shannonEntropy(allUnique)).toBeGreaterThan(4.5)
  })

  it('is symmetric — same entropy regardless of char order', () => {
    const a = shannonEntropy('abcabc')
    const b = shannonEntropy('cbacba')
    expect(a).toBeCloseTo(b, 10)
  })
})
