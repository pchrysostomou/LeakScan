import { describe, it, expect } from 'vitest'
import { redact } from '../engine/redact'

// ─── Redaction format ─────────────────────────────────────────────────────────

describe('redact', () => {
  it('fully masks short secrets (13 chars or fewer)', () => {
    expect(redact('shortkey')).toBe('••••••••')
    expect(redact('1234567890123')).toBe('••••••••')
  })

  it('shows first 8 + mask + last 4 for long secrets', () => {
    // 40-char secret
    const secret = 'gsk_AbCdEfGh1234567890IjKlMnOpQrStUvWxYz'
    const result = redact(secret)

    expect(result).toMatch(/^gsk_AbCd/)       // first 8 chars preserved
    expect(result).toMatch(/WxYz$/)            // last 4 chars preserved
    expect(result).toContain('••••••••')       // mask in middle
  })

  it('never returns the full original secret for long strings', () => {
    const secret = 'sk-AbCdEfGh1234567890IjKlMnOpQrStUvWxYz1234567890'
    const result = redact(secret)
    expect(result).not.toBe(secret)
    expect(result.length).toBeLessThan(secret.length)
  })

  it('is deterministic — same input always gives same output', () => {
    const secret = 'gsk_AbCdEfGh1234567890IjKlMnOpQrStUvWxYzABCD'
    expect(redact(secret)).toBe(redact(secret))
  })

  it('handles exactly the minimum reveal length boundary', () => {
    // MIN_REVEAL = HEAD_LEN (8) + TAIL_LEN (4) + 1 = 13
    // 13 chars = fully masked, 14 chars = partially revealed
    const thirteenChars = 'abcdefghijklm' // 13
    const fourteenChars = 'abcdefghijklmn' // 14

    expect(redact(thirteenChars)).toBe('••••••••')
    expect(redact(fourteenChars)).not.toBe('••••••••')
    expect(redact(fourteenChars)).toMatch(/^abcdefgh/)
  })
})
