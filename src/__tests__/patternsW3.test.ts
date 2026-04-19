// W3 pattern tests — covers the 8 new patterns added in Week 3.

import { describe, it, expect } from 'vitest'
import { PATTERNS } from '../patterns'
import { shannonEntropy } from '../engine/entropy'

// ─── Helper ───────────────────────────────────────────────────────────────────

function detects(patternId: string, text: string): boolean {
  const pattern = PATTERNS.find((p) => p.id === patternId)
  if (!pattern) throw new Error(`Pattern not found: ${patternId}`)
  const regex = new RegExp(pattern.regex.source, pattern.regex.flags)
  for (const m of text.matchAll(regex)) {
    const raw = m[1] ?? m[0]
    if (pattern.entropy === 0 || shannonEntropy(raw) >= pattern.entropy) return true
  }
  return false
}

// ─── Anthropic ────────────────────────────────────────────────────────────────

describe('anthropic-api-key', () => {
  it('detects Anthropic Claude API keys', () => {
    expect(detects('anthropic-api-key', 'ANTHROPIC_API_KEY=sk-ant-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp')).toBe(true)
  })

  it('ignores short strings', () => {
    expect(detects('anthropic-api-key', 'sk-ant-short')).toBe(false)
  })
})

// ─── DigitalOcean ─────────────────────────────────────────────────────────────

describe('digitalocean-pat', () => {
  it('detects DigitalOcean PATs', () => {
    expect(detects('digitalocean-pat', 'DO_TOKEN=dop_v1_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')).toBe(true)
  })

  it('ignores tokens without dop_v1_ prefix', () => {
    expect(detects('digitalocean-pat', 'TOKEN=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')).toBe(false)
  })
})

// ─── Linear ───────────────────────────────────────────────────────────────────

describe('linear-api-key', () => {
  it('detects Linear API keys', () => {
    expect(detects('linear-api-key', 'LINEAR_API_KEY=lin_api_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp')).toBe(true)
  })

  it('ignores short strings', () => {
    expect(detects('linear-api-key', 'lin_api_short')).toBe(false)
  })
})

// ─── Generic Secret ───────────────────────────────────────────────────────────

describe('generic-secret', () => {
  it('detects hardcoded secrets', () => {
    expect(detects('generic-secret', 'client_secret = "s3cr3t-v4lue-here!"')).toBe(true)
    expect(detects('generic-secret', 'api_secret: "my-super-secret-123"')).toBe(true)
  })

  it('ignores short values', () => {
    expect(detects('generic-secret', 'secret = "abc"')).toBe(false)
  })
})

// ─── Pattern count sanity check (cumulative) ──────────────────────────────────

describe('PATTERNS total count (W3)', () => {
  it('has 31 built-in patterns in W3', () => {
    expect(PATTERNS).toHaveLength(31)
  })

  it('all patterns have unique IDs', () => {
    const ids = PATTERNS.map(p => p.id)
    const unique = new Set(ids)
    expect(unique.size).toBe(ids.length)
  })

  it('all patterns have /g flag on regex', () => {
    for (const p of PATTERNS) {
      expect(p.regex.flags).toContain('g')
    }
  })

  it('all entropy thresholds are non-negative numbers', () => {
    for (const p of PATTERNS) {
      expect(typeof p.entropy).toBe('number')
      expect(p.entropy).toBeGreaterThanOrEqual(0)
    }
  })

  it('all severities are valid values', () => {
    const valid = new Set(['CRITICAL', 'HIGH', 'MEDIUM'])
    for (const p of PATTERNS) {
      expect(valid.has(p.severity)).toBe(true)
    }
  })
})
