import { describe, it, expect } from 'vitest'
import { PATTERNS } from '../patterns'
import { shannonEntropy } from '../engine/entropy'

// ─── Helper: run a single pattern against a line of text ─────────────────────

interface RawFinding {
  match: string
  entropy: number
  passedEntropyGate: boolean
}

function runPattern(patternId: string, text: string): RawFinding[] {
  const pattern = PATTERNS.find((p) => p.id === patternId)
  if (!pattern) throw new Error(`Pattern not found: ${patternId}`)

  const results: RawFinding[] = []
  const regex = new RegExp(pattern.regex.source, pattern.regex.flags)

  for (const m of text.matchAll(regex)) {
    const raw = m[1] ?? m[0]
    const entropy = shannonEntropy(raw)
    results.push({
      match: raw,
      entropy,
      passedEntropyGate: pattern.entropy === 0 || entropy >= pattern.entropy,
    })
  }
  return results
}

function detects(patternId: string, text: string): boolean {
  return runPattern(patternId, text).some((r) => r.passedEntropyGate)
}

// ─── Groq ─────────────────────────────────────────────────────────────────────

describe('groq-api-key', () => {
  it('detects a real Groq key', () => {
    expect(detects('groq-api-key', 'GROQ_API_KEY=gsk_AbCdEfGh1234567890IjKlMnOpQrStUvWxYz12345678')).toBe(true)
  })

  it('ignores placeholder text', () => {
    expect(detects('groq-api-key', 'GROQ_API_KEY=your-groq-api-key-here')).toBe(false)
    expect(detects('groq-api-key', 'GROQ_API_KEY=gsk_xxx')).toBe(false) // too short
  })
})

// ─── OpenAI ───────────────────────────────────────────────────────────────────

describe('openai-api-key', () => {
  it('detects a legacy sk- key', () => {
    expect(detects('openai-api-key', 'OPENAI_API_KEY=sk-AbCdEfGh1234567890IjKlMnOpQrStUvWxYz1234567890')).toBe(true)
  })

  it('detects a new sk-proj- key', () => {
    expect(detects('openai-api-key', 'OPENAI_KEY=sk-proj-AbCdEfGh1234567890IjKlMnOpQrStUvWxYz1234567890ABC')).toBe(true)
  })

  it('ignores short/placeholder keys', () => {
    expect(detects('openai-api-key', 'sk-your-openai-key')).toBe(false)
  })
})

// ─── Supabase / JWT ───────────────────────────────────────────────────────────

describe('supabase-anon-key', () => {
  it('detects a Supabase anon key (JWT format)', () => {
    // This is a real-format but non-functional test JWT
    const key = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjoxNzAwMDAwMDAwfQ.ABCDEFGHIJKLMNOPQRSTUVWX1234567890abcde'
    expect(detects('supabase-anon-key', `SUPABASE_ANON_KEY=${key}`)).toBe(true)
  })
})

// ─── GitHub PAT ───────────────────────────────────────────────────────────────

describe('github-pat', () => {
  it('detects classic GitHub PATs', () => {
    expect(detects('github-pat', 'token=ghp_AbCdEfGh1234567890IjKlMnOpQrStUvWxYz')).toBe(true)
    expect(detects('github-pat', 'AUTH=gho_AbCdEfGh1234567890IjKlMnOpQrStUvWxYz')).toBe(true)
  })

  it('ignores short strings', () => {
    expect(detects('github-pat', 'ghp_short')).toBe(false)
  })
})

// ─── AWS Access Key ───────────────────────────────────────────────────────────

describe('aws-access-key', () => {
  it('detects AWS access key IDs', () => {
    expect(detects('aws-access-key', 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE')).toBe(true)
  })

  it('ignores non-AKIA prefixed strings', () => {
    expect(detects('aws-access-key', 'ACCESS_KEY=BKIAIOSFODNN7EXAMPLE')).toBe(false)
  })
})

// ─── Stripe ───────────────────────────────────────────────────────────────────

describe('stripe-secret-key', () => {
  it('detects Stripe live secret keys', () => {
    expect(detects('stripe-secret-key', 'STRIPE_KEY=sk_live_AbCdEfGh1234567890IjKlMnOp')).toBe(true)
  })

  it('does NOT flag test keys (sk_test_) — those are safe to commit', () => {
    // Our pattern only targets live keys
    expect(detects('stripe-secret-key', 'STRIPE_KEY=sk_test_AbCdEfGh1234567890IjKlMnOp')).toBe(false)
  })
})

// ─── Private Key ─────────────────────────────────────────────────────────────

describe('private-key', () => {
  it('always detects PEM private key headers (entropy=0)', () => {
    expect(detects('private-key', '-----BEGIN RSA PRIVATE KEY-----')).toBe(true)
    expect(detects('private-key', '-----BEGIN EC PRIVATE KEY-----')).toBe(true)
    expect(detects('private-key', '-----BEGIN PRIVATE KEY-----')).toBe(true)
  })
})

// ─── Generic Password ─────────────────────────────────────────────────────────

describe('generic-password', () => {
  it('detects hardcoded passwords in code', () => {
    expect(detects('generic-password', 'password = "supersecret123"')).toBe(true)
    expect(detects('generic-password', "passwd: 'mypassword'")).toBe(true)
  })

  it('ignores short values (< 8 chars)', () => {
    expect(detects('generic-password', 'password = "pass"')).toBe(false)
  })

  it('ignores very low entropy placeholders', () => {
    // "aaaaaaaa" has entropy 0 — below 3.0 threshold
    expect(detects('generic-password', 'password = "aaaaaaaa"')).toBe(false)
  })
})

// ─── Connection String ────────────────────────────────────────────────────────

describe('connection-string', () => {
  it('detects postgres connection strings with credentials', () => {
    expect(detects('connection-string', 'DATABASE_URL=postgres://admin:s3cr3tP4ss@db.example.com:5432/mydb')).toBe(true)
  })

  it('detects mongodb connection strings', () => {
    expect(detects('connection-string', 'MONGO_URI=mongodb+srv://user:p4ssw0rd@cluster.mongodb.net/dbname')).toBe(true)
  })

  it('ignores connection strings without credentials', () => {
    expect(detects('connection-string', 'postgres://localhost:5432/mydb')).toBe(false)
  })
})
