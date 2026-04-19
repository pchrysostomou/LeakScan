// W2 pattern tests — covers the 12 new patterns added in Week 2.
// W1 patterns are tested in patterns.test.ts

import { describe, it, expect } from 'vitest'
import { PATTERNS } from '../patterns'
import { shannonEntropy } from '../engine/entropy'

// ─── Helper (same as patterns.test.ts) ────────────────────────────────────────

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

// ─── Stripe publishable ───────────────────────────────────────────────────────

describe('stripe-publishable-key', () => {
  it('detects live Stripe publishable key', () => {
    expect(detects('stripe-publishable-key', 'STRIPE_PK=pk_live_AbCdEfGh1234567890IjKlMn')).toBe(true)
  })

  it('ignores test keys', () => {
    expect(detects('stripe-publishable-key', 'pk_test_AbCdEfGh1234567890IjKlMnOp')).toBe(false)
  })
})

// ─── SendGrid ─────────────────────────────────────────────────────────────────

describe('sendgrid-api-key', () => {
  it('detects a SendGrid API key', () => {
    const key = 'SG.AbCdEfGh1234567890IjKl.AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGh'
    expect(detects('sendgrid-api-key', `SENDGRID_API_KEY=${key}`)).toBe(true)
  })

  it('ignores non-SG. prefixed strings', () => {
    expect(detects('sendgrid-api-key', 'apikey=some-other-key')).toBe(false)
  })
})

// ─── Twilio ───────────────────────────────────────────────────────────────────

describe('twilio-account-sid', () => {
  it('detects Twilio Account SID', () => {
    expect(detects('twilio-account-sid', 'TWILIO_SID=ACabcdef1234567890abcdef1234567890')).toBe(true)
  })

  it('ignores strings not starting with AC', () => {
    expect(detects('twilio-account-sid', 'BCabcdef1234567890abcdef1234567890')).toBe(false)
  })
})

describe('twilio-auth-token', () => {
  it('detects Twilio auth token near keyword', () => {
    expect(detects('twilio-auth-token', 'TWILIO_AUTH_TOKEN=abcdef1234567890abcdef1234567890')).toBe(true)
  })
})

// ─── Mailchimp ────────────────────────────────────────────────────────────────

describe('mailchimp-api-key', () => {
  it('detects Mailchimp API key format', () => {
    expect(detects('mailchimp-api-key', 'MC_KEY=abcdef1234567890abcdef1234567890-us6')).toBe(true)
  })

  it('ignores strings without -us suffix', () => {
    expect(detects('mailchimp-api-key', 'abcdef1234567890abcdef1234567890-eu1')).toBe(false)
  })
})

// ─── Slack ────────────────────────────────────────────────────────────────────

describe('slack-token', () => {
  it('detects xoxb bot token', () => {
    expect(detects('slack-token', 'SLACK_BOT_TOKEN=xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOp')).toBe(true)
  })

  it('detects xoxp user token', () => {
    expect(detects('slack-token', 'token=xoxp-1234567890123-1234567890123-AbCdEfGhIjKlMnOp')).toBe(true)
  })

  it('ignores non-xox prefixed strings', () => {
    expect(detects('slack-token', 'TOKEN=abc-1234567890')).toBe(false)
  })
})

describe('slack-webhook', () => {
  it('detects Slack webhook URL', () => {
    const url = 'https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx'
    expect(detects('slack-webhook', `SLACK_WEBHOOK=${url}`)).toBe(true)
  })
})

// ─── Discord ─────────────────────────────────────────────────────────────────

describe('discord-bot-token', () => {
  it('detects Discord bot token format', () => {
    // Discord tokens follow: base64_id.timestamp_b64.hmac_b64
    const token = 'MTIzNDU2Nzg5MDEyMzQ1Njc4.GAbCdE.AbCdEfGhIjKlMnOpQrStUvWxYz1234567'
    expect(detects('discord-bot-token', `DISCORD_TOKEN=${token}`)).toBe(true)
  })
})

// ─── Google / Firebase ────────────────────────────────────────────────────────

describe('google-api-key', () => {
  it('detects Google API keys', () => {
    expect(detects('google-api-key', 'GOOGLE_KEY=AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz1234567')).toBe(true)
  })

  it('ignores strings without AIza prefix', () => {
    expect(detects('google-api-key', 'key=BIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz1234567')).toBe(false)
  })
})

describe('google-oauth-client', () => {
  it('detects Google OAuth Client IDs', () => {
    expect(detects('google-oauth-client', 'CLIENT_ID=123456789012-abcdefghijklmnop.apps.googleusercontent.com')).toBe(true)
  })
})

describe('firebase-service-account', () => {
  it('always flags Firebase service account JSON (entropy=0)', () => {
    expect(detects('firebase-service-account', '"type": "service_account"')).toBe(true)
    expect(detects('firebase-service-account', '"type":"service_account"')).toBe(true)
  })
})

// ─── NPM ─────────────────────────────────────────────────────────────────────

describe('npm-access-token', () => {
  it('detects NPM access tokens', () => {
    expect(detects('npm-access-token', 'NPM_TOKEN=npm_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890')).toBe(true)
  })

  it('ignores short strings', () => {
    expect(detects('npm-access-token', 'npm_short')).toBe(false)
  })
})

// ─── Heroku ───────────────────────────────────────────────────────────────────

describe('heroku-api-key', () => {
  it('detects Heroku API key near heroku keyword', () => {
    expect(detects('heroku-api-key', 'HEROKU_API_KEY=12345678-1234-1234-1234-123456789abc')).toBe(true)
  })
})

// ─── Pattern count sanity check ───────────────────────────────────────────────

describe('PATTERNS total count', () => {
  it('has 31 built-in patterns (including W3 additions)', () => {
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
})
