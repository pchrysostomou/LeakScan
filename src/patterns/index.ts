// ─── Built-in secret patterns ─────────────────────────────────────────────────
//
// Each pattern has:
//   - id:       unique identifier (used in .leakscanignore)
//   - name:     human-readable name for output
//   - severity: CRITICAL / HIGH / MEDIUM
//   - regex:    detection pattern (must have /g flag for matchAll)
//   - entropy:  minimum Shannon entropy threshold to pass (0 = always flag)
//
// W1: 10 core patterns
// W2: 23 patterns — adds Slack, Discord, Firebase, SendGrid, Twilio,
//                   Mailchimp, npm, Google API/OAuth, Heroku, Stripe publishable
// W3: 31 patterns — adds Anthropic, Cloudflare, DigitalOcean, Vercel, Linear,
//                   HashiCorp Vault, Azure, Doppler, generic secret

import type { SecretPattern } from '../types'

export const PATTERNS: SecretPattern[] = [

  // ─── AI/ML Services ───────────────────────────────────────────────────────

  {
    id: 'groq-api-key',
    name: 'Groq API Key',
    severity: 'CRITICAL',
    regex: /gsk_[a-zA-Z0-9]{40,}/g,
    entropy: 4.5,
  },

  {
    id: 'openai-api-key',
    name: 'OpenAI API Key',
    severity: 'CRITICAL',
    // Matches both legacy sk- keys (sk- + 48 chars) and new sk-proj- keys
    // Using {45,} to accommodate all real variants while blocking short placeholders
    regex: /sk-(?:proj-)?[a-zA-Z0-9_-]{45,}/g,
    entropy: 4.5,
  },

  // ─── Cloud & Backend Services ─────────────────────────────────────────────

  {
    id: 'supabase-anon-key',
    name: 'Supabase / JWT Token',
    severity: 'HIGH',
    // JWT format: three base64url segments separated by dots
    // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 is the standard header
    regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    entropy: 5.0,
  },

  {
    id: 'github-pat',
    name: 'GitHub Personal Access Token',
    severity: 'CRITICAL',
    // Classic PATs: ghp_, gho_, ghu_, ghs_, ghr_
    regex: /gh[pousr]_[A-Za-z0-9]{36,}/g,
    entropy: 4.5,
  },

  {
    id: 'github-fine-grained',
    name: 'GitHub Fine-grained Token',
    severity: 'CRITICAL',
    regex: /github_pat_[A-Za-z0-9_]{82,}/g,
    entropy: 4.5,
  },

  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    severity: 'CRITICAL',
    // AWS access keys always start with AKIA and are 20 chars total
    regex: /AKIA[0-9A-Z]{16}/g,
    entropy: 3.5,
  },

  // ─── Payment ──────────────────────────────────────────────────────────────

  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret Key',
    severity: 'CRITICAL',
    regex: /sk_live_[a-zA-Z0-9]{24,}/g,
    entropy: 4.0,
  },

  {
    id: 'stripe-publishable-key',
    name: 'Stripe Publishable Key (live)',
    severity: 'MEDIUM',
    // publishable keys are safe in client-side code, but live keys in source are a red flag
    regex: /pk_live_[a-zA-Z0-9]{24,}/g,
    entropy: 4.0,
  },

  // ─── Communication Services ───────────────────────────────────────────────

  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API Key',
    severity: 'CRITICAL',
    // Format: SG. + 22 chars + . + 43 chars
    regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    entropy: 4.5,
  },

  {
    id: 'twilio-account-sid',
    name: 'Twilio Account SID',
    severity: 'HIGH',
    // Twilio Account SIDs always start with AC and are 34 chars total
    regex: /AC[a-f0-9]{32}/g,
    entropy: 3.5,
  },

  {
    id: 'twilio-auth-token',
    name: 'Twilio Auth Token',
    severity: 'CRITICAL',
    // 32-char lowercase hex string near twilio keyword
    regex: /(?:twilio|TWILIO).*?([a-f0-9]{32})/g,
    entropy: 3.5,
  },

  {
    id: 'mailchimp-api-key',
    name: 'Mailchimp API Key',
    severity: 'HIGH',
    // Format: 32 hex chars + "-us" + datacenter number (e.g. "-us6")
    regex: /[a-f0-9]{32}-us\d{1,2}/g,
    entropy: 3.5,
  },

  {
    id: 'slack-token',
    name: 'Slack Token',
    severity: 'HIGH',
    // xoxb = bot, xoxp = user, xoxa = app, xoxs = session, xoxr = refresh
    regex: /xox[bapsr]-[0-9A-Za-z-]{10,}/g,
    entropy: 4.0,
  },

  {
    id: 'slack-webhook',
    name: 'Slack Incoming Webhook',
    severity: 'HIGH',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
    entropy: 4.0,
  },

  {
    id: 'discord-bot-token',
    name: 'Discord Bot Token',
    severity: 'HIGH',
    // Discord bot tokens: base64(bot_id) + . + timestamp + . + hmac
    regex: /[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}/g,
    entropy: 4.5,
  },

  // ─── Google / Firebase ────────────────────────────────────────────────────

  {
    id: 'google-api-key',
    name: 'Google API Key',
    severity: 'HIGH',
    // All Google API keys start with AIza and are 39 chars total
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    entropy: 3.5,
  },

  {
    id: 'google-oauth-client',
    name: 'Google OAuth Client ID',
    severity: 'MEDIUM',
    regex: /[0-9]+-[a-z0-9_]+\.apps\.googleusercontent\.com/g,
    entropy: 3.5,
  },

  {
    id: 'firebase-service-account',
    name: 'Firebase Service Account Key',
    severity: 'CRITICAL',
    // Firebase service account JSON files contain this literal string
    regex: /"type"\s*:\s*"service_account"/g,
    entropy: 0, // always flag — literal string match, no entropy needed
  },

  // ─── Package Registries ───────────────────────────────────────────────────

  {
    id: 'npm-access-token',
    name: 'NPM Access Token',
    severity: 'HIGH',
    regex: /npm_[A-Za-z0-9]{36,}/g,
    entropy: 4.0,
  },

  // ─── PaaS / Hosting ───────────────────────────────────────────────────────

  {
    id: 'heroku-api-key',
    name: 'Heroku API Key',
    severity: 'CRITICAL',
    // Heroku API keys are UUID v4 format, near HEROKU/heroku keyword
    regex: /(?:heroku|HEROKU).*?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi,
    entropy: 3.0,
  },

  // ─── Cryptographic Keys ───────────────────────────────────────────────────

  {
    id: 'private-key',
    name: 'Private Key (PEM)',
    severity: 'CRITICAL',
    // Matches RSA, EC, DSA, PKCS8, and generic private keys
    regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    entropy: 0, // always flag — no entropy check needed for PEM headers
  },

  // ─── Generic Hardcoded Secrets ────────────────────────────────────────────

  {
    id: 'generic-password',
    name: 'Hardcoded Password',
    severity: 'MEDIUM',
    // Matches: password = "secret", passwd: 'value', pwd="pass" etc.
    // Requires >= 8 chars to avoid flagging short values
    regex: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']/gi,
    entropy: 3.0,
  },

  {
    id: 'connection-string',
    name: 'Database Connection String',
    severity: 'HIGH',
    // Matches postgres://, mysql://, mongodb://, mongodb+srv:// with credentials
    regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:]+:[^@]+@[^\s"']+/gi,
    entropy: 3.5,
  },

  // ─── W3: Extended Coverage ────────────────────────────────────────────────

  {
    id: 'anthropic-api-key',
    name: 'Anthropic API Key',
    severity: 'CRITICAL',
    // Claude API keys: sk-ant- prefix + random chars
    regex: /sk-ant-[a-zA-Z0-9_-]{40,}/g,
    entropy: 4.5,
  },

  {
    id: 'cloudflare-api-token',
    name: 'Cloudflare API Token',
    severity: 'CRITICAL',
    // Cloudflare API tokens are 40-char base64url strings
    regex: /(?:cloudflare|CLOUDFLARE).*?([a-zA-Z0-9_-]{40})/g,
    entropy: 4.5,
  },

  {
    id: 'digitalocean-pat',
    name: 'DigitalOcean Personal Access Token',
    severity: 'CRITICAL',
    // DO PATs: dop_v1_ prefix
    regex: /dop_v1_[a-f0-9]{64}/g,
    entropy: 4.0,
  },

  {
    id: 'vercel-token',
    name: 'Vercel Token',
    severity: 'HIGH',
    regex: /(?:vercel|VERCEL).*?([a-zA-Z0-9]{24,})/g,
    entropy: 4.5,
  },

  {
    id: 'linear-api-key',
    name: 'Linear API Key',
    severity: 'HIGH',
    regex: /lin_api_[a-zA-Z0-9]{40,}/g,
    entropy: 4.5,
  },

  {
    id: 'vault-token',
    name: 'HashiCorp Vault Token',
    severity: 'CRITICAL',
    // Vault tokens: s. (service), b. (batch), or hvs. prefixes
    regex: /(?:hvs|s|b)\.[a-zA-Z0-9]{24,}/g,
    entropy: 4.5,
  },

  {
    id: 'azure-subscription-key',
    name: 'Azure Subscription Key',
    severity: 'HIGH',
    // Azure API Management and Cognitive Services keys
    regex: /(?:azure|AZURE|ocp-apim-subscription-key).*?([a-f0-9]{32})/gi,
    entropy: 3.5,
  },

  {
    id: 'generic-secret',
    name: 'Hardcoded Secret',
    severity: 'MEDIUM',
    // Matches: secret = "value", api_secret: 'value', APP_SECRET="value"
    regex: /(?:secret|api_secret|app_secret|client_secret)\s*[:=]\s*["']([^"']{8,})["']/gi,
    entropy: 3.0,
  },

]

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Returns a pattern by its ID, or undefined if not found. */
export function getPatternById(id: string): SecretPattern | undefined {
  return PATTERNS.find((p) => p.id === id)
}

/** Returns all pattern IDs — used by .leakscanignore validation. */
export function getAllPatternIds(): string[] {
  return PATTERNS.map((p) => p.id)
}
