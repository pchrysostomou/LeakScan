# LeakScan

> CLI tool that scans Git repos for exposed secrets — API keys, passwords, tokens — in the current filesystem **and the full commit history**.

```
$ leakscan scan --path C:\Synapse

Scanning repository: Synapse
Files scanned: 247  Commits checked: 12  Time: 1.4s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 CRITICAL  Groq API Key
  File:    .env.local (line 12)
  Match:   GROQ_API_••••••••KlMnOp
  Note:    ⚠ File not in .gitignore — risk of accidental commit

HIGH  Supabase / JWT Token
  Commit:  a3f91bc (3 days ago)
  File:    README.md
  Match:   eyJhbGci••••••••1NiIsIn

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2 secrets found. (1 CRITICAL, 1 HIGH)
  Run leakscan fix for remediation steps.
```

---

## Why leakscan

The standard tooling for secret detection requires cloud services, Docker images, or complex config files. leakscan has:

- **Zero external services** — no API keys, no sign-up, no network calls
- **Git history scan** — finds secrets even after they've been deleted (they live forever in `git log`)
- **Shannon entropy filtering** — distinguishes real API keys from placeholder strings like `your-key-here`
- **31 built-in patterns** — covers every major cloud provider and developer tool
- **SARIF output** — integrates directly with GitHub Code Scanning

---

## Installation

```bash
# Clone and install globally
git clone https://github.com/pchrysostomou/LeakScan
cd leakscan
npm install
npm run build
npm link

# Now available globally
leakscan --help
```

---

## Usage

### Scan a repository (default — filesystem + git history)

```bash
leakscan scan
leakscan scan --path C:\my-project
```

### Filesystem only (skip git history)

```bash
leakscan scan --no-history
```

### Limit git history depth

```bash
leakscan scan --depth 50    # scan last 50 commits only
```

### Machine-readable output

```bash
# JSON — pipe to jq, scripts, etc.
leakscan scan --format json | jq '.findings[] | select(.severity == "CRITICAL")'

# SARIF — upload to GitHub Code Scanning
leakscan scan --format sarif > results.sarif
```

### View remediation steps

```bash
leakscan fix
```

### List all 31 detection patterns

```bash
leakscan patterns
```

```
leakscan patterns — Built-in detection rules
31 patterns loaded
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ID                         SEVERITY     ENTROPY    NAME
────────────────────────────────────────────────────────────────
groq-api-key                CRITICAL     4.5        Groq API Key
openai-api-key              CRITICAL     4.5        OpenAI API Key
anthropic-api-key           CRITICAL     4.5        Anthropic API Key
supabase-anon-key          HIGH         5.0        Supabase / JWT Token
github-pat                  CRITICAL     4.5        GitHub Personal Access Token
...
```

---

## How it works

### 1 — Filesystem scan

Recursively walks the repository, skipping `node_modules/`, `.git/`, binaries, and files > 1MB. Each text file is scanned line-by-line against all 31 patterns.

Detects if `.env*` files are missing from `.gitignore` and flags them.

### 2 — Git history scan

```
git log --all --no-merges --reverse
→ per commit: git show --unified=0 --diff-filter=AM
→ parse only "+" lines (additions)
→ apply patterns + entropy gate + redact
```

Even if a secret was deleted 50 commits ago, it's still in every clone of the repository. leakscan finds it.

### 3 — Shannon entropy filtering

A key differentiator: leakscan doesn't just match regex patterns. It measures how "random" a matched string is using Shannon entropy.

```
shannonEntropy("your-api-key-here")  → 3.1  → filtered out (placeholder)
shannonEntropy("gsk_a8Kj2mNpQr...")  → 5.2  → flagged (real secret)
```

This eliminates most false positives that plague simpler scanners.

### 4 — Redaction

The matched secret is **never displayed in full**. The output shows only the first 8 and last 4 characters:

```
gsk_AbCdE••••••••XxYz
```

This prevents leakscan's own output from becoming a secret leak in CI logs.

---

## .leakscanignore

Works like `.gitignore`. Create a `.leakscanignore` file in the repo root:

```
# Ignore test/fixture files (they intentionally contain fake secrets)
*.test.ts
fixtures/

# Ignore a specific pattern globally
pattern:generic-password

# Ignore a specific finding (after you've rotated the key and cleaned history)
finding:a3f91bc:README.md
```

---

## CI/CD integration

### GitHub Actions — fail on secrets

```yaml
# .github/workflows/security.yml
name: Secret Scan

on: [push, pull_request]

jobs:
  leakscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # fetch full history for git history scan

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - run: npm install -g leakscan

      - name: Scan for secrets
        run: leakscan scan
        # Exits with code 1 if findings found — fails the workflow automatically
```

### SARIF upload to GitHub Code Scanning

```yaml
      - name: Scan for secrets (SARIF)
        run: leakscan scan --format sarif > results.sarif || true

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Patterns reference

| Category | Patterns |
|----------|----------|
| AI/ML | Groq, OpenAI, Anthropic |
| Version Control | GitHub PAT, GitHub Fine-grained |
| Cloud | AWS Access Key, Cloudflare, DigitalOcean, Vercel, Heroku, Azure |
| Database | Supabase JWT, Connection strings, Firebase Service Account |
| Communication | Slack Token, Slack Webhook, Discord Bot, SendGrid, Twilio (2), Mailchimp |
| Payment | Stripe Secret, Stripe Publishable |
| Identity | Google API Key, Google OAuth Client ID |
| Infrastructure | HashiCorp Vault, NPM Token, Linear |
| Crypto | Private Key (PEM — RSA/EC/DSA) |
| Generic | Hardcoded Password, Hardcoded Secret, Database Connection String |

---

## Technical design

### Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Node.js 18+ |
| Language | TypeScript (strict, ES2022) |
| CLI framework | Commander.js |
| Git operations | simple-git |
| Terminal output | chalk@4 |
| Build | tsup (35ms, 30KB CJS bundle) |
| Tests | Vitest |

### Architecture

```
leakscan scan
  │
  ├─→ loadIgnoreRules()       .leakscanignore parser
  │
  ├─→ scanFilesystem()        recursive walk + entropy gate
  │      └─→ patterns[]       31 regex patterns
  │      └─→ shannonEntropy() false positive filter
  │      └─→ redact()         first8••••••••last4
  │
  ├─→ scanGitHistory()        simple-git commit diff scanner
  │      └─→ git log          all commits, oldest first
  │      └─→ git show --unified=0  additions only
  │      └─→ deduplication    same pattern+file → oldest commit wins
  │
  └─→ reporter                terminal | json | sarif
```

### Output formats

- **terminal** — chalk-colored, human-readable (default)
- **json** — machine-readable, pipe to `jq` or scripts
- **sarif** — SARIF 2.1.0, compatible with GitHub Code Scanning

---

## Development

```bash
# Install
npm install

# Type check
npm run lint

# Run tests
npm test           # single run
npm run test:watch # watch mode

# Build
npm run build      # 35ms, dist/index.js

# Test the CLI directly during development
npx ts-node src/index.ts scan --path .
```

### Test coverage

```
Test Files: 7
Tests:      96+ passing

src/__tests__/
  entropy.test.ts        7 tests  — Shannon entropy accuracy
  redact.test.ts         5 tests  — Redaction format + boundary cases
  patterns.test.ts      19 tests  — W1 patterns: true/false positives
  patternsW2.test.ts    24 tests  — W2 patterns + all-patterns sanity
  patternsW3.test.ts    12 tests  — W3 patterns + full sanity suite
  historyScanner.test.ts 13 tests  — Diff parser + date formatter
  ignore.test.ts        14 tests  — .leakscanignore parser
```

---

## The interview story

> "I built leakscan because during development of Synapse, a Supabase anon key accidentally appeared in plain text in a conversation. Instead of ignoring it, I built a tool that would have caught it automatically — both in the filesystem and deep in git history, even after deletion."

### What makes this portfolio-worthy

- **Shannon entropy filtering** — most hobby secret scanners just run regex. Adding entropy measurement shows understanding of why false positives happen and how to eliminate them at the algorithmic level.
- **Git history scan** — the `git show --unified=0 --diff-filter=AM` approach scans only the additions in each diff, not the full file content. This is the correct, efficient way to do it.
- **SARIF output** — knowing what SARIF is and implementing the 2.1.0 spec (with fingerprints for deduplication, `%SRCROOT%` URI bases, and numeric security severity for GitHub sorting) signals awareness of the security tooling ecosystem.
- **Redaction logic** — the tool never logs the full secret, even in its own output. This is a subtle but important security property that shows security-aware thinking.

---

