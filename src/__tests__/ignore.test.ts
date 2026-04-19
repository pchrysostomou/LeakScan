import { describe, it, expect } from 'vitest'
import { loadIgnoreRules, shouldIgnore, matchesAnyGlob } from '../config/ignoreParser'
import { writeFileSync, mkdirSync, rmSync, existsSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeTempDir(): string {
  const dir = join(tmpdir(), `leakscan-test-${Date.now()}`)
  mkdirSync(dir, { recursive: true })
  return dir
}

function writeIgnoreFile(dir: string, contents: string): void {
  writeFileSync(join(dir, '.leakscanignore'), contents, 'utf-8')
}

// ─── loadIgnoreRules ──────────────────────────────────────────────────────────

describe('loadIgnoreRules', () => {
  it('returns empty rules if .leakscanignore does not exist', () => {
    const dir = makeTempDir()
    const rules = loadIgnoreRules(dir)
    expect(rules.files).toHaveLength(0)
    expect(rules.patterns).toHaveLength(0)
    expect(rules.findings).toHaveLength(0)
    rmSync(dir, { recursive: true })
  })

  it('ignores blank lines and comments', () => {
    const dir = makeTempDir()
    writeIgnoreFile(dir, `
# This is a comment
  
# Another comment
`)
    const rules = loadIgnoreRules(dir)
    expect(rules.files).toHaveLength(0)
    expect(rules.patterns).toHaveLength(0)
    expect(rules.findings).toHaveLength(0)
    rmSync(dir, { recursive: true })
  })

  it('parses file globs correctly', () => {
    const dir = makeTempDir()
    writeIgnoreFile(dir, `*.test.ts\nfixtures/\nsrc/test/`)
    const rules = loadIgnoreRules(dir)
    expect(rules.files).toContain('*.test.ts')
    expect(rules.files).toContain('fixtures/')
    expect(rules.files).toContain('src/test/')
    rmSync(dir, { recursive: true })
  })

  it('parses pattern: prefix correctly', () => {
    const dir = makeTempDir()
    writeIgnoreFile(dir, 'pattern:generic-password\npattern:connection-string')
    const rules = loadIgnoreRules(dir)
    expect(rules.patterns).toContain('generic-password')
    expect(rules.patterns).toContain('connection-string')
    expect(rules.files).toHaveLength(0)
    rmSync(dir, { recursive: true })
  })

  it('parses finding: prefix correctly', () => {
    const dir = makeTempDir()
    writeIgnoreFile(dir, 'finding:a3f91bc:README.md\nfinding:deadbeef:src/config.ts')
    const rules = loadIgnoreRules(dir)
    expect(rules.findings).toContain('a3f91bc:README.md')
    expect(rules.findings).toContain('deadbeef:src/config.ts')
    rmSync(dir, { recursive: true })
  })

  it('handles mixed content correctly', () => {
    const dir = makeTempDir()
    writeIgnoreFile(dir, `
# Ignore test files
*.test.ts
fixtures/

# Ignore this pattern globally
pattern:generic-password

# Ignore a specific known finding
finding:a3f91bc:README.md
`)
    const rules = loadIgnoreRules(dir)
    expect(rules.files).toEqual(['*.test.ts', 'fixtures/'])
    expect(rules.patterns).toEqual(['generic-password'])
    expect(rules.findings).toEqual(['a3f91bc:README.md'])
    rmSync(dir, { recursive: true })
  })
})

// ─── shouldIgnore ─────────────────────────────────────────────────────────────

describe('shouldIgnore', () => {
  const rules = {
    files: ['*.test.ts', 'fixtures/'],
    patterns: ['generic-password'],
    findings: ['a3f91bc:README.md'],
  }

  it('suppresses findings matching a glob', () => {
    expect(shouldIgnore(rules, 'src/auth.test.ts', 'groq-api-key')).toBe(true)
    expect(shouldIgnore(rules, 'fixtures/sample.env', 'groq-api-key')).toBe(true)
  })

  it('suppresses findings matching an ignored pattern ID', () => {
    expect(shouldIgnore(rules, 'src/index.ts', 'generic-password')).toBe(true)
  })

  it('suppresses findings matching a commit:file key', () => {
    expect(shouldIgnore(rules, 'README.md', 'groq-api-key', 'a3f91bc')).toBe(true)
  })

  it('does NOT suppress findings that do not match any rule', () => {
    expect(shouldIgnore(rules, 'src/index.ts', 'groq-api-key')).toBe(false)
    expect(shouldIgnore(rules, 'README.md', 'groq-api-key', 'deadbeef')).toBe(false)
  })
})

// ─── matchesAnyGlob ───────────────────────────────────────────────────────────

describe('matchesAnyGlob', () => {
  it('matches wildcard extension globs', () => {
    expect(matchesAnyGlob('src/auth.test.ts', ['*.test.ts'])).toBe(true)
    expect(matchesAnyGlob('tests/foo.test.ts', ['*.test.ts'])).toBe(true)
  })

  it('matches directory globs', () => {
    expect(matchesAnyGlob('fixtures/env.example', ['fixtures/'])).toBe(true)
    expect(matchesAnyGlob('fixtures/nested/file.ts', ['fixtures/'])).toBe(true)
  })

  it('does not match unrelated paths', () => {
    expect(matchesAnyGlob('src/index.ts', ['*.test.ts'])).toBe(false)
    expect(matchesAnyGlob('src/index.ts', ['fixtures/'])).toBe(false)
  })

  it('handles multiple globs', () => {
    expect(matchesAnyGlob('src/auth.test.ts', ['fixtures/', '*.test.ts'])).toBe(true)
  })
})
