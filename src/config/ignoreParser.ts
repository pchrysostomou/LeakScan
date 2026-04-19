// .leakscanignore parser
//
// Syntax (same mental model as .gitignore):
//
//   # comments are ignored
//   *.test.ts              → file glob — ignore files matching this pattern
//   fixtures/              → directory glob — ignore entire directory
//   pattern:generic-password     → ignore a specific pattern ID globally
//   finding:a3f91bc:README.md    → ignore a specific finding by commit:file key
//
// If .leakscanignore doesn't exist, an empty IgnoreRules object is returned.

import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import type { IgnoreRules } from '../types'

const PATTERN_PREFIX = 'pattern:'
const FINDING_PREFIX = 'finding:'

/**
 * Loads and parses the .leakscanignore file from the given repo root.
 * Returns empty rules if the file doesn't exist.
 */
export function loadIgnoreRules(repoPath: string): IgnoreRules {
  const ignorePath = join(repoPath, '.leakscanignore')

  if (!existsSync(ignorePath)) {
    return { files: [], patterns: [], findings: [] }
  }

  const lines = readFileSync(ignorePath, 'utf-8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'))

  const files: string[] = []
  const patterns: string[] = []
  const findings: string[] = []

  for (const line of lines) {
    if (line.startsWith(FINDING_PREFIX)) {
      // finding:a3f91bc:README.md  →  "a3f91bc:README.md"
      findings.push(line.slice(FINDING_PREFIX.length))
    } else if (line.startsWith(PATTERN_PREFIX)) {
      // pattern:generic-password  →  "generic-password"
      patterns.push(line.slice(PATTERN_PREFIX.length))
    } else {
      // *.test.ts, fixtures/, etc. — file glob
      files.push(line)
    }
  }

  return { files, patterns, findings }
}

/**
 * Returns true if a finding should be suppressed based on loaded ignore rules.
 *
 * @param filePath  - The file path of the finding (relative to repo root)
 * @param patternId - The pattern ID of the finding
 * @param commitHash - The commit short hash (for git-history findings)
 */
export function shouldIgnore(
  rules: IgnoreRules,
  filePath: string,
  patternId: string,
  commitHash?: string
): boolean {
  // Check pattern-level ignores
  if (rules.patterns.includes(patternId)) return true

  // Check specific finding ignores (commit:file key)
  if (commitHash) {
    const key = `${commitHash}:${filePath}`
    if (rules.findings.includes(key)) return true
  }

  // Check file glob ignores
  if (matchesAnyGlob(filePath, rules.files)) return true

  return false
}

/**
 * Minimal glob matcher — supports * wildcards and directory suffixes.
 * Handles common patterns like *.test.ts, fixtures/, src/test/*, etc.
 */
export function matchesAnyGlob(filePath: string, globs: string[]): boolean {
  const normalised = filePath.replace(/\\/g, '/')

  return globs.some((glob) => {
    const normGlob = glob.replace(/\\/g, '/')

    // Directory glob: fixtures/ → matches anything inside fixtures/
    if (normGlob.endsWith('/')) {
      return normalised.includes(normGlob) || normalised.startsWith(normGlob)
    }

    // Convert glob to regex: * → [^/]*, ** → .*
    const regexStr = normGlob
      .replace(/[.+^${}()|[\]\\]/g, '\\$&') // escape regex special chars
      .replace(/\*\*/g, '###DOUBLESTAR###')
      .replace(/\*/g, '[^/]*')
      .replace(/###DOUBLESTAR###/g, '.*')

    const regex = new RegExp(`(^|/)${regexStr}($|/)`)
    return regex.test(normalised)
  })
}
