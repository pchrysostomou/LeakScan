// Filesystem scanner — walks a directory tree and scans each text file
// against all secret patterns, applying entropy filtering and ignore rules.
//
// Skipped automatically:
//   - node_modules/, .git/, dist/, build/, .next/, coverage/
//   - Binary files (detected by null byte check on first 512 bytes)
//   - Files > 1MB (unlikely to be source files with secrets)
//   - Files matching .leakscanignore globs

import { readdirSync, readFileSync, statSync, existsSync } from 'fs'
import { join, relative, extname } from 'path'

import { PATTERNS } from '../patterns'
import { shannonEntropy } from './entropy'
import { redact } from './redact'
import { shouldIgnore } from '../config/ignoreParser'

import type { Finding, IgnoreRules } from '../types'

// ─── Constants ────────────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '.nuxt',
  'coverage',
  '.turbo',
  '.cache',
  '__pycache__',
  '.mypy_cache',
  'venv',
  '.venv',
])

const MAX_FILE_SIZE = 1_048_576 // 1MB

// Binary-like file extensions we skip entirely
const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg',
  '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm',
  '.mp4', '.mp3', '.wav', '.ogg', '.webm',
  '.ttf', '.woff', '.woff2', '.eot',
  '.lock',   // package-lock.json is fine, but yarn.lock / pnpm-lock.yaml are noisy
])

// ─── Main scanner ─────────────────────────────────────────────────────────────

export interface FileScanResult {
  findings: Finding[]
  filesScanned: number
}

/**
 * Recursively walks a directory and scans all text files for secrets.
 * Uses a mutable context object to avoid module-level shared state.
 */
export function scanFilesystem(
  repoPath: string,
  ignoreRules: IgnoreRules
): FileScanResult {
  // Load .gitignore file list to annotate untracked .env files
  const gitignorePath = join(repoPath, '.gitignore')
  const gitignoreContents = existsSync(gitignorePath)
    ? readFileSync(gitignorePath, 'utf-8')
    : ''

  // Use a context object — avoids module-level mutable state bugs
  const ctx: ScanContext = {
    findings: [],
    filesScanned: 0,
    ignoreRules,
    gitignoreContents,
    rootPath: repoPath,
  }

  walk(ctx, repoPath)

  return { findings: ctx.findings, filesScanned: ctx.filesScanned }
}

// ─── Internal types ────────────────────────────────────────────────────────────

interface ScanContext {
  findings: Finding[]
  filesScanned: number
  ignoreRules: IgnoreRules
  gitignoreContents: string
  rootPath: string
}

// ─── Walker ───────────────────────────────────────────────────────────────────

function walk(ctx: ScanContext, currentPath: string): void {
  let entries: string[]
  try {
    entries = readdirSync(currentPath)
  } catch {
    return // unreadable directory — skip silently
  }

  for (const entry of entries) {
    const fullPath = join(currentPath, entry)
    const relPath = relative(ctx.rootPath, fullPath).replace(/\\/g, '/')

    let stat
    try {
      stat = statSync(fullPath)
    } catch {
      continue
    }

    if (stat.isDirectory()) {
      if (SKIP_DIRS.has(entry)) continue
      if (shouldIgnore(ctx.ignoreRules, relPath + '/', '', undefined)) continue
      walk(ctx, fullPath)
      continue
    }

    if (!stat.isFile()) continue
    if (stat.size > MAX_FILE_SIZE) continue
    if (SKIP_EXTENSIONS.has(extname(entry).toLowerCase())) continue
    if (shouldIgnore(ctx.ignoreRules, relPath, '', undefined)) continue

    // Read file and check for binary content
    let content: string
    try {
      const buffer = readFileSync(fullPath)
      // Binary check: look for null bytes in first 512 bytes
      const probe = buffer.subarray(0, 512)
      if (probe.includes(0)) continue // binary file
      content = buffer.toString('utf-8')
    } catch {
      continue // unreadable file — skip silently
    }

    ctx.filesScanned++

    const lines = content.split('\n')
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx]

      for (const pattern of PATTERNS) {
        // Skip if this pattern is globally ignored
        if (shouldIgnore(ctx.ignoreRules, relPath, pattern.id, undefined)) continue

        // Reset regex state (required when reusing /g regexes)
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags)

        for (const match of line.matchAll(regex)) {
          // For password patterns with a capture group, use group 1; otherwise match[0]
          const rawSecret = match[1] ?? match[0]

          // Entropy gate — filter out placeholder strings
          if (pattern.entropy > 0 && shannonEntropy(rawSecret) < pattern.entropy) {
            continue
          }

          const redacted = redact(rawSecret)

          // Check if this .env file is not in .gitignore (extra risk note)
          let note: string | undefined
          if (entry.startsWith('.env') && !isInGitignore(ctx.gitignoreContents, entry)) {
            note = `File not in .gitignore — risk of accidental commit`
          }

          ctx.findings.push({
            type: 'filesystem',
            patternId: pattern.id,
            patternName: pattern.name,
            severity: pattern.severity,
            secret: redacted,
            file: relPath,
            line: lineIdx + 1,
            note,
          })
        }
      }
    }
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Checks if a filename appears in the .gitignore contents */
function isInGitignore(gitignoreContents: string, filename: string): boolean {
  return gitignoreContents
    .split('\n')
    .some((line) => line.trim() === filename || line.trim() === `/${filename}`)
}
