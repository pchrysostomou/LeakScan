// Git history scanner — scans every commit's diff for secrets.
//
// Strategy:
//   1. git log --all --no-merges  → get list of all commits
//   2. Per commit: git show --unified=0 --no-color  → get the diff
//   3. Parse only lines starting with "+" (additions) — deletions can't leak
//   4. Extract file path from "@@" diff hunk headers
//   5. Apply patterns + entropy gate + redact
//   6. Deduplicate: same patternId+file across multiple commits → keep oldest
//   7. Respect --depth N to limit scan on large repos

import simpleGit from 'simple-git'
import { PATTERNS } from '../patterns'
import { shannonEntropy } from '../engine/entropy'
import { redact } from '../engine/redact'
import { shouldIgnore } from '../config/ignoreParser'
import type { Finding, IgnoreRules } from '../types'

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HistoryScanResult {
  findings: Finding[]
  commitsChecked: number
}

// ─── Main scanner ─────────────────────────────────────────────────────────────

/**
 * Scans all commits in a git repository for secret additions.
 *
 * @param repoPath    Absolute path to the git repository
 * @param ignoreRules Parsed .leakscanignore rules
 * @param depth       Optional — limit to the last N commits (undefined = all)
 */
export async function scanGitHistory(
  repoPath: string,
  ignoreRules: IgnoreRules,
  depth?: number
): Promise<HistoryScanResult> {
  const git = simpleGit(repoPath)

  // Verify this is actually a git repo
  const isRepo = await git.checkIsRepo()
  if (!isRepo) {
    return { findings: [], commitsChecked: 0 }
  }

  // Get commit list — oldest first so dedup keeps the first occurrence
  const logArgs: string[] = ['--all', '--no-merges', '--reverse']
  if (depth !== undefined && depth > 0) {
    logArgs.push(`-${depth}`)
  }

  const log = await git.log(logArgs)
  const commits = log.all

  // Deduplicate key: patternId + file path → only report the first commit
  // that introduced a given secret pattern into a given file
  const seen = new Set<string>()
  const findings: Finding[] = []

  for (const commit of commits) {
    // Get the full diff for this commit (additions only, 0 context lines)
    let diff: string
    try {
      diff = await git.show([
        commit.hash,
        '--unified=0',
        '--no-color',
        '--diff-filter=AM', // only Added and Modified files (not renames/deletes)
      ])
    } catch {
      continue // some commits (e.g. initial empty commit) can't be shown — skip
    }

    // Parse the diff into hunks, each associated with a file path
    const hunks = parseDiffHunks(diff)

    for (const { filePath, addedLines } of hunks) {
      // Skip files that match ignore globs
      if (shouldIgnore(ignoreRules, filePath, '', undefined)) continue

      for (const { lineContent } of addedLines) {
        for (const pattern of PATTERNS) {
          // Skip globally ignored patterns
          if (ignoreRules.patterns.includes(pattern.id)) continue

          // Build a fresh regex instance (avoids lastIndex state issues with /g)
          const regex = new RegExp(pattern.regex.source, pattern.regex.flags)

          for (const match of lineContent.matchAll(regex)) {
            const rawSecret = match[1] ?? match[0]

            // Entropy gate
            if (pattern.entropy > 0 && shannonEntropy(rawSecret) < pattern.entropy) {
              continue
            }

            const shortHash = commit.hash.slice(0, 7)

            // Check specific finding suppression (finding:hash:file)
            if (shouldIgnore(ignoreRules, filePath, pattern.id, shortHash)) continue

            // Deduplication — same pattern in same file → only report first commit
            const dedupKey = `${pattern.id}::${filePath}`
            if (seen.has(dedupKey)) continue
            seen.add(dedupKey)

            // Format date as relative label
            const commitDate = formatCommitDate(commit.date)

            findings.push({
              type: 'git-history',
              patternId: pattern.id,
              patternName: pattern.name,
              severity: pattern.severity,
              secret: redact(rawSecret),
              file: filePath,
              commit: shortHash,
              commitDate,
            })
          }
        }
      }
    }
  }

  return {
    findings,
    commitsChecked: commits.length,
  }
}

// ─── Diff parser ──────────────────────────────────────────────────────────────

interface DiffHunk {
  filePath: string
  addedLines: Array<{ lineContent: string }>
}

/**
 * Parses a git diff output into file hunks with their added lines.
 *
 * Diff format reference:
 *   diff --git a/src/file.ts b/src/file.ts
 *   --- a/src/file.ts
 *   +++ b/src/file.ts
 *   @@ -0,0 +1,5 @@
 *   +added line 1
 *   +added line 2
 *    context line (not prefixed by +)
 *   -removed line
 */
function parseDiffHunks(diff: string): DiffHunk[] {
  const hunks: DiffHunk[] = []
  let currentFile: string | null = null
  let currentAddedLines: Array<{ lineContent: string }> = []

  const lines = diff.split('\n')

  for (const line of lines) {
    // New file in diff: "diff --git a/path b/path"
    if (line.startsWith('diff --git ')) {
      // Save previous hunk if it has content
      if (currentFile !== null && currentAddedLines.length > 0) {
        hunks.push({ filePath: currentFile, addedLines: currentAddedLines })
      }

      // Extract the "b/" path (the new version)
      const match = line.match(/diff --git a\/.+ b\/(.+)/)
      currentFile = match ? match[1] : null
      currentAddedLines = []
      continue
    }

    // Binary file detection — skip binary diffs
    if (line.startsWith('Binary files')) {
      currentFile = null
      currentAddedLines = []
      continue
    }

    // Added line: starts with "+" but not "+++ b/path" (file header)
    if (line.startsWith('+') && !line.startsWith('+++')) {
      if (currentFile !== null) {
        currentAddedLines.push({ lineContent: line.slice(1) }) // strip the leading "+"
      }
    }
  }

  // Push the last file's hunk
  if (currentFile !== null && currentAddedLines.length > 0) {
    hunks.push({ filePath: currentFile, addedLines: currentAddedLines })
  }

  return hunks
}

// ─── Date formatter ──────────────────────────────────────────────────────────

/**
 * Formats a commit date string into a human-readable relative label.
 * Falls back to a short ISO date if parsing fails.
 */
function formatCommitDate(dateStr: string): string {
  let date: Date
  try {
    date = new Date(dateStr)
    if (isNaN(date.getTime())) return dateStr
  } catch {
    return dateStr
  }

  const now = Date.now()
  const diffMs = now - date.getTime()
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))

  if (diffDays === 0) return 'today'
  if (diffDays === 1) return '1 day ago'
  if (diffDays < 7) return `${diffDays} days ago`
  if (diffDays < 14) return '1 week ago'
  if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`
  if (diffDays < 60) return '1 month ago'
  if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`
  return `${Math.floor(diffDays / 365)} year${Math.floor(diffDays / 365) > 1 ? 's' : ''} ago`
}

// ─── Test exports (internal helpers exposed for unit tests) ───────────────────
// These are not part of the public API — only used in __tests__/

export const parseDiffHunksForTest = parseDiffHunks
export const formatCommitDateForTest = formatCommitDate
