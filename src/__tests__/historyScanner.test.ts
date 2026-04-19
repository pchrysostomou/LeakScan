// Tests for the git history scanner's diff parser.
//
// We test the internal logic using exported helpers.
// Full integration testing (against a real git repo) happens in CI.

import { describe, it, expect } from 'vitest'
import { formatCommitDateForTest, parseDiffHunksForTest } from '../git/historyScanner'

// ─── parseDiffHunks ───────────────────────────────────────────────────────────

describe('parseDiffHunks (internal diff parser)', () => {
  const sampleDiff = `diff --git a/src/config.ts b/src/config.ts
index abc123..def456 100644
--- a/src/config.ts
+++ b/src/config.ts
@@ -1,3 +1,5 @@
 const x = 1
+const API_KEY = "gsk_AbCdEfGh1234567890IjKlMnOpQrStUvWxYz12345678"
+const DB_URL = "postgres://user:pass@host/db"
-const old = "removed"
 const y = 2
diff --git a/README.md b/README.md
index 111111..222222 100644
--- a/README.md
+++ b/README.md
@@ -10,0 +11 @@
+GROQ_API_KEY=gsk_AbCdEfGh1234567890IjKlMnOpQrStUvWxYzABCDEFGH
`

  it('extracts file paths correctly', () => {
    const hunks = parseDiffHunksForTest(sampleDiff)
    expect(hunks.map(h => h.filePath)).toEqual(['src/config.ts', 'README.md'])
  })

  it('only captures added lines (+ prefix), not removed or context lines', () => {
    const hunks = parseDiffHunksForTest(sampleDiff)
    const configHunk = hunks.find(h => h.filePath === 'src/config.ts')!
    expect(configHunk.addedLines).toHaveLength(2)
    expect(configHunk.addedLines[0].lineContent).toContain('API_KEY')
    expect(configHunk.addedLines[1].lineContent).toContain('DB_URL')
    // "removed" line should NOT appear
    expect(configHunk.addedLines.some(l => l.lineContent.includes('removed'))).toBe(false)
  })

  it('strips the leading + from added lines', () => {
    const hunks = parseDiffHunksForTest(sampleDiff)
    const readmeHunk = hunks.find(h => h.filePath === 'README.md')!
    expect(readmeHunk.addedLines[0].lineContent.startsWith('+')).toBe(false)
  })

  it('does not include +++ file headers as added lines', () => {
    const hunks = parseDiffHunksForTest(sampleDiff)
    for (const hunk of hunks) {
      for (const line of hunk.addedLines) {
        expect(line.lineContent).not.toMatch(/^\+\+\+/)
      }
    }
  })

  it('handles empty diff gracefully', () => {
    expect(parseDiffHunksForTest('')).toHaveLength(0)
  })

  it('skips binary file entries', () => {
    const binaryDiff = `diff --git a/image.png b/image.png
Binary files a/image.png and b/image.png differ
diff --git a/src/index.ts b/src/index.ts
--- a/src/index.ts
+++ b/src/index.ts
@@ -0,0 +1 @@
+const x = 1
`
    const hunks = parseDiffHunksForTest(binaryDiff)
    // image.png should be skipped entirely
    expect(hunks.find(h => h.filePath === 'image.png')).toBeUndefined()
    // src/index.ts should still be parsed
    expect(hunks.find(h => h.filePath === 'src/index.ts')).toBeDefined()
  })
})

// ─── formatCommitDate ─────────────────────────────────────────────────────────

describe('formatCommitDate', () => {
  it('returns "today" for very recent commits', () => {
    const now = new Date().toISOString()
    expect(formatCommitDateForTest(now)).toBe('today')
  })

  it('returns "1 day ago" for yesterday', () => {
    const yesterday = new Date(Date.now() - 86_400_000).toISOString()
    expect(formatCommitDateForTest(yesterday)).toBe('1 day ago')
  })

  it('returns "N days ago" for recent days', () => {
    const fiveDaysAgo = new Date(Date.now() - 5 * 86_400_000).toISOString()
    expect(formatCommitDateForTest(fiveDaysAgo)).toBe('5 days ago')
  })

  it('returns "1 week ago" for 7-13 days', () => {
    const eightDaysAgo = new Date(Date.now() - 8 * 86_400_000).toISOString()
    expect(formatCommitDateForTest(eightDaysAgo)).toBe('1 week ago')
  })

  it('returns "N weeks ago" for 14-29 days', () => {
    const threeWeeksAgo = new Date(Date.now() - 21 * 86_400_000).toISOString()
    expect(formatCommitDateForTest(threeWeeksAgo)).toBe('3 weeks ago')
  })

  it('returns "1 month ago" for 30-59 days', () => {
    const fortyDaysAgo = new Date(Date.now() - 40 * 86_400_000).toISOString()
    expect(formatCommitDateForTest(fortyDaysAgo)).toBe('1 month ago')
  })

  it('returns fallback for invalid dates', () => {
    const result = formatCommitDateForTest('not-a-date')
    expect(result).toBe('not-a-date') // falls back to original string
  })
})
