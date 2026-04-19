// Shared TypeScript interfaces for leakscan

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM'
export type OutputFormat = 'terminal' | 'json' | 'sarif'
export type FindingType = 'filesystem' | 'git-history'

// ─── Pattern ─────────────────────────────────────────────────────────────────

export interface SecretPattern {
  id: string
  name: string
  severity: Severity
  regex: RegExp
  entropy: number // minimum Shannon entropy threshold (0 = always flag)
}

// ─── Finding ─────────────────────────────────────────────────────────────────

export interface Finding {
  type: FindingType
  patternId: string
  patternName: string
  severity: Severity
  secret: string      // ALWAYS redacted — never the raw value
  file: string
  line?: number       // filesystem findings only
  commit?: string     // git-history findings only (short hash, 7 chars)
  commitDate?: string // git-history findings only
  note?: string       // e.g. "File not in .gitignore — risk of accidental commit"
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

export interface ScanOptions {
  path: string
  format: OutputFormat
  history: boolean  // whether to scan git history (default: false in W1)
  depth?: number    // max commits to scan (undefined = all)
}

export interface ScanResult {
  repoName: string
  filesScanned: number
  commitsChecked: number
  timeMs: number
  findings: Finding[]
}

// ─── Ignore rules ─────────────────────────────────────────────────────────────

export interface IgnoreRules {
  files: string[]    // glob patterns for ignored files/dirs
  patterns: string[] // pattern IDs to ignore globally
  findings: string[] // specific "commit:file" keys to ignore
}

// ─── Config ───────────────────────────────────────────────────────────────────

export interface LeakscanConfig {
  defaultFormat?: OutputFormat
  defaultDepth?: number
}
