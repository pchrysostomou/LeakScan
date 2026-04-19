// Terminal reporter — outputs findings in a formatted, color-coded terminal view.
// Uses chalk@4 (CJS) for colors, same as GitAI.

import chalk from 'chalk'
import type { Finding, ScanResult } from '../types'

// ─── Severity colors ──────────────────────────────────────────────────────────

function severityBadge(severity: Finding['severity']): string {
  switch (severity) {
    case 'CRITICAL':
      return chalk.bgRed.white.bold(` ${severity} `)
    case 'HIGH':
      return chalk.red.bold(severity)
    case 'MEDIUM':
      return chalk.yellow.bold(severity)
  }
}

function severityLine(severity: Finding['severity'], text: string): string {
  switch (severity) {
    case 'CRITICAL':
      return chalk.red(text)
    case 'HIGH':
      return chalk.red(text)
    case 'MEDIUM':
      return chalk.yellow(text)
  }
}

// ─── Report ───────────────────────────────────────────────────────────────────

const DIVIDER = chalk.gray('━'.repeat(48))

/**
 * Prints a full scan report to stdout.
 */
export function printReport(result: ScanResult): void {
  // ── Summary header ──────────────────────────────────────────────────────────
  console.log()
  console.log(
    chalk.bold('Scanning repository:'),
    chalk.cyan(result.repoName)
  )

  const timeLabel =
    result.timeMs < 1000
      ? `${result.timeMs}ms`
      : `${(result.timeMs / 1000).toFixed(1)}s`

  const historyLabel =
    result.commitsChecked > 0
      ? `  Commits checked: ${chalk.white(result.commitsChecked)}`
      : ''

  console.log(
    chalk.gray(
      `Files scanned: ${result.filesScanned}${historyLabel}  Time: ${timeLabel}`
    )
  )
  console.log(DIVIDER)

  if (result.findings.length === 0) {
    console.log()
    console.log(chalk.green('✔'), chalk.bold('No secrets found.'))
    console.log(chalk.gray('  Repository looks clean.'))
    console.log()
    return
  }

  // ── Findings ────────────────────────────────────────────────────────────────
  console.log()

  for (const f of result.findings) {
    // Badge + pattern name
    console.log(`${severityBadge(f.severity)}  ${chalk.bold(f.patternName)}`)

    if (f.type === 'filesystem') {
      // File + line
      const location =
        f.line !== undefined
          ? `${chalk.cyan(f.file)} ${chalk.gray(`(line ${f.line})`)}`
          : chalk.cyan(f.file)
      console.log(`  ${chalk.gray('File:')}    ${location}`)
    } else {
      // Commit details
      const dateLabel = f.commitDate ? chalk.gray(` (${f.commitDate})`) : ''
      console.log(
        `  ${chalk.gray('Commit:')}  ${chalk.yellow(f.commit ?? '?')}${dateLabel}`
      )
      console.log(`  ${chalk.gray('File:')}    ${chalk.cyan(f.file)}`)
    }

    // Redacted secret
    console.log(
      `  ${chalk.gray('Match:')}   ${severityLine(f.severity, f.secret)}`
    )

    // Optional note (e.g. "File not in .gitignore")
    if (f.note) {
      console.log(`  ${chalk.gray('Note:')}    ${chalk.yellow('⚠')} ${chalk.yellow(f.note)}`)
    }

    console.log()
  }

  // ── Footer ──────────────────────────────────────────────────────────────────
  console.log(DIVIDER)
  const count = result.findings.length
  const label = count === 1 ? 'secret' : 'secrets'

  // Group by severity for summary
  const critical = result.findings.filter((f) => f.severity === 'CRITICAL').length
  const high = result.findings.filter((f) => f.severity === 'HIGH').length
  const medium = result.findings.filter((f) => f.severity === 'MEDIUM').length

  const parts: string[] = []
  if (critical > 0) parts.push(chalk.red.bold(`${critical} CRITICAL`))
  if (high > 0) parts.push(chalk.red(`${high} HIGH`))
  if (medium > 0) parts.push(chalk.yellow(`${medium} MEDIUM`))

  console.log(
    chalk.bold(`${count} ${label} found.`),
    parts.length > 0 ? `(${parts.join(', ')})` : '',
  )
  console.log(
    chalk.gray(`  Run ${chalk.cyan('leakscan fix')} for remediation steps.`)
  )
  console.log()
}
