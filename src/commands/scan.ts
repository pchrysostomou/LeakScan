// `leakscan scan` command handler
//
// Usage:
//   leakscan scan
//   leakscan scan --path C:\my-repo
//   leakscan scan --path C:\my-repo --format json
//   leakscan scan --path C:\my-repo --format sarif
//   leakscan scan --path C:\my-repo --no-history   (skip git history, filesystem only)
//   leakscan scan --path C:\my-repo --depth 100    (limit commits scanned)

import { resolve, basename } from 'path'
import { existsSync } from 'fs'
import chalk from 'chalk'
import ora from 'ora'

import { scanFilesystem } from '../engine/fileScanner'
import { scanGitHistory } from '../git/historyScanner'
import { loadIgnoreRules } from '../config/ignoreParser'
import { printReport } from '../reporter/terminal'
import { formatJson } from '../reporter/json'
import { formatSarif } from '../reporter/sarif'

import type { ScanOptions, ScanResult } from '../types'

// ─── Command handler ──────────────────────────────────────────────────────────

export async function scanCommand(opts: {
  path?: string
  format?: string
  history?: boolean
  depth?: string
}): Promise<void> {
  const repoPath = resolve(opts.path ?? process.cwd())

  // Validate path
  if (!existsSync(repoPath)) {
    console.error(chalk.red(`\n  ✖ Path not found: ${repoPath}\n`))
    process.exit(1)
  }

  const options: ScanOptions = {
    path: repoPath,
    format: (opts.format as ScanOptions['format']) ?? 'terminal',
    // With Commander's --no-history pattern:
    //   opts.history = true  (default — scan history)
    //   opts.history = false (when --no-history flag passed)
    history: opts.history ?? true,
    depth: opts.depth ? parseInt(opts.depth, 10) : undefined,
  }

  // Load ignore rules from .leakscanignore
  const ignoreRules = loadIgnoreRules(repoPath)

  const repoName = basename(repoPath)
  const isTerminal = options.format === 'terminal'

  const spinner = ora({
    text: chalk.gray(`Scanning ${chalk.cyan(repoName)}...`),
    spinner: 'dots',
  })

  if (isTerminal) spinner.start()

  const startTime = Date.now()
  const findings: ScanResult['findings'] = []
  let filesScanned = 0
  let commitsChecked = 0

  try {
    // ── Phase 1: Filesystem scan ─────────────────────────────────────────────
    if (isTerminal) {
      spinner.text = chalk.gray(`Scanning files in ${chalk.cyan(repoName)}...`)
    }

    const fsResult = scanFilesystem(repoPath, ignoreRules)
    findings.push(...fsResult.findings)
    filesScanned = fsResult.filesScanned

    // ── Phase 2: Git history scan ────────────────────────────────────────────
    if (options.history) {
      const depthLabel = options.depth ? ` (last ${options.depth} commits)` : ''
      if (isTerminal) {
        spinner.text = chalk.gray(
          `Scanning git history${depthLabel} in ${chalk.cyan(repoName)}...`
        )
      }

      const histResult = await scanGitHistory(repoPath, ignoreRules, options.depth)
      findings.push(...histResult.findings)
      commitsChecked = histResult.commitsChecked
    }

    if (isTerminal) spinner.stop()
  } catch (err) {
    if (isTerminal) spinner.stop()
    const msg = err instanceof Error ? err.message : String(err)
    console.error(chalk.red(`\n  ✖ Scan failed: ${msg}\n`))
    process.exit(1)
  }

  const timeMs = Date.now() - startTime

  const result: ScanResult = {
    repoName,
    filesScanned,
    commitsChecked,
    timeMs,
    findings,
  }

  // ── Output ──────────────────────────────────────────────────────────────────
  switch (options.format) {
    case 'terminal':
      printReport(result)
      break

    case 'json':
      process.stdout.write(formatJson(result) + '\n')
      break

    case 'sarif':
      process.stdout.write(formatSarif(result) + '\n')
      break
  }

  // Exit with code 1 if findings found — important for CI/CD integration
  if (findings.length > 0) {
    process.exit(1)
  }
}
