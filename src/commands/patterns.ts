// `leakscan patterns` — lists all built-in detection patterns.
// Shows pattern ID, name, severity, and entropy threshold in a table.

import chalk from 'chalk'
import { PATTERNS } from '../patterns'

// ─── Severity colors (inline for the table) ───────────────────────────────────

function colorSeverity(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return chalk.bgRed.white.bold(` ${sev} `)
    case 'HIGH':     return chalk.red.bold(sev)
    case 'MEDIUM':   return chalk.yellow.bold(sev)
    default:         return sev
  }
}

// ─── Command handler ──────────────────────────────────────────────────────────

export function patternsCommand(): void {
  console.log()
  console.log(chalk.bold('leakscan patterns') + chalk.gray(' — Built-in detection rules'))
  console.log(chalk.gray(`${PATTERNS.length} patterns loaded`))
  console.log(chalk.gray('━'.repeat(64)))
  console.log()

  // Column headers
  console.log(
    chalk.gray(
      `${'ID'.padEnd(26)} ${'SEVERITY'.padEnd(12)} ${'ENTROPY'.padEnd(10)} NAME`
    )
  )
  console.log(chalk.gray('─'.repeat(64)))

  for (const p of PATTERNS) {
    const entropyLabel = p.entropy === 0 ? chalk.gray('always') : p.entropy.toFixed(1)
    const idCol = chalk.cyan(p.id.padEnd(26))
    const sevCol = colorSeverity(p.severity).padEnd(p.severity === 'CRITICAL' ? 21 : 20)

    console.log(`${idCol} ${sevCol} ${String(entropyLabel).padEnd(10)} ${p.name}`)
  }

  console.log()
  console.log(
    chalk.gray(
      'Entropy: minimum Shannon entropy required to flag a match (0 = always flag).'
    )
  )
  console.log(
    chalk.gray(
      'Use .leakscanignore with pattern:<id> to suppress a pattern globally.'
    )
  )
  console.log()
}
