import { Command } from 'commander'
import chalk from 'chalk'
import { scanCommand } from './commands/scan'
import { fixCommand } from './commands/fix'
import { patternsCommand } from './commands/patterns'

const program = new Command()

// ─── Program metadata ─────────────────────────────────────────────────────────

program
  .name('leakscan')
  .description(
    chalk.red.bold('leakscan') +
      ' — Scan Git repos for exposed secrets\n' +
      chalk.gray(
        '  API keys · Passwords · Tokens · Git history'
      )
  )
  .version('0.1.0', '-v, --version', 'Output the current version')

// ─── scan ─────────────────────────────────────────────────────────────────────

program
  .command('scan')
  .description(
    'Scan a repository for exposed secrets in the filesystem (and optionally git history)'
  )
  .option(
    '-p, --path <dir>',
    'Path to the git repository (default: current directory)'
  )
  .option(
    '-f, --format <format>',
    'Output format: terminal | json | sarif',
    'terminal'
  )
  .option(
    '--no-history',
    'Skip git history scan — filesystem only'
  )
  .option(
    '--depth <n>',
    'Limit git history scan to the last N commits'
  )
  .action(scanCommand)

// ─── fix ─────────────────────────────────────────────────────────────────────

program
  .command('fix')
  .description(
    'Show remediation steps for found secrets — read-only, does not modify files'
  )
  .action(() => fixCommand())

// ─── patterns ─────────────────────────────────────────────────────────────────

program
  .command('patterns')
  .description('List all built-in secret detection patterns')
  .action(patternsCommand)

// ─── Global error handling ────────────────────────────────────────────────────

program.on('command:*', (operands: string[]) => {
  console.error(chalk.red(`\n  Unknown command: ${operands[0]}`))
  console.error(chalk.gray('  Run leakscan --help to see available commands\n'))
  process.exit(1)
})

program.parse(process.argv)

// Show help if no command given
if (process.argv.length < 3) {
  program.help()
}
