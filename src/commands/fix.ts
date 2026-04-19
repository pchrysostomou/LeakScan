// `leakscan fix` command — read-only remediation guidance.
// Prints step-by-step instructions for each finding type.
// Does NOT modify any files — safe to run at any time.

import chalk from 'chalk'
import type { Finding } from '../types'

// ─── Provider rotation links ──────────────────────────────────────────────────

const ROTATION_LINKS: Record<string, string> = {
  'groq-api-key':       'https://console.groq.com/keys',
  'openai-api-key':     'https://platform.openai.com/api-keys',
  'supabase-anon-key':  'https://app.supabase.com/project/_/settings/api',
  'github-pat':         'https://github.com/settings/tokens',
  'github-fine-grained':'https://github.com/settings/tokens?type=beta',
  'aws-access-key':     'https://console.aws.amazon.com/iam/home#/security_credentials',
  'stripe-secret-key':  'https://dashboard.stripe.com/apikeys',
  'private-key':        '(generate a new key pair and update all systems using the old key)',
  'generic-password':   '(update the password in your credentials manager)',
  'connection-string':  '(rotate the database password and update all connection strings)',
}

// ─── Command handler ──────────────────────────────────────────────────────────

export function fixCommand(findings?: Finding[]): void {
  console.log()
  console.log(chalk.bold('leakscan fix') + chalk.gray(' — Remediation Guide'))
  console.log(chalk.gray('━'.repeat(48)))
  console.log()

  if (!findings || findings.length === 0) {
    console.log(chalk.green('✔'), 'No findings to remediate.')
    console.log(chalk.gray('  Run'), chalk.cyan('leakscan scan'), chalk.gray('first.'))
    console.log()
    return
  }

  findings.forEach((f, i) => {
    console.log(
      chalk.bold(`${i + 1}. ${f.patternName}`),
      chalk.gray(`(${f.severity})`)
    )

    if (f.type === 'filesystem') {
      console.log(chalk.gray(`   File: ${f.file}${f.line ? ` line ${f.line}` : ''}`))
      console.log()
      console.log(chalk.yellow('   Steps:'))
      console.log(`   ${chalk.gray('1.')} Rotate the key immediately (link below)`)
      console.log(`   ${chalk.gray('2.')} Remove it from ${chalk.cyan(f.file)}`)
      console.log(`   ${chalk.gray('3.')} Add the variable to ${chalk.cyan('.env')} and ${chalk.cyan('.gitignore')}`)
      console.log(`   ${chalk.gray('4.')} Use ${chalk.cyan('process.env.VAR_NAME')} in code — never hardcode`)
    } else {
      console.log(chalk.gray(`   Commit: ${f.commit}  File: ${f.file}`))
      console.log()
      console.log(chalk.yellow('   Steps:'))
      console.log(`   ${chalk.gray('1.')} Rotate the key immediately (link below)`)
      console.log(`   ${chalk.gray('2.')} ${chalk.bold('Remove from git history')} (the key is still in every clone):`)
      console.log()
      console.log(chalk.gray('      Option A — git-filter-repo (recommended):'))
      console.log(
        chalk.cyan(
          `      pip install git-filter-repo\n      git filter-repo --path ${f.file} --invert-paths`
        )
      )
      console.log()
      console.log(chalk.gray('      Option B — BFG Repo Cleaner:'))
      console.log(
        chalk.cyan(
          `      java -jar bfg.jar --delete-files ${f.file}\n      git reflog expire --expire=now --all && git gc --prune=now --aggressive`
        )
      )
      console.log()
      console.log(
        `   ${chalk.gray('3.')} Force-push all branches: ${chalk.cyan('git push --force --all')}`
      )
      console.log(
        `   ${chalk.gray('4.')} Notify all collaborators to re-clone — their local copies still have the secret`
      )
    }

    const link = ROTATION_LINKS[f.patternId]
    if (link) {
      console.log()
      console.log(`   ${chalk.gray('Rotate here:')} ${chalk.blue(link)}`)
    }

    console.log()
    if (i < findings.length - 1) {
      console.log(chalk.gray('─'.repeat(48)))
      console.log()
    }
  })

  console.log(chalk.gray('━'.repeat(48)))
  console.log(
    chalk.bold('⚠'),
    chalk.yellow(
      'Rotating the key is step 1. Cleaning git history is step 2. Do both.'
    )
  )
  console.log()
}
