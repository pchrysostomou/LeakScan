// JSON reporter — machine-readable output for tool integrations and scripts.
// The JSON schema mirrors ScanResult exactly, making it easy to pipe into jq, scripts, etc.
//
// Usage: leakscan scan --format json | jq '.findings[] | select(.severity == "CRITICAL")'

import type { ScanResult } from '../types'

/**
 * Formats a ScanResult as pretty-printed JSON and returns the string.
 * Caller is responsible for writing to stdout.
 */
export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2)
}
