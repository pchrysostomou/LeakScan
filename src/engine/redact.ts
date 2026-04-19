// Redaction — we NEVER display the full secret in terminal output or logs.
// Showing a full secret in CI output would be a leak in itself.
//
// Format:  <first 8 chars>••••••••<last 4 chars>
// Example: gsk_AbCdEfGh••••••••IjKl

const MASK = '••••••••'
const HEAD_LEN = 8
const TAIL_LEN = 4
const MIN_REVEAL = HEAD_LEN + TAIL_LEN + 1 // must be longer than this to partially reveal

/**
 * Redacts a secret string, showing only the first 8 and last 4 characters.
 * Secrets shorteer than the reveal threshold are fully masked.
 */
export function redact(secret: string): string {
  if (secret.length <= MIN_REVEAL) {
    // Too short to safely reveal any part — mask entirely
    return MASK
  }

  const head = secret.slice(0, HEAD_LEN)
  const tail = secret.slice(-TAIL_LEN)
  return `${head}${MASK}${tail}`
}
