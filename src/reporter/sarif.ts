// SARIF 2.1.0 reporter — Static Analysis Results Interchange Format.
//
// SARIF is the standard format used by GitHub Code Scanning.
// When this file is uploaded via github/codeql-action/upload-sarif@v3,
// findings appear directly in the GitHub Security tab.
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// Schema: https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json

import type { Finding, ScanResult, SecretPattern } from '../types'
import { PATTERNS } from '../patterns'

// ─── SARIF type stubs (subset we need) ───────────────────────────────────────

interface SarifLog {
  $schema: string
  version: '2.1.0'
  runs: SarifRun[]
}

interface SarifRun {
  tool: {
    driver: {
      name: string
      version: string
      informationUri: string
      rules: SarifRule[]
    }
  }
  results: SarifResult[]
  artifacts?: SarifArtifact[]
}

interface SarifRule {
  id: string
  name: string
  shortDescription: { text: string }
  fullDescription: { text: string }
  defaultConfiguration: { level: 'error' | 'warning' | 'note' }
  properties: {
    tags: string[]
    security_severity: string // GitHub uses this for CVSS-style sorting
  }
}

interface SarifResult {
  ruleId: string
  level: 'error' | 'warning' | 'note'
  message: { text: string }
  locations: SarifLocation[]
  partialFingerprints?: Record<string, string>
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId?: string }
    region?: { startLine: number; startColumn?: number }
  }
  logicalLocations?: Array<{ name: string; kind: string }>
}

interface SarifArtifact {
  location: { uri: string; uriBaseId?: string }
}

// ─── Severity mapping ─────────────────────────────────────────────────────────

function severityToLevel(sev: Finding['severity']): 'error' | 'warning' | 'note' {
  switch (sev) {
    case 'CRITICAL': return 'error'
    case 'HIGH':     return 'warning'
    case 'MEDIUM':   return 'note'
  }
}

// GitHub Code Scanning uses numeric security severity for sorting
function severityToNumeric(sev: Finding['severity']): string {
  switch (sev) {
    case 'CRITICAL': return '9.0'
    case 'HIGH':     return '7.0'
    case 'MEDIUM':   return '5.0'
  }
}

// ─── Rule builder ─────────────────────────────────────────────────────────────

function buildRule(pattern: SecretPattern): SarifRule {
  return {
    id: pattern.id,
    name: pattern.name.replace(/\s+/g, ''), // CamelCase for SARIF rule names
    shortDescription: {
      text: `${pattern.name} exposed in source`,
    },
    fullDescription: {
      text: `A ${pattern.name} was found hardcoded in the repository. Exposed credentials should be rotated immediately and moved to environment variables or a secrets manager.`,
    },
    defaultConfiguration: {
      level: severityToLevel(pattern.severity),
    },
    properties: {
      tags: ['security', 'secret-detection', pattern.severity.toLowerCase()],
      security_severity: severityToNumeric(pattern.severity),
    },
  }
}

// ─── Result builder ───────────────────────────────────────────────────────────

function buildResult(finding: Finding): SarifResult {
  const level = severityToLevel(finding.severity)

  // Build location — git-history findings don't have a line number
  const region = finding.line !== undefined ? { startLine: finding.line } : undefined
  const uri = finding.file.replace(/\\/g, '/') // SARIF URIs use forward slashes

  const location: SarifLocation = {
    physicalLocation: {
      artifactLocation: {
        uri,
        uriBaseId: '%SRCROOT%', // relative to repo root
      },
      ...(region ? { region } : {}),
    },
  }

  // Add git history context as logical location
  if (finding.type === 'git-history' && finding.commit) {
    location.logicalLocations = [
      {
        name: `commit:${finding.commit}${finding.commitDate ? ` (${finding.commitDate})` : ''}`,
        kind: 'module',
      },
    ]
  }

  const messageText = finding.type === 'git-history'
    ? `${finding.patternName} found in git history (commit ${finding.commit ?? '?'}${finding.commitDate ? `, ${finding.commitDate}` : ''}). Match: ${finding.secret}`
    : `${finding.patternName} found in ${finding.file}${finding.line ? ` at line ${finding.line}` : ''}. Match: ${finding.secret}${finding.note ? `. Note: ${finding.note}` : ''}`

  return {
    ruleId: finding.patternId,
    level,
    message: { text: messageText },
    locations: [location],
    // Fingerprint helps GitHub deduplicate results across runs
    partialFingerprints: {
      'secretLocation/v1': `${finding.patternId}:${finding.file}:${finding.type === 'git-history' ? finding.commit ?? '' : String(finding.line ?? '')}`,
    },
  }
}

// ─── Main formatter ───────────────────────────────────────────────────────────

/**
 * Formats a ScanResult as a SARIF 2.1.0 JSON string.
 * Compatible with GitHub Code Scanning (upload via codeql-action/upload-sarif@v3).
 */
export function formatSarif(result: ScanResult): string {
  // Build rule set from all patterns (not just ones that fired — GitHub needs all rules declared)
  const rules = PATTERNS.map(buildRule)

  // Build results
  const results = result.findings.map(buildResult)

  // Collect unique artifact URIs (deduplicated)
  const artifactUris = [...new Set(result.findings.map(f => f.file.replace(/\\/g, '/')))]
  const artifacts: SarifArtifact[] = artifactUris.map(uri => ({
    location: { uri, uriBaseId: '%SRCROOT%' },
  }))

  const sarifLog: SarifLog = {
    $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'leakscan',
            version: '0.1.0',
            informationUri: 'https://github.com/pchrysostomou/LeakScan',
            rules,
          },
        },
        results,
        artifacts,
      },
    ],
  }

  return JSON.stringify(sarifLog, null, 2)
}
