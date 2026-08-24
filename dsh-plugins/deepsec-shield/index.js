import { runCli, parseJsonOutput } from './lib/cli.js'

// `@deepseek-ai/dsh-tools` ships with every dsh profile; fall back to a
// passthrough so the plugin still loads under older/preview loaders.
let defineTool = (spec) => spec
try {
  const mod = await import('@deepseek-ai/dsh-tools')
  if (typeof mod.defineTool === 'function') defineTool = mod.defineTool
} catch {
  /* register raw tool specs instead */
}

let z = null
try {
  z = (await import('@deepseek-ai/schemastery')).default
} catch {
  /* plain descriptor objects below already work as a schema stand-in */
}

export const name = 'deepsec-shield'
export const inject = ['tools']

const configFields = {
  command: str('DeepSec CLI invocation. Use "deepsec" when installed on PATH, or a Python form such as "py -3 -m deepsec".', 'deepsec'),
  timeoutMs: num('Per-command timeout in milliseconds (0 disables). L3 scans of large trees can take minutes.', 600000),
  maxFindings: num('Maximum findings returned to the model per scan; extras are counted in the summary only.', 50),
  maxOutputChars: num('Cap on captured CLI stdout/stderr per run, in characters.', 40000),
}

export const Config = z ? z.object(configFields) : { type: 'object', properties: configFields }

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export function apply(ctx, config = {}) {
  const opts = {
    command: config.command || 'deepsec',
    timeoutMs: numberOr(config.timeoutMs, 600000),
    maxFindings: Math.max(1, numberOr(config.maxFindings, 50)),
    maxOutputChars: Math.max(1000, numberOr(config.maxOutputChars, 40000)),
  }

  const disposers = [
    ctx.tools.register(defineTool(scanTool(opts))),
    ctx.tools.register(defineTool(agentAuditTool(opts))),
    ctx.tools.register(defineTool(supplyChainTool(opts))),
    ctx.tools.register(defineTool(reportTool(opts))),
  ].filter(Boolean)

  return () => {
    for (const dispose of disposers) dispose()
  }
}

function scanTool(opts) {
  return {
    name: 'deepsec_scan',
    description:
      'Run a DeepSec Shield security scan over a source file or directory (L1 pattern/secret/AI-mistake detection, ' +
      'L2 Tree-sitter AST analysis for injection/XSS/SSRF/path traversal, optional L3 semantic review). ' +
      'Returns a severity summary plus the top findings with rule, location and suggested fix. ' +
      'L1/L2 run fully locally; pass remoteL3=true only when sending source to the configured LLM is acceptable.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute or workspace-relative file/directory to scan.' },
      layers: { type: 'string', description: 'Comma-separated layers: "all" (default, L3 stays local), "l1", "l2", "l3", or a combination such as "l1,l2". Explicit l3 enables remote LLM review when a provider key is configured.' },
      includeTests: { type: 'boolean', description: 'Also scan test, fixture and example directories (skipped by default).' },
      remoteL3: { type: 'boolean', description: 'Explicitly opt in to sending source code to the configured LLM provider for L3 review.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: renderScan(value) }],
    },
    async execute(args, exec) {
      const cliArgs = ['shield', 'scan', args.path]
      if (args.layers && args.layers !== 'all') cliArgs.push('--layer', args.layers)
      if (args.includeTests) cliArgs.push('--include-tests')
      if (args.remoteL3) cliArgs.push('--remote-l3')
      cliArgs.push('--format', 'json', '--output', '-')

      const res = await runCli({ ...opts, signal: exec?.signal }, cliArgs, [0, 2])
      const failure = asFailure(res)
      if (failure) return failure

      const parsed = parseJsonOutput(res.stdout)
      if (!parsed || typeof parsed !== 'object') {
        return {
          ok: false,
          error: 'DeepSec produced unparseable JSON output.',
          exitCode: res.code,
          stdout: tail(res.stdout, 2000),
          stderr: tail(res.stderr, 2000),
        }
      }

      const findings = Array.isArray(parsed.findings) ? parsed.findings : []
      const active = findings.filter((item) => !item.dismissed)
      const summary = summarize(active, opts.maxFindings)
      return {
        ok: true,
        exitCode: res.code,
        hasActiveHighOrCritical: res.code === 2,
        summary: {
          ...summary.meta,
          filesScanned: parsed.filesScanned ?? null,
          elapsedMs: parsed.elapsedMs ?? null,
          layers: parsed.layers ?? [],
          totalFindings: findings.length,
          activeFindings: active.length,
          dismissedFindings: findings.length - active.length,
          bySeverity: summary.bySeverity,
        },
        findings: summary.findings,
        findingsTruncated: summary.truncated,
      }
    },
  }
}

function agentAuditTool(opts) {
  return {
    name: 'deepsec_agent_audit',
    description:
      'Audit an AI-agent configuration/source tree for prompt injection, data exfiltration and tool-abuse risks ' +
      'using DeepSec Shield agent-security rules. Read-only analysis; returns findings with the same shape as deepsec_scan.',
    parameters: {
      path: { type: 'string', required: true, description: 'Agent source or configuration path to audit.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: renderScan(value) }],
    },
    async execute(args, exec) {
      const cliArgs = ['shield', 'agent-audit', args.path, '--format', 'json', '--output', '-']
      const res = await runCli({ ...opts, signal: exec?.signal }, cliArgs, [0, 2])
      const failure = asFailure(res)
      if (failure) return failure

      const parsed = parseJsonOutput(res.stdout)
      if (!parsed || typeof parsed !== 'object') {
        return { ok: false, error: 'DeepSec produced unparseable JSON output.', exitCode: res.code, stderr: tail(res.stderr, 2000) }
      }
      const findings = Array.isArray(parsed.findings) ? parsed.findings : []
      const active = findings.filter((item) => !item.dismissed)
      const summary = summarize(active, opts.maxFindings)
      return {
        ok: true,
        exitCode: res.code,
        hasActiveHighOrCritical: res.code === 2,
        summary: {
          ...summary.meta,
          totalFindings: findings.length,
          activeFindings: active.length,
          bySeverity: summary.bySeverity,
        },
        findings: summary.findings,
        findingsTruncated: summary.truncated,
      }
    },
  }
}

function supplyChainTool(opts) {
  return {
    name: 'deepsec_supply_chain',
    description:
      'Check dependency manifests (package.json / requirements.txt) for typosquatting and dependency-confusion risks ' +
      'via DeepSec Shield supply-chain analysis. Declare internal package names as privatePackages so public-registry ' +
      'shadowing of them is reported.',
    parameters: {
      path: { type: 'string', description: 'Directory, package.json, or requirements.txt to check. Defaults to ".".' },
      privatePackages: { type: 'array', items: { type: 'string' }, description: 'Private/internal dependency names that must never resolve from a public registry.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: renderScan(value) }],
    },
    async execute(args, exec) {
      const cliArgs = ['shield', 'supply-chain', 'check', args.path || '.']
      for (const pkg of args.privatePackages || []) cliArgs.push('--private-package', String(pkg))
      cliArgs.push('--format', 'json', '--output', '-')

      const res = await runCli({ ...opts, signal: exec?.signal }, cliArgs, [0, 2])
      const failure = asFailure(res)
      if (failure) return failure

      const parsed = parseJsonOutput(res.stdout)
      if (!parsed || typeof parsed !== 'object') {
        return { ok: false, error: 'DeepSec produced unparseable JSON output.', exitCode: res.code, stderr: tail(res.stderr, 2000) }
      }
      const findings = Array.isArray(parsed.findings) ? parsed.findings : []
      const active = findings.filter((item) => !item.dismissed)
      const summary = summarize(active, opts.maxFindings)
      return {
        ok: true,
        exitCode: res.code,
        hasActiveHighOrCritical: res.code === 2,
        summary: {
          ...summary.meta,
          filesScanned: parsed.filesScanned ?? null,
          totalFindings: findings.length,
          activeFindings: active.length,
          bySeverity: summary.bySeverity,
        },
        findings: summary.findings,
        findingsTruncated: summary.truncated,
      }
    },
  }
}

function reportTool(opts) {
  return {
    name: 'deepsec_report',
    description:
      'Render a saved DeepSec JSON scan result as markdown, html, sarif or text, optionally generating an ' +
      'interactive attack-chain visualization. Use after deepsec_scan saved a result file, or on any prior scan output.',
    parameters: {
      source: { type: 'string', required: true, description: 'Path to a DeepSec JSON result file.' },
      format: { type: 'string', description: 'Report format: markdown (default), html, sarif, json, or text.' },
      output: { type: 'string', description: 'Output file path; defaults to the source path with a matching suffix.' },
      chain: { type: 'boolean', description: 'Also generate an attack-chain HTML page and JSON data file.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: value.ok ? value.output : `deepsec report failed: ${value.error || `exit ${value.exitCode}`}\n${tail(value.stderr || '', 500)}` }],
    },
    async execute(args, exec) {
      const cliArgs = ['report', args.source]
      if (args.format) cliArgs.push('--format', args.format)
      if (args.output) cliArgs.push('--output', args.output)
      if (args.chain) cliArgs.push('--chain')

      const res = await runCli({ ...opts, signal: exec?.signal }, cliArgs, [0])
      const failure = asFailure(res)
      if (failure) return failure
      return { ok: true, exitCode: res.code, output: res.stdout.trim() }
    },
  }
}

// ---- shared helpers -------------------------------------------------------

function summarize(findings, limit) {
  const bySeverity = {}
  for (const item of findings) {
    const key = item.severity || 'info'
    bySeverity[key] = (bySeverity[key] || 0) + 1
  }
  const sorted = [...findings].sort(
    (a, b) => rank(a.severity) - rank(b.severity) || String(a.target || '').localeCompare(String(b.target || '')),
  )
  return {
    bySeverity,
    meta: { highestSeverity: sorted.length ? sorted[0].severity : null },
    findings: sorted.slice(0, limit).map(pickFinding),
    truncated: findings.length > limit,
  }
}

function pickFinding(item) {
  return {
    severity: item.severity || 'info',
    title: item.title || item.description || '',
    description: item.description || '',
    target: item.target || item.file || '',
    line: item.line ?? null,
    rule: item.detection_rule || '',
    layer: item.detection_layer || '',
    suggestion: item.suggestion || '',
    evidence: tail(item.evidence || '', 300),
    fixAvailable: Array.isArray(item.fix) && item.fix.length > 0,
  }
}

function rank(severity) {
  const index = SEVERITY_ORDER.indexOf(String(severity || '').toLowerCase())
  return index === -1 ? SEVERITY_ORDER.length : index
}

function asFailure(res) {
  if (res.timedOut) {
    return { ok: false, error: 'DeepSec command timed out and was terminated.', exitCode: res.code, stderr: tail(res.stderr, 2000) }
  }
  if (res.aborted) {
    return { ok: false, error: 'DeepSec command was cancelled.', exitCode: res.code }
  }
  if (!res.accepted) {
    return {
      ok: false,
      error: `DeepSec exited with code ${res.code}.`,
      exitCode: res.code,
      stdout: tail(res.stdout, 2000),
      stderr: tail(res.stderr, 2000),
    }
  }
  return null
}

function renderScan(value) {
  if (!value || value.ok === false) {
    const detail = value?.stderr || value?.stdout || value?.error || 'unknown error'
    return `DeepSec scan failed: ${value?.error || `exit ${value?.exitCode}`}\n${tail(String(detail), 1500)}`
  }
  const s = value.summary || {}
  const parts = Object.entries(s.bySeverity || {})
    .sort((a, b) => rank(a[0]) - rank(b[0]))
    .map(([severity, count]) => `${severity}: ${count}`)
    .join(', ')
  const lines = [
    `DeepSec Shield 扫描完成 — ${s.activeFindings ?? s.totalFindings ?? 0} 个活跃发现（${parts || 'none'}）` +
      (s.filesScanned != null ? `，扫描 ${s.filesScanned} 个文件` : '') +
      (s.elapsedMs != null ? `，耗时 ${s.elapsedMs} ms` : ''),
  ]
  if (value.hasActiveHighOrCritical) lines.push('存在活跃的 high/critical 发现（CLI 退出码 2）。')
  for (const f of value.findings || []) {
    lines.push(`[${f.severity}] ${f.target}${f.line != null ? ':' + f.line : ''} ${f.rule ? `(${f.rule}) ` : ''}${f.title}`)
    if (f.suggestion) lines.push(`  ↳ ${f.suggestion}`)
  }
  if (value.findingsTruncated) lines.push(`（仅显示前 ${value.findings.length} 条，完整统计见 summary）`)
  return lines.join('\n')
}

function tail(text, max) {
  const value = String(text || '')
  return value.length > max ? `…${value.slice(value.length - max)}` : value
}

function numberOr(value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback
}

function str(description, fallback) {
  return z ? z.string().description(description).default(fallback) : { type: 'string', description, default: fallback }
}

function num(description, fallback) {
  return z ? z.number().description(description).default(fallback) : { type: 'number', description, default: fallback }
}
