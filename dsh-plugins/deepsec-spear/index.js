import { runCli } from './lib/cli.js'

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

export const name = 'deepsec-spear'
export const inject = ['tools']

const configFields = {
  command: str('DeepSec CLI invocation. Use "deepsec" when installed on PATH, or a Python form such as "py -3 -m deepsec".', 'deepsec'),
  timeoutMs: num('Per-command timeout in milliseconds (0 disables). Full spear runs can take an hour or more.', 3600000),
  maxOutputChars: num('Cap on captured CLI stdout/stderr per run, in characters. Detailed artifacts live under ~/.deepsec/runs/.', 60000),
}

export const Config = z ? z.object(configFields) : { type: 'object', properties: configFields }

const AUTHORIZATION_NOTICE =
  'Authorized use only: run against systems you are explicitly permitted to test. ' +
  'The DeepSec CLI verifies the signed scope manifest (signature, time window, target membership), ' +
  'rejects private/reserved addresses, and writes an audit log to ~/.deepsec/runs/.'

export function apply(ctx, config = {}) {
  const opts = {
    command: config.command || 'deepsec',
    timeoutMs: numberOr(config.timeoutMs, 3600000),
    maxOutputChars: Math.max(1000, numberOr(config.maxOutputChars, 60000)),
  }

  const disposers = [
    ctx.tools.register(defineTool(scopeSignTool(opts))),
    ctx.tools.register(defineTool(scopeVerifyTool(opts))),
    ctx.tools.register(defineTool(reconTool(opts))),
    ctx.tools.register(defineTool(runTool(opts))),
    ctx.tools.register(defineTool(catalogTool(opts))),
  ].filter(Boolean)

  return () => {
    for (const dispose of disposers) dispose()
  }
}

function scopeSignTool(opts) {
  return {
    name: 'deepsec_scope_sign',
    description:
      'Sign a Spear scope manifest (JSON allow-list of targets and time window) with DEEPSEC_SCOPE_SIGNING_KEY. ' +
      'Spear run/recon refuse to start without a signed manifest whose targets cover the requested host. ' +
      'The signing key must be provided out-of-band by the authorizing party (e.g. a secret manager), never invented by the agent.',
    parameters: {
      scopeFile: { type: 'string', required: true, description: 'Path to the unsigned (or previously signed) JSON scope manifest to sign in place.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: renderText(value) }],
    },
    async execute(args, exec) {
      const res = await runCli({ ...opts, signal: exec?.signal }, ['scope', 'sign', args.scopeFile], [0])
      return textResult(res, 'scope sign')
    },
  }
}

function scopeVerifyTool(opts) {
  return {
    name: 'deepsec_scope_verify',
    description:
      'Validate a scope manifest: JSON structure, target count, time-window status (valid/expired) and signature check ' +
      'against DEEPSEC_SCOPE_SIGNING_KEY. Use this before proposing any Spear command to confirm the authorization is actually usable.',
    parameters: {
      scopeFile: { type: 'string', required: true, description: 'Path to the JSON scope manifest to validate.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: renderText(value) }],
    },
    async execute(args, exec) {
      const res = await runCli({ ...opts, signal: exec?.signal }, ['scope', 'verify', args.scopeFile], [0])
      return textResult(res, 'scope verify')
    },
  }
}

function reconTool(opts) {
  return {
    name: 'deepsec_spear_recon',
    description:
      `Run reconnaissance only (no exploitation) against an authorized target using DeepSec Spear. ${AUTHORIZATION_NOTICE}`,
    parameters: {
      target: { type: 'string', required: true, description: 'Authorized target domain, IP, or URL; must be covered by the signed scope manifest.' },
      authorized: { type: 'string', required: true, description: 'Path to the signed JSON scope manifest authorizing this target.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: renderText(value) }],
    },
    async execute(args, exec) {
      const guard = requireAuthorization(args)
      if (guard) return guard
      const cliArgs = ['spear', 'recon', args.target, '--authorized', args.authorized]
      const res = await runCli({ ...opts, signal: exec?.signal }, cliArgs, [0])
      return textResult(res, 'spear recon')
    },
  }
}

function runTool(opts) {
  return {
    name: 'deepsec_spear_run',
    description:
      `Run a full authorized penetration test (recon → discovery → verified exploitation with agent reasoning) against a target using DeepSec Spear. ${AUTHORIZATION_NOTICE}`,
    parameters: {
      target: { type: 'string', required: true, description: 'Authorized target host, IP, URL or repository; must be covered by the signed scope manifest.' },
      authorized: { type: 'string', required: true, description: 'Path to the signed JSON scope manifest authorizing this target and time window.' },
      scope: { type: 'string', description: 'Assessment scope: full (default), web, api, or mobile.' },
      mode: { type: 'string', description: 'Depth preset: quick, standard (default), or deep.' },
      output: { type: 'string', description: 'Optional path for the run report.' },
      role: { type: 'string', description: 'DeepSec role for this run (pentester, redteam, ctf_player, …); roles never bypass scope authorization.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: renderText(value) }],
    },
    async execute(args, exec) {
      const guard = requireAuthorization(args)
      if (guard) return guard
      const cliArgs = ['spear', 'run', args.target, '--authorized', args.authorized]
      if (args.scope) cliArgs.push('--scope', args.scope)
      if (args.mode) cliArgs.push('--mode', args.mode)
      if (args.output) cliArgs.push('--output', args.output)
      if (args.role) cliArgs.push('--role', args.role)
      const res = await runCli({ ...opts, signal: exec?.signal }, cliArgs, [0])
      return textResult(res, 'spear run')
    },
  }
}

function catalogTool(opts) {
  return {
    name: 'deepsec_spear_catalog',
    description:
      'List DeepSec Spear roles and the external tool catalog permitted for a role (read-only; launches no traffic). ' +
      'Use it to pick a role or check which external tools (nmap, nuclei, httpx, …) the catalog expects on PATH.',
    parameters: {
      role: { type: 'string', description: 'Optional role name; omit to use the configured default role.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: renderText(value) }],
    },
    async execute(args, exec) {
      const results = []
      const roles = await runCli({ ...opts, signal: exec?.signal }, ['spear', 'roles'], [0])
      results.push(textResult(roles, 'spear roles'))
      const toolArgs = ['spear', 'tools']
      if (args.role) toolArgs.push('--role', args.role)
      const tools = await runCli({ ...opts, signal: exec?.signal }, toolArgs, [0])
      results.push(textResult(tools, 'spear tools'))
      return {
        ok: results.every((item) => item.ok),
        roles: results[0],
        tools: results[1],
      }
    },
  }
}

// ---- shared helpers -------------------------------------------------------

// Belt-and-braces on top of the required-parameter schema: Spear commands
// never execute without an explicit signed-manifest path.
function requireAuthorization(args) {
  if (!args.authorized || !String(args.authorized).trim()) {
    return {
      ok: false,
      error: 'Refused: spear commands require the "authorized" parameter pointing at a signed scope manifest. ' + AUTHORIZATION_NOTICE,
    }
  }
  return null
}

function textResult(res, label) {
  if (res.timedOut) {
    return { ok: false, error: `DeepSec ${label} timed out and was terminated.`, exitCode: res.code, stderr: tail(res.stderr, 2000) }
  }
  if (res.aborted) {
    return { ok: false, error: `DeepSec ${label} was cancelled.`, exitCode: res.code }
  }
  if (!res.accepted) {
    return {
      ok: false,
      error: `DeepSec ${label} exited with code ${res.code}. Authorization failures look like "not authorized" / scope errors in stderr.`,
      exitCode: res.code,
      stdout: tail(res.stdout, 4000),
      stderr: tail(res.stderr, 4000),
    }
  }
  return {
    ok: true,
    exitCode: res.code,
    output: res.stdout.trim(),
    outputTruncated: res.stdoutTruncated,
    stderr: tail(res.stderr, 1000),
    artifactsHint: 'Run artifacts and the authorization audit log are stored under ~/.deepsec/runs/.',
  }
}

function renderText(value) {
  if (!value || value.ok === false) {
    const detail = value?.stderr || value?.output || value?.stdout || value?.error || 'unknown error'
    return `DeepSec spear 命令失败: ${value?.error || `exit ${value?.exitCode}`}\n${tail(String(detail), 1500)}`
  }
  const text = value.output || ''
  return text + (value.outputTruncated ? '\n（输出已截断，完整结果见 ~/.deepsec/runs/）' : '')
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
