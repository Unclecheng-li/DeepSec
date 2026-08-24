import { spawn } from 'node:child_process'

// Grace period between SIGTERM and SIGKILL when a run is cancelled or times out.
const KILL_GRACE_MS = 5000

/**
 * Run the DeepSec CLI as a child process and capture its output.
 *
 * Exit-code contract of the `deepsec` CLI: audit commands exit with code 2
 * when active high/critical findings exist, which is a *successful* scan with
 * results — callers decide via `acceptExitCodes`.
 *
 * Resolves with:
 *   { code, accepted, stdout, stderr, stdoutTruncated, stderrTruncated, timedOut, aborted }
 */
export function runCli(options, args, acceptExitCodes = [0]) {
  const {
    command = 'deepsec',
    cwd,
    timeoutMs = 0,
    maxOutputChars = 40000,
    signal,
  } = options || {}

  return new Promise((resolve, reject) => {
    const base = String(command || '').trim().split(/\s+/).filter(Boolean)
    if (base.length === 0) {
      reject(new Error('DeepSec command is empty; set the "command" plugin config (e.g. "deepsec" or "py -3 -m deepsec").'))
      return
    }

    let child
    try {
      child = spawn(base[0], [...base.slice(1), ...args], {
        cwd: cwd || undefined,
        env: process.env,
        windowsHide: true,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (error) {
      reject(spawnError(error, command))
      return
    }

    let stdout = ''
    let stderr = ''
    let stdoutTruncated = false
    let stderrTruncated = false
    let timedOut = false
    let aborted = false
    let settled = false

    const append = (chunk, kind) => {
      const text = chunk.toString('utf8')
      const current = kind === 'stdout' ? stdout : stderr
      if (current.length >= maxOutputChars) {
        if (kind === 'stdout') stdoutTruncated = true
        else stderrTruncated = true
        return
      }
      const room = maxOutputChars - current.length
      const piece = text.length > room ? text.slice(0, room) : text
      if (kind === 'stdout') {
        stdout += piece
        if (text.length > room) stdoutTruncated = true
      } else {
        stderr += piece
        if (text.length > room) stderrTruncated = true
      }
    }

    let killTimer = null
    const killHard = () => {
      if (killTimer === null) {
        killTimer = setTimeout(() => child.kill('SIGKILL'), KILL_GRACE_MS)
        killTimer.unref()
      }
    }
    const terminate = (reason) => {
      if (reason === 'timeout') timedOut = true
      else aborted = true
      child.kill('SIGTERM')
      killHard()
    }

    const timer = timeoutMs > 0 ? setTimeout(() => terminate('timeout'), timeoutMs) : null
    if (timer) timer.unref()
    const onAbort = () => terminate('abort')

    const cleanup = () => {
      if (timer) clearTimeout(timer)
      if (killTimer) clearTimeout(killTimer)
      if (signal) signal.removeEventListener('abort', onAbort)
    }

    if (signal) {
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }

    child.on('error', (error) => {
      if (settled) return
      settled = true
      cleanup()
      reject(spawnError(error, command))
    })
    child.stdout.on('data', (chunk) => append(chunk, 'stdout'))
    child.stderr.on('data', (chunk) => append(chunk, 'stderr'))
    child.on('close', (code) => {
      if (settled) return
      settled = true
      cleanup()
      resolve({
        code: code === null ? (aborted ? 'aborted' : 'killed') : code,
        accepted: acceptExitCodes.includes(code),
        stdout,
        stderr,
        stdoutTruncated,
        stderrTruncated,
        timedOut,
        aborted,
      })
    })
  })
}

function spawnError(error, command) {
  const message = String((error && error.message) || error)
  if (error && (error.code === 'ENOENT' || message.includes('ENOENT'))) {
    return new Error(
      `DeepSec CLI not found via command "${command}". ` +
        'Install DeepSec first (pip install -e /path/to/DeepSec, or pip install deepsec), ' +
        'or point the plugin "command" config at a Python interpreter such as "py -3 -m deepsec".',
    )
  }
  return error instanceof Error ? error : new Error(message)
}

/**
 * Extract the last JSON document embedded in mixed CLI output.
 * The CLI may print warnings or rich-console noise around the JSON payload.
 */
export function parseJsonOutput(text) {
  const direct = tryParse(text)
  if (direct !== undefined) return direct
  const start = text.indexOf('{')
  const end = text.lastIndexOf('}')
  if (start === -1 || end > start) {
    const sliced = tryParse(text.slice(start, end + 1))
    if (sliced !== undefined) return sliced
  }
  return undefined
}

function tryParse(text) {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}
