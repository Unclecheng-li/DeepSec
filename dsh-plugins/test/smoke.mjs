// Smoke test: drive both dsh plugins through a fake Cordis ctx and exercise
// them against the real `deepsec` CLI installed on this machine.
//
//   node dsh-plugins/test/smoke.mjs
//
// Covers: tool registration, L1 scan, supply-chain check, scope sign/verify
// roundtrip, and the authorization gate (spear run against a target that is
// NOT in the signed scope must fail cleanly without any traffic).

import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import assert from 'node:assert/strict'

const shield = await import('../deepsec-shield/index.js')
const spear = await import('../deepsec-spear/index.js')

function makeCtx() {
  const tools = new Map()
  return {
    tools: {
      register(spec) {
        tools.set(spec.name, spec)
        return () => tools.delete(spec.name)
      },
    },
    get _tools() {
      return tools
    },
  }
}

const ctx = makeCtx()
const disposeShield = shield.apply(ctx, {})
const disposeSpear = spear.apply(ctx, {})

const expected = [
  'deepsec_scan',
  'deepsec_agent_audit',
  'deepsec_supply_chain',
  'deepsec_report',
  'deepsec_scope_sign',
  'deepsec_scope_verify',
  'deepsec_spear_recon',
  'deepsec_spear_run',
  'deepsec_spear_catalog',
]
for (const name of expected) assert.ok(ctx._tools.has(name), `tool ${name} should be registered`)
assert.equal(ctx._tools.size, expected.length, 'exactly the expected tools should be registered')
console.log(`✓ ${expected.length} tools registered`)

const exec = (name, args) => ctx._tools.get(name).execute(args, {})

const dir = mkdtempSync(join(tmpdir(), 'deepsec-dsh-smoke-'))
try {
  // 1. L1 scan over a snippet with a hardcoded secret.
  writeFileSync(
    join(dir, 'app.py'),
    'import os\n\nAPI_TOKEN = "sk-live-abc123def456ghi789jkl012mno345pqr678"\nPASSWORD = "hunter2-super-secret-value"\n',
  )
  const scan = await exec('deepsec_scan', { path: dir, layers: 'l1' })
  assert.equal(scan.ok, true, `scan should succeed: ${JSON.stringify(scan).slice(0, 400)}`)
  assert.ok(scan.summary.activeFindings >= 1, 'hardcoded secret should be found')
  assert.ok(scan.findings.length >= 1)
  console.log(`✓ deepsec_scan: ${scan.summary.activeFindings} finding(s), bySeverity=${JSON.stringify(scan.summary.bySeverity)}`)

  const rendered = ctx._tools.get('deepsec_scan').output.render({}, scan)
  assert.ok(rendered[0].text.includes('DeepSec Shield'), 'render should summarize the scan')
  console.log('✓ deepsec_scan render ok')

  // 2. Supply-chain check over a manifest with a distance-1 typosquatted
  //    dependency (the detector uses plain Levenshtein == 1, so adjacent
  //    transpositions like "reqeusts" are intentionally out of scope).
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'smoke-demo', version: '1.0.0', dependencies: { expres: '^4.18.0' } }, null, 2),
  )
  const supply = await exec('deepsec_supply_chain', { path: dir, privatePackages: ['@company/internal-lib'] })
  assert.equal(supply.ok, true, `supply-chain check should succeed: ${JSON.stringify(supply).slice(0, 400)}`)
  assert.ok(supply.summary.activeFindings >= 1, 'the typosquatted dependency should be flagged')
  console.log(`✓ deepsec_supply_chain: ${supply.summary.activeFindings} finding(s)`)

  // 3. Scope sign → verify roundtrip.
  const scopePath = join(dir, 'scope.json')
  writeFileSync(
    scopePath,
    JSON.stringify(
      {
        version: 1,
        targets: ['https://assessment.example.com'],
        valid_from: '2020-01-01T00:00:00+00:00',
        valid_until: '2099-01-01T00:00:00+00:00',
        prohibited_cidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'],
        signer: 'smoke-test',
        signature_algorithm: 'hmac-sha256',
      },
      null,
      2,
    ),
  )
  process.env.DEEPSEC_SCOPE_SIGNING_KEY = 'smoke-signing-key-0123456789'
  const signed = await exec('deepsec_scope_sign', { scopeFile: scopePath })
  assert.equal(signed.ok, true, `scope sign should succeed: ${JSON.stringify(signed).slice(0, 400)}`)
  assert.ok(JSON.parse(readFileSync(scopePath, 'utf8')).signature, 'signature should be written into the manifest')
  console.log('✓ deepsec_scope_sign ok')

  const verified = await exec('deepsec_scope_verify', { scopeFile: scopePath })
  assert.equal(verified.ok, true, `scope verify should succeed: ${JSON.stringify(verified).slice(0, 400)}`)
  console.log(`✓ deepsec_scope_verify: ${verified.output.replace(/\n/g, ' | ')}`)

  // 4. Authorization gate: target NOT covered by the signed scope must be refused.
  const denied = await exec('deepsec_spear_run', { target: 'https://not-in-scope.example.net', authorized: scopePath })
  assert.equal(denied.ok, false, 'spear run against an unauthorized target must fail')
  assert.match(
    JSON.stringify(denied),
    /authoriz|scope|target/i,
    'the failure should surface the authorization reason',
  )
  console.log(`✓ authorization gate held (exit ${denied.exitCode})`)

  // 5. Missing `authorized` parameter is refused by the plugin itself.
  const refused = await exec('deepsec_spear_recon', { target: 'https://assessment.example.com' })
  assert.equal(refused.ok, false)
  assert.match(refused.error, /Refused/)
  console.log('✓ plugin-level guard refused recon without a scope manifest')

  console.log('\nALL SMOKE TESTS PASSED')
} finally {
  delete process.env.DEEPSEC_SCOPE_SIGNING_KEY
  rmSync(dir, { recursive: true, force: true })
  if (typeof disposeShield === 'function') disposeShield()
  if (typeof disposeSpear === 'function') disposeSpear()
}
