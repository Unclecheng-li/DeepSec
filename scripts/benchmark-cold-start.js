const { spawnSync } = require("node:child_process");
const path = require("node:path");

const thresholdMs = 3000;
const startedAt = performance.now();
const result = spawnSync(process.execPath, [path.join("dist", "cli.js"), "--help"], {
  encoding: "utf8",
  windowsHide: true
});
const elapsedMs = performance.now() - startedAt;

if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  process.stderr.write(result.stderr || "DeepSec CLI cold-start probe failed.\n");
  process.exit(result.status ?? 1);
}
console.log(`DeepSec CLI cold start: ${elapsedMs.toFixed(0)} ms (target < ${thresholdMs} ms)`);
if (elapsedMs >= thresholdMs) {
  process.exitCode = 1;
}
