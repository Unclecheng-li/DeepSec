import assert from "node:assert/strict";
import test from "node:test";
import { scanWithDeepSecCli } from "../src/deepsecBridge";

test("does not replace the TypeScript scanner when no DeepSec interpreter is configured", async () => {
  const result = await scanWithDeepSecCli({
    filePath: "example.ts",
    layers: { l1: true, l2: true, l3: false }
  });

  assert.equal(result, undefined);
});
