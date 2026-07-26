import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

test("VSCode manifest exposes dashboard, batch-fix, and Pro subscription commands", async () => {
  const [manifestRaw, vscodeIgnore] = await Promise.all([
    fs.readFile("package.json", "utf8"),
    fs.readFile(".vscodeignore", "utf8")
  ]);
  const manifest = JSON.parse(manifestRaw) as {
    activationEvents: string[];
    contributes: {
      commands: Array<{ command: string; title: string }>;
      menus: {
        "view/item/context": Array<{ command: string; when: string }>;
      };
      configuration: {
        properties: Record<string, { default?: unknown }>;
      };
    };
  };
  const command = manifest.contributes.commands.find((item) => item.command === "deepsec.exportDashboard");
  const batchFixCommand = manifest.contributes.commands.find((item) => item.command === "deepsec.applyAllSafeFixes");
  const proBatchFixCommand = manifest.contributes.commands.find((item) => item.command === "deepsec.applyAllProFixes");
  const findingFixCommand = manifest.contributes.commands.find((item) => item.command === "deepsec.applyFindingFix");
  const subscriptionCommand = manifest.contributes.commands.find((item) => item.command === "deepsec.showSubscriptionStatus");
  const findingFixMenu = manifest.contributes.menus["view/item/context"].find(
    (item) => item.command === "deepsec.applyFindingFix"
  );

  assert.ok(manifest.activationEvents.includes("onCommand:deepsec.exportDashboard"));
  assert.ok(manifest.activationEvents.includes("onCommand:deepsec.applyAllSafeFixes"));
  assert.ok(manifest.activationEvents.includes("onCommand:deepsec.applyAllProFixes"));
  assert.ok(manifest.activationEvents.includes("onCommand:deepsec.applyFindingFix"));
  assert.ok(manifest.activationEvents.includes("onCommand:deepsec.showSubscriptionStatus"));
  assert.ok(command);
  assert.equal(command.title, "DeepSec: Export Findings Dashboard");
  assert.equal(batchFixCommand?.title, "DeepSec: Apply All Safe Fixes in Current File");
  assert.equal(proBatchFixCommand?.title, "DeepSec: Review and Apply All Pro Fixes in Current File");
  assert.equal(findingFixCommand?.title, "DeepSec: Apply Finding Fix");
  assert.equal(findingFixMenu?.when, "view == deepsecFindings && viewItem == vibeguardFindingFixable");
  assert.equal(subscriptionCommand?.title, "DeepSec: Show Pro Subscription Status");
  assert.equal(manifest.contributes.configuration.properties["deepsec.packageVerification"]?.default, "remote");
  assert.equal(manifest.contributes.configuration.properties["vibeguard.packageVerification"]?.default, "remote");
  assert.match(vscodeIgnore, /^deploy\/\*\*$/m);
});
