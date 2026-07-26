import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(__dirname, "../..");

test("Docker image builds the DeepSec Python core and native TUI", async () => {
  const [dockerfile, dockerignore] = await Promise.all([
    fs.readFile(path.join(repositoryRoot, "Dockerfile"), "utf8"),
    fs.readFile(path.join(repositoryRoot, ".dockerignore"), "utf8")
  ]);

  assert.match(dockerfile, /^FROM rust:1-bookworm AS tui-build/m);
  assert.match(dockerfile, /^FROM python:3\.12-slim/m);
  assert.match(dockerfile, /cargo build --release --locked/);
  assert.match(dockerfile, /pip install --no-cache-dir \./);
  assert.match(dockerfile, /deepsec-tui-native/);
  assert.match(dockerfile, /ENTRYPOINT \["deepsec"\]/);
  assert.match(dockerfile, /CMD \["tui"\]/);
  assert.match(dockerignore, /^node_modules\/$/m);
  assert.match(dockerignore, /^dist\/$/m);
});

test("development and release workflows pin Node.js 22 LTS", async () => {
  const [nvmrc, ci, release, packageRaw] = await Promise.all([
    fs.readFile(path.join(repositoryRoot, ".nvmrc"), "utf8"),
    fs.readFile(path.join(repositoryRoot, ".github", "workflows", "ci.yml"), "utf8"),
    fs.readFile(path.join(repositoryRoot, ".github", "workflows", "release.yml"), "utf8"),
    fs.readFile(path.join(repositoryRoot, "package.json"), "utf8")
  ]);
  const packageJson = JSON.parse(packageRaw) as { scripts?: Record<string, string> };

  assert.equal(nvmrc.trim(), "22");
  assert.doesNotMatch(ci, /node-version:\s*24/);
  assert.match(ci, /node-version:\s*22/);
  assert.doesNotMatch(release, /node-version:\s*24/);
  assert.match(release, /node-version:\s*22/);
  assert.match(packageJson.scripts?.test ?? "", /assert-node-lts/);
});

test("CI uses current actions and validates DeepSec delivery targets", async () => {
  const [ci, release] = await Promise.all([
    fs.readFile(path.join(repositoryRoot, ".github", "workflows", "ci.yml"), "utf8"),
    fs.readFile(path.join(repositoryRoot, ".github", "workflows", "release.yml"), "utf8")
  ]);

  for (const workflow of [ci, release]) {
    assert.doesNotMatch(workflow, /actions\/(?:checkout|setup-node|setup-java|upload-artifact)@v4/);
    assert.match(workflow, /actions\/checkout@v5/);
    assert.match(workflow, /actions\/setup-node@v5/);
  }
  assert.match(ci, /actions\/setup-java@v5/);
  assert.match(release, /actions\/setup-java@v5/);
  assert.match(ci, /chmod \+x \.\/gradlew/);
  assert.match(release, /chmod \+x \.\/gradlew/);
  assert.match(ci, /python -m pytest tests\/deepsec/);
  assert.match(ci, /cargo check --locked --manifest-path tui\/Cargo\.toml/);
  assert.match(ci, /docker compose config --quiet/);
  assert.match(ci, /deepsec:ci shield scan/);
});
