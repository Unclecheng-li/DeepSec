import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding, FindingType, Severity } from "./types";

const execFileAsync = promisify(execFile);

export interface DeepSecBridgeRequest {
  filePath: string;
  layers: { l1: boolean; l2: boolean; l3: boolean };
  pythonPath?: string;
}

export interface DeepSecSpearRequest {
  target: string;
  scopeManifest: string;
  pythonPath: string;
}

export interface DeepSecSpearResult {
  stdout: string;
  stderr: string;
}

interface DeepSecJsonResult {
  findings?: unknown[];
}

/**
 * Calls the Python DeepSec core only when an interpreter path is explicitly
 * configured. Callers treat undefined as a signal to keep the TypeScript
 * scanner active for backwards-compatible installations.
 */
export async function scanWithDeepSecCli(request: DeepSecBridgeRequest): Promise<Finding[] | undefined> {
  const pythonPath = request.pythonPath?.trim();
  if (!pythonPath) {
    return undefined;
  }
  const layer = selectedLayers(request.layers);
  if (!layer) {
    return [];
  }
  try {
    const { stdout } = await execFileAsync(
      pythonPath,
      ["-m", "deepsec", "shield", "scan", request.filePath, "--layer", layer, "--format", "json", "--output", "-"],
      { windowsHide: true, maxBuffer: 2 * 1024 * 1024 }
    );
    return parseFindings(stdout);
  } catch (error) {
    // Shield exits 2 when it finds high/critical results. execFile exposes the
    // valid JSON through the error object in that expected nonzero case.
    const stdout = error && typeof error === "object" && "stdout" in error ? (error as { stdout?: unknown }).stdout : undefined;
    return typeof stdout === "string" ? parseFindings(stdout) : undefined;
  }
}

/** Runs Spear only through its signed-manifest CLI gate. */
export async function runDeepSecSpearCli(request: DeepSecSpearRequest): Promise<DeepSecSpearResult> {
  const { stdout, stderr } = await execFileAsync(
    request.pythonPath,
    ["-m", "deepsec", "spear", "run", request.target, "--authorized", request.scopeManifest],
    { windowsHide: true, maxBuffer: 8 * 1024 * 1024 }
  );
  return { stdout, stderr };
}

function parseFindings(stdout: string): Finding[] | undefined {
  try {
    const parsed = JSON.parse(stdout) as DeepSecJsonResult;
    return (parsed.findings ?? []).flatMap(toFinding);
  } catch {
    return undefined;
  }
}

function selectedLayers(layers: DeepSecBridgeRequest["layers"]): string | undefined {
  const selected = (["l1", "l2", "l3"] as const).filter((layer) => layers[layer]).map((layer) => layer.toUpperCase());
  return selected.length > 0 ? selected.join(",") : undefined;
}

function toFinding(value: unknown): Finding[] {
  if (!value || typeof value !== "object") {
    return [];
  }
  const item = value as Record<string, unknown>;
  const severity = normalizeSeverity(item.severity);
  const type = normalizeType(item.type);
  const layer = item.detection_layer;
  const rule = item.detection_rule;
  const file = item.file ?? item.target;
  if (!severity || !type || typeof layer !== "string" || typeof rule !== "string" || typeof file !== "string") {
    return [];
  }
  return [
    {
      id: typeof item.id === "string" ? item.id : `deepsec_${rule}_${item.line ?? 1}`,
      type,
      severity,
      message: typeof item.message === "string" ? item.message : typeof item.description === "string" ? item.description : rule,
      file,
      line: numeric(item.line, 1),
      column: numeric(item.column, 1),
      endLine: optionalNumber(item.end_line ?? item.endLine),
      endColumn: optionalNumber(item.end_column ?? item.endColumn),
      evidence: typeof item.evidence === "string" ? item.evidence : "",
      suggestion: typeof item.suggestion === "string" ? item.suggestion : undefined,
      detection_layer: layer === "L1" || layer === "L2" || layer === "L3" ? layer : "L3",
      detection_rule: rule,
      timestamp: timestamp(item.timestamp),
      dismissed: Boolean(item.dismissed)
    }
  ];
}

function normalizeSeverity(value: unknown): Severity | undefined {
  return value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info" ? value : undefined;
}

function normalizeType(value: unknown): FindingType | undefined {
  const allowed: FindingType[] = [
    "hallucinated_package",
    "hardcoded_secret",
    "insecure_config",
    "ai_pattern_error",
    "sql_injection",
    "xss",
    "ssrf",
    "path_traversal",
    "insecure_deserialization",
    "command_injection",
    "open_redirect",
    "information_leakage",
    "missing_security_measure",
    "other"
  ];
  return typeof value === "string" ? allowed.find((item) => item === value) ?? "other" : undefined;
}

function numeric(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(1, Math.round(value)) : fallback;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(1, Math.round(value)) : undefined;
}

function timestamp(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }
  return Date.now();
}
