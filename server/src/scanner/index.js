import { scanRepository } from "./repoScanner.js";
import { scanUrl } from "./urlScanner.js";
import { parseTarget } from "./target.js";
import { buildRiskSummary } from "./risk.js";

export async function scanTarget(rawTarget) {
  const startedAt = new Date();
  const target = parseTarget(rawTarget);

  const baseReport = target.type === "github"
    ? await scanRepository(target)
    : await scanUrl(target);

  const completedAt = new Date();
  const summary = buildRiskSummary(baseReport.findings);

  return {
    id: crypto.randomUUID(),
    target: target.display,
    targetType: target.type,
    scannedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
    summary,
    ...baseReport
  };
}
