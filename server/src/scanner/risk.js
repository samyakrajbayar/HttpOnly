const severityWeights = {
  critical: 35,
  high: 25,
  medium: 12,
  low: 5,
  info: 0
};

export function createFinding({
  title,
  description,
  severity = "info",
  category = "General",
  evidence = "",
  recommendation = ""
}) {
  return {
    id: crypto.randomUUID(),
    title,
    description,
    severity,
    category,
    evidence,
    recommendation
  };
}

export function buildRiskSummary(findings) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const finding of findings) {
    counts[finding.severity] += 1;
  }

  const rawScore = findings.reduce(
    (total, finding) => total + severityWeights[finding.severity],
    0
  );
  const score = Math.min(100, rawScore);

  let classification = "Clean";
  if (score >= 70 || counts.critical > 0) classification = "Critical";
  else if (score >= 45 || counts.high > 0) classification = "High";
  else if (score >= 20 || counts.medium > 0) classification = "Medium";
  else if (score > 0) classification = "Low";

  return {
    score,
    classification,
    counts,
    totalFindings: findings.length
  };
}
