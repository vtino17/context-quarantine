import type {
  BundleAudit,
  CandidateAudit,
  PolicyDiff,
} from "@contextquarantine/core";

const icon = (admission: CandidateAudit["admission"]): string =>
  admission === "promote" ? "✓" : admission === "quarantine" ? "△" : "×";

export function formatAudit(audit: BundleAudit): string {
  const lines = [
    `ContextQuarantine · ${audit.bundleId}`,
    `Status: ${audit.status.toUpperCase()} · ${audit.promoted} promote · ${audit.quarantined} quarantine · ${audit.rejected} reject`,
    "",
  ];
  for (const candidate of audit.candidates) {
    lines.push(
      `${icon(candidate.admission)} ${candidate.candidateId} · ${candidate.admission.toUpperCase()} · risk ${candidate.riskScore}`
    );
    for (const entry of candidate.issues) {
      lines.push(`  ${entry.severity.toUpperCase()} ${entry.code}: ${entry.message}`);
    }
  }
  return lines.join("\n");
}

export function formatCandidate(candidate: CandidateAudit): string {
  const lines = [
    `Candidate: ${candidate.candidateId}`,
    `Admission: ${candidate.admission.toUpperCase()}`,
    `Risk score: ${candidate.riskScore}/100`,
    `Corroborating domains: ${candidate.corroboratingDomains.join(", ") || "none"}`,
    `Inherited taint: ${candidate.inheritedTaint.join(", ") || "none"}`,
    `Expires: ${candidate.expiresAt}`,
  ];
  for (const entry of candidate.issues) {
    lines.push(`${entry.severity.toUpperCase()} ${entry.code}: ${entry.message}`);
  }
  return lines.join("\n");
}

export function formatPolicyDiff(diff: PolicyDiff): string {
  const lines = [
    `Policy diff: ${diff.from} → ${diff.to}`,
    `Weakened controls: ${diff.weakenedControls.length}`,
    ...diff.weakenedControls.map((entry) => `- ${entry}`),
    "",
    `Strengthened controls: ${diff.strengthenedControls.length}`,
    ...diff.strengthenedControls.map((entry) => `+ ${entry}`),
  ];
  return lines.join("\n");
}
