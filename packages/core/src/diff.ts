import type { PolicyDiff, QuarantinePolicy, TrustLevel } from "./types.js";

export function diffPolicies(from: QuarantinePolicy, to: QuarantinePolicy): PolicyDiff {
  const weakenedControls: string[] = [];
  const strengthenedControls: string[] = [];
  const compareBoolean = (
    field: "rejectSecrets" | "rejectEncodedInstructions" | "rejectHiddenUnicode" | "requireDerivationTrace",
    label: string
  ): void => {
    if (from.rules[field] && !to.rules[field]) weakenedControls.push(`${label} was disabled.`);
    if (!from.rules[field] && to.rules[field]) strengthenedControls.push(`${label} was enabled.`);
  };
  if (to.rules.minCorroboratingDomains < from.rules.minCorroboratingDomains) {
    weakenedControls.push(`Corroboration requirement decreased from ${from.rules.minCorroboratingDomains} to ${to.rules.minCorroboratingDomains} domains.`);
  } else if (to.rules.minCorroboratingDomains > from.rules.minCorroboratingDomains) {
    strengthenedControls.push(`Corroboration requirement increased from ${from.rules.minCorroboratingDomains} to ${to.rules.minCorroboratingDomains} domains.`);
  }
  for (const origin of to.rules.instructionOriginIds.filter((entry) => !from.rules.instructionOriginIds.includes(entry))) {
    weakenedControls.push(`Origin "${origin}" gained instruction-writing authority.`);
  }
  for (const namespace of from.rules.protectedNamespaces.filter((entry) => !to.rules.protectedNamespaces.includes(entry))) {
    weakenedControls.push(`Namespace "${namespace}" is no longer protected.`);
  }
  for (const trust of ["trusted", "bounded", "untrusted"] as TrustLevel[]) {
    const before = from.rules.maxTtlHours[trust];
    const after = to.rules.maxTtlHours[trust];
    if (after > before) weakenedControls.push(`${trust} TTL limit increased from ${before}h to ${after}h.`);
    if (after < before) strengthenedControls.push(`${trust} TTL limit decreased from ${before}h to ${after}h.`);
  }
  compareBoolean("rejectSecrets", "Secret rejection");
  compareBoolean("rejectEncodedInstructions", "Encoded-payload rejection");
  compareBoolean("rejectHiddenUnicode", "Hidden-Unicode rejection");
  compareBoolean("requireDerivationTrace", "Derivation tracing");
  return { from: from.id, to: to.id, weakenedControls, strengthenedControls };
}
