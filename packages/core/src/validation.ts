import type {
  MemoryBundle,
  MemoryType,
  OriginKind,
  Sensitivity,
  TrustLevel,
} from "./types.js";

export interface ValidationIssue {
  path: string;
  message: string;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);
const isText = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;
const isDate = (value: unknown): value is string =>
  isText(value) && Number.isFinite(Date.parse(value));
const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every(isText);
const trustLevels = new Set<TrustLevel>(["trusted", "bounded", "untrusted"]);
const originKinds = new Set<OriginKind>(["human", "agent", "tool", "service", "web"]);
const memoryTypes = new Set<MemoryType>(["fact", "preference", "instruction", "decision"]);
const sensitivities = new Set<Sensitivity>(["public", "internal", "secret"]);

export function validateBundle(value: unknown): ValidationIssue[] {
  if (!isObject(value)) return [{ path: "$", message: "Bundle must be an object." }];
  const issues: ValidationIssue[] = [];
  if (value.schemaVersion !== "1.0") issues.push({ path: "schemaVersion", message: 'Must equal "1.0".' });
  if (!isText(value.id)) issues.push({ path: "id", message: "ID is required." });
  if (!isObject(value.policy)) {
    issues.push({ path: "policy", message: "Policy is required." });
  } else {
    const policy = value.policy;
    if (policy.schemaVersion !== "1.0") issues.push({ path: "policy.schemaVersion", message: 'Must equal "1.0".' });
    if (!isText(policy.id)) issues.push({ path: "policy.id", message: "ID is required." });
    if (!isText(policy.description)) issues.push({ path: "policy.description", message: "Description is required." });
    if (!isObject(policy.rules)) {
      issues.push({ path: "policy.rules", message: "Rules are required." });
    } else {
      const rules = policy.rules;
      if (!Number.isInteger(rules.minCorroboratingDomains) || (rules.minCorroboratingDomains as number) < 1) {
        issues.push({ path: "policy.rules.minCorroboratingDomains", message: "Must be a positive integer." });
      }
      for (const field of ["instructionOriginIds", "protectedNamespaces"] as const) {
        if (!isStringArray(rules[field])) issues.push({ path: `policy.rules.${field}`, message: "Must be an array of strings." });
      }
      if (!isObject(rules.maxTtlHours) || ![rules.maxTtlHours?.trusted, rules.maxTtlHours?.bounded, rules.maxTtlHours?.untrusted].every((entry) =>
        typeof entry === "number" && Number.isFinite(entry) && entry > 0)) {
        issues.push({ path: "policy.rules.maxTtlHours", message: "Must define positive trusted, bounded, and untrusted limits." });
      }
      for (const field of ["rejectSecrets", "rejectEncodedInstructions", "rejectHiddenUnicode", "requireDerivationTrace"] as const) {
        if (typeof rules[field] !== "boolean") issues.push({ path: `policy.rules.${field}`, message: "Must be boolean." });
      }
    }
  }
  if (!Array.isArray(value.origins) || value.origins.length === 0) {
    issues.push({ path: "origins", message: "At least one origin is required." });
  } else {
    value.origins.forEach((origin, index) => {
      const path = `origins[${index}]`;
      if (!isObject(origin)) {
        issues.push({ path, message: "Must be an object." });
        return;
      }
      for (const field of ["id", "label", "domain"] as const) {
        if (!isText(origin[field])) issues.push({ path: `${path}.${field}`, message: "Must be non-empty." });
      }
      if (!originKinds.has(origin.kind as OriginKind)) issues.push({ path: `${path}.kind`, message: "Unknown origin kind." });
      if (!trustLevels.has(origin.trust as TrustLevel)) issues.push({ path: `${path}.trust`, message: "Unknown trust level." });
    });
  }
  if (!Array.isArray(value.activeMemory)) {
    issues.push({ path: "activeMemory", message: "Must be an array." });
  }
  if (!Array.isArray(value.candidates)) {
    issues.push({ path: "candidates", message: "Must be an array." });
  } else {
    value.candidates.forEach((candidate, index) => {
      const path = `candidates[${index}]`;
      if (!isObject(candidate)) {
        issues.push({ path, message: "Must be an object." });
        return;
      }
      for (const field of ["id", "namespace", "content", "originId", "sourceRef", "contentDigest"] as const) {
        if (!isText(candidate[field])) issues.push({ path: `${path}.${field}`, message: "Must be non-empty." });
      }
      if (!memoryTypes.has(candidate.memoryType as MemoryType)) issues.push({ path: `${path}.memoryType`, message: "Unknown memory type." });
      if (!sensitivities.has(candidate.sensitivity as Sensitivity)) issues.push({ path: `${path}.sensitivity`, message: "Unknown sensitivity." });
      if (!isDate(candidate.observedAt)) issues.push({ path: `${path}.observedAt`, message: "Must be an ISO date." });
      if (
        typeof candidate.requestedTtlHours !== "number"
        || !Number.isFinite(candidate.requestedTtlHours)
        || candidate.requestedTtlHours <= 0
      ) issues.push({ path: `${path}.requestedTtlHours`, message: "Must be positive." });
      for (const field of ["tags", "derivedFrom"] as const) {
        if (!isStringArray(candidate[field])) issues.push({ path: `${path}.${field}`, message: "Must be an array of strings." });
      }
      if (!Array.isArray(candidate.claims)) {
        issues.push({ path: `${path}.claims`, message: "Must be an array." });
      } else {
        candidate.claims.forEach((claim, claimIndex) => {
          if (!isObject(claim) || !["subject", "predicate", "value"].every((field) => isText(claim[field]))) {
            issues.push({ path: `${path}.claims[${claimIndex}]`, message: "Must define subject, predicate, and value." });
          }
        });
      }
    });
  }
  const objects = (entry: unknown): Record<string, unknown>[] =>
    Array.isArray(entry) ? entry.filter(isObject) : [];
  const originIds = objects(value.origins).map((entry) => entry.id).filter(isText);
  const activeIds = objects(value.activeMemory).map((entry) => entry.id).filter(isText);
  const candidateIds = objects(value.candidates).map((entry) => entry.id).filter(isText);
  if (new Set(originIds).size !== originIds.length) issues.push({ path: "origins", message: "Origin IDs must be unique." });
  if (new Set(activeIds).size !== activeIds.length) issues.push({ path: "activeMemory", message: "Active memory IDs must be unique." });
  if (new Set(candidateIds).size !== candidateIds.length) issues.push({ path: "candidates", message: "Candidate IDs must be unique." });
  if (candidateIds.some((id) => activeIds.includes(id))) issues.push({ path: "candidates", message: "Candidate and active memory IDs must not overlap." });
  return issues;
}

export function assertBundle(value: unknown): asserts value is MemoryBundle {
  const issues = validateBundle(value);
  if (issues.length > 0) {
    throw new Error(`Invalid memory bundle:\n${issues.map((entry) => `- ${entry.path}: ${entry.message}`).join("\n")}`);
  }
}
