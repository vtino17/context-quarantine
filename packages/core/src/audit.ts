import { canonicalJson, hashValue, sha256 } from "./canonical.js";
import type {
  AdmissionIssue,
  BundleAudit,
  CandidateAudit,
  Claim,
  MemoryBundle,
  MemoryCandidate,
  MemoryOrigin,
} from "./types.js";
import { assertBundle } from "./validation.js";

const hiddenUnicode = /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/u;
const instructionLanguage =
  /\b(ignore|override|disregard|system message|developer message|always remember|you must|do not reveal|upload|exfiltrate|send (?:the|all)|delete|execute|run this)\b/i;
const encodedPayload = /(?:[A-Za-z0-9+/]{32,}={0,2}|(?:%[0-9A-Fa-f]{2}){8,})/;
const secretPattern =
  /(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{16,}|\bAKIA[0-9A-Z]{16}\b|\bBearer\s+[A-Za-z0-9._~+/-]{16,})/;

const normalize = (value: string): string =>
  value.normalize("NFKC").trim().replace(/\s+/g, " ").toLowerCase();
const claimKey = (claims: Claim[]): string =>
  canonicalJson(
    claims
      .map((claim) => ({
        subject: normalize(claim.subject),
        predicate: normalize(claim.predicate),
        value: normalize(claim.value),
      }))
      .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)))
  );
const relationKey = (claim: Claim): string =>
  `${normalize(claim.subject)}\u0000${normalize(claim.predicate)}`;

function issue(
  candidateId: string,
  code: string,
  severity: AdmissionIssue["severity"],
  message: string
): AdmissionIssue {
  return { candidateId, code, severity, message };
}

function expiresAt(candidate: MemoryCandidate): string {
  return new Date(
    Date.parse(candidate.observedAt) + candidate.requestedTtlHours * 3_600_000
  ).toISOString();
}

function inspectCandidate(
  candidate: MemoryCandidate,
  origin: MemoryOrigin | undefined,
  bundle: MemoryBundle,
  now: Date
): AdmissionIssue[] {
  const issues: AdmissionIssue[] = [];
  const rules = bundle.policy.rules;
  if (!origin) {
    issues.push(issue(candidate.id, "unknown-origin", "reject", `Origin "${candidate.originId}" is not declared.`));
    return issues;
  }
  if (!/^[a-f0-9]{64}$/i.test(candidate.contentDigest)) {
    issues.push(issue(candidate.id, "invalid-digest", "reject", "Content digest must be a SHA-256 hex string."));
  } else if (sha256(candidate.content) !== candidate.contentDigest.toLowerCase()) {
    issues.push(issue(candidate.id, "digest-mismatch", "reject", "Content does not match its declared digest."));
  }
  if (Date.parse(candidate.observedAt) > now.getTime() + 60_000) {
    issues.push(issue(candidate.id, "future-observation", "reject", "Observation timestamp is in the future."));
  }
  if (Date.parse(expiresAt(candidate)) <= now.getTime()) {
    issues.push(issue(candidate.id, "expired-candidate", "review", "Candidate has already exceeded its requested lifetime."));
  }
  const ttlLimit = rules.maxTtlHours[origin.trust];
  if (candidate.requestedTtlHours > ttlLimit) {
    issues.push(issue(candidate.id, "ttl-overreach", "review", `Requested TTL ${candidate.requestedTtlHours}h exceeds the ${origin.trust} limit of ${ttlLimit}h.`));
  }
  if (rules.rejectSecrets && (candidate.sensitivity === "secret" || secretPattern.test(candidate.content))) {
    issues.push(issue(candidate.id, "secret-persistence", "reject", "Secret material must not enter persistent agent memory."));
  }
  if (rules.rejectHiddenUnicode && hiddenUnicode.test(candidate.content)) {
    issues.push(issue(candidate.id, "hidden-unicode", "reject", "Content contains invisible or bidirectional control characters."));
  }
  if (rules.rejectEncodedInstructions && encodedPayload.test(candidate.content)) {
    issues.push(issue(candidate.id, "encoded-payload", "reject", "Content contains a long encoded payload that cannot be safely interpreted as memory."));
  }
  if (candidate.memoryType === "instruction" && !rules.instructionOriginIds.includes(origin.id)) {
    issues.push(issue(candidate.id, "unauthorized-instruction", "reject", `Origin "${origin.id}" may not create persistent instructions.`));
  }
  if (candidate.memoryType !== "instruction" && origin.trust !== "trusted" && instructionLanguage.test(candidate.content)) {
    issues.push(issue(candidate.id, "instruction-disguised-as-data", "reject", "Untrusted data contains instruction-like language."));
  }
  if (rules.protectedNamespaces.includes(candidate.namespace) && origin.trust !== "trusted") {
    issues.push(issue(candidate.id, "protected-namespace", "reject", `Only trusted origins may write namespace "${candidate.namespace}".`));
  }
  if (candidate.memoryType === "preference" && origin.trust !== "trusted") {
    issues.push(issue(candidate.id, "untrusted-preference", "review", "Personal preferences require a trusted origin."));
  }
  if (["fact", "decision"].includes(candidate.memoryType) && candidate.claims.length === 0) {
    issues.push(issue(candidate.id, "missing-structured-claim", "review", "Facts and decisions need structured claims for contradiction checks."));
  }
  if (candidate.derivedFrom.includes(candidate.id)) {
    issues.push(issue(candidate.id, "self-derivation", "reject", "Candidate cannot derive from itself."));
  }
  return issues;
}

export function auditMemoryBundle(value: unknown, now = new Date()): BundleAudit {
  assertBundle(value);
  const bundle = value;
  const origins = new Map(bundle.origins.map((origin) => [origin.id, origin]));
  const active = new Map(bundle.activeMemory.map((record) => [record.id, record]));
  const candidates = new Map(bundle.candidates.map((candidate) => [candidate.id, candidate]));
  const preliminary = new Map(
    bundle.candidates.map((candidate) => [
      candidate.id,
      inspectCandidate(candidate, origins.get(candidate.originId), bundle, now),
    ])
  );
  const safeClaims = new Map<string, Set<string>>();
  for (const candidate of bundle.candidates) {
    const origin = origins.get(candidate.originId);
    if (
      origin &&
      candidate.claims.length > 0 &&
      preliminary.get(candidate.id)?.length === 0
    ) {
      const domains = safeClaims.get(claimKey(candidate.claims)) ?? new Set<string>();
      domains.add(origin.domain);
      safeClaims.set(claimKey(candidate.claims), domains);
    }
  }
  const audits: CandidateAudit[] = bundle.candidates.map((candidate) => {
    const origin = origins.get(candidate.originId);
    const issues = [...(preliminary.get(candidate.id) ?? [])];
    const domains = [...(safeClaims.get(claimKey(candidate.claims)) ?? [])].sort();
    if (
      origin &&
      origin.trust !== "trusted" &&
      ["fact", "decision"].includes(candidate.memoryType) &&
      domains.length < bundle.policy.rules.minCorroboratingDomains
    ) {
      issues.push(
        issue(
          candidate.id,
          "insufficient-corroboration",
          "review",
          `${domains.length} independent origin domain(s) do not meet the required ${bundle.policy.rules.minCorroboratingDomains}.`
        )
      );
    }
    const contradictions: string[] = [];
    for (const claim of candidate.claims) {
      for (const record of bundle.activeMemory) {
        if (Date.parse(record.expiresAt) > now.getTime()) {
          for (const existingClaim of record.claims) {
            if (
              relationKey(existingClaim) === relationKey(claim) &&
              normalize(existingClaim.value) !== normalize(claim.value)
            ) {
              contradictions.push(record.id);
            }
          }
        }
      }
      for (const other of bundle.candidates) {
        if (other.id !== candidate.id) {
          for (const otherClaim of other.claims) {
            if (
              relationKey(otherClaim) === relationKey(claim) &&
              normalize(otherClaim.value) !== normalize(claim.value)
            ) {
              contradictions.push(other.id);
            }
          }
        }
      }
    }
    if (contradictions.length > 0) {
      issues.push(issue(candidate.id, "memory-contradiction", "review", `Claim conflicts with: ${[...new Set(contradictions)].sort().join(", ")}.`));
    }
    const inheritedTaint = new Set<string>();
    if (origin?.trust === "untrusted") inheritedTaint.add("untrusted-origin");
    if (origin?.trust === "bounded") inheritedTaint.add("bounded-origin");
    for (const parentId of candidate.derivedFrom) {
      const parentActive = active.get(parentId);
      const parentCandidate = candidates.get(parentId);
      if (parentActive) parentActive.taint.forEach((entry) => inheritedTaint.add(entry));
      else if (!parentCandidate && bundle.policy.rules.requireDerivationTrace) {
        issues.push(issue(candidate.id, "missing-derivation", "reject", `Derivation parent "${parentId}" was not supplied.`));
      } else if (parentCandidate) {
        const parentIssues = preliminary.get(parentId) ?? [];
        if (parentIssues.length > 0) {
          inheritedTaint.add(`quarantined-parent:${parentId}`);
          issues.push(issue(candidate.id, "tainted-derivation", "review", `Parent candidate "${parentId}" is not clean.`));
        }
      }
    }
    if ([...inheritedTaint].some((entry) => entry !== "untrusted-origin" && entry !== "bounded-origin")) {
      issues.push(issue(candidate.id, "inherited-taint", "review", "Derived memory inherits restrictive taint from its provenance chain."));
    }
    const admission = issues.some((entry) => entry.severity === "reject")
      ? "reject"
      : issues.length > 0
        ? "quarantine"
        : "promote";
    return {
      candidateId: candidate.id,
      admission,
      riskScore: Math.min(
        100,
        issues.reduce((score, entry) => score + (entry.severity === "reject" ? 45 : 20), 0)
      ),
      corroboratingDomains: domains,
      inheritedTaint: [...inheritedTaint].sort(),
      expiresAt: expiresAt(candidate),
      issues,
    };
  });
  const promoted = audits.filter((entry) => entry.admission === "promote").length;
  const quarantined = audits.filter((entry) => entry.admission === "quarantine").length;
  const rejected = audits.filter((entry) => entry.admission === "reject").length;
  const base = {
    bundleId: bundle.id,
    policyId: bundle.policy.id,
    status: (rejected + quarantined === 0 ? "clean" : promoted === 0 ? "blocked" : "partial") as BundleAudit["status"],
    promoted,
    quarantined,
    rejected,
    candidates: audits,
    issues: audits.flatMap((entry) => entry.issues),
    auditedAt: now.toISOString(),
  };
  return { ...base, auditHash: hashValue(base) };
}
