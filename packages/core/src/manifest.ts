import { auditMemoryBundle } from "./audit.js";
import { canonicalJson, hashValue, sha256 } from "./canonical.js";
import type {
  BundleAudit,
  ManifestVerification,
  MemoryBundle,
  PromotionManifest,
} from "./types.js";
import { assertBundle } from "./validation.js";

export function compilePromotionManifest(input: {
  bundle: unknown;
  audit: BundleAudit;
  issuedAt?: Date;
}): PromotionManifest {
  assertBundle(input.bundle);
  const bundle = input.bundle;
  const expected = auditMemoryBundle(bundle, new Date(input.audit.auditedAt));
  if (canonicalJson(expected) !== canonicalJson(input.audit)) {
    throw new Error("Audit payload does not match a fresh evaluation of this bundle.");
  }
  if (input.audit.status === "blocked") {
    throw new Error("Cannot compile a promotion manifest for a blocked bundle.");
  }
  const audits = new Map(input.audit.candidates.map((entry) => [entry.candidateId, entry]));
  const issuedAt = (input.issuedAt ?? new Date()).toISOString();
  const records = bundle.candidates
    .filter((candidate) => audits.get(candidate.id)?.admission === "promote")
    .map((candidate) => {
      const audit = audits.get(candidate.id)!;
      const origin = bundle.origins.find((entry) => entry.id === candidate.originId)!;
      return {
        id: `mem:${candidate.id}`,
        candidateId: candidate.id,
        memoryType: candidate.memoryType,
        namespace: candidate.namespace,
        content: candidate.content,
        contentDigest: candidate.contentDigest,
        claims: candidate.claims,
        originDomains: [...new Set([origin.domain, ...audit.corroboratingDomains])].sort(),
        promotedAt: issuedAt,
        expiresAt: audit.expiresAt,
        taint: audit.inheritedTaint,
      };
    });
  const base = {
    manifestVersion: "1.0" as const,
    bundleId: bundle.id,
    bundleHash: hashValue(bundle),
    policyHash: hashValue(bundle.policy),
    auditHash: input.audit.auditHash,
    auditedAt: input.audit.auditedAt,
    issuedAt,
    records,
    rejectedCandidateIds: input.audit.candidates
      .filter((entry) => entry.admission !== "promote")
      .map((entry) => entry.candidateId),
  };
  return { ...base, manifestHash: sha256(canonicalJson(base)) };
}

export function verifyPromotionManifest(input: {
  manifest: PromotionManifest;
  bundle?: unknown;
}): ManifestVerification {
  const manifest = input.manifest;
  const base = {
    manifestVersion: manifest.manifestVersion,
    bundleId: manifest.bundleId,
    bundleHash: manifest.bundleHash,
    policyHash: manifest.policyHash,
    auditHash: manifest.auditHash,
    auditedAt: manifest.auditedAt,
    issuedAt: manifest.issuedAt,
    records: manifest.records,
    rejectedCandidateIds: manifest.rejectedCandidateIds,
  };
  const checks = {
    manifestHash: sha256(canonicalJson(base)) === manifest.manifestHash,
    bundleHash: true,
    policyHash: true,
    auditHash: true,
    promotedOnly: new Set(manifest.records.map((entry) => entry.candidateId)).size === manifest.records.length,
  };
  if (input.bundle !== undefined) {
    assertBundle(input.bundle);
    const bundle = input.bundle as MemoryBundle;
    const audit = auditMemoryBundle(bundle, new Date(manifest.auditedAt));
    const promoted = new Set(audit.candidates.filter((entry) => entry.admission === "promote").map((entry) => entry.candidateId));
    checks.bundleHash = hashValue(bundle) === manifest.bundleHash;
    checks.policyHash = hashValue(bundle.policy) === manifest.policyHash;
    checks.auditHash = audit.auditHash === manifest.auditHash;
    checks.promotedOnly =
      checks.promotedOnly &&
      manifest.records.every((record) => promoted.has(record.candidateId)) &&
      manifest.records.length === promoted.size;
  }
  const errors = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => `${name} check failed`);
  return { valid: errors.length === 0, checks, errors };
}
