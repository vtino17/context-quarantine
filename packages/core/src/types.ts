export type TrustLevel = "trusted" | "bounded" | "untrusted";
export type OriginKind = "human" | "agent" | "tool" | "service" | "web";
export type MemoryType = "fact" | "preference" | "instruction" | "decision";
export type Sensitivity = "public" | "internal" | "secret";
export type Admission = "promote" | "quarantine" | "reject";

export interface MemoryOrigin {
  id: string;
  label: string;
  kind: OriginKind;
  trust: TrustLevel;
  domain: string;
}

export interface Claim {
  subject: string;
  predicate: string;
  value: string;
}

export interface MemoryCandidate {
  id: string;
  memoryType: MemoryType;
  namespace: string;
  content: string;
  originId: string;
  observedAt: string;
  sourceRef: string;
  contentDigest: string;
  sensitivity: Sensitivity;
  requestedTtlHours: number;
  tags: string[];
  claims: Claim[];
  derivedFrom: string[];
}

export interface ActiveMemory {
  id: string;
  memoryType: MemoryType;
  namespace: string;
  content: string;
  contentDigest: string;
  claims: Claim[];
  originDomains: string[];
  promotedAt: string;
  expiresAt: string;
  taint: string[];
}

export interface QuarantineRules {
  minCorroboratingDomains: number;
  instructionOriginIds: string[];
  protectedNamespaces: string[];
  maxTtlHours: Record<TrustLevel, number>;
  rejectSecrets: boolean;
  rejectEncodedInstructions: boolean;
  rejectHiddenUnicode: boolean;
  requireDerivationTrace: boolean;
}

export interface QuarantinePolicy {
  schemaVersion: "1.0";
  id: string;
  description: string;
  rules: QuarantineRules;
}

export interface MemoryBundle {
  schemaVersion: "1.0";
  id: string;
  policy: QuarantinePolicy;
  origins: MemoryOrigin[];
  activeMemory: ActiveMemory[];
  candidates: MemoryCandidate[];
}

export interface AdmissionIssue {
  code: string;
  severity: "review" | "reject";
  message: string;
  candidateId?: string;
}

export interface CandidateAudit {
  candidateId: string;
  admission: Admission;
  riskScore: number;
  corroboratingDomains: string[];
  inheritedTaint: string[];
  expiresAt: string;
  issues: AdmissionIssue[];
}

export interface BundleAudit {
  bundleId: string;
  policyId: string;
  status: "clean" | "partial" | "blocked";
  promoted: number;
  quarantined: number;
  rejected: number;
  candidates: CandidateAudit[];
  issues: AdmissionIssue[];
  auditedAt: string;
  auditHash: string;
}

export interface PromotionRecord {
  id: string;
  candidateId: string;
  memoryType: MemoryType;
  namespace: string;
  content: string;
  contentDigest: string;
  claims: Claim[];
  originDomains: string[];
  promotedAt: string;
  expiresAt: string;
  taint: string[];
}

export interface PromotionManifest {
  manifestVersion: "1.0";
  bundleId: string;
  bundleHash: string;
  policyHash: string;
  auditHash: string;
  auditedAt: string;
  issuedAt: string;
  records: PromotionRecord[];
  rejectedCandidateIds: string[];
  manifestHash: string;
}

export interface ManifestVerification {
  valid: boolean;
  checks: {
    manifestHash: boolean;
    bundleHash: boolean;
    policyHash: boolean;
    auditHash: boolean;
    promotedOnly: boolean;
  };
  errors: string[];
}

export interface PolicyDiff {
  from: string;
  to: string;
  weakenedControls: string[];
  strengthenedControls: string[];
}
