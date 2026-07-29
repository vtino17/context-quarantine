import { describe, expect, it } from "vitest";
import {
  auditMemoryBundle,
  createSafeBundle,
  createWeakenedPolicy,
  diffPolicies,
  samplePolicy,
} from "@contextquarantine/core";
import { formatAudit, formatPolicyDiff } from "../src/format.js";

const now = new Date("2026-07-29T05:30:00.000Z");

describe("CLI formatting", () => {
  it("renders a clean admission summary", () => {
    const output = formatAudit(auditMemoryBundle(createSafeBundle(now), now));
    expect(output).toContain("Status: CLEAN");
    expect(output).toContain("4 promote");
  });

  it("renders policy weakening signals", () => {
    const output = formatPolicyDiff(diffPolicies(samplePolicy, createWeakenedPolicy()));
    expect(output).toContain("Corroboration requirement decreased");
    expect(output).toContain("Secret rejection was disabled");
  });
});
