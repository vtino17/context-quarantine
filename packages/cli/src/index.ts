#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  auditMemoryBundle,
  compilePromotionManifest,
  createSafeBundle,
  diffPolicies,
  verifyPromotionManifest,
} from "@contextquarantine/core";
import type {
  MemoryBundle,
  PromotionManifest,
  QuarantinePolicy,
} from "@contextquarantine/core";
import { formatAudit, formatCandidate, formatPolicyDiff } from "./format.js";

const help = `ContextQuarantine — deterministic admission firewall for agent memory

Usage:
  context-quarantine scan <bundle.json> [--at <ISO date>] [--json]
  context-quarantine explain <bundle.json> --candidate <id> [--at <ISO date>]
  context-quarantine promote <bundle.json> --output <manifest.json> [--at <ISO date>]
  context-quarantine verify <manifest.json> [--bundle <bundle.json>]
  context-quarantine diff <previous-policy-or-bundle.json> <next-policy-or-bundle.json> [--json]
  context-quarantine init [path]

Exit codes: 0 clean/valid, 2 blocked, 3 partial, 4 weakened policy, 5 invalid input.`;

const option = (args: string[], name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const readJson = async (path: string): Promise<unknown> =>
  JSON.parse(await readFile(resolve(path), "utf8")) as unknown;
const outputJson = (value: unknown): void => {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
};
const evaluationDate = (args: string[]): Date => {
  const input = option(args, "--at");
  if (!input) return new Date();
  const date = new Date(input);
  if (!Number.isFinite(date.getTime())) throw new Error(`Invalid --at date: ${input}`);
  return date;
};
const policyFrom = (value: unknown): QuarantinePolicy => {
  if (!value || typeof value !== "object") throw new Error("Policy input must be an object.");
  const record = value as Record<string, unknown>;
  return (record.policy ?? value) as QuarantinePolicy;
};

async function run(args: string[]): Promise<number> {
  const [command, first, second] = args;
  if (!command || ["--help", "-h", "help"].includes(command)) {
    console.log(help);
    return 0;
  }
  if (command === "init") {
    const path = resolve(first ?? "context-quarantine.json");
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(createSafeBundle(), null, 2)}\n`, "utf8");
    console.log(`Created ${path}`);
    return 0;
  }
  if (["scan", "explain", "promote"].includes(command)) {
    if (!first || first.startsWith("--")) throw new Error(`${command} requires a bundle path.`);
    const bundle = await readJson(first);
    const audit = auditMemoryBundle(bundle, evaluationDate(args));
    if (command === "scan") {
      if (args.includes("--json")) outputJson(audit);
      else console.log(formatAudit(audit));
    }
    if (command === "explain") {
      const candidateId = option(args, "--candidate");
      if (!candidateId) throw new Error("explain requires --candidate <id>.");
      const candidate = audit.candidates.find((entry) => entry.candidateId === candidateId);
      if (!candidate) throw new Error(`Unknown candidate: ${candidateId}`);
      console.log(formatCandidate(candidate));
    }
    if (command === "promote") {
      const output = option(args, "--output");
      if (!output) throw new Error("promote requires --output <manifest.json>.");
      const manifest = compilePromotionManifest({
        bundle,
        audit,
        issuedAt: evaluationDate(args),
      });
      await mkdir(dirname(resolve(output)), { recursive: true });
      await writeFile(resolve(output), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
      console.log(`Promotion manifest: ${resolve(output)}`);
      console.log(`Promoted records: ${manifest.records.length}`);
    }
    return audit.status === "clean" ? 0 : audit.status === "blocked" ? 2 : 3;
  }
  if (command === "verify") {
    if (!first || first.startsWith("--")) throw new Error("verify requires a manifest path.");
    const manifest = (await readJson(first)) as PromotionManifest;
    const bundlePath = option(args, "--bundle");
    const bundle = bundlePath ? await readJson(bundlePath) : undefined;
    const verification = verifyPromotionManifest({ manifest, bundle });
    outputJson(verification);
    return verification.valid ? 0 : 2;
  }
  if (command === "diff") {
    if (!first || !second || second.startsWith("--")) {
      throw new Error("diff requires previous and next policy or bundle paths.");
    }
    const diff = diffPolicies(
      policyFrom(await readJson(first)),
      policyFrom(await readJson(second))
    );
    if (args.includes("--json")) outputJson(diff);
    else console.log(formatPolicyDiff(diff));
    return diff.weakenedControls.length > 0 ? 4 : 0;
  }
  throw new Error(`Unknown command: ${command}\n\n${help}`);
}

run(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    console.error(`ContextQuarantine error: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 5;
  });

export type { MemoryBundle };
