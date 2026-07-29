# Policy semantics

## Corroboration

`minCorroboratingDomains` applies to facts and decisions from bounded or untrusted origins. Candidates corroborate one another when their normalized structured claims match. Only clean candidates from distinct origin domains count.

Trusted origins bypass corroboration; they do not bypass digest, timestamp, secret, hidden-Unicode, or derivation checks.

## Instruction authority

`instructionOriginIds` is an explicit allowlist. A candidate typed as an instruction is rejected when its origin is absent. Instruction-like language disguised as untrusted facts, preferences, or decisions is also rejected.

This is a lexical safety boundary, not a full natural-language classifier. Keep the allowlist narrow even when an external classifier is available.

## Lifetime and namespaces

`maxTtlHours` defines separate ceilings for each trust level. Requests above the ceiling are quarantined rather than silently truncated. `protectedNamespaces` deny bounded and untrusted writes.

## Content defenses

- `rejectSecrets` rejects secret-labelled content and common token/key formats.
- `rejectEncodedInstructions` rejects long base64-like or percent-encoded payloads.
- `rejectHiddenUnicode` rejects invisible and bidirectional control characters.
- `requireDerivationTrace` rejects references to unavailable provenance parents.

## Regression detection

The policy diff identifies weaker changes: lower corroboration, new instruction writers, removed namespace protections, longer TTLs, and disabled content or provenance defenses. Run it against a protected baseline in CI.
