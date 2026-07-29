# Threat model

ContextQuarantine is designed to reduce:

- indirect prompt injection persisted as memory;
- untrusted sources writing durable behavioral instructions;
- false facts admitted from one origin;
- session summaries laundering poisoned source content;
- secret or credential persistence;
- invisible Unicode and opaque encoded payloads;
- stale or overlong untrusted memory;
- contradictions hidden by append-only memory;
- policy weakening before admission.

## Out of scope

The engine does not:

- authenticate origin IDs or trust domains;
- determine whether a corroborated claim is objectively true;
- detect every natural-language instruction or secret format;
- inspect images, binaries, embeddings, or encrypted content;
- stop same-turn prompt injection before memory admission;
- prevent colluding origin domains;
- sign manifests or provide non-repudiation;
- replace sandboxing, least privilege, or human review.

## Production hardening

Use workload identity and signed provenance, content-addressed source snapshots, protected policies, append-only audit storage, domain-specific secret detection, sandboxed decoders, and a separate reviewer for quarantined memory. Never let the agent that proposes a memory redefine its own trust level or admission policy.
