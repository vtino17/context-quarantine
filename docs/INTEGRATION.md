# Integration guide

ContextQuarantine belongs on the write path before any persistent memory database, vector store, profile, session summary, or checked-in agent instruction file.

## Recommended flow

1. Capture the exact candidate content and compute its digest.
2. Attach authenticated origin identity, trust domain, timestamp, and source reference.
3. Express factual content as structured claims.
4. Include every provenance parent when content was summarized or transformed.
5. Run `scan --json`.
6. Route quarantined candidates to a human or domain-specific verifier.
7. Compile a manifest and write only `records` to durable memory.
8. Preserve the bundle and manifest in an audit store.

## CI policy gate

```yaml
- name: Reject memory-policy regression
  run: context-quarantine diff memory/policy-baseline.json memory/intake.json

- name: Admit clean candidate memory
  run: |
    context-quarantine scan memory/intake.json --at "$RUN_TIMESTAMP"
    context-quarantine promote memory/intake.json \
      --at "$RUN_TIMESTAMP" \
      --output artifacts/promotion.json
```

The fixed timestamp makes audit output reproducible. Do not allow an agent to modify both the baseline and candidate policy in the same unreviewed change.

## Adapter guidance

Adapters should fail closed when origin authentication is missing. A web URL is not an origin identity by itself: bind it to the fetched origin, response digest, and retrieval event. When a model summarizes several inputs, set `derivedFrom` to every contributing record so restrictive taint survives compression.
