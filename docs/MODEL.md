# Memory intake model

A bundle contains the policy, known origins, existing active memory, and candidate writes evaluated in one deterministic admission run.

## Origins

Each origin has:

- `id`: stable identity used by policy;
- `kind`: `human`, `agent`, `tool`, `service`, or `web`;
- `trust`: `trusted`, `bounded`, or `untrusted`;
- `domain`: independence boundary used by corroboration.

Two IDs in the same domain count as one corroborating source. Production integrations should derive these fields from authenticated workload or user identity rather than accepting self-declared values.

## Candidates

| Field | Purpose |
| --- | --- |
| `memoryType` | `fact`, `preference`, `instruction`, or `decision`. |
| `namespace` | Policy compartment such as `research`, `workflow`, or `authority`. |
| `content` | Exact text proposed for persistence. |
| `originId` | Declared source identity. |
| `observedAt` | Trusted timestamp for lifetime calculation. |
| `sourceRef` | External source or event identifier. |
| `contentDigest` | SHA-256 digest of exact UTF-8 content. |
| `sensitivity` | `public`, `internal`, or `secret`. |
| `requestedTtlHours` | Requested durable lifetime. |
| `claims` | Structured subject/predicate/value statements. |
| `derivedFrom` | Candidate or active-memory parents. |

Facts and decisions should include structured claims. The engine normalizes these claims for corroboration and contradiction checks without calling a model.

## Admissions

- `promote`: every applicable control passes.
- `quarantine`: no hard rejection occurred, but review is required.
- `reject`: at least one hard policy violation occurred.

Bundle status is `clean` when every candidate promotes, `partial` when promotion and non-promotion are mixed, and `blocked` when no candidate can promote.
