# Security policy

## Reporting

Use GitHub private vulnerability reporting for sensitive findings. Do not publish exploit payloads, credentials, or private memory bundles in an issue. Include a sanitized reproduction, affected rule, impact, and suggested mitigation.

## Important limitations

ContextQuarantine is a deterministic policy engine, not an origin authenticator, factual oracle, malware sandbox, or digital-signature system. Its security depends on trustworthy origin metadata and a protected policy baseline. Read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) before production use.
