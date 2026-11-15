# Security policy

## Reporting a vulnerability

Report security issues in this repository to **security@securedai.org**.

Our full vulnerability disclosure policy, including scope and what to expect, is at
https://securedai.org/disclosure and in machine-readable form at
https://securedai.org/.well-known/security.txt

Please do not open a public issue for a security report.

## Scope

This service decides whether an agent's proposed action is permitted. Anything that gets
an `allow` out of it that should not be is the most serious class of defect here.

Specifically in scope:

- Any path that lets the agent's own account of a call reach the evaluator in place of
  independently derived facts. That inversion is the one thing this service exists to
  prevent.
- Any path that returns something other than a denial when a fact cannot be established:
  a resolver that throws, times out, disagrees with another resolver, or is missing.
- Any way to create or modify an envelope through this service. There is no write path by
  design, and a way around that is a finding.
- Forging or replaying a decision record, or getting one signed that the supervisor did
  not decide.
- An unknown envelope id, a malformed request or an internal error producing anything a
  caller could read as permission to proceed.

Also in scope: a credential or customer data reaching a decision record, since records are
written to a ledger and read during assessments.
