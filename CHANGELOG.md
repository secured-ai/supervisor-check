# Changelog

## 0.1.0

First release.

An independent checker outside the agent's reasoning loop. It derives the facts
of a proposed call from the systems of record rather than reading them out of
the agent's arguments, evaluates them against the intent envelope, and signs
the decision.

- Steps 1 to 3 of the spec's evaluation order depend on nothing the agent
  supplies, and are evaluated before anything it does.
- `resolveFacts` fails closed. A fact that cannot be established denies, and
  resolvers that disagree with each other deny.
- The envelope store has no write path at all, because an enforcement point
  that can be told what to allow is not one.
- A supervisor that throws still denies.
- Decision records are signed ES256 over canonical JSON.

The package publishes compiled JavaScript from `dist`. Node refuses to strip
types under `node_modules`, so pointing at the TypeScript sources would throw
on a consumer's first import.
