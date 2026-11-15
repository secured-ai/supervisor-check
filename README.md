# Supervisor Check

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/secured-ai/supervisor-check/badge)](https://scorecard.dev/viewer/?uri=github.com/secured-ai/supervisor-check)

An independent checker outside the agent's reasoning loop. It derives the facts of a
proposed call from your systems of record, evaluates those facts against the deployment's
[intent envelope](https://github.com/secured-ai/intent-envelope), and signs the decision.

Layer 04 of the
[Zero-Trust Agent Reference Architecture](https://securedai.org/architecture).

## Why this exists when the envelope library already decides

The reference implementation evaluates a call against an envelope, and this does not
reimplement one line of that: it calls `evaluate()` from `intent-envelope`. Two
enforcement points that drifted by one clause would be worse than one, and that is what
the conformance suite exists to prevent.

What it adds is the part the specification requires and deliberately leaves to the
deployment. Intent Envelope 0.1, section 2.1, requirement 2:

> What the agent supplies at call time remains the agent's own claim. The envelope is
> trustworthy; the arguments and targets of a particular tool call are not, because they
> come from the thing being constrained. An enforcement point MUST evaluate constraints
> against independently derived facts, such as what a record actually contains or who a
> recipient actually is, rather than against the agent's description of the call.

The library ships a `defaultFacts` that reads the agent's own arguments, because a
library cannot know where your truth lives. That default is precisely the agent's claim.
This service is where the real answer gets plugged in.

So the order is fixed:

1. derive the facts from the systems of record
2. build the call from those facts, never from the agent's account
3. evaluate the envelope against that call, using the reference evaluator
4. sign the decision

It also runs somewhere else. The reference enforcement point is middleware inside the
agent's runtime, and anything that compromised that runtime can patch it. A control the
thing it constrains can edit is not a control.

## What that catches

The agent says it is emailing a colleague:

```json
{ "tool": "send_email", "arguments": { "to": ["u-1"] },
  "claimed": { "recipients": ["colleague@example.com"] } }
```

The directory says `u-1` is `attacker@evil.net`. The envelope permits `@example.com`.
The call is denied on `recipients`, and the record carries the contradiction:

```json
{ "outcome": "deny", "rule": "recipients",
  "detail": "attacker@evil.net is not on recipients.allow",
  "derived": { "recipients": "directory" },
  "contradictions": [
    { "field": "recipients", "claimed": ["colleague@example.com"], "actual": ["attacker@evil.net"] }
  ] }
```

Nothing here asked the model what it meant. The agent's account is kept, as evidence that
it misreported its own call, and it is never what gets evaluated.

The same shape catches an understated refund. The agent says $5, the ledger says $300, and
the envelope escalates above $100. It escalates on $300.

## Failing closed

A fact that cannot be established is a denial, not a reason to fall back to the agent's
version. Falling back would mean anything that can take the directory offline gets its own
claims evaluated instead.

That covers a resolver that throws, one that times out, and two resolvers that disagree
with each other, because at that point neither can be trusted. A crash inside the
supervisor denies too: there is no path through the service that lets a call proceed
because the supervisor had a bad day.

An unknown envelope id is also a denial rather than a `404`, so a caller cannot read a
missing envelope as permission to carry on.

## Resolvers

A resolver answers one question against one system of record.

```ts
import { Supervisor, FactsUnavailable, type Resolver } from 'supervisor-check';

const directory: Resolver = {
  name: 'directory',
  async resolve(call) {
    const ids = (call.arguments?.to as string[]) ?? [];
    const people = await lookUp(ids);              // your directory, your call
    if (people.length !== ids.length) {
      throw new FactsUnavailable('directory', 'one of these ids is not a person');
    }
    return { recipients: people.map(p => p.email) };
  },
};
```

Throwing means the fact is not established, which denies. Returning a wrong answer
quietly is the only real failure mode, so resolvers should read from the system of record
rather than from anything the agent can write to.

## Running it

Node 22.18 or newer, which strips the types without a build step. Not on npm yet.

```
git clone https://github.com/secured-ai/supervisor-check
cd supervisor-check && npm ci
```

```ts
import { createSupervisorServer, EnvelopeStore, Supervisor } from 'supervisor-check';

const store = new EnvelopeStore('./envelopes');
await store.load();

const server = createSupervisorServer({
  store,
  supervisor: new Supervisor({ resolvers: [directory, ledger] }),
  signingKeyPem: process.env.SUPERVISOR_KEY,
  kid: 'supervisor-1',
  onRecord: (record, jws) => ledgerSink.write(jws ?? JSON.stringify(record)),
});
server.listen(8080);
```

`POST /check` with `{ envelope_id, call, agent_identity?, principal?, run? }` returns the
outcome, the rule that decided it, what was derived and from where, the decision record
and a compact JWS over it. `GET /healthz` reports how many envelopes are loaded.

### The envelope store has no write path

Not a guarded one, not an authenticated one: none. Section 2.1 requirement 1 says
creating or modifying an envelope must be privileged and beyond the governed agent,
because "if an agent can draft its own, or widen an existing one, the system is asking
permission from itself". An endpoint that could write envelopes would be the most
valuable thing in the deployment to compromise, so it does not exist. Envelopes are files,
changed through whatever review your policy repository already has, and loaded at start.

### Why the record is signed

Section 5 asks for one record per evaluation, written where the decision was made. A log
line is written by the host that took the action, so a compromised host can write whatever
it likes about what it did. A record signed here, with a key the agent host never holds,
says what the supervisor actually decided. That is the difference between a log and
evidence, and it is what the Agent Action Ledger and a conformance assessment both read.

ES256 over compact JWS, the same shape the certification attestations use, so one
published JWK verifies both.

## What 0.1 does not do

**It decides escalations, it does not route them.** A call that escalates comes back as
`escalate` with the named human and the timeout from the envelope. Delivering that to a
person, holding the call while it waits, and applying `on_no_response` belongs with the
approval path, and that is the next milestone.

**It does not supply an `escalate.when` syntax.** The envelope's default matcher handles
`key` and `key <op> number|'string'`. Anything richer is passed in as `conditionMatcher`.
Spec section 7 lists a standard syntax as an open question for 0.2, and inventing one here
would prejudge it.

## Tests

```
npm test
```

Fakes only: in-memory resolvers, a temp envelope directory, a generated key. Nothing
reaches the network and nothing needs a credential.

## License

Apache-2.0.
