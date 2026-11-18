# Changelog

## 0.2.0

The supervisor now knows who is asking, and the agent host can tell whether
the answer is real. Both were missing, and a security review of a deployment
would have found it in the first hour.

### Breaking

- `createSupervisorServer` requires `callers`. There is no unauthenticated
  mode. A supervisor anyone can query is an oracle: ask enough questions with
  different values and the envelope is mapped, which is exactly the
  reconnaissance an attacker wants before steering an agent. It also let anyone
  put records in the ledger through `onRecord`.
- It refuses to serve plain HTTP unless `insecurePlaintext` is set, for
  deployments where TLS terminates in a mesh or sidecar on the same host.
- `/healthz` reports liveness only. It used to report how many envelopes were
  loaded.
- A caller asking about an envelope it is not registered for gets the same
  denial, word for word, as one asking about an envelope that does not exist,
  so envelope ids cannot be enumerated.

### Added

- Signed requests. Each caller holds an Ed25519 key and signs the method, path,
  a timestamp, a single-use nonce and a digest of the body. The supervisor holds
  only public keys. Requests more than 60 seconds out are refused, nonces are
  single use, and a nonce is only spent by a request whose signature verified,
  so a forger cannot burn a real caller's nonces.
- Client certificates, when the supervisor terminates TLS itself. With a
  `ca` configured the handshake requires a certificate that chains to it, and
  its SHA-256 fingerprint must also be pinned to a caller. Pinned, because any
  certificate the CA ever issued has a subject name. Configuring client
  certificates means requiring them; signing-only callers use a listener
  without a `ca`.
- A presented credential that fails is a failure, not a fallback: a valid
  certificate with a bad signature is refused, and a certificate and signature
  naming different callers are refused.
- Per-caller rate limiting, default 600 a minute.
- `onAuthFailure`, which is told the real reason for each refusal. The caller
  only ever sees `unauthenticated`.
- The response signature is bound to the request: the JWS header carries the
  SHA-256 of the request body, the caller's nonce and the caller's id. It lives
  in the header so the decision record keeps the shape spec section 5 gives it
  and the ledger stores it unchanged.
- `SupervisorClient`, the agent host's side. It takes the outcome only from a
  record whose signature verifies against a key pinned in the client, for this
  request, this nonce and this caller. Unreachable, slow, any status but 200,
  unsigned, wrongly signed, or answering a different question: every one of
  those is a deny, there is no setting that makes any of them an allow, and
  `check` never throws.

### Fixed

- A client reading the plain `outcome` field beside the signed record could be
  flipped from deny to allow by anything on the path. The client no longer reads
  it.

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
