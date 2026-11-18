// The agent host's side of the conversation.
//
// Authenticating callers protects the supervisor. It does nothing for the
// agent host, which still has to believe the answer, and the obvious way to
// read the answer is wrong. The response carries `outcome` at the top level,
// in plain JSON, beside a signed record. Anything on the path can rewrite the
// plain JSON from deny to allow and leave the signature alone, and a client
// that reads `outcome` will act on the rewrite.
//
// So this client takes nothing from the response that the signature does not
// cover, and it treats every way of failing to establish an answer as a deny:
//
//   unreachable, timed out, refused       deny
//   any status but 200                    deny
//   no signature                          deny
//   a signature that does not verify      deny, against a key pinned here,
//                                         never one fetched from the server
//   signed, but for a different request   deny: a captured allow is not a
//                                         reusable token
//   signed for this request               whatever the signed record says
//
// There is no setting that turns any of these into an allow. A control that
// fails open under load or a network blip is a control an attacker can switch
// off by causing either.

import type { CheckRequest } from './supervisor.ts';
import { verifyWithHeader, type DecisionRecord } from './record.ts';
import { HEADERS, sha256hex, signRequest } from './auth.ts';

export interface ClientOptions {
  /** The supervisor's base URL, for example https://supervisor.internal:8443 */
  url: string;
  /** This host's id, as registered in the supervisor's callers. */
  callerId: string;
  /** Ed25519 private key, PKCS8 PEM, matching the publicKeyPem the supervisor holds for this caller. */
  privateKeyPem: string;
  /**
   * The supervisor's ES256 public key, SPKI PEM. Pinned here and never taken
   * from a response, because a key the server supplies proves only that
   * whoever answered had a key.
   */
  supervisorPublicKeyPem: string;
  /** Default 2000. The agent waits this long for an answer, then denies. */
  timeoutMs?: number;
  /** For an mTLS-capable dispatcher, or for tests. Defaults to global fetch. */
  fetch?: typeof fetch;
  now?: () => number;
}

export type ClientOutcome = 'allow' | 'deny' | 'escalate';

export interface ClientDecision {
  outcome: ClientOutcome;
  /** Why, in words a person reading the agent's logs can act on. */
  reason: string;
  /** True only when the outcome came from a record whose signature verified for this request. */
  verified: boolean;
  record?: DecisionRecord;
  jws?: string;
  escalate_to?: string | null;
}

function deny(reason: string): ClientDecision {
  return { outcome: 'deny', reason, verified: false };
}

export class SupervisorClient {
  private readonly opts: ClientOptions;

  constructor(opts: ClientOptions) {
    if (!opts.url || !opts.callerId || !opts.privateKeyPem || !opts.supervisorPublicKeyPem) {
      throw new Error('url, callerId, privateKeyPem and supervisorPublicKeyPem are all required');
    }
    this.opts = opts;
  }

  /** Never throws. Every failure is a deny with a reason. */
  async check(request: CheckRequest): Promise<ClientDecision> {
    try {
      return await this.checkOrThrow(request);
    } catch (e) {
      return deny(`the supervisor's answer could not be established: ${(e as Error).message}`);
    }
  }

  private async checkOrThrow(request: CheckRequest): Promise<ClientDecision> {
    const path = '/check';
    const body = Buffer.from(JSON.stringify(request));
    const headers = signRequest('POST', path, body, this.opts.callerId, this.opts.privateKeyPem,
      (this.opts.now ?? Date.now)());
    const nonce = headers[HEADERS.nonce];
    const doFetch = this.opts.fetch ?? fetch;

    // An explicit timer, not AbortSignal.timeout(). That one is unreferenced,
    // so it only fires while something else holds the process open: a stalled
    // transport that holds nothing would leave the agent waiting forever
    // instead of denying. It covers reading the body as well as the headers,
    // because a supervisor that answers 200 and then stalls is as unanswered
    // as one that never answers. The timer races the whole exchange, so the
    // deny happens even if the transport ignores the abort.
    const controller = new AbortController();
    const timeoutMs = this.opts.timeoutMs ?? 2000;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error(`no answer within ${timeoutMs}ms`));
      }, timeoutMs);
    });

    const exchange = async (): Promise<{ status: number; payload: { jws?: unknown } | null }> => {
      const res = await doFetch(new URL(path, this.opts.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body,
        signal: controller.signal,
      });
      if (res.status !== 200) return { status: res.status, payload: null };
      return { status: 200, payload: await res.json() as { jws?: unknown } };
    };

    let answer: { status: number; payload: { jws?: unknown } | null };
    try {
      answer = await Promise.race([exchange(), timedOut]);
    } catch (e) {
      return deny(`the supervisor could not be reached: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
    if (answer.status !== 200 || !answer.payload) return deny(`the supervisor answered ${answer.status}`);

    const payload = answer.payload;
    if (typeof payload.jws !== 'string' || !payload.jws) {
      // Includes the supervisor's own unsigned denials, for an unknown envelope
      // or a crash. Those were denials anyway; nothing unsigned can be an allow.
      return deny('the answer was not signed, so it cannot be an allow');
    }

    const verified = verifyWithHeader(payload.jws, this.opts.supervisorPublicKeyPem);
    if (!verified) return deny('the answer was signed, but not by the pinned supervisor key');

    const { header, record } = verified;
    if (header.req !== sha256hex(body)) return deny('the signed answer is for a different request');
    if (header.nonce !== nonce) return deny('the signed answer does not carry this request\'s nonce, so it may be a replay');
    if (header.aud !== this.opts.callerId) return deny('the signed answer was issued to a different caller');
    if (record.envelope_id !== request.envelope_id) return deny('the signed answer is about a different envelope');

    if (record.result === 'allow' || record.result === 'escalate' || record.result === 'deny') {
      return {
        outcome: record.result,
        reason: `${record.rule}: ${record.detail}`,
        verified: true,
        record,
        jws: payload.jws,
        escalate_to: record.escalated_to ?? null,
      };
    }
    return deny(`the signed record has an outcome this client does not know: ${String(record.result)}`);
  }
}
