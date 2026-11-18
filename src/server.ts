// The supervisor as a service, because out of process is the point.
//
// The reference enforcement point is middleware inside the agent's own runtime.
// Anything that compromised that runtime can patch it, and a control that the
// thing it constrains can edit is not a control. This runs somewhere else,
// holds its own signing key, and the agent host reaches it over the network
// with no way to change what it decides.
//
// Two endpoints and nothing else. There is deliberately no way to write an
// envelope over HTTP: see the note in envelopes.ts.

import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import type { EnvelopeStore } from './envelopes.ts';
import { UnknownEnvelope } from './envelopes.ts';
import type { Supervisor, CheckRequest } from './supervisor.ts';
import { buildRecord, sign, type DecisionRecord } from './record.ts';
import { CallerRegistry, RateLimiter, sha256hex, type AuthFailure, type Caller } from './auth.ts';

export interface ServeOptions {
  store: EnvelopeStore;
  supervisor: Supervisor;
  /** PEM. Absent means records are returned unsigned, which the response states. */
  signingKeyPem?: string;
  kid?: string;
  /** Called with every record, for whatever ledger the deployment runs. */
  onRecord?: (record: DecisionRecord, jws: string | null) => void;

  /**
   * Who may ask. Required: there is no unauthenticated mode, because a
   * supervisor anyone can query is an oracle for the policy it enforces.
   * See auth.ts.
   */
  callers: Caller[];

  /**
   * Terminate TLS here. With `ca`, every connection must present a client
   * certificate that chains to it, enforced in the handshake, and a caller
   * identified by certificate also needs its fingerprint pinned. Without
   * `ca`, no certificate is asked for and callers sign their requests.
   */
  tls?: { key: string | Buffer; cert: string | Buffer; ca?: string | Buffer | Array<string | Buffer> };

  /**
   * Serve plain HTTP. Only for a deployment where TLS terminates in front of
   * this process, in a service mesh or a sidecar, and the hop between the two
   * never leaves the host. It must be said out loud, so it is a flag rather
   * than the default. Callers still sign every request either way.
   */
  insecurePlaintext?: boolean;

  /** Per caller. Default 600. */
  rateLimitPerMinute?: number;

  /**
   * Told why each refusal happened. The response a caller gets is
   * deliberately vague, since telling an attacker which part of a forged
   * request failed is a free lesson in forging the next one. The reason goes
   * here instead, for whoever is watching.
   */
  onAuthFailure?: (reason: AuthFailure | 'forbidden_envelope' | 'rate_limited', detail: { remote?: string; caller?: string }) => void;

  /** For tests. */
  now?: () => number;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body, null, 2);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(text);
}

async function readBody(req: IncomingMessage, limit = 256 * 1024): Promise<Buffer> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new Error('request body too large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

/**
 * One answer for "that envelope does not exist" and "that envelope is not
 * yours". If they differed, a caller could enumerate every other host's
 * envelope ids by watching which way it was refused.
 */
function noSuchEnvelope(envelopeId: string) {
  return {
    outcome: 'deny', rule: 'envelope',
    detail: `no envelope ${envelopeId} is available to this caller`,
    envelope_id: envelopeId, decided_at: new Date().toISOString(), signed: false,
  };
}

export function createSupervisorServer(opts: ServeOptions): HttpServer | HttpsServer {
  if (!opts.tls && !opts.insecurePlaintext) {
    throw new Error('the supervisor will not serve plain HTTP by default: pass tls, or set insecurePlaintext ' +
      'when TLS terminates in front of it on the same host');
  }
  const now = opts.now ?? Date.now;
  const registry = new CallerRegistry(opts.callers, { now });
  const limiter = new RateLimiter(opts.rateLimitPerMinute ?? 600, now);
  const refuse = (res: ServerResponse, req: IncomingMessage, reason: AuthFailure | 'forbidden_envelope' | 'rate_limited', caller?: string) => {
    opts.onAuthFailure?.(reason, { remote: req.socket.remoteAddress, caller });
    if (reason === 'rate_limited') return send(res, 429, { error: 'rate_limited' });
    return send(res, 401, { error: 'unauthenticated' });
  };

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    // Reports liveness and nothing else. It used to report how many envelopes
    // were loaded, which is a small fact, and a free one to anybody who asked.
    if (req.method === 'GET' && req.url === '/healthz') {
      return send(res, 200, { ok: true });
    }
    if (req.method !== 'POST' || req.url !== '/check') {
      return send(res, 404, { error: 'not_found' });
    }

    let raw: Buffer;
    try {
      raw = await readBody(req);
    } catch (e) {
      return send(res, 400, { error: 'bad_request', detail: (e as Error).message });
    }

    // Before the body is parsed, and long before anything is evaluated. An
    // unauthenticated request learns nothing, not even whether its JSON was valid.
    const auth = registry.authenticate(req, raw);
    if (!auth.ok) return refuse(res, req, auth.reason);
    if (!limiter.take(auth.caller.id)) return refuse(res, req, 'rate_limited', auth.caller.id);

    let body: CheckRequest;
    try {
      body = JSON.parse(raw.toString('utf8') || '{}') as CheckRequest;
    } catch (e) {
      return send(res, 400, { error: 'bad_request', detail: (e as Error).message });
    }
    if (!body || typeof body.envelope_id !== 'string' || !body.call || typeof body.call.tool !== 'string') {
      return send(res, 400, { error: 'bad_request', detail: 'envelope_id and call.tool are required' });
    }

    // An unknown envelope is a denial, not an error. A caller that asked for an
    // envelope this service does not have must not read a 404 as "carry on".
    if (!registry.mayAsk(auth.caller, body.envelope_id)) {
      opts.onAuthFailure?.('forbidden_envelope', { remote: req.socket.remoteAddress, caller: auth.caller.id });
      return send(res, 200, noSuchEnvelope(body.envelope_id));
    }
    let stored;
    try {
      stored = opts.store.get(body.envelope_id);
    } catch (e) {
      if (!(e instanceof UnknownEnvelope)) throw e;
      return send(res, 200, noSuchEnvelope(body.envelope_id));
    }

    let result;
    try {
      result = await opts.supervisor.check(stored.envelope, body);
    } catch (e) {
      // Even a crash denies. There is no path through this handler that lets a
      // call proceed because the supervisor had a bad day.
      return send(res, 200, {
        outcome: 'deny', rule: 'supervisor', detail: `the supervisor failed: ${(e as Error).message}`,
        envelope_id: body.envelope_id, decided_at: new Date().toISOString(), signed: false,
      });
    }

    const record = buildRecord(result, body.call, stored.digest, {
      agent_identity: body.agent_identity, principal: body.principal,
    });
    const jws = opts.signingKeyPem
      ? sign(record, opts.signingKeyPem, opts.kid, {
          req: sha256hex(raw), aud: auth.caller.id, ...(auth.nonce ? { nonce: auth.nonce } : {}),
        })
      : null;
    opts.onRecord?.(record, jws);

    return send(res, 200, { ...result, record, signed: Boolean(jws), jws });
  };

  const wrapped = (req: IncomingMessage, res: ServerResponse) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) send(res, 500, { error: 'internal' });
    });
  };

  if (opts.tls) {
    // With a client CA configured, every connection must present a
    // certificate that chains to it, and the handshake enforces that before
    // any request is read. Which caller a certificate belongs to is still
    // decided per request, by pinned fingerprint, because the CA vouches for
    // everything it ever issued and that is not the same as vouching for a
    // caller. Without a client CA no certificate is requested, and callers
    // authenticate by signing.
    //
    // An earlier version asked for a certificate without demanding one, so
    // signing-only callers could share the listener, and checked each
    // certificate per request instead. That worked, and it meant switching
    // certificate validation off in the handshake, which a reviewer is right
    // to read as a red flag. Requiring the certificate is the stronger
    // posture: if you configure client certificates, you get them.
    const mutual = opts.tls.ca ? { ca: opts.tls.ca, requestCert: true, rejectUnauthorized: true } : {};
    return createHttpsServer({
      key: opts.tls.key, cert: opts.tls.cert,
      ...mutual,
      minVersion: 'TLSv1.2',
    }, wrapped);
  }
  return createHttpServer(wrapped);
}
