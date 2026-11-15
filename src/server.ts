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

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { EnvelopeStore } from './envelopes.ts';
import { UnknownEnvelope } from './envelopes.ts';
import type { Supervisor, CheckRequest } from './supervisor.ts';
import { buildRecord, sign, type DecisionRecord } from './record.ts';

export interface ServeOptions {
  store: EnvelopeStore;
  supervisor: Supervisor;
  /** PEM. Absent means records are returned unsigned, which the response states. */
  signingKeyPem?: string;
  kid?: string;
  /** Called with every record, for whatever ledger the deployment runs. */
  onRecord?: (record: DecisionRecord, jws: string | null) => void;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body, null, 2);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(text);
}

async function readJson(req: IncomingMessage, limit = 256 * 1024): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new Error('request body too large');
    chunks.push(chunk as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

export function createSupervisorServer(opts: ServeOptions): Server {
  return createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/healthz') {
      return send(res, 200, { ok: true, envelopes: opts.store.size });
    }
    if (req.method !== 'POST' || req.url !== '/check') {
      return send(res, 404, { error: 'not_found' });
    }

    let body: CheckRequest;
    try {
      body = await readJson(req) as CheckRequest;
    } catch (e) {
      return send(res, 400, { error: 'bad_request', detail: (e as Error).message });
    }
    if (!body || typeof body.envelope_id !== 'string' || !body.call || typeof body.call.tool !== 'string') {
      return send(res, 400, { error: 'bad_request', detail: 'envelope_id and call.tool are required' });
    }

    // An unknown envelope is a denial, not an error. A caller that asked for an
    // envelope this service does not have must not read a 404 as "carry on".
    let stored;
    try {
      stored = opts.store.get(body.envelope_id);
    } catch (e) {
      if (!(e instanceof UnknownEnvelope)) throw e;
      return send(res, 200, {
        outcome: 'deny', rule: 'envelope', detail: e.message,
        envelope_id: body.envelope_id, decided_at: new Date().toISOString(), signed: false,
      });
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
    const jws = opts.signingKeyPem ? sign(record, opts.signingKeyPem, opts.kid) : null;
    opts.onRecord?.(record, jws);

    return send(res, 200, { ...result, record, signed: Boolean(jws), jws });
  });
}
