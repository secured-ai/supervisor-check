// The decision record, signed.
//
// Intent Envelope 0.1, section 5, asks for one record per evaluation carrying
// the envelope id and revision, the agent, the principal, the tool and target,
// the result, the rule that decided it and the cost, written where the decision
// was made rather than assembled from logs afterwards.
//
// This signs it as well, for a reason specific to running out of process. A log
// line is written by the host that took the action, so a host that was
// compromised can write whatever it likes about what it did. A record signed
// here, by a key the agent host never holds, says what the supervisor actually
// decided. That is the difference between a log and evidence, and it is what
// the Agent Action Ledger and a conformance assessment both need.
//
// ES256 over compact JWS, the same shape the certification attestations use, so
// one published JWK verifies both.

import { createHash, createSign, createVerify, createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import type { CheckResult } from './supervisor.ts';
import type { ProposedCall } from './resolvers.ts';

export interface DecisionRecord {
  envelope_id: string;
  revision?: number;
  envelope_digest: string;
  agent_identity?: string;
  principal?: string;
  tool: string;
  target: string[] | null;
  result: string;
  rule: string;
  detail: string;
  cost_usd: number;
  escalated_to?: string | null;
  decided_at: string;
  /** Which system of record established which fact. */
  derived_from: Record<string, string>;
  /** Fields where the agent's account did not match the system of record. */
  contradicted: string[];
}

export function buildRecord(
  result: CheckResult, call: ProposedCall, envelopeDigest: string,
  meta: { agent_identity?: string; principal?: string } = {},
): DecisionRecord {
  return {
    envelope_id: result.envelope_id,
    revision: result.revision,
    envelope_digest: envelopeDigest,
    agent_identity: meta.agent_identity,
    principal: meta.principal,
    tool: call.tool,
    target: null,
    result: result.outcome,
    rule: result.rule,
    detail: result.detail,
    cost_usd: 0,
    escalated_to: result.escalate_to ?? null,
    decided_at: result.decided_at,
    derived_from: result.derived,
    contradicted: result.contradictions.map(c => c.field),
  };
}

/** Stable key order, so the same record hashes and signs the same way twice. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return '{' + entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',') + '}';
}

export function digestOf(value: unknown): string {
  return 'sha256:' + createHash('sha256').update(canonical(value)).digest('hex');
}

const b64url = (buf: Buffer) => buf.toString('base64url');

/** Compact JWS, ES256, detached from nothing: the payload is the record. */
export function sign(record: DecisionRecord, privateKeyPem: string, kid?: string): string {
  const key: KeyObject = createPrivateKey(privateKeyPem);
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT', ...(kid ? { kid } : {}) })));
  const payload = b64url(Buffer.from(canonical(record)));
  const signer = createSign('SHA256');
  signer.update(`${header}.${payload}`);
  const sig = signer.sign({ key, dsaEncoding: 'ieee-p1363' });
  return `${header}.${payload}.${b64url(sig)}`;
}

export function publicKeyOf(privateKeyPem: string): string {
  return createPublicKey(createPrivateKey(privateKeyPem))
    .export({ type: 'spki', format: 'pem' }).toString();
}

export function verify(jws: string, publicKeyPem: string): DecisionRecord | null {
  const parts = jws.split('.');
  if (parts.length !== 3) return null;
  const [header, payload, sig] = parts;
  const v = createVerify('SHA256');
  v.update(`${header}.${payload}`);
  const ok = v.verify(
    { key: createPublicKey(publicKeyPem), dsaEncoding: 'ieee-p1363' },
    Buffer.from(sig, 'base64url'));
  if (!ok) return null;
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as DecisionRecord;
}
