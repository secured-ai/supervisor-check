// Fakes only: in-memory resolvers, a temp envelope directory, a generated key.
// Nothing reaches the network and nothing needs a credential.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Supervisor } from '../src/supervisor.ts';
import { EnvelopeStore, UnknownEnvelope } from '../src/envelopes.ts';
import { FactsUnavailable, resolveFacts, type Resolver } from '../src/resolvers.ts';
import { buildRecord, canonical, digestOf, publicKeyOf, sign, verify } from '../src/record.ts';
import type { Envelope } from 'intent-envelope';

const ENVELOPE: Envelope = {
  id: 'support-bot',
  revision: 3,
  tools: { allow: [{ name: 'send_email' }, { name: 'issue_refund' }] },
  recipients: { allow: ['@example.com'] },
  limits: { max_tool_calls: 100, max_spend_usd: 500 },
  escalate: [{ when: "amount_usd > 100", to: 'dana@example.com', timeout_seconds: 3600 }],
  on_no_response: 'deny',
} as unknown as Envelope;

/** A directory that reports who an id actually belongs to. */
const directory = (map: Record<string, string>): Resolver => ({
  name: 'directory',
  async resolve(call) {
    const ids = (call.arguments?.to as string[] | undefined) ?? [];
    const out: string[] = [];
    for (const id of ids) {
      const real = map[id];
      if (!real) throw new FactsUnavailable('directory', `no record of recipient ${id}`);
      out.push(real);
    }
    return { recipients: out };
  },
});

/** A ledger that reports what a transfer is actually worth. */
const ledger = (amounts: Record<string, number>): Resolver => ({
  name: 'ledger',
  async resolve(call) {
    const ref = call.arguments?.order as string | undefined;
    if (ref === undefined) return {};
    const amount = amounts[ref];
    if (amount === undefined) throw new FactsUnavailable('ledger', `no order ${ref}`);
    return { amount_usd: amount, context: { amount_usd: amount } };
  },
});

function supervisor(resolvers: Resolver[]) {
  return new Supervisor({ resolvers, now: () => new Date('2026-11-14T12:00:00Z') });
}

// ---------- the point of the whole service ----------

test('the agent does not get its own claim evaluated', async () => {
  // The agent says it is emailing a colleague. The directory says that id is
  // an outside address. The envelope only permits @example.com.
  const s = supervisor([directory({ 'u-1': 'attacker@evil.net' })]);
  const out = await s.check(ENVELOPE, {
    envelope_id: 'support-bot',
    call: {
      tool: 'send_email',
      arguments: { to: ['u-1'] },
      claimed: { recipients: ['colleague@example.com'] },
    },
  });
  assert.equal(out.outcome, 'deny');
  assert.equal(out.rule, 'recipients');
  assert.match(out.detail, /attacker@evil\.net/);
  assert.deepEqual(out.contradictions, [
    { field: 'recipients', claimed: ['colleague@example.com'], actual: ['attacker@evil.net'] },
  ]);
});

test('a call the directory confirms is allowed, and says who confirmed it', async () => {
  const s = supervisor([directory({ 'u-2': 'dana@example.com' })]);
  const out = await s.check(ENVELOPE, {
    envelope_id: 'support-bot',
    call: { tool: 'send_email', arguments: { to: ['u-2'] }, claimed: { recipients: ['dana@example.com'] } },
  });
  assert.equal(out.outcome, 'allow');
  assert.equal(out.derived.recipients, 'directory');
  assert.deepEqual(out.contradictions, []);
});

test('facts that cannot be established deny, they do not fall back to the agent', async () => {
  const s = supervisor([directory({})]);          // the directory knows nobody
  const out = await s.check(ENVELOPE, {
    envelope_id: 'support-bot',
    call: { tool: 'send_email', arguments: { to: ['u-9'] }, claimed: { recipients: ['dana@example.com'] } },
  });
  assert.equal(out.outcome, 'deny');
  assert.equal(out.rule, 'facts');
  assert.match(out.detail, /no record of recipient u-9/);
});

test('a resolver that hangs denies rather than waiting forever', async () => {
  const slow: Resolver = { name: 'slow', resolve: () => new Promise(() => {}) };
  const s = new Supervisor({ resolvers: [slow], resolveTimeoutMs: 20, now: () => new Date() });
  const out = await s.check(ENVELOPE, {
    envelope_id: 'support-bot', call: { tool: 'send_email', arguments: { to: ['u-1'] } },
  });
  assert.equal(out.outcome, 'deny');
  assert.match(out.detail, /did not answer within 20ms/);
});

test('two resolvers that disagree deny, because neither can be trusted', async () => {
  const a: Resolver = { name: 'a', resolve: async () => ({ recipients: ['x@example.com'] }) };
  const b: Resolver = { name: 'b', resolve: async () => ({ recipients: ['y@example.com'] }) };
  await assert.rejects(
    () => resolveFacts({ tool: 't' }, [a, b]),
    (e: FactsUnavailable) => /disagrees with a about recipients/.test(e.message));
});

test('escalation fires on the derived amount, not the claimed one', async () => {
  // The agent says the refund is $5. The ledger says the order is $900.
  const s = supervisor([ledger({ 'o-7': 300 })]);
  const out = await s.check(ENVELOPE, {
    envelope_id: 'support-bot',
    call: { tool: 'issue_refund', arguments: { order: 'o-7' }, claimed: { estimated_cost_usd: 5 } },
  });
  assert.equal(out.outcome, 'escalate');
  assert.equal(out.escalate_to, 'dana@example.com');
  assert.equal(out.timeout_seconds, 3600);
  assert.deepEqual(out.contradictions, [{ field: 'amount_usd', claimed: 5, actual: 300 }]);
});

test('a small refund the ledger agrees with is allowed', async () => {
  const s = supervisor([ledger({ 'o-8': 12 })]);
  const out = await s.check(ENVELOPE, {
    envelope_id: 'support-bot',
    call: { tool: 'issue_refund', arguments: { order: 'o-8' }, claimed: { estimated_cost_usd: 12 } },
  });
  assert.equal(out.outcome, 'allow');
});

test('a tool outside the envelope is denied before anything else happens', async () => {
  const s = supervisor([directory({ 'u-2': 'dana@example.com' })]);
  const out = await s.check(ENVELOPE, {
    envelope_id: 'support-bot', call: { tool: 'delete_account', arguments: { to: ['u-2'] } },
  });
  assert.equal(out.outcome, 'deny');
  assert.equal(out.rule, 'tools.allow');
});

test('the agent cannot widen the envelope through context', async () => {
  const s = supervisor([directory({ 'u-1': 'attacker@evil.net' })]);
  const out = await s.check(ENVELOPE, {
    envelope_id: 'support-bot',
    call: {
      tool: 'send_email',
      arguments: { to: ['u-1'], recipients_allow: ['@evil.net'], approved: true },
      claimed: { recipients: ['attacker@evil.net'] },
    },
  });
  assert.equal(out.outcome, 'deny');
});

// ---------- the envelope store ----------

async function storeWith(files: Record<string, unknown>) {
  const dir = await mkdtemp(join(tmpdir(), 'sc-'));
  for (const [name, body] of Object.entries(files)) {
    await writeFile(join(dir, name), JSON.stringify(body));
  }
  const store = new EnvelopeStore(dir);
  await store.load();
  return store;
}

test('the store has no write path at all', async () => {
  const store = await storeWith({ 'a.json': ENVELOPE });
  // Requirement 2.1(1): an agent that can write an envelope is asking
  // permission from itself. The guard is that the method does not exist.
  for (const name of ['put', 'set', 'write', 'save', 'create', 'update', 'delete']) {
    assert.equal((store as unknown as Record<string, unknown>)[name], undefined,
      `EnvelopeStore must not expose ${name}`);
  }
});

test('an unknown envelope id throws rather than returning a different one', async () => {
  const store = await storeWith({ 'a.json': ENVELOPE });
  assert.throws(() => store.get('not-this-one'), UnknownEnvelope);
  assert.equal(store.get('support-bot').envelope.revision, 3);
});

test('one id defined twice is refused at load', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sc-'));
  await writeFile(join(dir, 'a.json'), JSON.stringify(ENVELOPE));
  await writeFile(join(dir, 'b.json'), JSON.stringify(ENVELOPE));
  await assert.rejects(() => new EnvelopeStore(dir).load(),
    (e: UnknownEnvelope) => /defined twice/.test(e.message));
});

test('the digest changes when the envelope text does', async () => {
  const a = await storeWith({ 'a.json': ENVELOPE });
  const b = await storeWith({ 'a.json': { ...ENVELOPE, revision: 4 } });
  assert.notEqual(a.get('support-bot').digest, b.get('support-bot').digest);
  assert.match(a.get('support-bot').digest, /^sha256:[0-9a-f]{64}$/);
});

// ---------- the record ----------

const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

test('a record is signed by a key the agent host never holds, and verifies', async () => {
  const s = supervisor([directory({ 'u-2': 'dana@example.com' })]);
  const call = { tool: 'send_email', arguments: { to: ['u-2'] } };
  const out = await s.check(ENVELOPE, { envelope_id: 'support-bot', call });
  const record = buildRecord(out, call, 'sha256:deadbeef', { agent_identity: 'agent-1', principal: 'user-7' });

  const jws = sign(record, PEM, 'sup-1');
  const back = verify(jws, publicKeyOf(PEM));
  assert.ok(back);
  assert.equal(back!.result, 'allow');
  assert.equal(back!.envelope_id, 'support-bot');
  assert.equal(back!.revision, 3);
  assert.equal(back!.agent_identity, 'agent-1');
  assert.equal(back!.principal, 'user-7');
  assert.equal(back!.derived_from.recipients, 'directory');
});

test('a tampered record does not verify', () => {
  const record = {
    envelope_id: 'e', envelope_digest: 'sha256:x', tool: 't', target: null,
    result: 'deny', rule: 'tools', detail: 'd', cost_usd: 0, decided_at: 'now',
    derived_from: {}, contradicted: [],
  };
  const jws = sign(record, PEM);
  const [h, , s2] = jws.split('.');
  const forged = Buffer.from(JSON.stringify({ ...record, result: 'allow' })).toString('base64url');
  assert.equal(verify(`${h}.${forged}.${s2}`, publicKeyOf(PEM)), null);
});

test('a record signed by another key does not verify', () => {
  const other = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    .privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const record = {
    envelope_id: 'e', envelope_digest: 'sha256:x', tool: 't', target: null,
    result: 'allow', rule: 'allow', detail: '', cost_usd: 0, decided_at: 'now',
    derived_from: {}, contradicted: [],
  };
  assert.equal(verify(sign(record, other), publicKeyOf(PEM)), null);
});

test('canonical form does not depend on key order', () => {
  assert.equal(canonical({ b: 1, a: [2, { d: 4, c: 3 }] }), canonical({ a: [2, { c: 3, d: 4 }] , b: 1 }));
  assert.equal(digestOf({ x: 1, y: 2 }), digestOf({ y: 2, x: 1 }));
});

test('a contradiction is on the record even when the call was allowed', async () => {
  // The agent understated the amount but it is still under the escalation
  // threshold. Allowed, and the misreport is still evidence.
  const s = supervisor([ledger({ 'o-9': 40 })]);
  const call = { tool: 'issue_refund', arguments: { order: 'o-9' }, claimed: { estimated_cost_usd: 1 } };
  const out = await s.check(ENVELOPE, { envelope_id: 'support-bot', call });
  assert.equal(out.outcome, 'allow');
  const record = buildRecord(out, call, 'sha256:x');
  assert.deepEqual(record.contradicted, ['amount_usd']);
});

test('a tool outside the envelope is denied before any system of record is touched', async () => {
  let asked = 0;
  const counting: Resolver = {
    name: 'counting',
    resolve: async () => { asked++; return { recipients: ['dana@example.com'] }; },
  };
  const s = supervisor([counting]);
  const out = await s.check(ENVELOPE, {
    envelope_id: 'support-bot', call: { tool: 'delete_account', arguments: { to: ['u-2'] } },
  });
  assert.equal(out.outcome, 'deny');
  assert.equal(out.rule, 'tools.allow');
  // The point: an agent cannot use a tool it has no grant for to make this
  // service query the directory on its behalf.
  assert.equal(asked, 0, 'resolvers must not run for a tool that is not on tools.allow');
});

test('an expired envelope denies before any system of record is touched', async () => {
  let asked = 0;
  const counting: Resolver = { name: 'counting', resolve: async () => { asked++; return {}; } };
  const s = supervisor([counting]);
  const expired = { ...ENVELOPE, expires: '2020-01-01T00:00:00Z' } as unknown as Envelope;
  const out = await s.check(expired, {
    envelope_id: 'support-bot', call: { tool: 'send_email', arguments: { to: ['u-2'] } },
  });
  assert.equal(out.outcome, 'deny');
  assert.equal(out.rule, 'expires');
  assert.equal(asked, 0);
});

test('a tool on tools.deny is denied even when it is also on allow', async () => {
  const s = supervisor([]);
  const both = { ...ENVELOPE, tools: { allow: [{ name: 'issue_refund' }], deny: ['issue_refund'] } } as unknown as Envelope;
  const out = await s.check(both, { envelope_id: 'support-bot', call: { tool: 'issue_refund' } });
  assert.equal(out.outcome, 'deny');
  assert.equal(out.rule, 'tools.deny');
});

// ---------- the service ----------

// Every request to the service is signed now. One registered caller, allowed
// the envelope these tests use, and a fetch that signs like the real client.
const CALLER = (() => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    id: 'host-1',
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
})();
const CALLERS = [{ id: CALLER.id, publicKeyPem: CALLER.publicKeyPem, envelopes: ['support-bot', 'nope'] }];

async function signedCheck(port: number, payload: unknown): Promise<Response> {
  const { signRequest } = await import('../src/auth.ts');
  const body = Buffer.from(JSON.stringify(payload));
  return fetch(`http://127.0.0.1:${port}/check`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...signRequest('POST', '/check', body, CALLER.id, CALLER.privateKeyPem) },
    body,
  });
}

test('the service denies an unknown envelope rather than erroring', async () => {
  const { createSupervisorServer } = await import('../src/server.ts');
  const store = await storeWith({ 'a.json': ENVELOPE });
  const server = createSupervisorServer({ store, supervisor: supervisor([]), callers: CALLERS, insecurePlaintext: true });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as { port: number };

  const res = await signedCheck(port, { envelope_id: 'nope', call: { tool: 'send_email' } });
  const body = await res.json() as Record<string, unknown>;
  server.close();

  assert.equal(res.status, 200, 'a caller must not be able to read a 404 as carry on');
  assert.equal(body.outcome, 'deny');
  assert.equal(body.rule, 'envelope');
});

test('the service signs the record and returns a verifiable jws', async () => {
  const { createSupervisorServer } = await import('../src/server.ts');
  const store = await storeWith({ 'a.json': ENVELOPE });
  const server = createSupervisorServer({
    store, supervisor: supervisor([directory({ 'u-2': 'dana@example.com' })]), signingKeyPem: PEM, kid: 'sup-1',
    callers: CALLERS, insecurePlaintext: true,
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as { port: number };

  const res = await signedCheck(port, {
      envelope_id: 'support-bot', agent_identity: 'agent-1', principal: 'user-7',
      call: { tool: 'send_email', arguments: { to: ['u-2'] } },
    });
  const body = await res.json() as Record<string, unknown>;
  server.close();

  assert.equal(body.outcome, 'allow');
  assert.equal(body.signed, true);
  const back = verify(body.jws as string, publicKeyOf(PEM));
  assert.ok(back);
  assert.equal(back!.envelope_digest, store.get('support-bot').digest);
  assert.equal(back!.agent_identity, 'agent-1');
});

test('a supervisor that throws still denies', async () => {
  const { createSupervisorServer } = await import('../src/server.ts');
  const store = await storeWith({ 'a.json': ENVELOPE });
  const broken = { check: async () => { throw new Error('boom'); } } as unknown as Supervisor;
  const server = createSupervisorServer({ store, supervisor: broken, callers: CALLERS, insecurePlaintext: true });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as { port: number };

  const res = await signedCheck(port, { envelope_id: 'support-bot', call: { tool: 'send_email' } });
  const body = await res.json() as Record<string, unknown>;
  server.close();

  assert.equal(body.outcome, 'deny');
  assert.equal(body.rule, 'supervisor');
});
