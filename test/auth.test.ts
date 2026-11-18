// Who may ask the supervisor a question, and whether the agent host can
// believe the answer.
//
// Fakes only, like the rest of the suite: loopback servers, generated keys,
// and certificates made by openssl into a temp directory for this run. Nothing
// reaches the network and nothing needs a credential.
//
// Most of these are not feature tests. Each one pins a way an attacker on the
// path, or a compromised agent host, would otherwise get an allow it should
// not have, or learn a policy it should not see. The ones that matter most are
// named in the CI claims check, so deleting one is as loud as breaking it.

import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';

import { createSupervisorServer, type ServeOptions } from '../src/server.ts';
import { EnvelopeStore } from '../src/envelopes.ts';
import { Supervisor, type CheckRequest } from '../src/supervisor.ts';
import { CallerRegistry, signRequest, sha256hex, normaliseFingerprint, HEADERS, type Caller } from '../src/auth.ts';
import { SupervisorClient } from '../src/client.ts';
import { publicKeyOf, verifyWithHeader } from '../src/record.ts';
import type { Resolver } from '../src/resolvers.ts';
import type { Envelope } from 'intent-envelope';

// ------------------------------------------------------------- fixtures

function ed25519() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}
function es256() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
}

const HOST_A = { id: 'host-a', ...ed25519() };
const HOST_B = { id: 'host-b', ...ed25519() };
const STRANGER = ed25519();
const SUPERVISOR_KEY = es256();
const SUPERVISOR_PUB = publicKeyOf(SUPERVISOR_KEY);

const SUPPORT: Envelope = {
  id: 'support-bot', revision: 1,
  tools: { allow: [{ name: 'send_email' }] },
  limits: { max_tool_calls: 100 },
  on_no_response: 'deny',
} as unknown as Envelope;
const OTHER: Envelope = { ...SUPPORT, id: 'other-bot' } as unknown as Envelope;

const noFacts: Resolver = { name: 'none', async resolve() { return {}; } };

async function store() {
  const dir = await mkdtemp(join(tmpdir(), 'sc-auth-'));
  await writeFile(join(dir, 'a.json'), JSON.stringify(SUPPORT));
  await writeFile(join(dir, 'b.json'), JSON.stringify(OTHER));
  const s = new EnvelopeStore(dir);
  await s.load();
  return s;
}

/** A supervisor that counts how often anything reached it. */
function counting() {
  const real = new Supervisor({ resolvers: [noFacts], now: () => new Date('2026-11-18T12:00:00Z') });
  const spy = { calls: 0, async check(e: Envelope, r: CheckRequest) { spy.calls++; return real.check(e, r); } };
  return spy;
}

const CALLERS: Caller[] = [
  // host-a may also ask about "ghost", which does not exist, so the two ways
  // of being told no can be compared like for like.
  { id: HOST_A.id, publicKeyPem: HOST_A.publicKeyPem, envelopes: ['support-bot', 'ghost'] },
  { id: HOST_B.id, publicKeyPem: HOST_B.publicKeyPem, envelopes: ['other-bot'] },
];

async function serve(extra: Partial<ServeOptions> = {}) {
  const spy = counting();
  const failures: string[] = [];
  const server = createSupervisorServer({
    store: await store(),
    supervisor: spy as unknown as Supervisor,
    signingKeyPem: SUPERVISOR_KEY, kid: 'sup-1',
    callers: CALLERS, insecurePlaintext: true,
    onAuthFailure: (reason) => failures.push(reason),
    ...extra,
  });
  OPEN.add(server as Server);
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as AddressInfo).port;
  return { server, spy, failures, port, url: `http://127.0.0.1:${port}` };
}

// Every server any test starts, so a test that fails between starting one and
// closing it cannot leave it holding the process open. Without this a failing
// assertion hangs the run instead of failing it, which is how a mutation test
// first found the problem.
const OPEN = new Set<Server>();
after(() => {
  for (const s of OPEN) { s.closeAllConnections?.(); s.close(); }
});

const ASK: CheckRequest = { envelope_id: 'support-bot', call: { tool: 'send_email' } };

async function post(url: string, body: Buffer, headers: Record<string, string> = {}) {
  const res = await fetch(`${url}/check`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body,
  });
  return { status: res.status, body: await res.json() as Record<string, unknown> };
}

function signedAs(who: { id: string; privateKeyPem: string }, body: Buffer, now?: number) {
  return signRequest('POST', '/check', body, who.id, who.privateKeyPem, now);
}

// ------------------------------------------------------ starting at all

test('a supervisor with no callers will not start', async () => {
  await assert.rejects(async () => serve({ callers: [] }), /oracle/);
});

test('plain HTTP must be asked for by name', async () => {
  await assert.rejects(async () => serve({ insecurePlaintext: false }), /plain HTTP/);
});

test('the registry refuses callers it could not authenticate', () => {
  const ok = { id: 'x', publicKeyPem: HOST_A.publicKeyPem, envelopes: ['e'] };
  assert.throws(() => new CallerRegistry([ok, { ...ok }]), /share the id/);
  assert.throws(() => new CallerRegistry([{ id: 'x', envelopes: ['e'] }]), /no credential/);
  assert.throws(() => new CallerRegistry([{ ...ok, envelopes: [] }]), /must list the envelopes/);
  assert.throws(() => new CallerRegistry([{ ...ok, publicKeyPem: publicKeyOf(es256()) }]), /must be Ed25519/);
  assert.throws(() => new CallerRegistry([{ id: 'x', certFingerprint: 'abcd', envelopes: ['e'] }]), /SHA-256/);
});

// --------------------------------------------- the request side, signed

test('an unsigned request is refused before anything is evaluated', async () => {
  const { server, spy, failures, url } = await serve();
  const res = await post(url, Buffer.from(JSON.stringify(ASK)));
  server.close();
  assert.equal(res.status, 401);
  assert.deepEqual(res.body, { error: 'unauthenticated' }, 'a refusal must not say which part failed');
  assert.equal(spy.calls, 0, 'nothing may be evaluated for an unauthenticated caller');
  assert.deepEqual(failures, ['no_credentials']);
});

test('a request signed by a key the supervisor does not hold is refused', async () => {
  const { server, spy, failures, url } = await serve();
  const body = Buffer.from(JSON.stringify(ASK));
  const forged = await post(url, body, signedAs({ id: HOST_A.id, privateKeyPem: STRANGER.privateKeyPem }, body));
  const nobody = await post(url, body, signedAs({ id: 'host-z', privateKeyPem: STRANGER.privateKeyPem }, body));
  server.close();
  assert.equal(forged.status, 401);
  assert.equal(nobody.status, 401);
  assert.equal(spy.calls, 0);
  assert.deepEqual(failures, ['bad_signature', 'unknown_caller']);
});

test('a body changed after signing is refused', async () => {
  const { server, spy, url } = await serve();
  const signedBody = Buffer.from(JSON.stringify(ASK));
  const sentBody = Buffer.from(JSON.stringify({ ...ASK, call: { tool: 'issue_refund' } }));
  const res = await post(url, sentBody, signedAs(HOST_A, signedBody));
  server.close();
  assert.equal(res.status, 401);
  assert.equal(spy.calls, 0);
});

test('a replayed request is refused', async () => {
  const { server, failures, url } = await serve();
  const body = Buffer.from(JSON.stringify(ASK));
  const headers = signedAs(HOST_A, body);
  const first = await post(url, body, headers);
  const again = await post(url, body, headers);
  server.close();
  assert.equal(first.status, 200);
  assert.equal(again.status, 401);
  assert.deepEqual(failures, ['replayed_nonce']);
});

test('a request from too far in the past or the future is refused', async () => {
  const { server, failures, url } = await serve();
  const body = Buffer.from(JSON.stringify(ASK));
  const old = await post(url, body, signedAs(HOST_A, body, Date.now() - 5 * 60_000));
  const future = await post(url, body, signedAs(HOST_A, body, Date.now() + 5 * 60_000));
  server.close();
  assert.equal(old.status, 401);
  assert.equal(future.status, 401);
  assert.deepEqual(failures, ['stale_timestamp', 'stale_timestamp']);
});

test('a forged request cannot burn a real caller\'s nonce', async () => {
  // If nonces were recorded before the signature was checked, anyone who could
  // guess or observe one could deny a real caller service by spending it first.
  const { server, url } = await serve();
  const body = Buffer.from(JSON.stringify(ASK));
  const real = signedAs(HOST_A, body);
  const forged = { ...real, [HEADERS.signature]: signedAs({ id: HOST_A.id, privateKeyPem: STRANGER.privateKeyPem }, body)[HEADERS.signature]! };
  const attack = await post(url, body, forged);
  const genuine = await post(url, body, real);
  server.close();
  assert.equal(attack.status, 401);
  assert.equal(genuine.status, 200, 'the forged attempt must not have consumed the nonce');
});

// ---------------------------------------------------- what a caller sees

test('a caller cannot ask about another caller\'s envelope, or tell that it exists', async () => {
  const { server, spy, url } = await serve();
  const theirs = Buffer.from(JSON.stringify({ envelope_id: 'other-bot', call: { tool: 'send_email' } }));
  const ghost = Buffer.from(JSON.stringify({ envelope_id: 'ghost', call: { tool: 'send_email' } }));
  const a = await post(url, theirs, signedAs(HOST_A, theirs));
  const b = await post(url, ghost, signedAs(HOST_A, ghost));
  server.close();

  assert.equal(a.status, 200);
  assert.equal(a.body.outcome, 'deny');
  assert.equal(spy.calls, 0, 'another caller\'s envelope must never be evaluated on this caller\'s behalf');

  // The two refusals must be indistinguishable apart from the id asked about
  // and the clock. If they differed, every envelope id in the deployment could
  // be enumerated by watching which way the answer came back.
  const shape = (r: Record<string, unknown>, id: string) =>
    JSON.stringify({ ...r, decided_at: 'T', envelope_id: 'E', detail: String(r.detail).replace(id, 'E') });
  assert.equal(shape(a.body, 'other-bot'), shape(b.body, 'ghost'));
});

test('the signed answer is bound to the request, the nonce and the caller', async () => {
  const { server, url } = await serve();
  const body = Buffer.from(JSON.stringify(ASK));
  const headers = signedAs(HOST_A, body);
  const res = await post(url, body, headers);
  server.close();

  const v = verifyWithHeader(res.body.jws as string, SUPERVISOR_PUB);
  assert.ok(v, 'the answer should verify against the supervisor key');
  assert.equal(v!.header.req, sha256hex(body));
  assert.equal(v!.header.nonce, headers[HEADERS.nonce]);
  assert.equal(v!.header.aud, HOST_A.id);
  assert.equal(v!.record.envelope_id, 'support-bot', 'the record keeps its spec section 5 shape');
  assert.ok(!('req' in v!.record), 'the binding lives in the header, not the record the ledger stores');
});

test('one caller is rate limited without affecting another', async () => {
  const { server, failures, url } = await serve({ rateLimitPerMinute: 3 });
  const ask = async (who: typeof HOST_A, envelope: string) => {
    const body = Buffer.from(JSON.stringify({ envelope_id: envelope, call: { tool: 'send_email' } }));
    return (await post(url, body, signedAs(who, body))).status;
  };
  const a = [await ask(HOST_A, 'support-bot'), await ask(HOST_A, 'support-bot'), await ask(HOST_A, 'support-bot'), await ask(HOST_A, 'support-bot')];
  const b = await ask(HOST_B, 'other-bot');
  server.close();
  assert.deepEqual(a, [200, 200, 200, 429]);
  assert.equal(b, 200);
  assert.deepEqual(failures, ['rate_limited']);
});

test('the health check reveals nothing about the policy', async () => {
  const { server, url } = await serve();
  const res = await fetch(`${url}/healthz`);
  const body = await res.json();
  server.close();
  assert.deepEqual(body, { ok: true });
});

// --------------------------------------------------------- the client

function client(url: string, extra: Partial<ConstructorParameters<typeof SupervisorClient>[0]> = {}) {
  return new SupervisorClient({
    url, callerId: HOST_A.id, privateKeyPem: HOST_A.privateKeyPem,
    supervisorPublicKeyPem: SUPERVISOR_PUB, ...extra,
  });
}

test('the client returns a verified allow when everything checks out', async () => {
  const { server, url } = await serve();
  const out = await client(url).check(ASK);
  server.close();
  assert.equal(out.outcome, 'allow', out.reason);
  assert.equal(out.verified, true);
  assert.ok(out.record && out.jws);
});

test('the client acts on the signed record, never on the plain outcome beside it', async () => {
  // A deny, genuinely. Then something on the path rewrites the plain JSON to
  // say allow, and the client must still see the deny it was signed as.
  const { server, url } = await serve();
  const tamper: typeof fetch = async (input, init) => {
    const res = await fetch(input, init);
    const body = await res.json() as Record<string, unknown>;
    body.outcome = 'allow';
    body.rule = 'tools.allow';
    if (body.record) (body.record as Record<string, unknown>).result = 'allow';
    return new Response(JSON.stringify(body), { status: res.status });
  };
  const out = await client(url, { fetch: tamper }).check({ envelope_id: 'support-bot', call: { tool: 'issue_refund' } });
  server.close();
  assert.equal(out.outcome, 'deny');
  assert.equal(out.verified, true, 'the deny came from the verified record');
});

test('a captured allow cannot be replayed as the answer to another question', async () => {
  const { server, url } = await serve();
  const captured = await (async () => {
    const body = Buffer.from(JSON.stringify(ASK));
    return (await post(url, body, signedAs(HOST_A, body))).body;
  })();
  const replay: typeof fetch = async () => new Response(JSON.stringify(captured), { status: 200 });
  const out = await client(url, { fetch: replay }).check({ envelope_id: 'support-bot', call: { tool: 'issue_refund' } });
  server.close();
  assert.equal(captured.outcome, 'allow', 'the captured answer has to be a genuine allow for this test to mean anything');
  assert.equal(out.outcome, 'deny');
  assert.match(out.reason, /different request/);
});

test('the client fails closed when the supervisor cannot be reached', async () => {
  const { server, url } = await serve();
  server.close();
  await new Promise(r => setTimeout(r, 20));
  const out = await client(url).check(ASK);
  assert.equal(out.outcome, 'deny');
  assert.equal(out.verified, false);
  assert.match(out.reason, /could not be reached/);
});

test('the client fails closed when the supervisor is too slow', async () => {
  const hang: typeof fetch = (_input, init) => new Promise((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () => reject(new Error('timed out')));
  });
  const out = await client('http://127.0.0.1:9', { fetch: hang, timeoutMs: 50 }).check(ASK);
  assert.equal(out.outcome, 'deny');
  assert.match(out.reason, /could not be reached/);
});

test('the client fails closed when the answer starts and then stalls', async () => {
  // Headers arrive with a 200, then the body never finishes. A timeout that
  // stopped at the headers would leave the agent waiting here indefinitely.
  const stall: typeof fetch = async () => new Response(new ReadableStream({ start() { /* never enqueues, never closes */ } }), { status: 200 });
  const started = Date.now();
  const out = await client('http://127.0.0.1:9', { fetch: stall, timeoutMs: 80 }).check(ASK);
  assert.equal(out.outcome, 'deny');
  assert.match(out.reason, /no answer within 80ms/);
  assert.ok(Date.now() - started < 2000, 'the deny should arrive at the timeout, not whenever the stream gives up');
});

test('an unsigned answer is never an allow', async () => {
  const { server, url } = await serve({ signingKeyPem: undefined });
  const out = await client(url).check(ASK);
  server.close();
  assert.equal(out.outcome, 'deny', 'the supervisor said allow, unsigned, and that must not be enough');
  assert.match(out.reason, /not signed/);
});

test('a signature from any key but the pinned one is refused', async () => {
  const { server, url } = await serve();
  const out = await client(url, { supervisorPublicKeyPem: publicKeyOf(es256()) }).check(ASK);
  server.close();
  assert.equal(out.outcome, 'deny');
  assert.match(out.reason, /pinned/);
});

test('the client never throws, whatever comes back', async () => {
  const garbage: typeof fetch = async () => new Response('<html>not json</html>', { status: 200 });
  const out = await client('http://127.0.0.1:9', { fetch: garbage }).check(ASK);
  assert.equal(out.outcome, 'deny');
});

// --------------------------------------------------- client certificates

async function pki() {
  const dir = await mkdtemp(join(tmpdir(), 'sc-pki-'));
  const ssl = (...args: string[]) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  const key = (name: string) => ssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`);
  const csr = (name: string, cn: string) => ssl('req', '-new', '-key', `${name}.key`, '-subj', `/CN=${cn}`, '-out', `${name}.csr`);

  for (const ca of ['ca', 'rogue']) {
    key(ca);
    ssl('req', '-x509', '-new', '-key', `${ca}.key`, '-subj', `/CN=${ca}`, '-days', '1', '-out', `${ca}.crt`);
  }
  await writeFile(join(dir, 'srv.ext'), 'subjectAltName=IP:127.0.0.1,DNS:localhost\n');
  await writeFile(join(dir, 'cli.ext'), 'extendedKeyUsage=clientAuth\n');
  const issue = (name: string, cn: string, ca: string, ext: string) => {
    key(name); csr(name, cn);
    ssl('x509', '-req', '-in', `${name}.csr`, '-CA', `${ca}.crt`, '-CAkey', `${ca}.key`, '-CAcreateserial',
      '-days', '1', '-extfile', ext, '-out', `${name}.crt`);
  };
  issue('srv', 'localhost', 'ca', 'srv.ext');
  issue('pinned', 'host-m', 'ca', 'cli.ext');
  issue('unpinned', 'host-m', 'ca', 'cli.ext');   // same CA, same subject, different key
  issue('outsider', 'host-m', 'rogue', 'cli.ext');

  const read = async (f: string) => readFile(join(dir, f), 'utf8');
  const fp = async (f: string) => new X509Certificate(await read(f)).fingerprint256;
  return {
    ca: await read('ca.crt'), srvKey: await read('srv.key'), srvCrt: await read('srv.crt'),
    cli: {
      pinned: { key: await read('pinned.key'), cert: await read('pinned.crt'), fp: await fp('pinned.crt') },
      unpinned: { key: await read('unpinned.key'), cert: await read('unpinned.crt') },
      outsider: { key: await read('outsider.key'), cert: await read('outsider.crt'), fp: await fp('outsider.crt') },
    },
  };
}

function tlsPost(port: number, ca: string, body: Buffer, cli?: { key: string; cert: string }, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; body: Record<string, unknown> }>((resolve, reject) => {
    const req = httpsRequest({
      host: '127.0.0.1', port, path: '/check', method: 'POST', ca, servername: 'localhost',
      ...(cli ? { key: cli.key, cert: cli.cert } : {}),
      headers: { 'content-type': 'application/json', 'content-length': body.length, ...headers },
    }, res => {
      const chunks: Buffer[] = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

async function serveTls() {
  const p = await pki();
  const failures: string[] = [];
  const spy = counting();
  const server = createSupervisorServer({
    store: await store(), supervisor: spy as unknown as Supervisor,
    signingKeyPem: SUPERVISOR_KEY,
    tls: { key: p.srvKey, cert: p.srvCrt, ca: p.ca },
    callers: [
      ...CALLERS,
      { id: 'host-m', certFingerprint: p.cli.pinned.fp, envelopes: ['support-bot'] },
      // Pinned, but issued by a CA the supervisor does not trust.
      { id: 'host-x', certFingerprint: p.cli.outsider.fp, envelopes: ['support-bot'] },
    ],
    onAuthFailure: (reason) => failures.push(reason),
  });
  OPEN.add(server as Server);
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  return { server, p, failures, spy, port: (server.address() as AddressInfo).port };
}

const BODY = Buffer.from(JSON.stringify(ASK));

test('a pinned client certificate identifies its caller', async () => {
  const { server, p, port } = await serveTls();
  const res = await tlsPost(port, p.ca, BODY, p.cli.pinned);
  server.close();
  assert.equal(res.status, 200);
  assert.equal(res.body.outcome, 'allow');
  const v = verifyWithHeader(res.body.jws as string, SUPERVISOR_PUB);
  assert.equal(v!.header.aud, 'host-m');
  // The fingerprint openssl and Node print is the hash of the DER the server
  // sees, which is what makes a pinned value copied from either one work.
  assert.equal(normaliseFingerprint(p.cli.pinned.fp).length, 64);
});

test('a certificate from the same CA that is not pinned identifies no one', async () => {
  const { server, p, failures, spy, port } = await serveTls();
  const res = await tlsPost(port, p.ca, BODY, p.cli.unpinned);
  server.close();
  assert.equal(res.status, 401, 'same CA and same subject name must not be enough');
  assert.equal(spy.calls, 0);
  assert.deepEqual(failures, ['certificate_not_pinned']);
});

test('a pinned certificate that does not chain to the configured CA is refused', async () => {
  const { server, p, failures, port } = await serveTls();
  const res = await tlsPost(port, p.ca, BODY, p.cli.outsider);
  server.close();
  assert.equal(res.status, 401, 'pinning a fingerprint must not bypass the chain check');
  assert.deepEqual(failures, ['certificate_not_pinned']);
});

test('a valid certificate does not rescue a bad signature', async () => {
  const { server, p, failures, port } = await serveTls();
  const bad = signedAs({ id: HOST_A.id, privateKeyPem: STRANGER.privateKeyPem }, BODY);
  const res = await tlsPost(port, p.ca, BODY, p.cli.pinned, bad);
  server.close();
  assert.equal(res.status, 401);
  assert.deepEqual(failures, ['bad_signature']);
});

test('a certificate and a signature must name the same caller', async () => {
  const { server, p, failures, port } = await serveTls();
  const res = await tlsPost(port, p.ca, BODY, p.cli.pinned, signedAs(HOST_A, BODY));
  server.close();
  assert.equal(res.status, 401);
  assert.deepEqual(failures, ['identity_mismatch']);
});

test('a signed request over TLS needs no client certificate', async () => {
  const { server, p, port } = await serveTls();
  const res = await tlsPost(port, p.ca, BODY, undefined, signedAs(HOST_A, BODY));
  server.close();
  assert.equal(res.status, 200);
  assert.equal(res.body.outcome, 'allow');
});
