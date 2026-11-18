// Who is allowed to ask the supervisor a question.
//
// Until 0.2 the answer was anyone who could reach the port. That sounds
// harmless, since the supervisor only answers questions and never acts, and
// it is not, for three reasons:
//
//   1. The envelope becomes an oracle. Ask "may agent X refund $499 to Y" a
//      few hundred times with different values and you have mapped the
//      policy: which tools, which recipients, where the limits sit. That map
//      is exactly what an attacker wants before steering an agent.
//
//   2. Anything that can call it can put records in the ledger, through
//      onRecord, and a ledger anyone can write to is evidence of nothing.
//
//   3. It is the enforcement point. A security team reviewing the deployment
//      will ask how the agent host proves who it is, and "it does not" ends
//      the review.
//
// So every request is authenticated before it is parsed, and a caller may
// only ask about the envelopes it is registered for. Two ways to prove
// identity, because deployments differ:
//
//   Signed requests. The caller holds an Ed25519 private key and signs the
//   method, path, a timestamp, a single-use nonce and a digest of the body.
//   The supervisor holds only public keys, so a leak of the supervisor's
//   configuration does not let anyone impersonate a caller. This works
//   through proxies and meshes that terminate TLS, which mTLS does not.
//
//   Client certificates. When the supervisor terminates TLS itself, a caller
//   can present a certificate that chains to the configured CA and whose
//   SHA-256 fingerprint is pinned to that caller. Pinned rather than matched
//   by subject name, because any certificate the CA ever issued carries a
//   subject, and the CA is not the thing being trusted here.
//
// A presented credential that fails is a failure, not a fallback. A request
// with a valid certificate and a bad signature is refused: a bad signature is
// the interesting fact about that request, and quietly preferring the
// credential that worked would hide it.

import { createHash, createPublicKey, sign as edSign, verify as edVerify, createPrivateKey, randomBytes, type KeyObject } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import type { TLSSocket } from 'node:tls';

export interface Caller {
  /** A stable name for the agent host, used in records and logs. */
  id: string;
  /** Ed25519 public key, SPKI PEM. The caller signs every request with the matching private key. */
  publicKeyPem?: string;
  /**
   * SHA-256 fingerprint of the caller's client certificate, in any common
   * spelling: `AB:CD:...` as openssl prints it, or bare hex.
   */
  certFingerprint?: string;
  /**
   * The envelope ids this caller may ask about, and nothing else. An agent
   * host has no business learning what another host's agents are allowed to
   * do, and without this every caller is an oracle for every policy.
   */
  envelopes: string[];
}

export const HEADERS = {
  caller: 'x-supervisor-caller',
  timestamp: 'x-supervisor-timestamp',
  nonce: 'x-supervisor-nonce',
  signature: 'x-supervisor-signature',
} as const;

/** How far a request's clock may disagree with ours. */
export const MAX_SKEW_MS = 60_000;

const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;

export type AuthFailure =
  | 'no_credentials'
  | 'unknown_caller'
  | 'bad_signature'
  | 'stale_timestamp'
  | 'bad_nonce'
  | 'replayed_nonce'
  | 'certificate_not_pinned'
  | 'identity_mismatch';

export type AuthResult =
  | { ok: true; caller: Caller; via: 'signature' | 'certificate' | 'both'; nonce: string | null }
  | { ok: false; reason: AuthFailure };

export function sha256hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * The exact bytes a caller signs.
 *
 * The version prefix is there so a future change to this string cannot be
 * confused with today's. The body enters as a digest rather than raw so a
 * signature over a large body stays cheap to check, and because the digest is
 * also what the response is bound to.
 */
export function signingString(method: string, path: string, timestamp: string, nonce: string, body: Buffer): string {
  return ['SC1', method.toUpperCase(), path, timestamp, nonce, sha256hex(body)].join('\n');
}

export function normaliseFingerprint(fp: string): string {
  return fp.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
}

function header(headers: IncomingHttpHeaders, name: string): string | undefined {
  const v = headers[name];
  return Array.isArray(v) ? v[0] : v;
}

/** Signs a request for the client side. Exported so a caller in any runtime can reproduce it. */
export function signRequest(
  method: string, path: string, body: Buffer, callerId: string, privateKeyPem: string,
  now: number = Date.now(), nonce: string = randomBytes(18).toString('base64url'),
): Record<string, string> {
  const timestamp = String(now);
  const signature = edSign(null, Buffer.from(signingString(method, path, timestamp, nonce, body)),
    createPrivateKey(privateKeyPem)).toString('base64url');
  return {
    [HEADERS.caller]: callerId,
    [HEADERS.timestamp]: timestamp,
    [HEADERS.nonce]: nonce,
    [HEADERS.signature]: signature,
  };
}

export interface RegistryOptions {
  now?: () => number;
}

export class CallerRegistry {
  private readonly byId = new Map<string, { caller: Caller; key: KeyObject | null }>();
  private readonly byFingerprint = new Map<string, Caller>();
  /** caller id + nonce -> when it can be forgotten. */
  private readonly seen = new Map<string, number>();
  private readonly now: () => number;

  constructor(callers: Caller[], opts: RegistryOptions = {}) {
    this.now = opts.now ?? Date.now;
    if (!Array.isArray(callers) || callers.length === 0) {
      throw new Error('at least one caller is required: a supervisor anyone can query is an oracle for the policy it enforces');
    }
    for (const caller of callers) {
      if (!caller.id || typeof caller.id !== 'string') throw new Error('every caller needs an id');
      if (this.byId.has(caller.id)) throw new Error(`two callers share the id ${caller.id}`);
      if (!caller.publicKeyPem && !caller.certFingerprint) {
        throw new Error(`caller ${caller.id} has no credential: give it a publicKeyPem, a certFingerprint, or both`);
      }
      if (!Array.isArray(caller.envelopes) || caller.envelopes.length === 0
          || caller.envelopes.some(e => typeof e !== 'string' || !e)) {
        throw new Error(`caller ${caller.id} must list the envelopes it may ask about`);
      }
      let key: KeyObject | null = null;
      if (caller.publicKeyPem) {
        key = createPublicKey(caller.publicKeyPem);
        if (key.asymmetricKeyType !== 'ed25519') {
          throw new Error(`caller ${caller.id}: request signing keys must be Ed25519, got ${key.asymmetricKeyType}`);
        }
      }
      if (caller.certFingerprint) {
        const fp = normaliseFingerprint(caller.certFingerprint);
        if (fp.length !== 64) throw new Error(`caller ${caller.id}: certFingerprint must be a SHA-256 fingerprint`);
        if (this.byFingerprint.has(fp)) throw new Error(`two callers pin the same certificate fingerprint`);
        this.byFingerprint.set(fp, caller);
      }
      this.byId.set(caller.id, { caller, key });
    }
  }

  /** May this caller ask about this envelope. */
  mayAsk(caller: Caller, envelopeId: string): boolean {
    return caller.envelopes.includes(envelopeId);
  }

  private certificateCaller(socket: unknown): { caller: Caller | null; presented: boolean } {
    const tls = socket as TLSSocket;
    if (typeof tls?.getPeerCertificate !== 'function') return { caller: null, presented: false };
    const cert = tls.getPeerCertificate();
    if (!cert || !cert.raw) return { caller: null, presented: false };
    // A certificate that does not chain to the configured CA identifies no one,
    // whatever its fingerprint, so it is not even looked up.
    if (!tls.authorized) return { caller: null, presented: true };
    return { caller: this.byFingerprint.get(sha256hex(cert.raw)) ?? null, presented: true };
  }

  private forgetExpired(at: number): void {
    if (this.seen.size < 1024) return;
    for (const [k, until] of this.seen) if (until <= at) this.seen.delete(k);
  }

  authenticate(
    req: { method?: string; url?: string; headers: IncomingHttpHeaders; socket: unknown },
    body: Buffer,
  ): AuthResult {
    const now = this.now();
    const fromCert = this.certificateCaller(req.socket);

    const callerId = header(req.headers, HEADERS.caller);
    const timestamp = header(req.headers, HEADERS.timestamp);
    const nonce = header(req.headers, HEADERS.nonce);
    const signature = header(req.headers, HEADERS.signature);
    const signed = Boolean(callerId || timestamp || nonce || signature);

    let fromSig: Caller | null = null;
    if (signed) {
      if (!callerId || !timestamp || !nonce || !signature) return { ok: false, reason: 'bad_signature' };
      const entry = this.byId.get(callerId);
      if (!entry || !entry.key) return { ok: false, reason: 'unknown_caller' };
      if (!NONCE_RE.test(nonce)) return { ok: false, reason: 'bad_nonce' };
      const ts = Number(timestamp);
      if (!Number.isFinite(ts) || Math.abs(now - ts) > MAX_SKEW_MS) return { ok: false, reason: 'stale_timestamp' };

      let valid = false;
      try {
        valid = edVerify(null, Buffer.from(signingString(req.method ?? '', req.url ?? '', timestamp, nonce, body)),
          entry.key, Buffer.from(signature, 'base64url'));
      } catch {
        valid = false;
      }
      if (!valid) return { ok: false, reason: 'bad_signature' };

      // Only a request whose signature verified may spend a nonce. Recording
      // nonces before the check would let anyone burn a caller's nonces.
      const key = `${callerId}\n${nonce}`;
      if ((this.seen.get(key) ?? 0) > now) return { ok: false, reason: 'replayed_nonce' };
      this.forgetExpired(now);
      this.seen.set(key, now + 2 * MAX_SKEW_MS);
      fromSig = entry.caller;
    }

    if (fromSig && fromCert.caller && fromSig.id !== fromCert.caller.id) {
      return { ok: false, reason: 'identity_mismatch' };
    }
    if (fromSig) return { ok: true, caller: fromSig, via: fromCert.caller ? 'both' : 'signature', nonce: nonce! };
    if (fromCert.caller) return { ok: true, caller: fromCert.caller, via: 'certificate', nonce: null };
    return { ok: false, reason: fromCert.presented ? 'certificate_not_pinned' : 'no_credentials' };
  }
}

/**
 * A fixed window per caller. Crude, and enough: the point is that one
 * compromised agent host cannot use the supervisor to map a policy at line
 * rate, not to shape traffic.
 */
export class RateLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();
  private readonly perMinute: number;
  private readonly now: () => number;

  // Declared fields rather than constructor parameter properties, which Node's
  // type stripping rejects.
  constructor(perMinute: number, now: () => number = Date.now) {
    if (!(perMinute > 0)) throw new Error('rateLimitPerMinute must be positive');
    this.perMinute = perMinute;
    this.now = now;
  }
  take(callerId: string): boolean {
    const now = this.now();
    const w = this.windows.get(callerId);
    if (!w || now - w.start >= 60_000) {
      this.windows.set(callerId, { start: now, count: 1 });
      return true;
    }
    if (w.count >= this.perMinute) return false;
    w.count++;
    return true;
  }
}
