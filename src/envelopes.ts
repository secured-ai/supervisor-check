// The envelope store, and the one property it has to have.
//
// Intent Envelope 0.1, section 2.1, requirement 1: creating or modifying an
// envelope MUST be a privileged operation the governed agent cannot perform.
// "If an agent can draft its own, or widen an existing one, the system is
// asking permission from itself."
//
// So this store has no write path at all. Not a guarded one, not an
// authenticated one: none. Envelopes are loaded from disk at start and on an
// explicit reload, and the only way to change one is to change the file, which
// happens through whatever review the deployment already runs on its policy
// repository. An API that could write envelopes would be the most valuable
// endpoint in the deployment to compromise, so it does not exist.

import { readdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { extname, join } from 'node:path';
import type { Envelope } from 'intent-envelope';

export class UnknownEnvelope extends Error {}

export interface StoredEnvelope {
  envelope: Envelope;
  /** sha256 of the file as read, so a decision record can name the exact text. */
  digest: string;
  source: string;
}

export class EnvelopeStore {
  private readonly dir: string;
  private byId = new Map<string, StoredEnvelope>();

  constructor(dir: string) {
    this.dir = dir;
  }

  get size(): number { return this.byId.size; }
  get ids(): string[] { return [...this.byId.keys()].sort(); }

  async load(): Promise<number> {
    const next = new Map<string, StoredEnvelope>();
    let entries: string[];
    try {
      entries = await readdir(this.dir);
    } catch {
      throw new UnknownEnvelope(`cannot read the envelope directory at ${this.dir}`);
    }
    for (const name of entries.filter(n => extname(n) === '.json').sort()) {
      const source = join(this.dir, name);
      const text = await readFile(source, 'utf8');
      let envelope: Envelope;
      try {
        envelope = JSON.parse(text) as Envelope;
      } catch (e) {
        throw new UnknownEnvelope(`${name} is not valid JSON: ${(e as Error).message}`);
      }
      if (typeof envelope.id !== 'string' || envelope.id === '') {
        throw new UnknownEnvelope(`${name} has no id`);
      }
      if (next.has(envelope.id)) {
        // Two files claiming one id means the service would answer with
        // whichever loaded last, which is not something to discover later.
        throw new UnknownEnvelope(`${envelope.id} is defined twice, in ${next.get(envelope.id)!.source} and ${source}`);
      }
      next.set(envelope.id, {
        envelope, source,
        digest: 'sha256:' + createHash('sha256').update(text).digest('hex'),
      });
    }
    this.byId = next;
    return this.byId.size;
  }

  get(id: string): StoredEnvelope {
    const found = this.byId.get(id);
    // Denying an unknown envelope is the caller's job, but it should never get
    // a different envelope than the one it asked for.
    if (!found) throw new UnknownEnvelope(`no envelope with id ${id}`);
    return found;
  }

  has(id: string): boolean { return this.byId.has(id); }
}
