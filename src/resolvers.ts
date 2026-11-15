// Independent fact derivation, which is the whole reason this service exists.
//
// Intent Envelope 0.1, section 2.1, requirement 2:
//
//   "What the agent supplies at call time remains the agent's own claim. The
//    envelope is trustworthy; the arguments and targets of a particular tool
//    call are not, because they come from the thing being constrained. An
//    enforcement point MUST evaluate constraints against independently derived
//    facts, such as what a record actually contains or who a recipient actually
//    is, rather than against the agent's description of the call."
//
// The reference library takes a FactsExtractor as an argument and ships a
// default that reads the agent's own arguments, because the library cannot know
// where a deployment's truth lives. That default is the agent's claim, which the
// spec says must not be what gets evaluated. Supplying the real thing is the
// deployment's job, and this is where a deployment plugs it in.
//
// A resolver answers one question against a system of record: who is this
// recipient id actually, what does this record actually contain, what is this
// transfer actually worth. The answer replaces the agent's version before the
// envelope is evaluated.

export interface ResolvedFacts {
  /** Who would actually be contacted, as the directory reports them. */
  recipients?: string[];
  /** What data would actually be touched, as the store reports it. */
  data?: string[];
  /** What the call would actually cost or move. */
  amount_usd?: number;
  /** Anything else the deployment's escalate.when expressions refer to. */
  context?: Record<string, unknown>;
}

export interface Resolver {
  name: string;
  /**
   * Derive facts for this call from a system of record.
   *
   * Throwing means the fact could not be established. It does not mean the call
   * is fine, and resolution fails closed on it. See resolveFacts below.
   */
  resolve(call: ProposedCall): Promise<ResolvedFacts>;
}

export interface ProposedCall {
  tool: string;
  /** The agent's own account of the call. Evidence, never the basis of a decision. */
  arguments?: Record<string, unknown>;
  claimed?: {
    recipients?: string[];
    data?: string[];
    estimated_cost_usd?: number;
  };
}

export class FactsUnavailable extends Error {
  readonly resolver: string;
  constructor(resolver: string, message: string) {
    super(`${resolver}: ${message}`);
    this.resolver = resolver;
  }
}

export interface ResolutionReport {
  facts: ResolvedFacts;
  /** Which resolver supplied which field, for the decision record. */
  derivedBy: Record<string, string>;
  /** Fields the agent claimed that the systems of record contradicted. */
  contradictions: Array<{ field: string; claimed: unknown; actual: unknown }>;
}

function sameSet(a: unknown, b: unknown): boolean {
  if (!Array.isArray(a) || !Array.isArray(b)) return JSON.stringify(a) === JSON.stringify(b);
  if (a.length !== b.length) return false;
  const left = [...a].map(String).sort();
  const right = [...b].map(String).sort();
  return left.every((v, i) => v === right[i]);
}

/**
 * Run every resolver and merge what they establish.
 *
 * Fails closed. A resolver that throws, times out or is simply absent for a
 * field the envelope constrains leaves this service unable to say the call is
 * inside the envelope, and the supervisor denies rather than falling back to
 * the agent's version. Falling back would mean an agent could get its claims
 * evaluated by taking the directory offline.
 */
export async function resolveFacts(
  call: ProposedCall, resolvers: Resolver[], timeoutMs = 5000,
): Promise<ResolutionReport> {
  const facts: ResolvedFacts = {};
  const derivedBy: Record<string, string> = {};
  const contradictions: ResolutionReport['contradictions'] = [];

  for (const resolver of resolvers) {
    let got: ResolvedFacts;
    try {
      got = await withTimeout(resolver.resolve(call), timeoutMs, resolver.name);
    } catch (e) {
      throw e instanceof FactsUnavailable
        ? e : new FactsUnavailable(resolver.name, (e as Error).message);
    }
    for (const [field, value] of Object.entries(got)) {
      if (value === undefined) continue;
      if (field === 'context') {
        facts.context = { ...(facts.context ?? {}), ...(value as Record<string, unknown>) };
        derivedBy.context = [derivedBy.context, resolver.name].filter(Boolean).join(',');
        continue;
      }
      if (field in facts && !sameSet((facts as Record<string, unknown>)[field], value)) {
        throw new FactsUnavailable(resolver.name,
          `disagrees with ${derivedBy[field]} about ${field}, so neither can be trusted`);
      }
      (facts as Record<string, unknown>)[field] = value;
      derivedBy[field] = resolver.name;
    }
  }

  // Not a decision, a record. The envelope decides; this notes that the agent's
  // account of its own call did not match the system of record, which is worth
  // seeing on the ledger whether or not the call was allowed.
  const claimed = call.claimed ?? {};
  if (claimed.recipients && facts.recipients && !sameSet(claimed.recipients, facts.recipients)) {
    contradictions.push({ field: 'recipients', claimed: claimed.recipients, actual: facts.recipients });
  }
  if (claimed.data && facts.data && !sameSet(claimed.data, facts.data)) {
    contradictions.push({ field: 'data', claimed: claimed.data, actual: facts.data });
  }
  if (claimed.estimated_cost_usd !== undefined && facts.amount_usd !== undefined
      && claimed.estimated_cost_usd !== facts.amount_usd) {
    contradictions.push({ field: 'amount_usd', claimed: claimed.estimated_cost_usd, actual: facts.amount_usd });
  }

  return { facts, derivedBy, contradictions };
}

function withTimeout<T>(p: Promise<T>, ms: number, who: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new FactsUnavailable(who, `did not answer within ${ms}ms`)), ms);
    p.then(v => { clearTimeout(timer); resolve(v); },
           e => { clearTimeout(timer); reject(e); });
  });
}
