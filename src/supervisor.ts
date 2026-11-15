// The check itself.
//
// Order matters and is not negotiable:
//
//   1. derive the facts independently
//   2. build the call from the derived facts, never the agent's
//   3. evaluate the envelope against that call, using the reference evaluator
//   4. record the decision
//
// Step 3 calls intent-envelope's evaluate(). The decision rules of the spec are
// implemented once, in the reference implementation, and a second copy here
// that drifted by one clause would be worse than useless: two enforcement
// points that disagree about the same envelope is the failure the conformance
// suite exists to catch.
//
// What this adds is steps 1, 2 and 4, and the fact that it runs somewhere the
// agent cannot reach.

import { evaluate, type Call, type Decision, type Envelope, type RunState } from 'intent-envelope';
import { FactsUnavailable, resolveFacts, type ProposedCall, type ResolutionReport, type Resolver } from './resolvers.ts';

export type Outcome = 'allow' | 'deny' | 'escalate';

export interface CheckRequest {
  envelope_id: string;
  agent_identity?: string;
  principal?: string;
  call: ProposedCall;
  run?: RunState;
}

export interface CheckResult {
  outcome: Outcome;
  rule: string;
  detail: string;
  envelope_id: string;
  revision?: number;
  /** The facts used, and which system of record each came from. */
  derived: ResolutionReport['derivedBy'];
  /** Where the agent's account differed from the systems of record. */
  contradictions: ResolutionReport['contradictions'];
  escalate_to?: string;
  timeout_seconds?: number;
  decided_at: string;
}

export interface SupervisorOptions {
  resolvers: Resolver[];
  /** Supplies escalate.when, which 0.1 leaves to the enforcement point. */
  conditionMatcher?: (condition: string, context: Record<string, unknown>) => boolean;
  dataMatcher?: (target: string, pattern: string) => boolean;
  resolveTimeoutMs?: number;
  now?: () => Date;
}

export class Supervisor {
  private readonly opts: SupervisorOptions;

  constructor(opts: SupervisorOptions) {
    this.opts = opts;
  }

  /**
   * The fact-independent part of section 3, so it can run before resolution.
   * Deliberately not a second copy of the rules: it answers only the three
   * questions that cannot depend on derived facts, and returns null for
   * everything else so evaluate() decides it.
   */
  private denyOnTool(envelope: Envelope, req: CheckRequest, decided_at: string): CheckResult | null {
    const base = {
      envelope_id: req.envelope_id, revision: envelope.revision as number | undefined,
      derived: {}, contradictions: [], decided_at,
    };
    const expires = envelope.expires as string | undefined;
    if (expires && Date.parse(expires) < Date.parse(decided_at)) {
      return { ...base, outcome: 'deny', rule: 'expires', detail: `the envelope expired at ${expires}` };
    }
    const tools = envelope.tools as { allow?: Array<{ name: string }>; deny?: string[] } | undefined;
    if (tools?.deny?.includes(req.call.tool)) {
      return { ...base, outcome: 'deny', rule: 'tools.deny', detail: `${req.call.tool} is on tools.deny` };
    }
    if (!tools?.allow?.some(g => g.name === req.call.tool)) {
      return { ...base, outcome: 'deny', rule: 'tools.allow', detail: `${req.call.tool} is not on tools.allow` };
    }
    return null;
  }

  async check(envelope: Envelope, req: CheckRequest): Promise<CheckResult> {
    const now = (this.opts.now ?? (() => new Date()))();
    const decided_at = now.toISOString();

    // Steps 1 to 3 of section 3 depend on nothing the agent supplies: an expired
    // envelope, a tool on tools.deny, a tool absent from tools.allow. Deciding
    // them first means a call that was never going to be permitted does not send
    // this service out to query the directory and the ledger, which is both
    // wasted work and a way for an agent to probe systems of record using tools
    // it has no grant for.
    const early = this.denyOnTool(envelope, req, decided_at);
    if (early) return early;

    let report: ResolutionReport;
    try {
      report = await resolveFacts(req.call, this.opts.resolvers, this.opts.resolveTimeoutMs ?? 5000);
    } catch (e) {
      // Fail closed. An unresolvable fact is not permission to use the agent's
      // version of it: that would let anything that can take the directory
      // offline get its own claims evaluated instead.
      const why = e instanceof FactsUnavailable ? e.message : (e as Error).message;
      return {
        outcome: 'deny', rule: 'facts', detail: `could not establish the facts of this call: ${why}`,
        envelope_id: req.envelope_id, revision: envelope.revision as number | undefined,
        derived: {}, contradictions: [], decided_at,
      };
    }

    // The call as the systems of record describe it. The agent's account is
    // kept only in context, where the spec says it belongs: evidence about the
    // call, never something that can widen the envelope.
    const call: Call = {
      tool: req.call.tool,
      arguments: req.call.arguments,
      recipients: report.facts.recipients,
      data: report.facts.data,
      estimated_cost_usd: report.facts.amount_usd,
      context: {
        ...(report.facts.context ?? {}),
        agent_claimed: req.call.claimed ?? {},
        contradicted: report.contradictions.map(c => c.field),
      },
    };

    const decision: Decision = evaluate(envelope, call, req.run ?? {}, {
      conditionMatcher: this.opts.conditionMatcher,
      dataMatcher: this.opts.dataMatcher,
    });

    return {
      outcome: decision.result as Outcome,
      rule: decision.rule,
      detail: decision.detail,
      envelope_id: req.envelope_id,
      revision: envelope.revision as number | undefined,
      derived: report.derivedBy,
      contradictions: report.contradictions,
      escalate_to: decision.escalateTo,
      timeout_seconds: decision.timeoutSeconds,
      decided_at,
    };
  }
}
