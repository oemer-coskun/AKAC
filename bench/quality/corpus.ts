import { emptyState } from '../../reference/types.ts';
import type { Actor, Binding, Container, Grant, Knowledge, Level, Role, State } from '../../reference/types.ts';

/**
 * Deterministic synthetic corpus for the retrieval-quality evaluation. Everything
 * is generated from a seed: five business domains, thirty topics, templated
 * documents with slot values and filler, paraphrased queries whose wording differs
 * from the documents (so a lexical embedder is not handed the answer), and a
 * permission model shaped like a company: a role hierarchy, one knowledge base per
 * domain with nested classification folders, project scoping, named-reader
 * documents, derived artifacts whose sources may be narrower than the artifact,
 * and a second tenant. No real names, companies or documents.
 */
export type Topic = { id: string; domain: Domain; title: string; facts: string[]; queries: string[] };
export type Domain = 'hr' | 'finance' | 'engineering' | 'legal' | 'product';
export const DOMAINS: readonly Domain[] = ['hr', 'finance', 'engineering', 'legal', 'product'];

const t = (id: string, domain: Domain, title: string, facts: string[], queries: string[]): Topic => ({ id, domain, title, facts, queries });
export const TOPICS: readonly Topic[] = [
  t('annual-leave', 'hr', 'Annual leave', [
    'Full-time staff accrue {n} days of paid annual leave per calendar year.',
    'Up to five unused holiday days may be carried over into the first quarter of the next year.',
    'Leave requests are submitted in the people portal at least two weeks before the first day off.',
    'Managers in {city} approve vacation requests against the team coverage calendar.',
    'Public holidays observed in {city} are not deducted from the leave balance.',
    'Part-time employees receive a pro-rata share of the yearly holiday allowance.'],
  ['How much time off do I get each year?', 'Can I move my remaining vacation days to next year?', 'What is the process to book days away from work?']),
  t('parental-leave', 'hr', 'Parental leave', [
    'Birth parents receive {n} weeks of fully paid leave after the child arrives.',
    'Adoptive and foster parents are eligible for the same paid family leave.',
    'The second parent may take leave in up to three blocks within the first year.',
    'Notify the people team twelve weeks before the expected due date.',
    'Returning parents may work a reduced schedule for the first month back.',
    'Health insurance contributions continue unchanged during family leave.'],
  ['How long can I stay home after having a baby?', 'Do adopting parents get time off too?', 'When do I have to tell HR that I am expecting?']),
  t('remote-work', 'hr', 'Remote work', [
    'Employees may work from home up to {n} days per week with manager agreement.',
    'A monthly stipend covers internet and home office equipment.',
    'Working from another country for more than thirty days requires tax review.',
    'Core collaboration hours are 10:00 to 15:00 in the {city} time zone.',
    'Company laptops must use the corporate VPN outside the office network.',
    'Hybrid teams meet in person at least once per sprint.'],
  ['Am I allowed to do my job from my apartment?', 'Is there money for a desk and chair at home?', 'Can I spend a few months working abroad?']),
  t('performance-review', 'hr', 'Performance reviews', [
    'Performance conversations take place twice a year in {month} and in the autumn.',
    'Each review combines self-assessment, peer feedback and manager evaluation.',
    'Ratings are calibrated across the department before they are shared.',
    'Promotion cases are submitted by the manager with written evidence of impact.',
    'Employees who disagree with an assessment may request a second review.',
    'Goals are recorded in the talent system and revisited every quarter.'],
  ['How often does my boss evaluate my work?', 'How do I get promoted to the next level?', 'What if I think my rating was unfair?']),
  t('onboarding', 'hr', 'Onboarding', [
    'New hires receive their laptop and badge on the first morning in {city}.',
    'Every newcomer is paired with a buddy for the first {n} weeks.',
    'Mandatory security and privacy training must be finished within the first month.',
    'The welcome session explains benefits, payroll dates and the org chart.',
    'Managers prepare a thirty-sixty-ninety day plan before the start date.',
    'Access to internal tools is requested through the service desk on day one.'],
  ['What happens during my first week at the company?', 'Who helps a new starter settle in?', 'Which courses must I complete after joining?']),
  t('workplace-conduct', 'hr', 'Workplace conduct', [
    'Harassment or discrimination can be reported confidentially to the ethics hotline.',
    'Reports are investigated by a trained case manager within {n} working days.',
    'Retaliation against anyone who raises a concern is itself a disciplinary offence.',
    'Witness statements are stored in a restricted case file.',
    'Outcomes may include coaching, a written warning or termination.',
    'Anonymous reports are accepted through the external reporting line.'],
  ['Where can I raise a complaint about a colleague treating me badly?', 'Will I get in trouble for reporting misconduct?', 'Can I flag bullying without giving my name?']),

  t('expense-reimbursement', 'finance', 'Expense reimbursement', [
    'Business expenses are reimbursed within {n} days of an approved claim.',
    'Receipts must be uploaded to the expense tool for every item above twenty-five euros.',
    'Client dinners require the names of all attendees on the claim.',
    'Mileage for private cars is reimbursed at the statutory rate per kilometre.',
    'Claims older than ninety days are rejected by the finance team in {city}.',
    'Alcohol is only reimbursable when a client is present.'],
  ['How do I get my money back for a work purchase?', 'Do I need to keep the paper slip from the restaurant?', 'Can I claim fuel when driving my own vehicle for a customer visit?']),
  t('quarterly-forecast', 'finance', 'Quarterly forecast', [
    'The rolling forecast is refreshed in the second week of each quarter.',
    'Department heads submit headcount and spend assumptions for the next {n} quarters.',
    'Variance above five percent against plan must be explained in writing.',
    'The forecast model lives in the planning system maintained by {team}.',
    'Revenue assumptions are aligned with the sales pipeline review.',
    'The board receives a consolidated outlook after the controller signs off.'],
  ['When do we update our projection of spending and income?', 'Who has to explain it when costs run over budget?', 'Where is the planning spreadsheet for next quarters kept?']),
  t('procurement', 'finance', 'Procurement approval', [
    'Purchases above {n} thousand euros need a purchase order before commitment.',
    'Three competing quotes are required for new suppliers.',
    'Vendor onboarding includes a security questionnaire and bank detail verification.',
    'The procurement desk in {city} negotiates framework agreements.',
    'Software subscriptions are bought centrally to avoid duplicate licences.',
    'Emergency purchases are approved retroactively by the budget owner.'],
  ['What do I need before buying something expensive from a new company?', 'How many offers must I collect from suppliers?', 'Who signs off on a software tool we want to subscribe to?']),
  t('invoice-payment', 'finance', 'Invoice payment terms', [
    'Supplier invoices are paid on {n}-day terms from the invoice date.',
    'Invoices must reference a valid purchase order number.',
    'Accounts payable runs two payment batches per week.',
    'Changes to supplier bank details are confirmed by phone with a known contact.',
    'Early payment discounts are taken when the saving exceeds the cost of cash.',
    'Disputed invoices are put on hold until the requester confirms delivery.'],
  ['When will a vendor get paid after sending a bill?', 'A supplier says their account number changed, what should we do?', 'Why is a bill from a contractor not settled yet?']),
  t('corporate-card', 'finance', 'Corporate cards and travel budget', [
    'Corporate cards carry a monthly limit of {n} thousand euros.',
    'Flights longer than six hours may be booked in premium economy.',
    'Hotel bookings in {city} should stay within the published city rate.',
    'Card statements are reconciled in the expense tool by the fifth of the month.',
    'Personal use of the company card is not permitted.',
    'Lost cards are blocked immediately through the bank hotline.'],
  ['What is the spending cap on my company credit card?', 'Can I fly a better seat class on a long trip?', 'How expensive may my hotel be on a business trip?']),
  t('revenue-recognition', 'finance', 'Revenue recognition', [
    'Subscription revenue is recognised evenly over the service period.',
    'Implementation fees are deferred when they are not distinct from the subscription.',
    'Multi-year contracts are split into performance obligations at signature.',
    'Usage-based fees are recognised in the month the usage occurs.',
    'The revenue team in {city} reviews every contract above {n} hundred thousand euros.',
    'Discounts are allocated across obligations by standalone selling price.'],
  ['When do we book income from annual subscriptions?', 'How are setup charges treated in the accounts?', 'How do we account for a three-year customer deal?']),

  t('incident-response', 'engineering', 'Incident response', [
    'The on-call engineer acknowledges a page within {n} minutes.',
    'Severity one incidents open a bridge call and a dedicated chat channel.',
    'The incident commander coordinates while responders focus on mitigation.',
    'Status page updates are posted every thirty minutes during an outage.',
    'A blameless postmortem is written within five working days.',
    'The {team} team owns the paging rotation and escalation policy.'],
  ['What should I do when I get woken up by an alert?', 'Who is in charge while production is down?', 'When do we write up what went wrong after an outage?']),
  t('deployment-rollback', 'engineering', 'Deployment and rollback', [
    'Production deploys run through the pipeline with canary analysis on {n} percent of traffic.',
    'A failed canary triggers an automatic rollback to the previous release.',
    'Manual rollbacks use the release tool and require a ticket reference.',
    'Database migrations must be backward compatible with the previous release.',
    'Deploy freezes apply during the last week of the quarter.',
    'The {system} service is deployed from the main branch only.'],
  ['How do I undo a bad release?', 'Can we ship to production at the end of the quarter?', 'How do schema changes stay safe when reverting code?']),
  t('backup-restore', 'engineering', 'Database backup and restore', [
    'Primary databases take a full snapshot every night and stream write-ahead logs continuously.',
    'Point-in-time recovery is possible for the last {n} days.',
    'Restore drills are executed every quarter and timed against the recovery objective.',
    'Backups are encrypted and copied to a second region.',
    'The {system} cluster restore runbook lists every verification step.',
    'Backup retention follows the legal retention schedule.'],
  ['How far back can we recover lost data?', 'Do we ever practise bringing a database back from a copy?', 'Where are the database copies stored?']),
  t('secret-rotation', 'engineering', 'Credential rotation', [
    'Service credentials are rotated at least every {n} days.',
    'Secrets are stored in the vault and never committed to source control.',
    'A leaked key is revoked first and then replaced in every consumer.',
    'Rotation jobs for the {system} service run automatically at night.',
    'Human access to production secrets requires a break-glass approval.',
    'Signing keys use a separate hierarchy with offline roots.'],
  ['How often must passwords used by services be changed?', 'Someone pushed an API token to a repository, what now?', 'Where are application passwords kept?']),
  t('code-review', 'engineering', 'Code review guidelines', [
    'Every change needs approval from at least {n} reviewers before merge.',
    'Reviewers check tests, error handling and backwards compatibility.',
    'Large changes are split into smaller pull requests of a few hundred lines.',
    'Security-sensitive files require a review from the {team} team.',
    'Authors respond to comments within one working day.',
    'Automated linters run before a human looks at the change.'],
  ['How many people must look at my pull request?', 'What do reviewers pay attention to?', 'Who has to approve edits to authentication code?']),
  t('capacity-planning', 'engineering', 'Capacity planning and load testing', [
    'Services are load tested at {n} times the expected peak before launch.',
    'Capacity reviews forecast storage and compute for the next two quarters.',
    'Autoscaling limits are set per service and reviewed after incidents.',
    'The {system} service keeps thirty percent headroom at peak.',
    'Latency budgets are defined as p99 targets per endpoint.',
    'Cost per request is tracked alongside utilisation.'],
  ['How do we make sure the system survives a traffic spike?', 'How much spare server room should we keep?', 'How do we predict how many machines we need next year?']),

  t('nda-contracts', 'legal', 'Non-disclosure agreements', [
    'Mutual NDAs are signed before any confidential information is exchanged.',
    'The standard template has a term of {n} years after disclosure.',
    'Deviations from the template require review by legal counsel.',
    'Signed agreements are filed in the contract repository.',
    'Residual knowledge clauses are not accepted.',
    'NDAs with competitors need approval from the general counsel.'],
  ['What paperwork do we need before sharing secrets with a partner?', 'How long does a confidentiality agreement last?', 'Can I change the wording of our secrecy contract?']),
  t('data-retention', 'legal', 'Data retention and erasure', [
    'Personal data is kept only as long as the purpose requires.',
    'Customer records are erased {n} months after contract end unless a hold applies.',
    'Erasure requests from data subjects are answered within one month.',
    'Retention periods are listed per system in the records schedule.',
    'Backups age out according to the same schedule.',
    'The privacy office in {city} approves exceptions.'],
  ['How long do we keep information about former clients?', 'A person asked us to delete everything about them, what is the deadline?', 'Where is the list of how long each system stores records?']),
  t('open-source', 'legal', 'Open source licensing', [
    'Permissive licences such as MIT and Apache 2.0 are pre-approved.',
    'Copyleft components in distributed products need legal review.',
    'Third-party notices are shipped with every release.',
    'The dependency scanner flags unknown licences in the {system} build.',
    'Contributions to external projects require manager approval.',
    'Licence obligations are tracked for {n} product lines.'],
  ['Can we use a library with a GPL licence in our product?', 'Do I need permission to contribute a fix to a public project?', 'Which third-party code licences are fine without asking?']),
  t('vendor-termination', 'legal', 'Vendor contract termination', [
    'Supplier contracts may be terminated for convenience with {n} days notice.',
    'Termination for breach requires a written cure period first.',
    'Data held by the supplier is returned or destroyed at exit.',
    'Exit plans are mandatory for critical suppliers.',
    'Legal counsel drafts the termination letter.',
    'Auto-renewal dates are tracked in the contract repository.'],
  ['How do we end an agreement with a supplier?', 'What happens to our data when we stop working with a provider?', 'Can a service contract roll over without us noticing?']),
  t('litigation-hold', 'legal', 'Litigation hold', [
    'A legal hold suspends deletion for every record related to a dispute.',
    'Custodians acknowledge the hold notice within {n} days.',
    'Holds override the normal retention schedule until released by counsel.',
    'IT preserves mailboxes and shared drives of the named custodians.',
    'The hold register lists matters, custodians and systems.',
    'Releasing a hold is recorded with the approving counsel.'],
  ['We are being sued, do we have to stop deleting emails?', 'What must an employee do after receiving a preservation notice?', 'Who decides when records connected to a lawsuit can be destroyed again?']),
  t('trademark', 'legal', 'Trademark and brand use', [
    'The company name and logo are registered trademarks in {n} jurisdictions.',
    'Partners may use the logo only under the brand guidelines.',
    'Product names are cleared by legal before announcement.',
    'Infringement reports go to the brand protection mailbox.',
    'Domain names containing the brand are registered centrally.',
    'Co-branding requires a signed licence agreement.'],
  ['Can a partner put our logo on their website?', 'How do we check a new product name is safe to use?', 'Someone is copying our brand, whom do I tell?']),

  t('roadmap', 'product', 'Roadmap prioritisation', [
    'The roadmap is reviewed every {n} weeks by product and engineering leads.',
    'Initiatives are scored on reach, impact, confidence and effort.',
    'Customer commitments are tracked separately from the backlog.',
    'The {system} team publishes the quarterly themes.',
    'Unplanned requests enter the intake board for triage.',
    'Trade-offs are documented in a decision log.'],
  ['How do we decide which features to build next?', 'Where do I submit an idea for the product?', 'How are promises to customers handled in planning?']),
  t('pricing', 'product', 'Pricing changes', [
    'List prices are reviewed once a year before the fiscal year starts.',
    'Existing customers receive {n} days notice before a price increase.',
    'Discounts above twenty percent require deal desk approval.',
    'New packaging is tested with a pilot group first.',
    'Grandfathered plans are migrated at renewal.',
    'Pricing pages in {city} show local currency and tax.'],
  ['How much warning do customers get before we charge more?', 'Who approves a big price reduction for a deal?', 'What happens to clients on old subscription plans?']),
  t('user-research', 'product', 'User research', [
    'Research interviews follow a consent script and are recorded only with permission.',
    'Participants receive a gift voucher worth {n} euros.',
    'Insights are tagged in the research repository by theme.',
    'Usability tests run with at least five participants per round.',
    'Raw recordings are deleted after ninety days.',
    'Findings are presented at the monthly product review in {city}.'],
  ['How do we talk to customers to learn what they need?', 'Do we pay people who take part in interviews?', 'How long do we keep session videos from studies?']),
  t('feature-flags', 'product', 'Feature flags and beta programme', [
    'New features launch behind a flag and roll out to {n} percent of accounts first.',
    'Beta customers sign a short programme agreement.',
    'Flags are removed within two releases after full rollout.',
    'Kill switches exist for every feature that touches billing.',
    'The {system} flag service keeps an audit of every change.',
    'Beta feedback is collected in a dedicated channel.'],
  ['How do we let a few customers try something new first?', 'How can we switch off a broken capability quickly?', 'What must early access customers agree to?']),
  t('churn', 'product', 'Churn analysis', [
    'Monthly logo churn is reported in the {month} business review.',
    'Accounts with falling usage over {n} weeks are flagged to customer success.',
    'Exit surveys capture the main reason for cancellation.',
    'Win-back offers are limited to one per account.',
    'Churn cohorts are compared by plan, region and segment.',
    'Health scores combine usage, support tickets and billing status.'],
  ['Why are clients cancelling their subscriptions?', 'How do we spot a customer who is about to leave?', 'Can we offer something to bring back a lost account?']),
  t('accessibility', 'product', 'Accessibility requirements', [
    'All customer-facing screens meet WCAG 2.2 level AA.',
    'Keyboard navigation is tested for every new component.',
    'Colour contrast is checked automatically in the design system.',
    'Screen reader testing happens before each major release.',
    'Accessibility issues are triaged within {n} days.',
    'The {team} team maintains the accessible component library.'],
  ['Can blind users operate our app?', 'Which standard do our screens have to follow for disabled people?', 'How fast do we fix problems for users who cannot use a mouse?'])
];

const FILLER = [
  'This page is maintained by the {team} team and was last reviewed in {month}.',
  'Questions can be raised in the internal help channel.',
  'See the related pages in this space for background.',
  'The guidance applies to all entities unless local law requires otherwise.',
  'Changes to this page are announced in the monthly newsletter.',
  'Ask your manager if something here is unclear.'
];
const SLOTS: Record<string, readonly string[]> = {
  n: ['2', '3', '5', '7', '10', '14', '15', '20', '25', '30', '45', '60'],
  city: ['Northport', 'Lakeside', 'Eastvale', 'Harbor City', 'Westfield'],
  team: ['platform', 'people operations', 'controlling', 'security', 'design systems', 'developer experience'],
  system: ['ledger', 'orders', 'search', 'identity', 'billing', 'catalog'],
  month: ['March', 'April', 'June', 'September', 'November']
};

/** mulberry32: small, seedable, good enough for synthetic data. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let x = Math.imul(a ^ (a >>> 15), 1 | a);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;
const fill = (r: () => number, s: string) => s.replace(/\{(\w+)\}/g, (_, k: string) => pick(r, SLOTS[k] ?? [k]));
function shuffle<T>(r: () => number, xs: T[]): T[] {
  for (let i = xs.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [xs[i], xs[j]] = [xs[j]!, xs[i]!]; }
  return xs;
}

/** Roles per domain: confidential folders admit `conf`, restricted folders admit `restricted`. */
const DOMAIN_ROLES: Record<Domain, { conf: string[]; restricted: string[] }> = {
  hr: { conf: ['hr-partner'], restricted: ['hr-lead'] },
  finance: { conf: ['finance-analyst'], restricted: ['controller'] },
  engineering: { conf: ['senior-engineer'], restricted: ['eng-lead'] },
  legal: { conf: ['legal-counsel'], restricted: ['legal-counsel'] },
  product: { conf: ['product-manager', 'engineer'], restricted: ['executive'] }
};
/** Role hierarchy: a role inherits (holds) its juniors. Depth up to 5. */
const ROLES: Record<string, string[]> = {
  employee: [], engineer: ['employee'], 'senior-engineer': ['engineer'], 'eng-lead': ['senior-engineer'],
  'finance-analyst': ['employee'], controller: ['finance-analyst'], 'hr-partner': ['employee'], 'hr-lead': ['hr-partner'],
  'legal-counsel': ['employee'], 'product-manager': ['employee'],
  executive: ['eng-lead', 'controller', 'hr-lead', 'legal-counsel', 'product-manager']
};
const PROJECTS = ['atlas', 'borealis', 'cobalt'];
/** Classification mix of source documents: 20 % public, 40 % internal, 30 % confidential, 10 % restricted. */
const MIX: [Level, number][] = [['public', 0.2], ['internal', 0.4], ['confidential', 0.3], ['restricted', 0.1]];
const LEVEL_ORDER: Level[] = ['public', 'internal', 'confidential', 'restricted'];

/**
 * Principals of the evaluation. Each has a user and an agent; the agent's clearance
 * or roles may be narrower than the user's (effective clearance is the minimum, and
 * an agent's roles are checked by decide() but not by the index pre-filter).
 */
export type Principal = { name: string; user: Omit<Actor, 'id' | 'tenant' | 'kind' | 'active'>; agent: Omit<Actor, 'id' | 'tenant' | 'kind' | 'active'> };
export const PRINCIPALS: readonly Principal[] = [
  { name: 'intern', user: { roles: ['employee'], projects: [], clearance: 'internal' }, agent: { roles: ['employee'], projects: [], clearance: 'restricted' } },
  { name: 'engineer', user: { roles: ['senior-engineer'], projects: ['atlas'], clearance: 'confidential' }, agent: { roles: ['senior-engineer'], projects: ['atlas'], clearance: 'restricted' } },
  { name: 'controller', user: { roles: ['controller'], projects: ['borealis'], clearance: 'restricted' }, agent: { roles: ['controller'], projects: ['borealis'], clearance: 'restricted' } },
  { name: 'hr-lead', user: { roles: ['hr-lead'], projects: [], clearance: 'restricted' }, agent: { roles: ['hr-lead'], projects: [], clearance: 'restricted' } },
  // Agent capped below the user: clearance intersection.
  { name: 'executive', user: { roles: ['executive'], projects: PROJECTS, clearance: 'restricted' }, agent: { roles: ['executive'], projects: PROJECTS, clearance: 'confidential' } },
  // Agent with fewer roles than its user: the pre-filter (user tokens) admits more than decide() allows.
  { name: 'counsel-narrow-agent', user: { roles: ['legal-counsel'], projects: ['cobalt'], clearance: 'restricted' }, agent: { roles: ['employee'], projects: ['cobalt'], clearance: 'restricted' } }
];

/**
 * `paraphrase`: a natural question worded differently from the documents (semantic match needed).
 * `keyword`: the topic title plus a generic noun, i.e. vocabulary the documents share (lexical match suffices).
 */
export type Query = { id: string; topic: string; text: string; kind: 'paraphrase' | 'keyword' };
export type Corpus = { state: State; now: number; tenant: string; docs: { id: string; topic: string }[]; queries: Query[];
  /** One grant per (principal, query): a retrieval context accumulates sources per run, so every query gets its own run. */
  binding(principal: string, query: string): Binding };

export type CorpusOptions = { seed?: number; documents?: number; now?: number; queriesPerTopic?: number; otherTenantShare?: number };
/**
 * Builds the state. `documents` is the acme document count (default 3000);
 * a further `otherTenantShare` (default 0.1) goes to tenant `globex`, which no
 * principal belongs to: any globex result is a cross-tenant disclosure.
 */
export function buildCorpus(options: CorpusOptions = {}): Corpus {
  const seed = options.seed ?? 20260929, total = options.documents ?? 3000, now = options.now ?? 1_800_000_000_000;
  const r = rng(seed), s = emptyState();
  const docs: { id: string; topic: string }[] = [];
  for (const tenant of ['acme', 'globex']) {
    const p = tenant === 'acme' ? '' : 'g-';
    for (const [id, inherits] of Object.entries(ROLES)) s.roles[`${p}${id}`] = { id: `${p}${id}`, tenant, inherits: inherits.map(x => `${p}${x}`), active: true } satisfies Role;
    for (const d of DOMAINS) {
      const roles = DOMAIN_ROLES[d];
      const chain: [Level, string[], string | undefined][] = [['public', ['employee'], undefined], ['internal', ['employee'], 'public'],
        ['confidential', roles.conf, 'internal'], ['restricted', roles.restricted, 'confidential']];
      for (const [level, readerRoles, parent] of chain) {
        const id = `${p}c-${d}-${level}`;
        s.containers[id] = { id, tenant, kind: parent ? 'folder' : 'knowledge-base', ...(parent ? { parent: `${p}c-${d}-${parent}` } : {}),
          classification: level, readerRoles: readerRoles.map(x => `${p}${x}`), readers: [], projects: [], active: true } satisfies Container;
      }
    }
  }
  const users: string[] = PRINCIPALS.map(x => x.name);
  const make = (tenant: string, n: number) => {
    const p = tenant === 'acme' ? '' : 'g-';
    const mine: Knowledge[] = [];
    for (let i = 0; i < n; i++) {
      const topic = TOPICS[i % TOPICS.length]!, roles = DOMAIN_ROLES[topic.domain];
      let x = r(), level: Level = 'restricted';
      for (const [l, w] of MIX) { if (x < w) { level = l; break; } x -= w; }
      const facts = shuffle(r, [...topic.facts]).slice(0, 3 + Math.floor(r() * 2)).map(f => fill(r, f));
      // Some documents also mention a neighbouring topic of the same domain (hard negatives for ranking).
      const neighbours = TOPICS.filter(o => o.domain === topic.domain && o.id !== topic.id);
      if (r() < 0.3) facts.push(fill(r, pick(r, pick(r, neighbours).facts)));
      facts.push(fill(r, pick(r, FILLER)));
      const content = `${topic.title} (${pick(r, SLOTS.city!)}).\n\n${facts.join(' ')}`;
      const readerRoles = level === 'public' || level === 'internal' ? ['employee'] : level === 'confidential' ? roles.conf : roles.restricted;
      const named = level !== 'public' && level !== 'internal' && r() < 0.05;
      const project = level !== 'public' && r() < 0.15 ? [pick(r, PROJECTS)] : [];
      const id = `${p}d-${topic.id}-${i}`;
      const k: Knowledge = { id, tenant, version: 1, kind: 'document', origin: 'human', content, classification: level,
        projects: project, readerRoles: named ? [] : readerRoles.map(y => `${p}${y}`), readers: named ? [`${p}${pick(r, users)}`] : [],
        sources: [], active: true, container: `${p}c-${topic.domain}-${level}` };
      mine.push(k);
    }
    // About 5 % of the documents are model-derived artifacts of one or two same-topic sources: their own
    // label is the highest source level, but a source may carry a narrower audience (named reader, project).
    for (const k of mine) {
      if (r() >= 0.05) continue;
      const pool = mine.filter(o => o.id !== k.id && o.sources.length === 0 && o.id.split('-').slice(0, -1).join('-') === k.id.split('-').slice(0, -1).join('-'));
      const sources = shuffle(r, pool).slice(0, 1 + Math.floor(r() * 2));
      if (!sources.length) continue;
      const level = LEVEL_ORDER[Math.max(LEVEL_ORDER.indexOf(k.classification), ...sources.map(x => LEVEL_ORDER.indexOf(x.classification)))]!;
      const topic = TOPICS.find(tp => k.id.includes(`d-${tp.id}-`))!, roles = DOMAIN_ROLES[topic.domain];
      k.kind = 'artifact'; k.origin = 'model'; k.sources = sources.map(x => ({ id: x.id, version: x.version }));
      k.classification = level; k.container = `${p}c-${topic.domain}-${level}`;
      if (k.readers.length === 0) k.readerRoles = (level === 'public' || level === 'internal' ? ['employee'] : level === 'confidential' ? roles.conf : roles.restricted).map(y => `${p}${y}`);
    }
    for (const k of mine) { s.knowledge[k.id] = k; if (tenant === 'acme') docs.push({ id: k.id, topic: k.id.slice(2, k.id.lastIndexOf('-')) }); }
  };
  make('acme', total);
  make('globex', Math.round(total * (options.otherTenantShare ?? 0.1)));

  const per = options.queriesPerTopic ?? 3;
  const queries: Query[] = TOPICS.flatMap(tp => [...tp.queries.slice(0, per).map((text, i) => ({ id: `q-${tp.id}-${i}`, topic: tp.id, text, kind: 'paraphrase' as const })),
    { id: `q-${tp.id}-kw`, topic: tp.id, text: `${tp.title} guidance`, kind: 'keyword' as const }]);
  for (const pr of PRINCIPALS) {
    s.actors[pr.name] = { id: pr.name, tenant: 'acme', kind: 'user', active: true, ...structuredClone(pr.user) };
    s.actors[`${pr.name}-agent`] = { id: `${pr.name}-agent`, tenant: 'acme', kind: 'agent', active: true, ...structuredClone(pr.agent) };
    for (const q of queries) {
      const id = `run-${pr.name}-${q.id}`;
      s.grants[id] = { id, tenant: 'acme', subject: pr.name, agent: `${pr.name}-agent`, actions: ['read'], resources: ['*'], purposes: ['work'],
        notBefore: now - 1000, expiresAt: now + 3_600_000, active: true } satisfies Grant;
    }
  }
  s.epochs.acme = 0; s.epochs.globex = 0;
  return { state: s, now, tenant: 'acme', docs, queries,
    binding: (principal, query) => ({ tenant: 'acme', subject: principal, agent: `${principal}-agent`, grant: `run-${principal}-${query}` }) };
}
