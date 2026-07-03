import type { ArtifactType } from './types';

export type RuleType = 'sigma' | 'yara';

export interface DetectionRule {
  id: string;
  type: RuleType;
  name: string;
  description: string;
  source: string;
  sourceUrl: string;
  rawUrl: string;
  content?: string;
  tags: string[];
  score: number;       // match score — higher = more context signals matched
  matchedOn: string[]; // which context terms triggered this match
}

// ── Rule index entry ─────────────────────────────────────────────────

interface RuleIndexEntry {
  path: string;
  rawUrl: string;
  htmlUrl: string;
  tokens: string[];    // lowercased tokens extracted from path/filename
}

// ── KV cache helpers (localStorage only — no Cribl KV needed for indexes) ──

const INDEX_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

interface CachedIndex {
  entries: RuleIndexEntry[];
  ts: number;
}

function lsGet<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) as T : null;
  } catch { return null; }
}

function lsSet(key: string, value: unknown) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* best-effort */ }
}

// ── Load bundled static indexes ───────────────────────────────────────
// Indexes are pre-built and shipped with the app in public/ to avoid
// proxy/auth issues with the GitHub API at runtime.

async function loadStaticIndex(filename: string): Promise<RuleIndexEntry[]> {
  try {
    const res = await fetch(`${import.meta.env.BASE_URL}${filename}`);
    if (!res.ok) return [];
    return await res.json() as RuleIndexEntry[];
  } catch { return []; }
}

async function getSigmaIndex(): Promise<RuleIndexEntry[]> {
  const cached = lsGet<CachedIndex>('nautilus-sigma-index');
  if (cached && Date.now() - cached.ts < INDEX_TTL_MS) return cached.entries;
  const entries = await loadStaticIndex('sigma-index.json');
  lsSet('nautilus-sigma-index', { entries, ts: Date.now() });
  return entries;
}

async function getYaraIndex(): Promise<RuleIndexEntry[]> {
  const cached = lsGet<CachedIndex>('nautilus-yara-index');
  if (cached && Date.now() - cached.ts < INDEX_TTL_MS) return cached.entries;
  const entries = await loadStaticIndex('yara-index.json');
  lsSet('nautilus-yara-index', { entries, ts: Date.now() });
  return entries;
}

// ── Context builder ───────────────────────────────────────────────────
// Builds a flat set of lowercased search terms from all enrichment context.
// Covers: IOC value, malware families, threat labels, tags, MITRE software
// IDs/names, technique IDs, CVE IDs, group names, campaign names.

export interface DetectionContext {
  indicator:       string;
  artifactType:    ArtifactType;
  malwareFamily?:  string;
  threatLabel?:    string;
  tags?:           string[];
  mitreSoftware?:  { id: string; name: string; type: string }[];
  mitreTechniques?: { id: string; name: string; tactic: string }[];
  cveId?:          string;
}

function buildSearchTerms(ctx: DetectionContext): Map<string, number> {
  // term -> weight (higher = more specific / more useful match signal)
  const terms = new Map<string, number>();

  function add(term: string | undefined | null, weight: number) {
    if (!term) return;
    const t = term.toLowerCase().trim();
    if (t.length > 1) terms.set(t, Math.max(terms.get(t) ?? 0, weight));
    // Also add word-level tokens for multi-word terms
    t.split(/[\s_-]+/).forEach(part => {
      if (part.length > 2) terms.set(part, Math.max(terms.get(part) ?? 0, weight - 1));
    });
  }

  // Highest weight: specific identifiers
  if (ctx.artifactType === 'cve' || ctx.cveId) {
    const cve = (ctx.cveId ?? ctx.indicator).toLowerCase().replace('cve-', '');
    add(ctx.cveId ?? ctx.indicator, 10);
    add(`cve${cve.replace(/-/g, '')}`, 9);
    add(`ms${cve.split('-')[0]?.slice(-2)}-${cve.split('-')[1] ?? ''}`, 8);
  }

  // Malware family / threat label — most useful for YARA
  add(ctx.malwareFamily, 9);
  add(ctx.threatLabel,   8);

  // MITRE software names + IDs — covers tool/malware/group cross-references
  ctx.mitreSoftware?.forEach(sw => {
    add(sw.name, 8);
    add(sw.id.toLowerCase(), 7);  // S0002 etc
  });

  // MITRE technique IDs — useful for SIGMA (ATT&CK-tagged rules)
  ctx.mitreTechniques?.forEach(t => {
    add(t.id.toLowerCase().replace('.', ''), 7);  // t1059001 → matches t1059_001 etc
    add(t.id.toLowerCase(), 7);
    add(t.tactic, 4);
  });

  // Tags from enrichment
  ctx.tags?.forEach(tag => add(tag, 5));

  // IOC value itself (useful for domains/IPs that appear in rule strings)
  if (ctx.artifactType === 'domain' || ctx.artifactType === 'ip') {
    add(ctx.indicator, 6);
  }

  return terms;
}

// ── Scorer ────────────────────────────────────────────────────────────
// Score an index entry against the search terms.
// Returns { score, matchedOn } or null if no match.

function scoreEntry(entry: RuleIndexEntry, terms: Map<string, number>): { score: number; matchedOn: string[] } | null {
  const matchedOn: string[] = [];
  let score = 0;

  for (const [term, weight] of terms) {
    if (entry.tokens.some(t => t.includes(term) || term.includes(t))) {
      score += weight;
      matchedOn.push(term);
    }
  }

  return score > 0 ? { score, matchedOn } : null;
}

// ── Fetch rule content on demand ─────────────────────────────────────

export async function fetchRuleContent(rule: DetectionRule): Promise<string> {
  try {
    const res = await fetch(rule.rawUrl);
    if (!res.ok) return '# Could not fetch rule content';
    return await res.text();
  } catch {
    return '# Could not fetch rule content';
  }
}

// ── Main lookup ───────────────────────────────────────────────────────

export async function lookupDetectionRules(ctx: DetectionContext): Promise<DetectionRule[]> {
  const terms = buildSearchTerms(ctx);
  if (terms.size === 0) return [];

  // Fetch both indexes in parallel (both cached after first run)
  const [sigmaIndex, yaraIndex] = await Promise.all([
    getSigmaIndex().catch(() => [] as RuleIndexEntry[]),
    getYaraIndex().catch(() => [] as RuleIndexEntry[]),
  ]);

  const results: DetectionRule[] = [];

  for (const entry of sigmaIndex) {
    const match = scoreEntry(entry, terms);
    if (!match) continue;
    const name = (entry.path.split('/').pop() ?? entry.path).replace(/\.ya?ml$/, '').replace(/_/g, ' ');
    results.push({
      id: `sigma-${entry.path}`,
      type: 'sigma',
      name,
      description: entry.path,
      source: 'SigmaHQ',
      sourceUrl: entry.htmlUrl,
      rawUrl: entry.rawUrl,
      tags: ['sigma'],
      score: match.score,
      matchedOn: match.matchedOn,
    });
  }

  for (const entry of yaraIndex) {
    const match = scoreEntry(entry, terms);
    if (!match) continue;
    const name = (entry.path.split('/').pop() ?? entry.path).replace(/\.ya?ra?$/, '').replace(/_/g, ' ');
    results.push({
      id: `yara-${entry.path}`,
      type: 'yara',
      name,
      description: entry.path,
      source: 'Yara-Rules',
      sourceUrl: entry.htmlUrl,
      rawUrl: entry.rawUrl,
      tags: ['yara'],
      score: match.score,
      matchedOn: match.matchedOn,
    });
  }

  // Sort by score descending, cap at top 20 per type
  const sigma = results.filter(r => r.type === 'sigma').sort((a, b) => b.score - a.score).slice(0, 20);
  const yara  = results.filter(r => r.type === 'yara').sort((a, b) => b.score - a.score).slice(0, 20);

  return [...sigma, ...yara];
}
