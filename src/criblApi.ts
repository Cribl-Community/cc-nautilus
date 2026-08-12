// Cribl platform API helpers — lookup management and search jobs.
// All calls go through CRIBL_API_URL which the platform proxy intercepts.

const LOOKUP_ID = 'nautilus_ioc_blocklist.csv';
const SEARCH_GROUP = 'default_search';
const KV_BLOCKLIST = 'nautilus-blocklist';

// CSV columns for the blocklist
export interface BlocklistEntry {
  value: string;       // the IOC itself
  type: string;        // ip | domain | url | hash
  verdict: string;     // malicious | suspicious
  source: string;      // which provider confirmed it
  added: string;       // ISO timestamp
  note: string;        // free-text
}

function criblBase(): string {
  return ((window as unknown as Record<string, unknown>)['CRIBL_API_URL'] as string) ?? '';
}

// ── Blocklist helpers ──────────────────────────────────────────────
// Strategy: KV store is the source of truth for reading (reliable, JSON).
// On every write we also sync to the lookup CSV so pipelines can use it.

function entriesToCsv(entries: BlocklistEntry[]): string {
  const header = 'value,type,verdict,source,added,note';
  const rows = entries.map(e =>
    [e.value, e.type, e.verdict, e.source, e.added, e.note]
      .map(v => `"${String(v).replace(/"/g, '""')}"`)
      .join(',')
  );
  return [header, ...rows].join('\n');
}

async function ensureLookupFile(): Promise<void> {
  const base = criblBase();
  const checkRes = await fetch(`${base}/system/lookups/${encodeURIComponent(LOOKUP_ID)}`);
  if (checkRes.ok) return;
  await fetch(`${base}/system/lookups`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: LOOKUP_ID,
      description: 'Nautilus CTI — confirmed IOC blocklist',
      mode: 'memory',
    }),
  });
}

async function syncToLookup(entries: BlocklistEntry[]): Promise<void> {
  const base = criblBase();
  await ensureLookupFile();
  const csv = entriesToCsv(entries);
  // Upload CSV content
  await fetch(`${base}/system/lookups?filename=${encodeURIComponent(LOOKUP_ID)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'text/csv' },
    body: csv,
  });
  // Link the uploaded file to the lookup record
  await fetch(`${base}/system/lookups/${encodeURIComponent(LOOKUP_ID)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: LOOKUP_ID, fileInfo: { filename: LOOKUP_ID } }),
  });
}

// Read blocklist from KV store (source of truth for the app).
export async function loadBlocklist(): Promise<BlocklistEntry[]> {
  const base = criblBase();
  if (!base) return [];
  try {
    const res = await fetch(`${base}/kvstore/${KV_BLOCKLIST}`);
    if (!res.ok) return [];
    return (await res.json()) as BlocklistEntry[];
  } catch { return []; }
}

// Add an IOC: write to KV store, then sync the lookup CSV.
export async function addToBlocklist(entry: Omit<BlocklistEntry, 'added'>): Promise<{ ok: boolean; error?: string }> {
  const base = criblBase();
  if (!base) return { ok: false, error: 'Not running in Cribl environment' };
  try {
    const existing = await loadBlocklist();
    if (existing.some(e => e.value === entry.value)) return { ok: true };

    const next: BlocklistEntry[] = [
      ...existing,
      { ...entry, added: new Date().toISOString() },
    ];

    // Write to KV store first
    const kvRes = await fetch(`${base}/kvstore/${KV_BLOCKLIST}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(next),
    });
    if (!kvRes.ok) {
      const err = await kvRes.text().catch(() => `HTTP ${kvRes.status}`);
      return { ok: false, error: err };
    }

    // Best-effort sync to lookup CSV for pipeline use
    await syncToLookup(next).catch(() => { /* non-fatal */ });

    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'Unknown error' };
  }
}

// ── Cribl Search helpers ───────────────────────────────────────────

export interface SearchResult {
  _time?: string | number;
  _raw?: string;
  [key: string]: unknown;
}

export interface SearchJobResult {
  events: SearchResult[];
  totalEventCount: number;
  isFinished: boolean;
  jobId: string;
}

function parseNdjson(text: string): SearchResult[] {
  return text.split('\n').filter(Boolean).flatMap(line => {
    try { return [JSON.parse(line) as SearchResult]; } catch { return []; }
  });
}

// Run a Cribl Search query and poll until done, returning up to `limit` results.
export async function runCriblSearch(
  query: string,
  opts: { earliest?: string; latest?: string; limit?: number } = {}
): Promise<SearchJobResult> {
  const base = criblBase();
  if (!base) throw new Error('Not running in Cribl environment');

  const { earliest = '-24h', latest = 'now', limit = 100 } = opts;

  // Create the job
  const createRes = await fetch(`${base}/m/${SEARCH_GROUP}/search/jobs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, earliest, latest }),
  });
  if (!createRes.ok) {
    const msg = await createRes.text().catch(() => `HTTP ${createRes.status}`);
    throw new Error(msg);
  }
  const jobBody = await createRes.json() as Record<string, unknown>;
  const jobId = (jobBody.id ?? (jobBody as { items?: Array<{ id?: string }> }).items?.[0]?.id ?? (jobBody as { jobId?: string }).jobId) as string | undefined;
  if (!jobId) {
    throw new Error(`Search job created but no job ID returned: ${JSON.stringify(jobBody).slice(0, 200)}`);
  }

  // Poll until complete (max 30s). Use results-poll which returns as soon as data is available.
  const deadline = Date.now() + 30_000;
  let pollDone = false;
  while (!pollDone && Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 1000));
    try {
      const statusRes = await fetch(`${base}/m/${SEARCH_GROUP}/search/jobs/${jobId}/status`);
      if (statusRes.ok) {
        // Status shape varies — check both top-level and nested fields
        const s = await statusRes.json() as Record<string, unknown>;
        const statusStr = (s?.status ?? s?.state ?? s?.jobStatus ?? '') as string;
        if (/complet|fail|cancel/i.test(statusStr)) { pollDone = true; break; }
      }
      // Also check job directly
      const jobRes = await fetch(`${base}/m/${SEARCH_GROUP}/search/jobs/${jobId}`);
      if (jobRes.ok) {
        const j = await jobRes.json() as Record<string, unknown>;
        const st = (j?.status ?? j?.state ?? '') as string;
        if (/complet|fail|cancel/i.test(st)) { pollDone = true; break; }
      }
    } catch { /* keep polling */ }
  }

  // Use results-poll endpoint which handles both in-progress and completed jobs
  const resultsUrl = `${base}/m/${SEARCH_GROUP}/search/jobs/${jobId}/results-poll?limit=${limit}&offset=0`;
  const resultsRes = await fetch(resultsUrl);
  if (!resultsRes.ok) {
    // Fallback to plain results endpoint
    const fallbackRes = await fetch(
      `${base}/m/${SEARCH_GROUP}/search/jobs/${jobId}/results?limit=${limit}&offset=0`
    );
    if (!fallbackRes.ok) throw new Error(`Results fetch failed: HTTP ${fallbackRes.status}`);
    const text = await fallbackRes.text();
    const events = parseNdjson(text);
    return { events, totalEventCount: events.length, isFinished: true, jobId };
  }

  const text = await resultsRes.text();
  const events: SearchResult[] = parseNdjson(text);

  // Total count from job metadata
  let totalEventCount = events.length;
  try {
    const jobRes = await fetch(`${base}/m/${SEARCH_GROUP}/search/jobs/${jobId}`);
    if (jobRes.ok) {
      const j = await jobRes.json() as { totalEventCount?: number; events?: { total?: number } };
      totalEventCount = j?.totalEventCount ?? j?.events?.total ?? events.length;
    }
  } catch { /* use events.length */ }

  return { events, totalEventCount, isFinished: pollDone, jobId };
}
