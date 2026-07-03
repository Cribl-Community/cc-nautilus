import { feedKvGet, feedKvSet, feedKvDelete } from './storage';
import type {
  FeedConfig, FeedPreview, FeedFormat, FeedStatus, IndicatorType, SyncLogEntry, FeedAuth,
} from './feedTypes';

function isDev(): boolean {
  try {
    const url = (window as unknown as Record<string, unknown>)['CRIBL_API_URL'];
    return typeof url !== 'string' || !url;
  } catch { return true; }
}

// In dev, rewrite known feed hostnames through the Vite proxy.
// In prod (Cribl Cloud), the browser fetches the full URL directly —
// the Cribl service worker proxies it based on proxies.yml.
const DEV_HOST_MAP: [string, string][] = [
  ['feodotracker.abuse.ch',          '/feed-proxy/feodotracker'],
  ['threatfox.abuse.ch',             '/feed-proxy/threatfox'],
  ['urlhaus.abuse.ch',               '/feed-proxy/urlhaus'],
  ['www.spamhaus.org',               '/feed-proxy/spamhaus'],
  ['rules.emergingthreats.net',      '/feed-proxy/et'],
  ['www.cisa.gov',                   '/feed-proxy/cisa'],
  ['raw.githubusercontent.com',      '/feed-proxy/github'],
  ['check.torproject.org',           '/feed-proxy/torproject'],
  ['lists.blocklist.de',             '/feed-proxy/blocklistde'],
  ['data.phishtank.com',             '/feed-proxy/phishtank'],
  ['bazaar.abuse.ch',                '/feed-proxy/bazaar'],
];

function feedFetchUrl(rawUrl: string): string {
  if (!isDev()) return rawUrl;
  try {
    const parsed = new URL(rawUrl);
    const entry = DEV_HOST_MAP.find(([host]) => parsed.hostname === host);
    if (!entry) return rawUrl;
    return entry[1] + parsed.pathname + parsed.search;
  } catch { return rawUrl; }
}

const AUTH_KEY_PREFIX = 'feed_auth_';

export async function saveFeedAuthKey(feedId: string, secret: string): Promise<void> {
  await feedKvSet(AUTH_KEY_PREFIX + feedId, secret);
}

export async function loadFeedAuthKey(feedId: string): Promise<string | null> {
  return feedKvGet<string>(AUTH_KEY_PREFIX + feedId);
}

export async function deleteFeedAuthKey(feedId: string): Promise<void> {
  await feedKvDelete(AUTH_KEY_PREFIX + feedId);
}

async function buildAuthFetchArgs(
  rawUrl: string,
  feedId: string,
  auth: FeedAuth | undefined,
): Promise<{ url: string; headers: Record<string, string> }> {
  if (!auth || auth.type === 'none') {
    return { url: feedFetchUrl(rawUrl), headers: {} };
  }

  const secret = auth.kvKey ? await loadFeedAuthKey(feedId) : null;

  if (auth.type === 'header') {
    const headerName = auth.headerName ?? 'Authorization';
    const value = secret ? `Bearer ${secret}` : '';
    return { url: feedFetchUrl(rawUrl), headers: secret ? { [headerName]: value } : {} };
  }

  if (auth.type === 'basic') {
    const [user, pass] = (secret ?? ':').split(':');
    const encoded = btoa(`${user ?? ''}:${pass ?? ''}`);
    return { url: feedFetchUrl(rawUrl), headers: secret ? { Authorization: `Basic ${encoded}` } : {} };
  }

  if (auth.type === 'queryparam') {
    const paramName = auth.paramName ?? 'apikey';
    if (secret) {
      const parsed = new URL(rawUrl);
      parsed.searchParams.set(paramName, secret);
      return { url: feedFetchUrl(parsed.toString()), headers: {} };
    }
    return { url: feedFetchUrl(rawUrl), headers: {} };
  }

  return { url: feedFetchUrl(rawUrl), headers: {} };
}

const feedConfigKey     = (id: string) => `naut_feed_cfg_${id}`;
const feedIndicatorsKey = (id: string) => `naut_feed_ind_${id}`;
const FEEDS_INDEX_KEY   = 'naut_feeds_index';
const SYNC_LOG_KEY      = 'naut_feeds_sync_log';
export const FEED_INDICATOR_CAP = 50_000;

export function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
}

function detectFormat(content: string, url: string): FeedFormat {
  const trimmed = content.trim();
  if (trimmed.startsWith('{') && (trimmed.includes('"type":"bundle"') || trimmed.includes('"type": "bundle"'))) return 'stix';
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) return 'json';
  if (url.toLowerCase().endsWith('.json')) return 'json';
  const firstDataLine = trimmed.split('\n').find(l => l.trim() && !l.startsWith('#'));
  if (firstDataLine && firstDataLine.split('\t').length > 1) return 'tsv';
  if (firstDataLine && firstDataLine.split(',').length > 1) return 'csv';
  return 'plaintext';
}

function detectIndicatorType(samples: string[]): IndicatorType {
  const ipv4    = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$/;
  const urlPat  = /^https?:\/\//i;
  const hashPat = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
  const domainPat = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/i;

  const counts = { ip: 0, url: 0, hash: 0, domain: 0 };
  for (const s of samples) {
    const clean = s.trim();
    if (ipv4.test(clean)) counts.ip++;
    else if (urlPat.test(clean)) counts.url++;
    else if (hashPat.test(clean)) counts.hash++;
    else if (domainPat.test(clean)) counts.domain++;
  }
  const max = Math.max(...Object.values(counts));
  if (max === 0) return 'mixed';
  return (Object.entries(counts).find(([, v]) => v === max)?.[0] ?? 'mixed') as IndicatorType;
}

function parsePlaintext(content: string): string[] {
  return content
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && !l.startsWith(';'));
}

export function parseCSV(content: string, indicatorField: string): string[] {
  const fieldTrimmed = indicatorField.trim();
  if (!fieldTrimmed) {
    throw new Error(
      "CSV format requires an indicator field — set the column name for this feed"
    );
  }

  const lines = content
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean);

  const stripHash  = (line: string) => line.replace(/^#\s*/, '');
  const parseFields = (line: string) =>
    line.split(',').map(f => f.trim().replace(/^"|"$/g, '').toLowerCase());

  let headerIdx = -1;
  let colIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    const fields = parseFields(stripHash(lines[i]));
    if (fields.length >= 2) {
      const idx = fields.indexOf(fieldTrimmed.toLowerCase());
      if (idx !== -1) { headerIdx = i; colIdx = idx; break; }
    }
  }

  if (colIdx === -1) {
    const firstNonComment = lines.find(l => !l.startsWith('#')) ?? lines[0] ?? '';
    const sampleHeaders = parseFields(stripHash(firstNonComment));
    throw new Error(
      `Column '${fieldTrimmed}' not found in CSV headers: [${sampleHeaders.join(', ')}]`
    );
  }

  return lines
    .slice(headerIdx + 1)
    .filter(l => !l.startsWith('#'))
    .map(line => {
      const parts = line.split(',');
      return (parts[colIdx] ?? '').trim().replace(/^"|"$/g, '');
    })
    .filter(Boolean);
}

// TSV: first column is the indicator, remaining columns are ignored.
// Handles comment lines (# or ;) and blank lines.
function parseTSV(content: string, indicatorField: string): string[] {
  const fieldTrimmed = indicatorField.trim();
  const lines = content
    .replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && !l.startsWith(';'));

  // If a field name is given, treat first line as header and find that column
  if (fieldTrimmed) {
    const header = lines[0]?.split('\t').map(h => h.trim().toLowerCase()) ?? [];
    const colIdx = header.indexOf(fieldTrimmed.toLowerCase());
    if (colIdx !== -1) {
      return lines.slice(1).map(l => l.split('\t')[colIdx]?.trim() ?? '').filter(Boolean);
    }
  }

  // Default: first column
  return lines.map(l => l.split('\t')[0]?.trim() ?? '').filter(Boolean);
}

function parseJSON(content: string, indicatorField: string): string[] {
  let parsed: unknown;
  try { parsed = JSON.parse(content); } catch { return []; }
  if (!Array.isArray(parsed)) return [];
  if (parsed.length === 0) return [];
  if (typeof parsed[0] === 'string') return (parsed as string[]).filter(Boolean);
  const field = indicatorField.trim();
  return (parsed as Record<string, unknown>[])
    .map(obj => String(obj[field] ?? ''))
    .filter(Boolean);
}

// Parse STIX bundle — extract indicator values from pattern field.
// Pattern examples: [ipv4-addr:value = '1.2.3.4']  [domain-name:value = 'evil.com']
function parseSTIX(content: string): string[] {
  let bundle: unknown;
  try { bundle = JSON.parse(content); } catch { return []; }
  const b = bundle as Record<string, unknown>;
  const objects = Array.isArray(b.objects) ? (b.objects as Record<string, unknown>[]) : [];
  const indicators = objects.filter(o => o.type === 'indicator');
  const results: string[] = [];
  for (const ind of indicators) {
    const pattern = typeof ind.pattern === 'string' ? ind.pattern : '';
    // Extract all quoted values from the pattern
    const matches = pattern.matchAll(/=\s*'([^']+)'/g);
    for (const m of matches) {
      const val = m[1].trim();
      if (val) results.push(val);
    }
  }
  return results;
}

function parseIndicators(content: string, format: FeedFormat, indicatorField: string): string[] {
  switch (format) {
    case 'plaintext': return parsePlaintext(content);
    case 'tsv':       return parseTSV(content, indicatorField);
    case 'csv':       return parseCSV(content, indicatorField);
    case 'json':      return parseJSON(content, indicatorField);
    case 'stix':      return parseSTIX(content);
  }
}

export async function previewFeed(
  url: string,
  format: FeedFormat | 'auto',
  indicatorField: string,
  feedId?: string,
  auth?: FeedAuth,
): Promise<FeedPreview> {
  const { url: fetchUrl, headers } = await buildAuthFetchArgs(url, feedId ?? 'preview', auth);
  const res = await fetch(fetchUrl, Object.keys(headers).length ? { headers } : undefined);
  if (!res.ok) throw new Error(`Fetch failed: ${res.status} ${res.statusText}`);
  const text = await res.text();
  const rawLines = text.split('\n').filter(l => l.trim());

  const resolvedFormat: FeedFormat = format === 'auto' ? detectFormat(text, url) : format;
  const indicators = parseIndicators(text, resolvedFormat, indicatorField);
  const sampleIndicators = indicators.slice(0, 10);
  const detectedType = detectIndicatorType(
    sampleIndicators.length > 0 ? sampleIndicators : indicators.slice(0, 20)
  );

  return {
    rows: rawLines.slice(0, 20),
    detectedFormat: resolvedFormat,
    detectedType,
    estimatedCount: indicators.length,
    sampleIndicators,
  };
}

export async function syncFeed(feed: FeedConfig): Promise<{ feed: FeedConfig; logEntry: SyncLogEntry }> {
  const startedAt = new Date().toISOString();
  const startMs = Date.now();

  const makeFailEntry = (errorMsg: string): SyncLogEntry => ({
    id: crypto.randomUUID(),
    timestamp: startedAt,
    feedId: feed.id,
    feedName: feed.name,
    success: false,
    error: errorMsg,
    durationMs: Date.now() - startMs,
  });

  let text: string;
  try {
    const { url: fetchUrl, headers } = await buildAuthFetchArgs(feed.url, feed.id, feed.auth);
    const res = await fetch(fetchUrl, Object.keys(headers).length ? { headers } : undefined);

    // If 401/403 and no auth configured, mark needsAuth so the UI can surface it
    if ((res.status === 401 || res.status === 403) && (!feed.auth || feed.auth.type === 'none')) {
      const errorMsg = `${res.status} ${res.statusText} — this feed may require authentication`;
      const updatedFeed: FeedConfig = {
        ...feed, lastSync: startedAt, lastSyncError: errorMsg,
        lastSyncStage: 'fetch_failed', needsAuth: true,
      };
      const logEntry = makeFailEntry(errorMsg);
      await saveFeed(updatedFeed);
      return { feed: updatedFeed, logEntry };
    }

    if (!res.ok) throw new Error(`Feed fetch failed: ${res.status} ${res.statusText}`);
    text = await res.text();
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    const updatedFeed: FeedConfig = {
      ...feed, lastSync: startedAt, lastSyncError: errorMsg, lastSyncStage: 'fetch_failed',
    };
    const logEntry = makeFailEntry(errorMsg);
    await saveFeed(updatedFeed);
    return { feed: updatedFeed, logEntry };
  }

  let indicators: string[];
  try {
    indicators = parseIndicators(text, feed.format, feed.indicatorField);
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    const updatedFeed: FeedConfig = {
      ...feed, lastSync: startedAt, lastSyncError: errorMsg, lastSyncStage: 'parse_failed',
    };
    const logEntry = makeFailEntry(errorMsg);
    await saveFeed(updatedFeed);
    return { feed: updatedFeed, logEntry };
  }

  const normalized = indicators.map(v => v.toLowerCase().trim()).filter(Boolean);
  const truncated = normalized.length > FEED_INDICATOR_CAP;
  const toStore = truncated ? normalized.slice(0, FEED_INDICATOR_CAP) : normalized;
  await feedKvSet(feedIndicatorsKey(feed.id), toStore).catch(e =>
    console.error('[syncFeed] indicator persist failed:', e),
  );

  const updatedFeed: FeedConfig = {
    ...feed,
    lastSync: startedAt,
    lastSyncCount: indicators.length,
    lastSyncError: null,
    lastSyncStage: undefined,
    needsAuth: false,
    ...(truncated ? { lastSyncTruncated: true } : {}),
  };
  const logEntry: SyncLogEntry = {
    id: crypto.randomUUID(),
    timestamp: startedAt,
    feedId: feed.id,
    feedName: feed.name,
    success: true,
    indicatorCount: indicators.length,
    durationMs: Date.now() - startMs,
  };
  await saveFeed(updatedFeed);
  await loadSyncLog().then(existing => {
    const updated = [logEntry, ...existing].slice(0, 100);
    return feedKvSet(SYNC_LOG_KEY, updated);
  }).catch(e => console.error('[syncFeed] sync log persist failed:', e));
  return { feed: updatedFeed, logEntry };
}

export async function loadFeeds(): Promise<FeedConfig[]> {
  const ids = await feedKvGet<string[]>(FEEDS_INDEX_KEY);
  if (!Array.isArray(ids) || ids.length === 0) return [];
  const results = await Promise.allSettled(ids.map(id => feedKvGet<FeedConfig>(feedConfigKey(id))));
  return results
    .filter((r): r is PromiseFulfilledResult<FeedConfig> =>
      r.status === 'fulfilled' && r.value !== null
    )
    .map(r => r.value);
}

export async function saveFeed(feed: FeedConfig): Promise<void> {
  await feedKvSet(feedConfigKey(feed.id), feed);
  const ids = await feedKvGet<string[]>(FEEDS_INDEX_KEY);
  const current = Array.isArray(ids) ? ids : [];
  if (!current.includes(feed.id)) {
    await feedKvSet(FEEDS_INDEX_KEY, [...current, feed.id]);
  }
}

export async function deleteFeed(feedId: string): Promise<void> {
  await Promise.all([
    feedKvDelete(feedConfigKey(feedId)),
    feedKvDelete(feedIndicatorsKey(feedId)),
  ]);
  const ids = await feedKvGet<string[]>(FEEDS_INDEX_KEY);
  const current = Array.isArray(ids) ? ids : [];
  await feedKvSet(FEEDS_INDEX_KEY, current.filter(id => id !== feedId));
}

export async function loadFeedIndicators(feedId: string): Promise<string[]> {
  try {
    const data = await feedKvGet<string[]>(feedIndicatorsKey(feedId));
    return Array.isArray(data) ? data : [];
  } catch { return []; }
}

export async function loadSyncLog(): Promise<SyncLogEntry[]> {
  const raw = await feedKvGet<SyncLogEntry[]>(SYNC_LOG_KEY);
  return Array.isArray(raw) ? raw : [];
}

export function isStale(feed: FeedConfig): boolean {
  if (!feed.lastSync) return false;
  const cutoff = Date.now() - feed.ttlDays * 24 * 60 * 60 * 1000;
  return new Date(feed.lastSync).getTime() < cutoff;
}

export function deriveFeedStatus(feed: FeedConfig, syncing: boolean): FeedStatus {
  if (syncing) return 'syncing';
  if (!feed.lastSync) return 'never_synced';
  if (feed.lastSyncError) return feed.lastSyncStage ?? 'fetch_failed';
  return 'synced';
}

export function relativeTime(ts: string | null): string {
  if (!ts) return 'Never';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function makeFeedConfig(
  partial: Omit<FeedConfig, 'id' | 'addedAt' | 'lastSync' | 'lastSyncCount' | 'lastSyncError'>,
): FeedConfig {
  return {
    ...partial,
    id: crypto.randomUUID(),
    addedAt: new Date().toISOString(),
    lastSync: null,
    lastSyncCount: null,
    lastSyncError: null,
  };
}

// Check if a query matches any loaded feed indicators
export async function checkFeedMatches(query: string, feeds: FeedConfig[]): Promise<import('./feedTypes').FeedMatch[]> {
  const q = query.toLowerCase().trim();
  const matches: import('./feedTypes').FeedMatch[] = [];
  for (const feed of feeds) {
    if (!feed.lastSyncCount) continue;
    const indicators = await loadFeedIndicators(feed.id);
    if (indicators.includes(q)) {
      matches.push({
        feedId: feed.id,
        feedName: feed.name,
        indicatorType: feed.indicatorType,
        trustScore: feed.trustScore,
      });
    }
  }
  return matches;
}
