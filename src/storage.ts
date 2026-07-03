import type { ProviderKey, RoutingPrefs, KeyValidation } from './types';

const KEYS_PATH       = 'nautilus-keys-v2';
const ROUTING_PATH    = 'nautilus-routing-v2';
const VALIDATION_PATH = 'nautilus-validation-v1';
const HISTORY_PATH    = 'nautilus-history-v1';
const HISTORY_MAX     = 50;

function criblBase(): string | null {
  try {
    const url = (window as unknown as Record<string, unknown>)['CRIBL_API_URL'];
    return typeof url === 'string' && url ? url : null;
  } catch {
    return null;
  }
}

// Cribl's service worker proxy parses the KV GET response then reconstructs
// it by calling toString() on the parsed value — objects become "[object Object]".
// Workaround: store as a base64 string. The proxy parses a JSON string to a JS
// string, and string.toString() returns the string correctly. We recover the
// original value by base64-decoding on read.

function kvEncode(value: unknown): string {
  return btoa(encodeURIComponent(JSON.stringify(value)));
}

function kvDecode<T>(raw: string): T | null {
  try {
    const s = raw.trim();
    return JSON.parse(decodeURIComponent(atob(s))) as T;
  } catch { return null; }
}

async function kvGet<T>(path: string, lsKey: string): Promise<T | null> {
  const base = criblBase();
  if (base) {
    try {
      const r = await fetch(`${base}/kvstore/${path}`);
      if (!r.ok) return null;
      const raw = new TextDecoder().decode(await r.arrayBuffer());
      if (!raw || raw === '[object Object]') return null;
      let payload = raw;
      if (raw.startsWith('[') && raw.endsWith(']')) {
        try { payload = (JSON.parse(raw) as string[])[0]; } catch { /* use raw */ }
      }
      return kvDecode<T>(payload);
    } catch { return null; }
  }
  try {
    const raw = localStorage.getItem(lsKey);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch { return null; }
}

async function kvPut(path: string, lsKey: string, value: unknown): Promise<void> {
  const base = criblBase();
  if (base) {
    try {
      // Stored as a single-element array wrapping a base64 payload.
      // Cribl's fetch proxy calls toString() on the parsed response body —
      // arrays stringify cleanly, plain strings and objects do not.
      await fetch(`${base}/kvstore/${path}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([kvEncode(value)]),
      });
    } catch { /* best-effort */ }
    return;
  }
  try { localStorage.setItem(lsKey, JSON.stringify(value)); } catch { /* best-effort */ }
}

export async function loadKeys(): Promise<Record<string, ProviderKey>> {
  return (await kvGet<Record<string, ProviderKey>>(KEYS_PATH, 'nautilis-keys')) ?? {};
}

export async function saveKeys(keys: Record<string, ProviderKey>): Promise<void> {
  await kvPut(KEYS_PATH, 'nautilis-keys', keys);
}

export function getActiveKey(keys: Record<string, ProviderKey>, providerId: string): string | null {
  const pk = keys[providerId];
  if (!pk || !pk.keys.length) return null;
  return pk.keys[pk.activeIndex] ?? pk.keys[0] ?? null;
}

export function upsertKey(
  keys: Record<string, ProviderKey>,
  providerId: string,
  newKey: string
): Record<string, ProviderKey> {
  const existing = keys[providerId];
  if (existing) {
    const already = existing.keys.indexOf(newKey);
    if (already !== -1) {
      return { ...keys, [providerId]: { ...existing, activeIndex: already } };
    }
    return {
      ...keys,
      [providerId]: {
        ...existing,
        keys: [...existing.keys, newKey],
        activeIndex: existing.keys.length,
      },
    };
  }
  return {
    ...keys,
    [providerId]: { providerId, keys: [newKey], activeIndex: 0 },
  };
}

export function setActiveKey(
  keys: Record<string, ProviderKey>,
  providerId: string,
  index: number
): Record<string, ProviderKey> {
  const existing = keys[providerId];
  if (!existing) return keys;
  return { ...keys, [providerId]: { ...existing, activeIndex: index } };
}

export async function loadValidations(): Promise<Record<string, KeyValidation>> {
  return (await kvGet<Record<string, KeyValidation>>(VALIDATION_PATH, 'nautilus-validation')) ?? {};
}

export async function saveValidations(v: Record<string, KeyValidation>): Promise<void> {
  await kvPut(VALIDATION_PATH, 'nautilus-validation', v);
}

export async function loadRoutingPrefs(): Promise<RoutingPrefs> {
  return (await kvGet<RoutingPrefs>(ROUTING_PATH, 'nautilis-routing')) ?? {};
}

export async function saveRoutingPrefs(prefs: RoutingPrefs): Promise<void> {
  await kvPut(ROUTING_PATH, 'nautilis-routing', prefs);
}

export interface HistoryEntry {
  query:        string;
  artifactType: string;
  ts:           number;
  pivotCount?:  number;
}

export async function loadHistory(): Promise<HistoryEntry[]> {
  return (await kvGet<HistoryEntry[]>(HISTORY_PATH, 'nautilus-history')) ?? [];
}

// ── MITRE ATT&CK cache (split into 3 KV entries) ──────────────────

// KV 1: group profiles — name, aliases, ATT&CK ID, description, sectors, countries, associated groups
// KV 2: techniques — per-group technique list with full names and tactic
// KV 3: software/campaigns/mitigations — per-group malware, tools, campaigns, mitigations

export interface MitreProfileEntry {
  cachedAt: number;
  groups: {
    id:              string;
    name:            string;
    aliases:         string[];
    attackId:        string;
    desc:            string;
    sectors:         string[];
    countries:       string[];
    associatedGroups: string[];   // names only
  }[];
}

export interface MitreTechniquesEntry {
  cachedAt: number;
  // keyed by STIX group ID
  byGroup: Record<string, { id: string; name: string; tactic: string }[]>;
}

export interface MitreSoftwareEntry {
  cachedAt: number;
  // keyed by STIX group ID
  byGroup: Record<string, {
    software:    { id: string; name: string; type: string }[];
    campaigns:   { id: string; name: string }[];
    mitigations: { id: string; name: string }[];
  }>;
}

// Session-assembled full group record (joined from all three KVs)
export interface MitreCachedGroup {
  id:       string;
  name:     string;
  aliases:  string[];
  attackId: string;
  _desc?:   string;
  _related: {
    techniques:      { id: string; name: string; tactic: string }[];
    software:        { id: string; name: string; type: string }[];
    campaigns:       { id: string; name: string }[];
    mitigations:     { id: string; name: string }[];
    sectors:         string[];
    countries:       string[];
    associatedGroups: { id: string; name: string }[];
  };
}

export interface MitreCacheEntry {
  cachedAt: number;
  groups:   MitreCachedGroup[];
}

const MITRE_PROFILES_PATH   = 'nautilus-mitre-profiles-v1';
const MITRE_TECHNIQUES_PATH = 'nautilus-mitre-techniques-v1';
const MITRE_SOFTWARE_PATH   = 'nautilus-mitre-software-v1';

export async function loadMitreProfiles(): Promise<MitreProfileEntry | null> {
  return kvGet<MitreProfileEntry>(MITRE_PROFILES_PATH, 'nautilus-mitre-profiles');
}
export async function saveMitreProfiles(entry: MitreProfileEntry): Promise<void> {
  await kvPut(MITRE_PROFILES_PATH, 'nautilus-mitre-profiles', entry);
}

export async function loadMitreTechniques(): Promise<MitreTechniquesEntry | null> {
  return kvGet<MitreTechniquesEntry>(MITRE_TECHNIQUES_PATH, 'nautilus-mitre-techniques');
}
export async function saveMitreTechniques(entry: MitreTechniquesEntry): Promise<void> {
  await kvPut(MITRE_TECHNIQUES_PATH, 'nautilus-mitre-techniques', entry);
}

export async function loadMitreSoftware(): Promise<MitreSoftwareEntry | null> {
  return kvGet<MitreSoftwareEntry>(MITRE_SOFTWARE_PATH, 'nautilus-mitre-software');
}
export async function saveMitreSoftware(entry: MitreSoftwareEntry): Promise<void> {
  await kvPut(MITRE_SOFTWARE_PATH, 'nautilus-mitre-software', entry);
}

export async function loadMitreCache(): Promise<MitreCacheEntry | null> {
  const [profiles, techniques, software] = await Promise.all([
    loadMitreProfiles(),
    loadMitreTechniques(),
    loadMitreSoftware(),
  ]);
  if (!profiles) return null;
  const cachedAt = profiles.cachedAt;
  const groups: MitreCachedGroup[] = profiles.groups.map(p => ({
    id:       p.id,
    name:     p.name,
    aliases:  p.aliases,
    attackId: p.attackId,
    _desc:    p.desc || undefined,
    _related: {
      techniques:      techniques?.byGroup[p.id] ?? [],
      software:        software?.byGroup[p.id]?.software    ?? [],
      campaigns:       software?.byGroup[p.id]?.campaigns   ?? [],
      mitigations:     software?.byGroup[p.id]?.mitigations ?? [],
      sectors:         p.sectors,
      countries:       p.countries,
      associatedGroups: p.associatedGroups.map(name => ({ id: '', name })),
    },
  }));
  return { cachedAt, groups };
}

export function isMitreCacheFresh(entry: MitreCacheEntry): boolean {
  const TTL = 30 * 24 * 60 * 60 * 1000;
  return Date.now() - entry.cachedAt < TTL;
}

// ── Threat Feed KV helpers ──────────────────────────────────────────

export async function feedKvGet<T>(path: string): Promise<T | null> {
  return kvGet<T>(path, `nautilus-feed-${path}`);
}

export async function feedKvSet(path: string, value: unknown): Promise<void> {
  return kvPut(path, `nautilus-feed-${path}`, value);
}

export async function feedKvDelete(path: string): Promise<void> {
  const base = criblBase();
  if (base) {
    try { await fetch(`${base}/kvstore/${path}`, { method: 'DELETE' }); } catch { /* best-effort */ }
    return;
  }
  try { localStorage.removeItem(`nautilus-feed-${path}`); } catch { /* best-effort */ }
}

export async function pushHistory(entry: HistoryEntry, existing?: HistoryEntry[]): Promise<HistoryEntry[]> {
  const base    = existing ?? await loadHistory();
  const deduped = base.filter(e => e.query !== entry.query);
  const next    = [entry, ...deduped].slice(0, HISTORY_MAX);
  await kvPut(HISTORY_PATH, 'nautilus-history', next);
  return next;
}

export function removeKey(
  keys: Record<string, ProviderKey>,
  providerId: string,
  index: number
): Record<string, ProviderKey> {
  const existing = keys[providerId];
  if (!existing) return keys;
  const next = existing.keys.filter((_, i) => i !== index);
  const activeIndex = Math.min(existing.activeIndex, Math.max(0, next.length - 1));
  return { ...keys, [providerId]: { ...existing, keys: next, activeIndex } };
}
