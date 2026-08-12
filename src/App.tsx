import { useState, useEffect, useRef } from 'react';
import type { ArtifactType, ProviderKey, QueryResult, RoutingPrefs, KeyValidation, VtRelations, VtRelationGroup } from './types';
import { PROVIDERS, routedProviders } from './providers';
import { detectArtifact, ARTIFACT_LABELS, ARTIFACT_COLORS } from './detect';
import { loadKeys, saveKeys, upsertKey, setActiveKey, removeKey, getActiveKey, loadRoutingPrefs, saveRoutingPrefs, loadHistory, pushHistory, loadValidations, saveValidations } from './storage';
import type { HistoryEntry } from './storage';
import type { PanelData } from './panelData';
import { emptyPanels, hasGeo, hasReputation, hasNetwork, hasAnon, hasFile, hasCve, hasTimeline } from './panelData';
import { loadMitreCache, loadMitreProfiles, loadMitreTechniques, loadMitreSoftware, saveMitreProfiles, saveMitreTechniques, saveMitreSoftware } from './storage';
import type { MitreCacheEntry, MitreCachedGroup, MitreProfileEntry, MitreTechniquesEntry, MitreSoftwareEntry } from './storage';

import { GeoResultPanel, ReputationResultPanel, NetworkResultPanel, AnonResultPanel, FileResultPanel, DetectionResultPanel, CveLeftPanel, CveRightPanel, TimelineResultPanel, ThreatGroupSummaryPanel, ThreatGroupTechniquesPanel, ThreatGroupClassificationPanel, ThreatGroupTargetingPanel, DetectionRulesPanel, MitreAttackPanel } from './ResultPanels';
import { FindInLogs, CopyForAI } from './CriblPanel';
import ThreatFeeds from './ThreatFeeds';
import IocExtractor from './IocExtractor';
import BulkSearch from './BulkSearch';
import DatasetExplorer from './DatasetExplorer';
import type { FeedMatch } from './feedTypes';
import { loadFeeds, checkFeedMatches } from './feedService';
import type { MitreOverlayResult } from './mitreOverlay';
import { lookupMitreOverlay } from './mitreOverlay';
import type { DetectionRule } from './detectionRules';
import { lookupDetectionRules } from './detectionRules';
import type { DetectionContext } from './detectionRules';
import './App.css';


// ── Provider selector (left panel) ────────────────────────────────

// Tracks the current time as state so components can derive "age" values
// without calling Date.now() directly during render (which React treats as impure).
function useNow(intervalMs = 60_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

// ── Search bar ─────────────────────────────────────────────────────

async function hashFile(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function SearchBar({ onSearch, loading, value, onChange }: {
  onSearch: (q: string) => void;
  loading: boolean;
  value: string;
  onChange: (v: string) => void;
}) {
  const detected = value.trim() ? detectArtifact(value) : null;
  const color = detected ? ARTIFACT_COLORS[detected] : null;
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [hashing, setHashing] = useState(false);

  function submit() {
    if (value.trim()) onSearch(value.trim());
  }

  async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setHashing(true);
    const hash = await hashFile(file);
    setHashing(false);
    onChange(hash);
    onSearch(hash);
    // Reset so same file can be re-selected
    e.target.value = '';
  }

  return (
    <div className="search-bar-wrap">
      <div className="search-bar-row" style={color ? { borderColor: color.border } : undefined}>
        <input
          className="search-input"
          value={value}
          onChange={e => onChange(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && submit()}
          placeholder="IP, domain, URL, hash, filename, CVE-ID, threat group…"
          spellCheck={false}
          autoFocus
        />
        {value && <button className="search-clear" onClick={() => onChange('')}>✕</button>}
        <button className="search-btn" onClick={submit} disabled={!value.trim() || loading}>
          {loading ? '…' : 'Search'}
        </button>
        <button
          className="search-file-btn"
          onClick={() => fileInputRef.current?.click()}
          disabled={hashing || loading}
          title="Hash a file and search"
        >
          {hashing ? '…' : '📎'}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          style={{ display: 'none' }}
          onChange={e => void handleFileChange(e)}
        />
      </div>
      <div className="search-hint-row">
        {detected && detected !== 'unknown' && (
          <span className="artifact-chip" style={{ background: color!.bg, color: color!.color, borderColor: color!.border }}>
            {ARTIFACT_LABELS[detected]}
          </span>
        )}
        {detected === 'unknown' && value.trim() && (
          <span className="artifact-chip artifact-unknown">Unrecognized — try IP, domain, URL, hash, CVE, or threat group</span>
        )}
      </div>
    </div>
  );
}


// ── Settings panel ─────────────────────────────────────────────────

const ROUTABLE_TYPES: ArtifactType[] = ['ip', 'domain', 'url', 'hash', 'file', 'threat-group', 'cve'];

const TYPE_SHORT: Record<ArtifactType, string> = {
  ip: 'IP', domain: 'Domain', url: 'URL', hash: 'Hash',
  'threat-group': 'Actor', file: 'File', cve: 'CVE', unknown: '?',
};

async function validateKey(providerId: string, apiKey: string): Promise<KeyValidation> {
  try {
    if (providerId === 'greynoise') {
      const base = isDev() ? '/greynoise-proxy' : 'https://api.greynoise.io';
      const r = await fetch(`${base}/ping`, {
        headers: { key: apiKey }, signal: AbortSignal.timeout(8000),
      });
      if (r.status === 401) return { status: 'invalid', checkedAt: Date.now() };
      if (!r.ok) return { status: 'unknown', checkedAt: Date.now(), detail: `HTTP ${r.status}` };
      const d = await r.json() as Record<string, unknown>;
      return {
        status: 'valid', checkedAt: Date.now(),
        plan:    String(d.offering ?? d.plan ?? ''),
        expires: d.expiration ? String(d.expiration) : undefined,
      };
    }
    if (providerId === 'shodan') {
      const base = isDev() ? '/shodan-proxy' : 'https://api.shodan.io';
      const r = await fetch(`${base}/api-info?key=${encodeURIComponent(apiKey)}`, {
        signal: AbortSignal.timeout(8000),
      });
      if (r.status === 401) return { status: 'invalid', checkedAt: Date.now() };
      if (!r.ok) return { status: 'unknown', checkedAt: Date.now(), detail: `HTTP ${r.status}` };
      const d = await r.json() as Record<string, unknown>;
      return {
        status: 'valid', checkedAt: Date.now(),
        plan:    String(d.plan ?? ''),
        credits: `${d.query_credits ?? '?'} query / ${d.scan_credits ?? '?'} scan credits`,
      };
    }
    if (providerId === 'virustotal') {
      const base = isDev() ? '/vt-proxy' : 'https://www.virustotal.com';
      const r = await fetch(`${base}/api/v3/users/current`, {
        headers: { 'x-apikey': apiKey }, signal: AbortSignal.timeout(8000),
      });
      if (r.status === 401 || r.status === 403) return { status: 'invalid', checkedAt: Date.now() };
      if (r.status === 429) return { status: 'rate-limited', checkedAt: Date.now() };
      if (!r.ok) return { status: 'unknown', checkedAt: Date.now(), detail: `HTTP ${r.status}` };
      const d = await r.json() as Record<string, unknown>;
      const attrs = (d.data as Record<string, unknown> | undefined)?.attributes as Record<string, unknown> | undefined;
      return {
        status: 'valid', checkedAt: Date.now(),
        plan: String(attrs?.status ?? attrs?.type ?? ''),
      };
    }
    if (providerId === 'censys') {
      const base = isDev() ? '/censys-proxy' : 'https://search.censys.io';
      const [id, secret] = apiKey.split(':');
      const r = await fetch(`${base}/api/v2/account`, {
        headers: { 'Authorization': `Basic ${btoa(`${id}:${secret ?? ''}`)}` },
        signal: AbortSignal.timeout(8000),
      });
      if (r.status === 401 || r.status === 403) return { status: 'invalid', checkedAt: Date.now() };
      if (!r.ok) return { status: 'unknown', checkedAt: Date.now(), detail: `HTTP ${r.status}` };
      const d = await r.json() as Record<string, unknown>;
      const result = d.result as Record<string, unknown> | undefined;
      const quota  = result?.quota as Record<string, unknown> | undefined;
      return {
        status: 'valid', checkedAt: Date.now(),
        credits: quota ? `${quota.used ?? '?'}/${quota.allowance ?? '?'} queries used` : undefined,
      };
    }
    if (providerId === 'urlhaus' || providerId === 'malwarebazaar' || providerId === 'threatfox') {
      // All three abuse.ch services share one key — validate via ThreatFox IOC #1 (always exists)
      const tfBase = isDev() ? '/threatfox-proxy' : 'https://threatfox-api.abuse.ch';
      const r = await fetch(`${tfBase}/api/v1/`, {
        method: 'POST',
        headers: { 'Auth-Key': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'get_ioc', id: 1 }),
        signal: AbortSignal.timeout(8000),
      });
      if (r.status === 401 || r.status === 403) return { status: 'invalid', checkedAt: Date.now() };
      if (!r.ok) return { status: 'unknown', checkedAt: Date.now(), detail: `HTTP ${r.status}` };
      return { status: 'valid', checkedAt: Date.now(), plan: 'abuse.ch community' };
    }
    if (providerId === 'hybrid-analysis') {
      const haBase = isDev() ? '/hybrid-proxy' : 'https://hybrid-analysis.com';
      const r = await fetch(`${haBase}/api/v2/key/current`, {
        headers: { 'api-key': apiKey, 'User-Agent': 'Falcon' },
        signal: AbortSignal.timeout(8000),
      });
      if (r.status === 401 || r.status === 403) return { status: 'invalid', checkedAt: Date.now() };
      if (!r.ok) return { status: 'unknown', checkedAt: Date.now(), detail: `HTTP ${r.status}` };
      const d = await r.json() as Record<string, unknown>;
      return {
        status: 'valid', checkedAt: Date.now(),
        plan: String(d.auth_level_name ?? d.auth_level ?? ''),
      };
    }
    if (providerId === 'abuseipdb') {
      const base = isDev() ? '/abuseipdb-proxy' : 'https://api.abuseipdb.com';
      const r = await fetch(`${base}/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=1`, {
        headers: { 'Key': apiKey, 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000),
      });
      if (r.status === 401 || r.status === 403) return { status: 'invalid', checkedAt: Date.now() };
      if (r.status === 429) return { status: 'rate-limited', checkedAt: Date.now() };
      if (!r.ok) return { status: 'unknown', checkedAt: Date.now(), detail: `HTTP ${r.status}` };
      const remaining = r.headers.get('X-RateLimit-Remaining');
      const limit     = r.headers.get('X-RateLimit-Limit');
      return {
        status: 'valid', checkedAt: Date.now(),
        credits: remaining != null ? `${remaining}/${limit ?? '?'} remaining today` : undefined,
      };
    }
    if (providerId === 'ipinfo') {
      const base = isDev() ? '/ipinfo-proxy' : 'https://ipinfo.io';
      const r = await fetch(`${base}/me?token=${encodeURIComponent(apiKey)}`, {
        headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000),
      });
      if (r.status === 401 || r.status === 403) return { status: 'invalid', checkedAt: Date.now() };
      if (r.status === 429) return { status: 'rate-limited', checkedAt: Date.now() };
      if (!r.ok) return { status: 'unknown', checkedAt: Date.now(), detail: `HTTP ${r.status}` };
      const d = await r.json() as Record<string, unknown>;
      const services = d.services as Record<string, unknown> | undefined;
      const plan = services ? Object.keys(services).join(', ') : undefined;
      return { status: 'valid', checkedAt: Date.now(), plan };
    }
  } catch (e) {
    return { status: 'unknown', checkedAt: Date.now(), detail: e instanceof Error ? e.message : 'Network error' };
  }
  return { status: 'unknown', checkedAt: Date.now() };
}

function ValidationBadge({ v }: { v: KeyValidation | undefined }) {
  const now = useNow();
  if (!v) return null;
  const age = now - v.checkedAt;
  const stale = age > 24 * 60 * 60 * 1000;
  const cls = v.status === 'valid' ? 'val-valid' : v.status === 'invalid' ? 'val-invalid' : v.status === 'rate-limited' ? 'val-ratelimit' : 'val-unknown';
  const label = v.status === 'valid' ? '✓ Valid' : v.status === 'invalid' ? '✕ Invalid' : v.status === 'rate-limited' ? '⚠ Rate limited' : '? Unknown';
  const detail = [v.plan, v.credits, v.expires ? `Expires: ${v.expires}` : undefined].filter(Boolean).join(' · ');
  return (
    <div className={`val-badge ${cls} ${stale ? 'val-stale' : ''}`} title={stale ? 'Checked >24h ago' : undefined}>
      <span className="val-label">{label}</span>
      {detail && <span className="val-detail">{detail}</span>}
      <span className="val-age">{stale ? '(stale)' : new Date(v.checkedAt).toLocaleTimeString()}</span>
    </div>
  );
}

function KeysTab({
  keys,
  onKeysChange,
  validations,
  onValidationsChange,
}: {
  keys: Record<string, ProviderKey>;
  onKeysChange: (k: Record<string, ProviderKey>) => void;
  validations: Record<string, KeyValidation>;
  onValidationsChange: (v: Record<string, KeyValidation>) => void;
}) {
  const [inputValues, setInputValues] = useState<Record<string, string>>({});
  const [validating, setValidating] = useState<Record<string, boolean>>({});
  const [savedKeys, setSavedKeys] = useState<Record<string, boolean>>({});
  // 'free' and 'community' are merged into one tab labelled 'Free / Community'
  const TAB_ORDER   = ['free', 'trial', 'enterprise'] as const;
  const TAB_LABELS: Record<string, string> = { free: 'Free / Community', trial: 'Trial / Freemium', enterprise: 'Enterprise' };
  const tierToTab = (t: string) => t === 'community' ? 'free' : t;
  const [activeTier, setActiveTier] = useState<string>('free');

  function flashSaved(id: string) {
    setSavedKeys(v => ({ ...v, [id]: true }));
    setTimeout(() => setSavedKeys(v => ({ ...v, [id]: false })), 1500);
  }

  function handleAdd(providerId: string) {
    const val = (inputValues[providerId] ?? '').trim().replace(/•/g, '');
    if (!val) return;
    onKeysChange(upsertKey(keys, providerId, val));
    setInputValues(v => ({ ...v, [providerId]: '' }));
    flashSaved(providerId);
  }

  async function handleValidate(providerId: string) {
    const key = getActiveKey(keys, providerId);
    if (!key) return;
    setValidating(v => ({ ...v, [providerId]: true }));
    const result = await validateKey(providerId, key);
    const next = { ...validations, [providerId]: result };
    onValidationsChange(next);
    setValidating(v => ({ ...v, [providerId]: false }));
  }

  const providersByTab = TAB_ORDER.map(tab => ({
    tab,
    providers: PROVIDERS
      .filter(p => tierToTab(p.tier) === tab && (p.requiresKey || (p.authType !== 'none' && p.keyLabel)))
      .sort((a, b) => a.name.localeCompare(b.name)),
  })).filter(g => g.providers.length > 0);

  const activeGroup = providersByTab.find(g => g.tab === activeTier) ?? providersByTab[0];

  const githubKey = getActiveKey(keys, 'github') ?? '';
  const [githubInput, setGithubInput] = useState('');

  function handleAddGithub() {
    const val = githubInput.trim().replace(/•/g, '');
    if (!val) return;
    onKeysChange(upsertKey(keys, 'github', val));
    setGithubInput('');
    flashSaved('github');
  }

  return (
    <div className="settings-list">
      {/* ── Enrichment tools section ── */}
      <div className="keys-enrichment-section">
        <div className="keys-enrichment-title">Enrichment Tools</div>
        <div className="settings-provider-row">
          <div className="settings-provider-name">
            <span>GitHub</span>
            <div className="settings-provider-badges">
              {!githubKey && <span className="badge-optional">optional</span>}
              {!githubKey && (
                <a className="badge-upgrade" href="https://github.com/settings/tokens/new?scopes=public_repo&description=Nautilus" target="_blank" rel="noopener noreferrer">
                  Get free token ↗
                </a>
              )}
            </div>
          </div>
          <div className="keys-enrichment-desc">
            Personal access token for SIGMA/YARA rule search. Free GitHub account — only needs <code>public_repo</code> read scope. Raises code search to 30 req/min.
          </div>
          {githubKey && (
            <div className="settings-key-list">
              <div className="settings-key-item active">
                <span className="key-radio">●</span>
                <code className="key-preview">{githubKey.slice(0, 10)}{'•'.repeat(Math.max(0, githubKey.length - 10))}</code>
                <button className="key-remove" onClick={() => onKeysChange(removeKey(keys, 'github', 0))}>✕</button>
              </div>
            </div>
          )}
          <div className="key-add-row">
            <input
              className="key-add-input"
              value={githubInput}
              onChange={e => setGithubInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAddGithub()}
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
              type="password"
              autoComplete="off"
            />
            <button
              className={`key-add-btn${savedKeys['github'] ? ' saved' : ''}`}
              onClick={handleAddGithub}
              disabled={!githubInput.trim()}
            >
              {savedKeys['github'] ? '✓ Saved' : 'Add'}
            </button>
          </div>
        </div>
      </div>

      <div className="tier-tabs">
        {providersByTab.map(({ tab }) => (
          <button
            key={tab}
            className={`tier-tab-btn ${activeTier === tab ? 'active' : ''} tier-tab-${tab}`}
            onClick={() => setActiveTier(tab)}
          >
            {TAB_LABELS[tab]}
          </button>
        ))}
      </div>
      <div className="tier-tab-content">
        {activeGroup?.providers.map(p => {
            const pk = keys[p.id];
            const hasKey = !!pk?.keys.length;
            const optional = !p.requiresKey;
            const v = validations[p.id];
            return (
              <div key={p.id} className="settings-provider-row">
                <div className="settings-provider-name">
                  <span>{p.name}</span>
                  <div className="settings-provider-badges">
                    {optional && !hasKey && <span className="badge-optional">optional key</span>}
                    {!optional && !hasKey && <span className="badge-no-key">no key</span>}
                    {p.upgradeTo && !hasKey && (
                      <a className="badge-upgrade" href={p.upgradeTo} target="_blank" rel="noopener noreferrer">
                        Get key ↗
                      </a>
                    )}
                  </div>
                </div>
                <div className="settings-key-list">
                  {pk?.keys.map((k, i) => (
                    <div key={i} className={`settings-key-item ${i === pk.activeIndex ? 'active' : ''}`}>
                      <button className="key-radio" onClick={() => onKeysChange(setActiveKey(keys, p.id, i))} title="Set active">
                        {i === pk.activeIndex ? '●' : '○'}
                      </button>
                      <code className="key-preview">{k.slice(0, 10)}{'•'.repeat(Math.max(0, k.length - 10))}</code>
                      <button className="key-remove" onClick={() => onKeysChange(removeKey(keys, p.id, i))}>✕</button>
                    </div>
                  ))}
                </div>
                {hasKey && (
                  <div className="settings-validate-row">
                    {p.canValidate ? (
                      <>
                        <button
                          className="validate-btn"
                          onClick={() => void handleValidate(p.id)}
                          disabled={validating[p.id]}
                        >
                          {validating[p.id] ? 'Checking…' : 'Validate key'}
                        </button>
                        <ValidationBadge v={v} />
                      </>
                    ) : (
                      p.portalUrl && (
                        <a className="portal-link" href={p.portalUrl} target="_blank" rel="noopener noreferrer">
                          Check quota in portal ↗
                        </a>
                      )
                    )}
                  </div>
                )}
                <div className="key-add-row">
                  <input
                    className="key-add-input"
                    value={inputValues[p.id] ?? ''}
                    onChange={e => setInputValues(v => ({ ...v, [p.id]: e.target.value }))}
                    onKeyDown={e => e.key === 'Enter' && handleAdd(p.id)}
                    placeholder={p.keyPlaceholder || p.keyLabel}
                    type="password"
                    autoComplete="off"
                  />
                  <button
                    className={`key-add-btn${savedKeys[p.id] ? ' saved' : ''}`}
                    onClick={() => handleAdd(p.id)}
                    disabled={!(inputValues[p.id] ?? '').trim()}
                  >
                    {savedKeys[p.id] ? '✓ Saved' : 'Add'}
                  </button>
                </div>
              </div>
            );
          })}
      </div>
    </div>
  );
}

function RoutingTab({
  prefs,
  onPrefsChange,
}: {
  prefs: RoutingPrefs;
  onPrefsChange: (p: RoutingPrefs) => void;
}) {
  function isEnabled(providerId: string, type: ArtifactType): boolean {
    const p = prefs[providerId];
    if (!p) return true;
    return p[type] === undefined ? true : !!p[type];
  }

  function toggle(providerId: string, type: ArtifactType) {
    const current = isEnabled(providerId, type);
    const providerPrefs = { ...(prefs[providerId] ?? {}), [type]: !current };
    onPrefsChange({ ...prefs, [providerId]: providerPrefs });
  }

  function resetAll() {
    onPrefsChange({});
  }

  // Group providers by the artifact types they support so each column only
  // shows checkboxes where the provider actually has that capability.
  return (
    <div className="routing-tab">
      <div className="routing-description">
        Check which providers to query automatically for each artifact type.
        Unchecked providers are skipped unless you manually select them in the sidebar.
      </div>
      <div className="routing-table-wrap">
        <table className="routing-table">
          <thead>
            <tr>
              <th className="routing-th-provider">Provider</th>
              {ROUTABLE_TYPES.map(t => (
                <th key={t} className="routing-th-type">{TYPE_SHORT[t]}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {PROVIDERS.map(p => (
              <tr key={p.id} className="routing-row">
                <td className="routing-td-provider">
                  <span className="routing-provider-name">{p.shortName}</span>
                  <span className="routing-provider-tags">{p.tags.slice(0, 2).join(' · ')}</span>
                </td>
                {ROUTABLE_TYPES.map(t => {
                  const supports    = p.supports.includes(t);
                  const isEnterprise = p.tier === 'enterprise' || (p.enterpriseTypes?.includes(t) ?? false);
                  const enabled     = isEnabled(p.id, t);
                  return (
                    <td key={t} className="routing-td-check">
                      {supports ? (
                        <button
                          className={`routing-check ${enabled ? 'on' : 'off'}${isEnterprise ? ' enterprise' : ''}`}
                          onClick={() => toggle(p.id, t)}
                          title={isEnterprise
                            ? `${p.shortName} supports ${ARTIFACT_LABELS[t]} — requires a paid subscription`
                            : `${enabled ? 'Disable' : 'Enable'} ${p.shortName} for ${ARTIFACT_LABELS[t]}`}
                        >
                          {enabled ? '✓' : ''}
                        </button>
                      ) : (
                        <span className="routing-na">—</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="routing-footer">
        <button className="routing-reset-btn" onClick={resetAll}>Reset to defaults</button>
        <span className="routing-footer-note">Defaults: all capable providers enabled</span>
      </div>
    </div>
  );
}

function CacheTab({
  onBuildStart, onBuildEnd,
  cacheState, onCacheStateChange,
}: {
  onBuildStart?: (isUpdate: boolean) => void;
  onBuildEnd?: () => void;
  cacheState: MitreCacheStateMap;
  onCacheStateChange: (s: MitreCacheStateMap) => void;
}) {
  type ComponentKey = 'profiles' | 'techniques' | 'software';
  type KVInfo = { cachedAt: number; count: number } | null;
  const [kvInfo, setKvInfo] = useState<{ profiles: KVInfo; techniques: KVInfo; software: KVInfo }>({
    profiles: null, techniques: null, software: null,
  });
  const now = useNow();

  const anyLoading = cacheState.profiles.status === 'loading' ||
    cacheState.techniques.status === 'loading' ||
    cacheState.software.status === 'loading';

  useEffect(() => {
    Promise.all([loadMitreProfiles(), loadMitreTechniques(), loadMitreSoftware()]).then(([p, t, s]) => {
      setKvInfo({
        profiles:   p ? { cachedAt: p.cachedAt, count: p.groups.length } : null,
        techniques: t ? { cachedAt: t.cachedAt, count: Object.keys(t.byGroup).length } : null,
        software:   s ? { cachedAt: s.cachedAt, count: Object.keys(s.byGroup).length } : null,
      });
    });
  // builders update kvInfo directly after each build — mount-only read is sufficient
   
  }, []);

  function formatAge(ts: number): string {
    const days = Math.floor((now - ts) / 86400000);
    if (days === 0) return 'today';
    if (days === 1) return '1 day ago';
    return `${days} days ago`;
  }

  function isStale(ts: number): boolean {
    return now - ts > 45 * 86400000;
  }

  function setComponent(key: ComponentKey, patch: Partial<{ status: ComponentStatus; progress: string }>) {
    onCacheStateChange({ ...cacheState, [key]: { ...cacheState[key], ...patch } });
  }

  async function refreshComponent(key: ComponentKey) {
    const hasExisting = kvInfo[key] !== null;
    setComponent(key, { status: 'loading', progress: '' });
    onBuildStart?.(hasExisting);
    try {
      const prog = (msg: string) => setComponent(key, { progress: msg });
      if (key === 'profiles') {
        const entry = await buildMitreProfiles(prog);
        setKvInfo(prev => ({ ...prev, profiles: { cachedAt: entry.cachedAt, count: entry.groups.length } }));
      } else if (key === 'techniques') {
        const entry = await buildMitreTechniques(prog);
        setKvInfo(prev => ({ ...prev, techniques: { cachedAt: entry.cachedAt, count: Object.keys(entry.byGroup).length } }));
      } else {
        const entry = await buildMitreSoftware(prog);
        setKvInfo(prev => ({ ...prev, software: { cachedAt: entry.cachedAt, count: Object.keys(entry.byGroup).length } }));
      }
      invalidateMitreSessionCache(); // force re-read from KV on next search
      setComponent(key, { status: 'done', progress: '' });
      onBuildEnd?.();
    } catch {
      setComponent(key, { status: 'error', progress: '' });
      onBuildEnd?.();
    }
  }

  async function refreshAll() {
    const hasExisting = kvInfo.profiles !== null;
    onBuildStart?.(hasExisting);
    onCacheStateChange({
      profiles:   { status: 'loading', progress: 'Fetching shared data…' },
      techniques: { status: 'idle',    progress: 'Waiting…' },
      software:   { status: 'idle',    progress: 'Waiting…' },
    });
    try {
      // Fetch shared data once — avoids fetching intrusion-set and relationship 3x each
      setComponent('profiles', { progress: 'Fetching intrusion sets…' });
      const intrusionSets = await mitreFetchAll('intrusion-set');
      if (!intrusionSets.length) throw new Error('MITRE TAXII returned no intrusion-set objects');
      await mitreFetchDelay(5000);
      setComponent('profiles', { progress: 'Fetching relationships…' });
      const relationships = (await mitreFetchAll('relationship')).filter(r => !(r.revoked as boolean));
      await mitreFetchDelay(5000);
      const shared = { intrusionSets, relationships };

      const profEntry = await buildMitreProfiles(msg => setComponent('profiles', { progress: msg }), shared);
      setKvInfo(prev => ({ ...prev, profiles: { cachedAt: profEntry.cachedAt, count: profEntry.groups.length } }));
      setComponent('profiles', { status: 'done', progress: 'Done — cooling down before next component…' });
      await mitreFetchDelay(15000);

      setComponent('techniques', { status: 'loading', progress: '' });
      const techEntry = await buildMitreTechniques(msg => setComponent('techniques', { progress: msg }), shared);
      setKvInfo(prev => ({ ...prev, techniques: { cachedAt: techEntry.cachedAt, count: Object.keys(techEntry.byGroup).length } }));
      setComponent('techniques', { status: 'done', progress: 'Done — cooling down before next component…' });
      await mitreFetchDelay(15000);

      setComponent('software', { status: 'loading', progress: '' });
      const swEntry = await buildMitreSoftware(msg => setComponent('software', { progress: msg }), shared);
      setKvInfo(prev => ({ ...prev, software: { cachedAt: swEntry.cachedAt, count: Object.keys(swEntry.byGroup).length } }));
      setComponent('software', { status: 'done' });
      invalidateMitreSessionCache(); // force re-read from KV on next search

      onBuildEnd?.();
    } catch {
      onCacheStateChange({
        profiles:   { ...cacheState.profiles,   status: cacheState.profiles.status   === 'loading' ? 'error' : cacheState.profiles.status },
        techniques: { ...cacheState.techniques, status: cacheState.techniques.status === 'loading' ? 'error' : cacheState.techniques.status },
        software:   { ...cacheState.software,   status: cacheState.software.status   === 'loading' ? 'error' : cacheState.software.status },
      });
      onBuildEnd?.();
    }
  }

  const COMPONENTS: { key: ComponentKey; label: string; desc: string }[] = [
    { key: 'profiles',   label: 'Group Profiles',  desc: 'Names, aliases, ATT&CK IDs, descriptions, target sectors, countries, associated groups' },
    { key: 'techniques', label: 'Techniques',       desc: 'Per-group ATT&CK technique IDs, names, and tactics' },
    { key: 'software',   label: 'Software & Ops',   desc: 'Malware, tools, campaigns, and mitigations per group' },
  ];

  return (
    <div className="cache-tab">
      <div className="cache-section-title">Cached Data Sources</div>

      <div className="cache-card">
        <div className="cache-card-header">
          <div className="cache-card-title">
            <span className={`cache-status-dot ${kvInfo.profiles ? (isStale(kvInfo.profiles.cachedAt) ? 'stale' : 'fresh') : 'missing'}`} />
            MITRE ATT&amp;CK
          </div>
          <button className="cache-refresh-btn" onClick={refreshAll} disabled={anyLoading}>
            {anyLoading ? 'Updating…' : 'Refresh all'}
          </button>
        </div>

        <div className="cache-card-body">
          <table className="cache-component-table">
            <thead>
              <tr>
                <th>Component</th>
                <th>Contents</th>
                <th>Last updated</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {COMPONENTS.map(({ key, label, desc }) => {
                const info = kvInfo[key];
                const st   = cacheState[key];
                const stale = info && isStale(info.cachedAt);
                return (
                  <tr key={key}>
                    <td className="cache-comp-name">{label}</td>
                    <td className="cache-comp-desc">
                      {desc}
                      {info && <span className="cache-comp-count"> · {info.count} groups</span>}
                    </td>
                    <td className="cache-comp-age">
                      {info ? <span className={stale ? 'cache-info-warn' : ''}>{formatAge(info.cachedAt)}</span> : <span className="cache-info-empty">—</span>}
                    </td>
                    <td className="cache-comp-status">
                      {st.status === 'loading' && <span className="cache-info-active spinning">◎</span>}
                      {st.status === 'done'    && <span className="cache-info-ok">✓</span>}
                      {st.status === 'error'   && <span style={{ color: '#f85149' }}>✕</span>}
                      {st.status === 'idle'    && (info ? (stale ? <span className="cache-info-warn">⚠</span> : <span className="cache-info-ok">✓</span>) : <span className="cache-info-empty">—</span>)}
                    </td>
                    <td className="cache-comp-action">
                      <button className="cache-refresh-btn cache-refresh-sm" onClick={() => refreshComponent(key)} disabled={st.status === 'loading' || anyLoading}>
                        {st.status === 'loading' ? '…' : 'Refresh'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {COMPONENTS.map(({ key, label }) => {
            const st = cacheState[key];
            if (!st.progress && st.status !== 'done' && st.status !== 'error') return null;
            return (
              <div key={key} className={`cache-progress ${st.status === 'done' ? 'cache-progress-ok' : st.status === 'error' ? 'cache-progress-err' : ''}`}>
                <span className="cache-comp-prefix">{label}:</span>{' '}
                {st.status === 'done'  ? '✓ Done' :
                 st.status === 'error' ? 'Failed — check network and try again' :
                 st.progress}
              </div>
            );
          })}
        </div>
      </div>

      <div className="cache-hint">
        Each component can be refreshed independently. Shared across all users via Cribl KV store. Full refresh takes ~3 min — intrusion-set and relationship data is fetched once and shared across all three components.
      </div>
    </div>
  );
}

type ComponentStatus = 'idle' | 'loading' | 'done' | 'error';
type MitreCacheStateMap = { profiles: { status: ComponentStatus; progress: string }; techniques: { status: ComponentStatus; progress: string }; software: { status: ComponentStatus; progress: string } };

function KeysPanel({
  keys, onKeysChange, validations, onValidationsChange, onClose,
}: {
  keys: Record<string, ProviderKey>;
  onKeysChange: (k: Record<string, ProviderKey>) => void;
  validations: Record<string, KeyValidation>;
  onValidationsChange: (v: Record<string, KeyValidation>) => void;
  onClose: () => void;
}) {
  return (
    <div className="overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="panel settings-panel">
        <div className="panel-header">
          <span className="panel-title">API Keys</span>
          <button className="panel-close" onClick={onClose}>✕</button>
        </div>
        <KeysTab keys={keys} onKeysChange={onKeysChange} validations={validations} onValidationsChange={onValidationsChange} />
      </div>
    </div>
  );
}

function SettingsPanel({
  prefs, onPrefsChange, onClose,
  onMitreBuildStart, onMitreBuildEnd,
  mitreCacheState, onMitreCacheStateChange,
}: {
  prefs: RoutingPrefs;
  onPrefsChange: (p: RoutingPrefs) => void;
  onClose: () => void;
  onMitreBuildStart?: (isUpdate: boolean) => void;
  onMitreBuildEnd?: () => void;
  mitreCacheState: MitreCacheStateMap;
  onMitreCacheStateChange: (s: MitreCacheStateMap) => void;
}) {
  const [tab, setTab] = useState<'routing' | 'cache'>('routing');

  return (
    <div className="overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="panel settings-panel">
        <div className="panel-header">
          <span className="panel-title">Settings</span>
          <button className="panel-close" onClick={onClose}>✕</button>
        </div>
        <div className="settings-tabs">
          <button className={`settings-tab-btn ${tab === 'routing' ? 'active' : ''}`} onClick={() => setTab('routing')}>Query Routing</button>
          <button className={`settings-tab-btn ${tab === 'cache' ? 'active' : ''}`} onClick={() => setTab('cache')}>Cache</button>
        </div>
        {tab === 'routing' && <RoutingTab prefs={prefs} onPrefsChange={onPrefsChange} />}
        {tab === 'cache'   && <CacheTab onBuildStart={onMitreBuildStart} onBuildEnd={onMitreBuildEnd} cacheState={mitreCacheState} onCacheStateChange={onMitreCacheStateChange} />}
      </div>
    </div>
  );
}

// ── Docs hub ───────────────────────────────────────────────────────

const FEED_HOWTOS = [
  {
    id: 'overview',
    title: 'What are Threat Feeds?',
    body: `Threat Feeds let you subscribe to external indicator lists (IPs, domains, URLs, hashes) and sync them into Nautilus. Once synced, any artifact you search is checked against all your feeds — matches appear in the Reputation panel under "Feed Intelligence" with a weighted confidence score across all matching feeds.`,
  },
  {
    id: 'add-curated',
    title: 'Adding a curated feed',
    body: `Open Feeds → Feed Library. Each card shows the source, indicator type, trust score, and update frequency. Click Add Feed — it opens the edit form pre-filled with the correct URL, format, and field name. Save and hit Sync Now to pull the first batch of indicators.`,
  },
  {
    id: 'add-custom',
    title: 'Adding a custom feed URL',
    body: `Open Feeds → Add Custom Feed. Paste the URL, choose a format (CSV, TSV, JSON, Plaintext, or STIX Bundle), and set the field name if needed:\n\n• CSV/TSV: enter the column header that contains the indicator value (e.g. dst_ip, ioc_value, sha256_hash)\n• JSON: the field name inside each array object\n• Plaintext/TSV with no field: first column or whole line is used\n• STIX Bundle: no field needed — values are extracted from the pattern field automatically\n\nUse Test & Preview to verify the URL is reachable and the field resolves correctly before saving.`,
  },
  {
    id: 'formats',
    title: 'Supported formats',
    body: `Plaintext — one indicator per line, # and ; comment lines are skipped.\n\nCSV — comma-separated, with a header row. abuse.ch feeds use a "# col1,col2" header style — the parser finds it automatically.\n\nTSV — tab-separated. Leave the field blank to use the first column, or enter a header name to pick a specific column. Used for feeds like ipsum that include a score alongside the IP.\n\nJSON — array of strings, or array of objects with a named field.\n\nSTIX Bundle — STIX 2.x JSON bundles. Indicator objects are extracted and values parsed from the pattern field (e.g. [ipv4-addr:value = '1.2.3.4']).`,
  },
  {
    id: 'sync',
    title: 'Syncing and staleness',
    body: `Hit Sync Now on any feed card to pull fresh indicators. Indicators are stored in Cribl KV (or localStorage in dev) — the raw feed file is never kept, only the extracted values.\n\nEach feed has a "Stale after N days" setting. A feed turns amber when it hasn't been synced within that window. Auto-sync on app load re-syncs enabled feeds with auto-sync turned on whenever you open Nautilus.`,
  },
  {
    id: 'matching',
    title: 'How feed matching works',
    body: `After every search, Nautilus checks the queried artifact against all synced feeds. The check is exact-match on the normalized (lowercased, trimmed) indicator value.\n\nIf one or more feeds match, a "Feed Intelligence" section appears at the top of the Reputation panel listing each matching feed with its type and trust score. A weighted confidence score is calculated: average trust × a count multiplier (1 feed = ~40%, each additional feed adds ~15%, capped at 95%).`,
  },
  {
    id: 'new-hosts',
    title: 'Adding feeds from new domains',
    body: `Nautilus runs inside Cribl Cloud's sandboxed iframe. All outbound fetches go through a proxy declared in config/proxies.yml — any hostname not listed will return a 403 when you try to sync.\n\nIf you add a custom feed from a domain not already in the list, the sync will fail with a fetch error. Report the domain and it can be added to proxies.yml and repackaged.`,
  },
] as const;

function DocsHub({ onClose }: { onClose: () => void }) {
  const sorted = [...PROVIDERS].sort((a, b) => a.name.localeCompare(b.name));
  const [section, setSection] = useState<'providers' | 'feeds'>('providers');
  const [selectedProvider, setSelectedProvider] = useState(sorted[0].id);
  const [selectedFeed, setSelectedFeed] = useState<string>(FEED_HOWTOS[0].id);
  const provider = PROVIDERS.find(p => p.id === selectedProvider)!;
  const feedDoc  = FEED_HOWTOS.find(f => f.id === selectedFeed)!;

  return (
    <div className="overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="panel docs-panel">
        <div className="panel-header">
          <span className="panel-title">Documentation</span>
          <button className="panel-close" onClick={onClose}>✕</button>
        </div>
        <div className="docs-section-tabs">
          <button className={`docs-section-tab ${section === 'providers' ? 'active' : ''}`} onClick={() => setSection('providers')}>Providers</button>
          <button className={`docs-section-tab ${section === 'feeds' ? 'active' : ''}`} onClick={() => setSection('feeds')}>Threat Feeds</button>
        </div>
        {section === 'providers' && (
          <div className="docs-layout">
            <div className="docs-sidebar">
              {sorted.map(p => (
                <button
                  key={p.id}
                  className={`docs-nav-item ${selectedProvider === p.id ? 'active' : ''}`}
                  onClick={() => setSelectedProvider(p.id)}
                >{p.name}</button>
              ))}
            </div>
            <div className="docs-content">
              <div className="docs-provider-name">{provider.name}</div>
              <p className="docs-description">{provider.description}</p>
              {provider.notes && <div className="docs-notes">{provider.notes}</div>}
              <div className="docs-meta-grid">
                <div className="docs-meta-row"><span className="docs-meta-label">Auth</span><span>{provider.requiresKey ? provider.keyLabel : 'Public — no key required'}</span></div>
                <div className="docs-meta-row"><span className="docs-meta-label">Supports</span><span>{provider.supports.map(s => ARTIFACT_LABELS[s]).join(', ')}</span></div>
                <div className="docs-meta-row"><span className="docs-meta-label">Tags</span><span>{provider.tags.join(', ')}</span></div>
              </div>
              {provider.docsUrl
                ? <a className="docs-link-btn" href={provider.docsUrl} target="_blank" rel="noopener noreferrer">Official docs ↗</a>
                : <span className="docs-no-link">No public docs — contact vendor</span>
              }
            </div>
          </div>
        )}
        {section === 'feeds' && (
          <div className="docs-layout">
            <div className="docs-sidebar">
              {FEED_HOWTOS.map(f => (
                <button
                  key={f.id}
                  className={`docs-nav-item ${selectedFeed === f.id ? 'active' : ''}`}
                  onClick={() => setSelectedFeed(f.id)}
                >{f.title}</button>
              ))}
            </div>
            <div className="docs-content">
              <div className="docs-provider-name">{feedDoc.title}</div>
              <div className="docs-description docs-howto-body">
                {feedDoc.body.split('\n').map((line, i) =>
                  line.trim() === ''
                    ? <br key={i} />
                    : <p key={i}>{line}</p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Root ───────────────────────────────────────────────────────────

// ── Query status bar ───────────────────────────────────────────────

function FreeTierBanner({ results }: { results: QueryResult[] }) {
  const [open, setOpen] = useState(false);
  const notes = results
    .filter(r => r.status === 'ok')
    .flatMap(r => {
      const p = PROVIDERS.find(p => p.id === r.providerId);
      return p?.freeTierNote ? [{ name: p.shortName, note: p.freeTierNote }] : [];
    });
  if (!notes.length) return null;
  return (
    <div className="free-tier-banner">
      <button className="free-tier-toggle" onClick={() => setOpen(o => !o)}>
        <span className={`free-tier-arrow ${open ? 'open' : ''}`}>▶</span>
        <span className="free-tier-icon">⚠</span>
        <span className="free-tier-title">Free tier limitations ({notes.length})</span>
      </button>
      {open && (
        <div className="free-tier-notes">
          {notes.map(n => (
            <span key={n.name} className="free-tier-note"><strong>{n.name}:</strong> {n.note}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function QueryStatusBar({ results }: { results: QueryResult[] }) {
  const [open, setOpen] = useState(false);
  if (!results.length) return null;

  const okResults    = results.filter(r => r.status === 'ok');
  const otherResults = results.filter(r => r.status !== 'ok' && r.status !== 'unsupported');
  const errors       = results.filter(r => r.status === 'error').length;
  const noKey        = results.filter(r => r.status === 'no-key').length;
  const hasOther     = otherResults.length > 0;

  function Pill({ r }: { r: QueryResult }) {
    const provider = PROVIDERS.find(p => p.id === r.providerId);
    const name = provider?.shortName ?? r.providerId;
    const icon = r.status === 'ok' ? '✓' : r.status === 'no-key' ? '⚷' : r.status === 'pending' ? '◌' : '✗';
    const tip  = r.error ?? (r.status === 'no-key' ? 'No API key configured' : r.status === 'pending' ? 'Fetcher not yet implemented' : null);
    return (
      <span className={`qsb-item qsb-${r.status}${tip ? ' qsb-has-tip' : ''}`}>
        {icon} {name}{r.latencyMs ? ` ${r.latencyMs}ms` : ''}
        {tip && <span className="qsb-tooltip">{tip}</span>}
      </span>
    );
  }

  return (
    <div className="query-status-bar">
      <div className="qsb-items">
        {okResults.map(r => <Pill key={r.providerId} r={r} />)}
        {hasOther && (
          <button className="qsb-toggle" onClick={() => setOpen(o => !o)}>
            <span className={`free-tier-arrow ${open ? 'open' : ''}`}>▶</span>
            {errors > 0 && <span className="qsb-item qsb-error" style={{border:'none',background:'none'}}>{errors} error{errors > 1 ? 's' : ''}</span>}
            {noKey  > 0 && <span className="qsb-item qsb-no-key" style={{border:'none',background:'none'}}>⚷ {noKey} no key</span>}
          </button>
        )}
      </div>
      {open && (
        <div className="qsb-items qsb-items-secondary">
          {otherResults.map(r => <Pill key={r.providerId} r={r} />)}
        </div>
      )}
    </div>
  );
}

const CACHE_TTL_MS  = 60 * 60 * 1000; // 1 hour
const CACHE_MAX     = 30;

interface CacheEntry {
  results:      QueryResult[];
  panels:       PanelData;

  artifactType: ArtifactType;
  ts:           number;
}

const resultCache = new Map<string, CacheEntry>();

function cacheGet(query: string): CacheEntry | null {
  const entry = resultCache.get(query.toLowerCase());
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) { resultCache.delete(query.toLowerCase()); return null; }
  return entry;
}

function cacheSet(query: string, entry: CacheEntry) {
  const key = query.toLowerCase();
  resultCache.delete(key); // move to end (most recent)
  resultCache.set(key, entry);
  if (resultCache.size > CACHE_MAX) resultCache.delete(resultCache.keys().next().value!);
}

// ── Passive DNS ────────────────────────────────────────────────────

interface PdnsRecord {
  rrname:     string;
  rrtype:     string;
  rdata:      string | string[];
  time_first: number | null;
  time_last:  number | null;
  count?:     number;
  source:     'circl' | 'farsight';
}

function PdnsPanel({ records, loading, artifactType, onSearch }: {
  records: PdnsRecord[];
  loading: boolean;
  query: string;
  artifactType: ArtifactType;
  onSearch: (q: string) => void;
}) {
  const [sortCol, setSortCol] = useState<'time_last' | 'time_first' | 'count'>('time_last');
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc');
  const [filter, setFilter] = useState('');

  if (loading) return <div className="pdns-empty">Querying passive DNS…</div>;
  if (!records.length) return <div className="pdns-empty">No passive DNS records found for this indicator.</div>;

  function toggleSort(col: typeof sortCol) {
    if (sortCol === col) setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    else { setSortCol(col); setSortDir('desc'); }
  }

  const fmt = (ts: number | null) => {
    if (!ts) return '—';
    return new Date(ts * 1000).toISOString().slice(0, 10);
  };

  const rdataStr = (r: PdnsRecord) =>
    Array.isArray(r.rdata) ? r.rdata.join(', ') : r.rdata;

  const filterLow = filter.toLowerCase();
  const visible = records
    .filter(r => {
      if (!filter) return true;
      return r.rrname.toLowerCase().includes(filterLow)
        || rdataStr(r).toLowerCase().includes(filterLow)
        || r.rrtype.toLowerCase().includes(filterLow);
    })
    .sort((a, b) => {
      const av = sortCol === 'count' ? (a.count ?? 0) : (a[sortCol] ?? 0);
      const bv = sortCol === 'count' ? (b.count ?? 0) : (b[sortCol] ?? 0);
      return sortDir === 'desc' ? (bv as number) - (av as number) : (av as number) - (bv as number);
    });

  const circlCount   = records.filter(r => r.source === 'circl').length;
  const farsightCount = records.filter(r => r.source === 'farsight').length;

  const pivotValue = (r: PdnsRecord) =>
    artifactType === 'ip'
      ? (Array.isArray(r.rdata) ? r.rdata : [r.rdata]).find(v => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) && !/^\d+\.\d+\.\d+\.\d+$/.test(v)) ?? null
      : /^\d+\.\d+\.\d+\.\d+$/.test(r.rrname) || /^\d+\.\d+\.\d+\.\d+$/.test(rdataStr(r))
        ? rdataStr(r).split(',')[0]?.trim() ?? null
        : r.rrname;

  return (
    <div className="pdns-wrap">
      <div className="pdns-header">
        <div className="pdns-meta">
          <span className="pdns-count">{records.length} records</span>
          {circlCount > 0 && <span className="pdns-source-badge pdns-source-circl">CIRCL {circlCount}</span>}
          {farsightCount > 0 && <span className="pdns-source-badge pdns-source-farsight">Farsight {farsightCount}</span>}
        </div>
        <input
          className="pdns-filter"
          placeholder="Filter records…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
      </div>
      <div className="pdns-table-wrap">
        <table className="pdns-table">
          <thead>
            <tr>
              <th className="pdns-th">RRname</th>
              <th className="pdns-th">Type</th>
              <th className="pdns-th">RData</th>
              <th className="pdns-th pdns-th-sort" onClick={() => toggleSort('time_first')}>
                First seen {sortCol === 'time_first' ? (sortDir === 'desc' ? '↓' : '↑') : ''}
              </th>
              <th className="pdns-th pdns-th-sort" onClick={() => toggleSort('time_last')}>
                Last seen {sortCol === 'time_last' ? (sortDir === 'desc' ? '↓' : '↑') : ''}
              </th>
              <th className="pdns-th pdns-th-sort" onClick={() => toggleSort('count')}>
                Count {sortCol === 'count' ? (sortDir === 'desc' ? '↓' : '↑') : ''}
              </th>
              <th className="pdns-th">Source</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((r, i) => {
              const pivot = pivotValue(r);
              return (
                <tr key={i} className="pdns-row">
                  <td className="pdns-td pdns-mono">{r.rrname}</td>
                  <td className="pdns-td"><span className="pdns-rrtype">{r.rrtype}</span></td>
                  <td className="pdns-td pdns-mono">
                    {pivot ? (
                      <button className="pdns-pivot-btn" onClick={() => onSearch(pivot)} title="Search this value">
                        {rdataStr(r)}
                      </button>
                    ) : rdataStr(r)}
                  </td>
                  <td className="pdns-td pdns-date">{fmt(r.time_first)}</td>
                  <td className="pdns-td pdns-date">{fmt(r.time_last)}</td>
                  <td className="pdns-td pdns-count-cell">{r.count ?? '—'}</td>
                  <td className="pdns-td">
                    <span className={`pdns-source-badge pdns-source-${r.source}`}>{r.source === 'circl' ? 'CIRCL' : 'Farsight'}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function VtRelationsPanel({ relations, loading, onSearch }: {
  relations: VtRelations | null;
  loading: boolean;
  onSearch: (q: string) => void;
}) {
  if (loading) return <div className="vt-relations-loading">Loading relations…</div>;
  if (!relations) return null;

  const nonEmpty = relations.groups.filter(g => g.items.length > 0 || g.error);
  if (nonEmpty.length === 0) return <div className="vt-relations-empty">No relationships found for this indicator.</div>;

  return (
    <div className="vt-relations-layout">
      {relations.groups.map(group => {
        if (group.items.length === 0 && !group.error) return null;
        return (
          <div key={group.name} className="vt-relations-group">
            <div className="vt-relations-group-title">
              {group.label}
              {group.items.length > 0 && <span className="vt-relations-count">{group.items.length}</span>}
            </div>
            {group.error && <div className="vt-relations-error">{group.error}</div>}
            {group.items.map((item, i) => {
              const a = item.attributes ?? {};
              const label = vtItemLabel(item, group.name);
              const sub   = vtItemSub(item, group.name);
              const searchable = ['ip_address', 'domain', 'file', 'url', 'ip', 'hash', 'indicator'].includes(item.type);
              return (
                <div key={i} className="vt-relation-item">
                  <div className="vt-relation-item-main">
                    {searchable ? (
                      <button className="vt-relation-link" onClick={() => onSearch(label)} title="Search this IOC">
                        {label}
                      </button>
                    ) : (
                      <span className="vt-relation-label">{label}</span>
                    )}
                    {sub && <span className="vt-relation-sub">{sub}</span>}
                  </div>
                  {!!a.last_analysis_stats && (() => {
                    const stats = a.last_analysis_stats as Record<string, number>;
                    const mal = stats.malicious ?? 0;
                    const total = Object.values(stats).reduce((s, v) => s + v, 0);
                    if (!total) return null;
                    return (
                      <span className={`vt-relation-verdict ${mal > 0 ? 'mal' : 'clean'}`}>
                        {mal > 0 ? `${mal}/${total} malicious` : 'Clean'}
                      </span>
                    );
                  })()}
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}

function vtItemLabel(item: VtRelationGroup['items'][number], groupName: string): string {
  const a = item.attributes ?? {};
  switch (item.type) {
    // VT types
    case 'resolution':     return String(a.host_name ?? a.ip_address ?? item.id);
    case 'domain':         return String(a.id ?? item.id);
    case 'ip_address':     return String(a.id ?? item.id);
    case 'file':           return String(a.meaningful_name ?? a.sha256 ?? item.id);
    case 'url':            return String(a.url ?? item.id);
    case 'ssl_cert':       return String((a.subject as Record<string,unknown> | undefined)?.CN ?? item.id);
    case 'sandbox_report': return String(a.sandbox_name ?? item.id);
    // OTX pulse
    case 'pulse':          return String(a.name ?? item.id);
    // Pulsedive indicator / feed
    case 'indicator': {
      const ind = a.indicator ?? item.id;
      return String(ind);
    }
    case 'feed':           return String(a.name ?? item.id);
    // RF entity (type == the RF entity class e.g. "RelatedMalware")
    default: {
      if (groupName.startsWith('rf_')) {
        return String(a.name ?? a.id ?? item.id);
      }
      return item.id;
    }
  }
}

function vtItemSub(item: VtRelationGroup['items'][number], groupName: string): string | null {
  const a = item.attributes ?? {};
  // VT
  if (groupName === 'resolutions') {
    const date = a.date ? new Date((a.date as number) * 1000).toLocaleDateString() : null;
    return date ? `Resolved ${date}` : null;
  }
  if (item.type === 'file') {
    const size = a.size ? `${(a.size as number).toLocaleString()} bytes` : null;
    const type = (a.type_description ?? a.file_type ?? null) as string | null;
    return [type, size].filter(Boolean).join(' · ') || null;
  }
  if (item.type === 'ssl_cert') {
    const exp = a.validity as Record<string,unknown> | undefined;
    return exp?.not_after ? `Expires ${String(exp.not_after)}` : null;
  }
  // OTX pulse
  if (item.type === 'pulse') {
    const tags = a.tags as string[] | undefined;
    const author = (a.author as Record<string,unknown> | undefined)?.username ?? a.author_name;
    const parts: string[] = [];
    if (author) parts.push(String(author));
    if (tags?.length) parts.push(tags.slice(0, 3).join(', '));
    return parts.join(' · ') || null;
  }
  // Pulsedive indicator
  if (item.type === 'indicator') {
    const risk = a.risk as string | undefined;
    const type = a.type as string | undefined;
    return [type, risk].filter(Boolean).join(' · ') || null;
  }
  // RF entity
  if (groupName.startsWith('rf_')) {
    const score = (a.riskScore ?? a.risk_score) as number | undefined;
    return score !== undefined ? `Risk: ${score}` : null;
  }
  return null;
}

export default function App() {
  const [keys, setKeys] = useState<Record<string, ProviderKey>>({});
  const [prefs, setPrefs] = useState<RoutingPrefs>({});
  const [panels, setPanels] = useState<PanelData | null>(null);
  const [queryResults, setQueryResults] = useState<QueryResult[]>([]);
  const [queriedProviders, setQueriedProviders] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [mitreStatus, setMitreStatus] = useState<string | null>(null);
  const [mitreBuildStatus, setMitreBuildStatus] = useState<'idle' | 'building' | 'updating' | 'ready'>('idle');
  const [mitreCacheState, setMitreCacheState] = useState<MitreCacheStateMap>({
    profiles:   { status: 'idle', progress: '' },
    techniques: { status: 'idle', progress: '' },
    software:   { status: 'idle', progress: '' },
  });
  const [lastArtifact, setLastArtifact] = useState<ArtifactType | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showDocs, setShowDocs] = useState(false);
  const [searchValue, setSearchValue] = useState('');
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const historyRef = useRef<HistoryEntry[]>([]);
  const [validations, setValidations] = useState<Record<string, KeyValidation>>({});
  const [resultsTab, setResultsTab] = useState<'results' | 'relations' | 'detections' | 'pdns'>('results');
  const [relations, setRelations] = useState<VtRelations | null>(null);
  const [relationsLoading, setRelationsLoading] = useState(false);
  const [pdnsRecords, setPdnsRecords] = useState<PdnsRecord[]>([]);
  const [pdnsLoading, setPdnsLoading] = useState(false);
  const [lastQuery, setLastQuery] = useState<string>('');
  const [showKeys, setShowKeys]   = useState(false);
  const [showFeeds, setShowFeeds] = useState(false);
  const [feedMatches, setFeedMatches] = useState<FeedMatch[]>([]);
  const feedsRef = useRef<import('./feedTypes').FeedConfig[]>([]);
  const [searchMode, setSearchMode] = useState<'search' | 'extract' | 'bulk' | 'dataset'>('search');
  const [bulkInitialIndicators, setBulkInitialIndicators] = useState<string[]>([]);
  const [mitreOverlay, setMitreOverlay] = useState<MitreOverlayResult[]>([]);
  const [detectionRules, setDetectionRules] = useState<DetectionRule[]>([]);
  const [detectionRulesLoading, setDetectionRulesLoading] = useState(false);

  // Load feeds once on mount for match checking
  useEffect(() => {
    loadFeeds().then(f => { feedsRef.current = f; });
  }, []);

  // Keep ref in sync with state so async callbacks always see current history
  useEffect(() => { historyRef.current = history; }, [history]);

  useEffect(() => {
    void (async () => {
      const [k, p, h, v] = await Promise.all([loadKeys(), loadRoutingPrefs(), loadHistory(), loadValidations()]);
      setKeys(k);
      setPrefs(p);
      historyRef.current = h;
      setHistory(h);
      setValidations(v);
      const params = new URLSearchParams(window.location.search);
      const q = params.get('q');
      if (q) void runSearch(q, k, p);
    })();
   
  }, []);

  function handleKeysChange(next: Record<string, ProviderKey>) {
    setKeys(next);
    void saveKeys(next);
  }

  function handleValidationsChange(next: Record<string, KeyValidation>) {
    setValidations(next);
    void saveValidations(next);
  }

  function handlePrefsChange(next: RoutingPrefs) {
    setPrefs(next);
    void saveRoutingPrefs(next);
  }

  async function fetchPdns(query: string, artifactType: ArtifactType, k: Record<string, ProviderKey>): Promise<PdnsRecord[]> {
    const results: PdnsRecord[] = [];

    // ── CIRCL pDNS ─────────────────────────────────────────────────
    const circlKey = getActiveKey(k, 'circl');
    if (circlKey) {
      try {
        const base = isDev() ? '/circl-pdns-proxy' : 'https://www.circl.lu';
        const endpoint = artifactType === 'ip'
          ? `${base}/pdns/query/rdata/ip/${encodeURIComponent(query)}`
          : `${base}/pdns/query/${encodeURIComponent(query)}`;
        const [user, pass] = circlKey.split(':');
        const r = await fetch(endpoint, {
          headers: {
            'Authorization': `Basic ${btoa(`${user ?? ''}:${pass ?? ''}`)}`,
            'Accept': 'application/json',
          },
          signal: AbortSignal.timeout(15000),
        });
        if (r.ok) {
          const text = await r.text();
          // CIRCL returns newline-delimited JSON
          const lines = text.trim().split('\n').filter(Boolean);
          for (const line of lines) {
            try {
              const obj = JSON.parse(line) as Record<string, unknown>;
              results.push({
                rrname:     String(obj.rrname ?? '').replace(/\.$/, ''),
                rrtype:     String(obj.rrtype ?? 'A'),
                rdata:      Array.isArray(obj.rdata)
                  ? (obj.rdata as unknown[]).map(v => String(v).replace(/\.$/, ''))
                  : String(obj.rdata ?? '').replace(/\.$/, ''),
                time_first: typeof obj.time_first === 'number' ? obj.time_first : null,
                time_last:  typeof obj.time_last  === 'number' ? obj.time_last  : null,
                count:      typeof obj.count === 'number' ? obj.count : undefined,
                source:     'circl',
              });
            } catch { /* skip malformed line */ }
          }
        }
      } catch { /* best-effort */ }
    }

    // ── Farsight DNSDB ─────────────────────────────────────────────
    const farsightKey = getActiveKey(k, 'farsight');
    if (farsightKey) {
      try {
        const base = isDev() ? '/farsight-proxy' : 'https://api.dnsdb.info';
        const endpoint = artifactType === 'ip'
          ? `${base}/dnsdb/v2/lookup/rdata/ip/${encodeURIComponent(query)}?limit=500`
          : `${base}/dnsdb/v2/lookup/rrset/name/${encodeURIComponent(query)}?limit=500`;
        const r = await fetch(endpoint, {
          headers: {
            'X-API-Key': farsightKey,
            'Accept': 'application/x-ndjson',
          },
          signal: AbortSignal.timeout(15000),
        });
        if (r.ok) {
          const text = await r.text();
          const lines = text.trim().split('\n').filter(Boolean);
          for (const line of lines) {
            try {
              const obj = JSON.parse(line) as Record<string, unknown>;
              // Farsight wraps records in an "obj" key for v2
              const rec = (obj.obj ?? obj) as Record<string, unknown>;
              if (!rec.rrname) continue;
              results.push({
                rrname:     String(rec.rrname ?? '').replace(/\.$/, ''),
                rrtype:     String(rec.rrtype ?? 'A'),
                rdata:      Array.isArray(rec.rdata)
                  ? (rec.rdata as unknown[]).map(v => String(v).replace(/\.$/, ''))
                  : String(rec.rdata ?? '').replace(/\.$/, ''),
                time_first: typeof rec.time_first === 'number' ? rec.time_first : null,
                time_last:  typeof rec.time_last  === 'number' ? rec.time_last  : null,
                count:      typeof rec.count === 'number' ? rec.count : undefined,
                source:     'farsight',
              });
            } catch { /* skip malformed line */ }
          }
        }
      } catch { /* best-effort */ }
    }

    // Deduplicate: same rrname+rrtype+rdata from both sources — keep both rows (different source badge)
    return results;
  }

  async function fetchRelations(query: string, artifactType: ArtifactType, k: Record<string, ProviderKey>): Promise<VtRelations> {
    const isSupported = ['ip','domain','hash','url'].includes(artifactType);

    // ── VirusTotal ──────────────────────────────────────────────────
    const vtGroupsPromise = (async (): Promise<VtRelationGroup[]> => {
      const vtKey = getActiveKey(k, 'virustotal');
      if (!vtKey || !isSupported) return [];
      const vtBase = isDev() ? '/vt-proxy' : 'https://www.virustotal.com';
      const headers = { 'x-apikey': vtKey, 'Accept': 'application/json' };
      type RelDef = { name: string; label: string; path: string };
      let relDefs: RelDef[] = [];
      if (artifactType === 'ip') {
        const id = encodeURIComponent(query);
        relDefs = [
          { name: 'resolutions',                 label: 'VT · DNS Resolutions',     path: `/api/v3/ip_addresses/${id}/resolutions?limit=10` },
          { name: 'communicating_files',         label: 'VT · Communicating Files', path: `/api/v3/ip_addresses/${id}/communicating_files?limit=10` },
          { name: 'historical_ssl_certificates', label: 'VT · SSL Certificates',    path: `/api/v3/ip_addresses/${id}/historical_ssl_certificates?limit=10` },
          { name: 'referrer_files',              label: 'VT · Referrer Files',       path: `/api/v3/ip_addresses/${id}/referrer_files?limit=10` },
        ];
      } else if (artifactType === 'hash') {
        const id = encodeURIComponent(query);
        relDefs = [
          { name: 'contacted_domains', label: 'VT · Contacted Domains',  path: `/api/v3/files/${id}/contacted_domains?limit=10` },
          { name: 'contacted_ips',     label: 'VT · Contacted IPs',      path: `/api/v3/files/${id}/contacted_ips?limit=10` },
          { name: 'contacted_urls',    label: 'VT · Contacted URLs',      path: `/api/v3/files/${id}/contacted_urls?limit=10` },
          { name: 'dropped_files',     label: 'VT · Dropped Files',       path: `/api/v3/files/${id}/dropped_files?limit=10` },
          { name: 'execution_parents', label: 'VT · Execution Parents',   path: `/api/v3/files/${id}/execution_parents?limit=10` },
          { name: 'behaviours',        label: 'VT · Sandbox Behaviours',  path: `/api/v3/files/${id}/behaviours?limit=5` },
        ];
      } else if (artifactType === 'domain') {
        const id = encodeURIComponent(query);
        relDefs = [
          { name: 'resolutions',                 label: 'VT · DNS Resolutions',     path: `/api/v3/domains/${id}/resolutions?limit=10` },
          { name: 'communicating_files',         label: 'VT · Communicating Files', path: `/api/v3/domains/${id}/communicating_files?limit=10` },
          { name: 'subdomains',                  label: 'VT · Subdomains',           path: `/api/v3/domains/${id}/subdomains?limit=10` },
          { name: 'historical_ssl_certificates', label: 'VT · SSL Certificates',    path: `/api/v3/domains/${id}/historical_ssl_certificates?limit=10` },
        ];
      } else if (artifactType === 'url') {
        const id = btoa(query).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        relDefs = [
          { name: 'last_serving_ip_address', label: 'VT · Serving IP',       path: `/api/v3/urls/${id}/last_serving_ip_address` },
          { name: 'network_location',        label: 'VT · Network Location',  path: `/api/v3/urls/${id}/network_location` },
          { name: 'redirects_to',            label: 'VT · Redirects To',      path: `/api/v3/urls/${id}/redirects_to?limit=10` },
        ];
      }
      return Promise.all(relDefs.map(async (def): Promise<VtRelationGroup> => {
        try {
          const res = await fetch(`${vtBase}${def.path}`, { headers, signal: AbortSignal.timeout(10000) });
          if (!res.ok) return { name: def.name, label: def.label, items: [], error: `HTTP ${res.status}` };
          const json = await res.json() as Record<string, unknown>;
          const raw = json.data;
          const items = Array.isArray(raw) ? raw : (raw ? [raw] : []);
          return { name: def.name, label: def.label, items: items as VtRelationGroup['items'] };
        } catch (e) {
          return { name: def.name, label: def.label, items: [], error: e instanceof Error ? e.message : 'Error' };
        }
      }));
    })();

    // ── OTX ────────────────────────────────────────────────────────
    const otxGroupsPromise = (async (): Promise<VtRelationGroup[]> => {
      const otxKey = getActiveKey(k, 'otx');
      if (!otxKey || !isSupported) return [];
      try {
        const base = isDev() ? '/otx-proxy' : 'https://otx.alienvault.com';
        const headers = { 'X-OTX-API-KEY': otxKey, 'Accept': 'application/json' };
        let section = '';
        if (artifactType === 'ip')          section = `IPv4/${encodeURIComponent(query)}`;
        else if (artifactType === 'domain') section = `domain/${encodeURIComponent(query)}`;
        else if (artifactType === 'hash')   section = `file/${encodeURIComponent(query)}`;
        else if (artifactType === 'url')    section = `url/${encodeURIComponent(btoa(query))}`;
        const res = await fetch(`${base}/api/v1/indicators/${section}/general`, { headers, signal: AbortSignal.timeout(20000) });
        if (!res.ok) return [];
        const json = await res.json() as Record<string, unknown>;
        const groups: VtRelationGroup[] = [];
        const pulseInfo = json.pulse_info as Record<string, unknown> | undefined;
        const pulses = pulseInfo?.pulses as unknown[] | undefined;
        if (Array.isArray(pulses) && pulses.length > 0) {
          groups.push({
            name: 'otx_pulses', label: 'OTX · Threat Pulses',
            items: pulses.slice(0, 20).map((p: unknown) => {
              const pulse = p as Record<string, unknown>;
              return { id: String(pulse.id ?? ''), type: 'pulse', attributes: pulse };
            }),
          });
        }
        const urlList = json.url_list as unknown[] | undefined;
        if (Array.isArray(urlList) && urlList.length > 0) {
          groups.push({
            name: 'otx_urls', label: 'OTX · Associated URLs',
            items: urlList.slice(0, 20).map((u: unknown) => {
              const url = u as Record<string, unknown>;
              return { id: String(url.url ?? ''), type: 'url', attributes: url };
            }),
          });
        }
        return groups;
      } catch { return []; }
    })();

    // ── Pulsedive ──────────────────────────────────────────────────
    const pdGroupsPromise = (async (): Promise<VtRelationGroup[]> => {
      const pdKey = getActiveKey(k, 'pulsedive');
      if (!pdKey || !isSupported) return [];
      try {
        const base = isDev() ? '/pulsedive-proxy' : 'https://pulsedive.com';
        const res = await fetch(
          `${base}/api/indicator.php?pretty=1&key=${encodeURIComponent(pdKey)}&indicator=${encodeURIComponent(query)}&get=links`,
          { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) }
        );
        if (!res.ok) return [];
        const json = await res.json() as Record<string, unknown>;
        const groups: VtRelationGroup[] = [];
        const related = json.related as unknown[] | undefined;
        if (Array.isArray(related) && related.length > 0) {
          groups.push({
            name: 'pd_related', label: 'Pulsedive · Related Indicators',
            items: related.slice(0, 20).map((r: unknown) => {
              const rel = r as Record<string, unknown>;
              return { id: String(rel.indicator ?? rel.iid ?? ''), type: String(rel.type ?? 'indicator'), attributes: rel };
            }),
          });
        }
        const feeds = json.feeds as unknown[] | undefined;
        if (Array.isArray(feeds) && feeds.length > 0) {
          groups.push({
            name: 'pd_feeds', label: 'Pulsedive · Feed Memberships',
            items: feeds.slice(0, 20).map((f: unknown) => {
              const feed = f as Record<string, unknown>;
              return { id: String(feed.name ?? feed.fid ?? ''), type: 'feed', attributes: feed };
            }),
          });
        }
        return groups;
      } catch { return []; }
    })();

    // ── Recorded Future ────────────────────────────────────────────
    const rfGroupsPromise = (async (): Promise<VtRelationGroup[]> => {
      const rfKey = getActiveKey(k, 'recordedfuture');
      if (!rfKey || !isSupported) return [];
      try {
        const base = isDev() ? '/rf-proxy' : 'https://api.recordedfuture.com';
        const headers = { 'X-RFToken': rfKey, 'Accept': 'application/json' };
        const fields = 'fields=relatedEntities';
        let endpoint = '';
        if (artifactType === 'ip')          endpoint = `${base}/v2/ip/${encodeURIComponent(query)}?${fields}`;
        else if (artifactType === 'domain') endpoint = `${base}/v2/domain/${encodeURIComponent(query)}?${fields}`;
        else if (artifactType === 'hash')   endpoint = `${base}/v2/hash/${encodeURIComponent(query)}?${fields}`;
        else if (artifactType === 'url')    endpoint = `${base}/v2/url/${encodeURIComponent(query)}?${fields}`;
        const res = await fetch(endpoint, { headers, signal: AbortSignal.timeout(12000) });
        if (!res.ok) return [];
        const json = await res.json() as Record<string, unknown>;
        const d = json.data as Record<string, unknown> | undefined;
        const relatedEntities = d?.relatedEntities as unknown[] | undefined;
        if (!Array.isArray(relatedEntities)) return [];
        const groups: VtRelationGroup[] = [];
        relatedEntities.forEach((group: unknown) => {
          const g = group as Record<string, unknown>;
          const type = String(g.type ?? '');
          const entities = g.entities as unknown[] | undefined;
          if (!Array.isArray(entities) || entities.length === 0) return;
          const label = type.replace(/^Related/, 'RF · ').replace(/([A-Z])/g, ' $1').trim();
          groups.push({
            name: `rf_${type.toLowerCase()}`, label,
            items: entities.slice(0, 20).map((e: unknown) => {
              const ent = e as Record<string, unknown>;
              return { id: String(ent.id ?? ent.name ?? ''), type, attributes: ent };
            }),
          });
        });
        return groups;
      } catch { return []; }
    })();

    // All four providers run in parallel
    const [vtGroups, otxGroups, pdGroups, rfGroups] = await Promise.all([
      vtGroupsPromise, otxGroupsPromise, pdGroupsPromise, rfGroupsPromise,
    ]);
    return { artifactType, query, groups: [...vtGroups, ...otxGroups, ...pdGroups, ...rfGroups] };
  }

  async function runSearch(query: string, k: Record<string, ProviderKey>, prefs: RoutingPrefs) {
    const artifactType = detectArtifact(query);
    setLastArtifact(artifactType);

    // Post-enrichment: feeds, MITRE overlay, detection rules — runs from cache or live
    async function runPostEnrichment(panels: PanelData, aType: ArtifactType, q: string) {
      if (feedsRef.current.length > 0) {
        checkFeedMatches(q, feedsRef.current).then(setFeedMatches);
      }
      const malwareNames = [
        ...panels.reputation.malwareFamily.map(m => m.value),
        ...panels.reputation.threatLabel.map(m => m.value),
      ];
      let overlay: MitreOverlayResult[] = [];
      if (malwareNames.length > 0) {
        overlay = await lookupMitreOverlay(malwareNames);
        setMitreOverlay(overlay);
      }
      const supportsRules = ['ip', 'domain', 'url', 'hash', 'cve'].includes(aType);
      if (supportsRules) {
        setDetectionRulesLoading(true);
        const detCtx: DetectionContext = {
          indicator:       q,
          artifactType:    aType,
          malwareFamily:   panels.reputation.malwareFamily[0]?.value,
          threatLabel:     panels.reputation.threatLabel[0]?.value,
          tags:            panels.reputation.tags.map(t => t.value),
          mitreSoftware:   overlay.map(m => ({ id: m.softwareId, name: m.softwareName, type: m.softwareType })),
          mitreTechniques: overlay.flatMap(m => m.techniques),
          cveId:           aType === 'cve' ? q : undefined,
        };
        lookupDetectionRules(detCtx)
          .then(rules => { setDetectionRules(rules); setDetectionRulesLoading(false); })
          .catch(() => setDetectionRulesLoading(false));
      }
    }

    // Check cache first — hit means instant display, no API calls
    const cached = cacheGet(query);
    if (cached) {
      setQueryResults(cached.results);
      setPanels(cached.panels);
      setLastArtifact(cached.artifactType);
      setRelations(null);
      setPdnsRecords([]);
      setResultsTab('results');
      setLastQuery(query);
      setFeedMatches([]);
      setMitreOverlay([]);
      setDetectionRules([]);
      setDetectionRulesLoading(false);
      const next = await pushHistory({ query, artifactType: cached.artifactType, ts: Date.now() }, historyRef.current);
      historyRef.current = next;
      setHistory(next);
      void runPostEnrichment(cached.panels, cached.artifactType, query);
      return;
    }

    setLoading(true);
    setPanels(null);
    setQueryResults([]);
    setRelations(null);
    setPdnsRecords([]);
    setResultsTab('results');
    setLastQuery(query);
    setFeedMatches([]);
    setMitreOverlay([]);
    setDetectionRules([]);
    setDetectionRulesLoading(false);

    const active = routedProviders(artifactType, prefs)
      .filter(pr => !pr.requiresKey || !!getActiveKey(k, pr.id))
      .map(pr => pr.id);
    setQueriedProviders(active);

    // Stream results — each provider updates panels as soon as it lands
    const allResults: QueryResult[] = [];
    let settled = 0;

    await new Promise<void>(resolve => {
      if (active.length === 0) { resolve(); return; }

      active.forEach(id => {
        fetchProvider(id, query, artifactType, getActiveKey(k, id), msg => setMitreStatus(msg), () => setMitreBuildStatus('building'), () => setMitreBuildStatus('ready')).then(result => {
          allResults.push(result);
          // Merge incrementally: rebuild panels from all results so far
          const builtPanels = buildPanels(allResults, artifactType);
          setQueryResults([...allResults]);
          setPanels(builtPanels);
          settled++;
          if (settled === active.length) resolve();
        });
      });
    });

    const finalPanels = buildPanels(allResults, artifactType);
    cacheSet(query, { results: allResults, panels: finalPanels, artifactType, ts: Date.now() });
    setPanels(finalPanels);

    const next = await pushHistory({ query, artifactType, ts: Date.now() }, historyRef.current);
    historyRef.current = next;
    setHistory(next);
    setLoading(false);
    setMitreStatus(null);

    void runPostEnrichment(finalPanels, artifactType, query);
  }

  function handleSearch(query: string) {
    setSearchValue(query);
    void runSearch(query, keys, prefs);
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-logo">
          <span className="app-logo-icon">◎</span>
          <span className="app-logo-name">Nautilus</span>
        </div>
        <div className="app-header-actions">
          {(mitreBuildStatus === 'building' || mitreBuildStatus === 'updating') && (
            <div className={`mitre-header-indicator${mitreBuildStatus === 'updating' ? ' mitre-header-updating' : ' mitre-header-building'}`} title={mitreStatus ?? (mitreBuildStatus === 'updating' ? 'Updating MITRE ATT&CK cache…' : 'Building MITRE ATT&CK cache…')}>
              <span className="spinning mitre-header-spin">◎</span>
              <span className="mitre-header-label">MITRE</span>
            </div>
          )}
          {mitreBuildStatus === 'ready' && (
            <div className="mitre-header-indicator mitre-header-ready" title="MITRE ATT&CK cache ready — click to dismiss" onClick={() => setMitreBuildStatus('idle')}>
              <span>✓</span>
              <span className="mitre-header-label">MITRE</span>
            </div>
          )}
          <button className="header-btn" onClick={() => setShowKeys(true)}>API Keys</button>
          <button className="header-btn" onClick={() => setShowFeeds(true)}>Feeds</button>
          <button className="header-btn" onClick={() => setShowDocs(true)}>Docs</button>
          <button className="header-btn" onClick={() => setShowSettings(true)}>&#x2699; Settings</button>
        </div>
      </header>

      <div className="app-body">
        {(() => {
          const historyFiltered = history.filter(h => h.artifactType !== 'unknown').slice(0, 50);
          if (!historyFiltered.length) return null;
          return (
          <aside className="history-sidebar">
            <div className="history-sidebar-title">Recent</div>
            {historyFiltered.map((h, i) => (
              <button key={i} className="history-sidebar-item" onClick={() => handleSearch(h.query)}>
                <div className="hsi-top">
                  <span className="hsi-type">{h.artifactType === 'threat-group' ? 'ACTOR' : h.artifactType.toUpperCase()}</span>
                </div>
                <span className="hsi-query">{h.query}</span>
                <span className="hsi-time">{new Date(h.ts).toLocaleDateString()}</span>
              </button>
            ))}
          </aside>
          );
        })()}
        <main className="app-main">
          <div className="search-mode-bar">
            <div className="search-mode-toggle">
              <button className={`search-mode-btn${searchMode === 'search'  ? ' active' : ''}`} onClick={() => setSearchMode('search')}>Search</button>
              <button className={`search-mode-btn${searchMode === 'extract' ? ' active' : ''}`} onClick={() => setSearchMode('extract')}>Extract IOCs</button>
              <button className={`search-mode-btn${searchMode === 'bulk'    ? ' active' : ''}`} onClick={() => setSearchMode('bulk')}>Bulk Search</button>
              <button className={`search-mode-btn${searchMode === 'dataset' ? ' active' : ''}`} onClick={() => setSearchMode('dataset')}>Dataset</button>
            </div>
          </div>

          {searchMode === 'search' && (
            <SearchBar onSearch={handleSearch} loading={loading} value={searchValue} onChange={setSearchValue} />
          )}

          {searchMode === 'extract' && (
            <IocExtractor
              onBulkSearch={indicators => { setBulkInitialIndicators(indicators); setSearchMode('bulk'); }}
              onSingleSearch={q => { setSearchValue(q); setSearchMode('search'); handleSearch(q); }}
            />
          )}

          {searchMode === 'bulk' && (
            <BulkSearch
              onSingleSearch={q => { setSearchValue(q); setSearchMode('search'); handleSearch(q); }}
              keys={keys}
              prefs={prefs}
              initialIndicators={bulkInitialIndicators}
            />
          )}

          {searchMode === 'dataset' && (
            <DatasetExplorer />
          )}

          {searchMode === 'search' && !panels && !loading && (
            <div className="empty-state">
              <div className="empty-icon">◎</div>
              <div className="empty-title">Enter an artifact to begin</div>
              <div className="empty-sub">Supports IP · Domain · URL · Hash · File · CVE · Threat Group</div>
            </div>
          )}

          {searchMode === 'search' && loading && (
            <div className="query-progress-bar">
              <span className="spinning query-progress-spin">◎</span>
              <span className="query-progress-text">Querying {queriedProviders.map(id => PROVIDERS.find(p => p.id === id)?.shortName).filter(Boolean).join(' · ')}</span>
            </div>
          )}


          {searchMode === 'search' && queryResults.length > 0 && !loading && (() => {
            const showActions = panels && lastArtifact && lastArtifact !== 'unknown';
            return (
              <div className="results-toolbar">
                <div className="results-toolbar-left">
                  <QueryStatusBar results={queryResults} />
                  <FreeTierBanner results={queryResults} />
                </div>
                {showActions && (
                  <div className="results-toolbar-right">
                    <FindInLogs query={queryResults[0]?.query ?? ''} artifactType={lastArtifact!} />
                    <CopyForAI
                      query={lastQuery}
                      artifactType={lastArtifact!}
                      panels={panels!}
                      mitreOverlay={mitreOverlay}
                      detectionRules={detectionRules}
                      feedMatches={feedMatches}
                      relations={relations}
                    />
                  </div>
                )}
              </div>
            );
          })()}

          {searchMode === 'search' && panels && !loading && feedMatches.length === 0 && !hasCve(panels) && !hasGeo(panels) && !hasReputation(panels) && !hasAnon(panels) && !hasNetwork(panels) && !hasFile(panels) && !panels.detection && (() => {
            const lockedOut = lastArtifact
              ? routedProviders(lastArtifact, prefs).filter(p => p.requiresKey && !getActiveKey(keys, p.id))
              : [];
            return (
              <div className="empty-state">
                <div className="empty-title">No data found by provider{queryResults.filter(r => r.status === 'ok').length !== 1 ? 's' : ''}</div>
                {lockedOut.length > 0
                  ? <div className="empty-sub">Add API keys for: <strong>{lockedOut.map(p => p.shortName).join(', ')}</strong></div>
                  : <div className="empty-sub">Queried providers returned no results for this artifact.</div>
                }
              </div>
            );
          })()}

          {searchMode === 'search' && panels && lastArtifact && (hasGeo(panels) || hasReputation(panels) || hasNetwork(panels) || hasAnon(panels) || hasFile(panels) || !!panels.detection || hasCve(panels) || hasTimeline(panels)) && (() => {
            const hasRelationsProvider = ['virustotal','otx','pulsedive','recordedfuture'].some(id => !!getActiveKey(keys, id));
            const showRelations = hasRelationsProvider && ['ip','domain','url','hash'].includes(lastArtifact);
            const showDetections = (['ip','domain','url','hash','cve'] as ArtifactType[]).includes(lastArtifact) && (detectionRulesLoading || detectionRules.length > 0);
            const showPdns = ['ip','domain'].includes(lastArtifact) && (
              !!getActiveKey(keys, 'circl') || !!getActiveKey(keys, 'farsight')
            );
            if (!showRelations && !showDetections && !showPdns) return null;
            const loadRelations = async () => {
              if (relations || relationsLoading) return;
              setRelationsLoading(true);
              const r = await fetchRelations(lastQuery, lastArtifact!, keys);
              setRelations(r);
              setRelationsLoading(false);
            };
            const loadPdns = async () => {
              if (pdnsRecords.length > 0 || pdnsLoading) return;
              setPdnsLoading(true);
              const recs = await fetchPdns(lastQuery, lastArtifact!, keys);
              setPdnsRecords(recs);
              setPdnsLoading(false);
            };
            return (
              <div className="results-view-tabs">
                <button
                  className={`results-view-tab ${resultsTab === 'results' ? 'active' : ''}`}
                  onClick={() => setResultsTab('results')}
                >Results</button>
                {showPdns && (
                  <button
                    className={`results-view-tab ${resultsTab === 'pdns' ? 'active' : ''}`}
                    onClick={() => { setResultsTab('pdns'); void loadPdns(); }}
                  >Passive DNS</button>
                )}
                {showRelations && (
                  <button
                    className={`results-view-tab ${resultsTab === 'relations' ? 'active' : ''}`}
                    onClick={() => { setResultsTab('relations'); void loadRelations(); }}
                  >Relations</button>
                )}
                {showDetections && (
                  <button
                    className={`results-view-tab ${resultsTab === 'detections' ? 'active' : ''}`}
                    onClick={() => setResultsTab('detections')}
                  >Detections</button>
                )}
              </div>
            );
          })()}

          {searchMode === 'search' && panels && lastArtifact && resultsTab === 'pdns' && (
            <div className="relations-scroll-wrap">
              <PdnsPanel records={pdnsRecords} loading={pdnsLoading} query={lastQuery} artifactType={lastArtifact} onSearch={q => { setSearchValue(q); handleSearch(q); }} />
            </div>
          )}

          {searchMode === 'search' && panels && lastArtifact && resultsTab === 'relations' && (
            <div className="relations-scroll-wrap">
              <VtRelationsPanel relations={relations} loading={relationsLoading} onSearch={q => { setSearchValue(q); handleSearch(q); }} />
            </div>
          )}

          {searchMode === 'search' && panels && lastArtifact && resultsTab === 'detections' && (
            <div className="detections-tab-view">
              {mitreOverlay.length > 0 && <MitreAttackPanel overlay={mitreOverlay} />}
              <DetectionRulesPanel rules={detectionRules} loading={detectionRulesLoading} />
            </div>
          )}

          {searchMode === 'search' && panels && lastArtifact && resultsTab === 'results' && (hasGeo(panels) || hasReputation(panels) || hasNetwork(panels) || hasAnon(panels) || hasFile(panels) || !!panels.detection || hasCve(panels) || hasTimeline(panels) || !!panels.mitre || feedMatches.length > 0) && (
            <div className="panels-layout">
              {/* Left column */}
              <div className="panels-col panels-col-left">
                {lastArtifact === 'threat-group' && (hasReputation(panels) || !!panels.mitre) && (
                  <ThreatGroupSummaryPanel rep={panels.reputation} mitre={panels.mitre} onSearch={q => { setSearchValue(q); handleSearch(q); }} />
                )}
                {lastArtifact === 'threat-group' && !!panels.mitre && (
                  <ThreatGroupTechniquesPanel mitre={panels.mitre} />
                )}
                {(lastArtifact === 'ip' || lastArtifact === 'domain') && (
                  <GeoResultPanel geo={panels.geo} />
                )}
                {(lastArtifact === 'ip' || lastArtifact === 'domain' || lastArtifact === 'url') && (
                  <NetworkResultPanel network={panels.network} />
                )}
                {(lastArtifact === 'hash' || lastArtifact === 'url' || lastArtifact === 'file') && (
                  <FileResultPanel file={panels.file} />
                )}
                {panels.detection && <DetectionResultPanel detection={panels.detection} />}
                {lastArtifact === 'cve' && hasCve(panels) && <CveLeftPanel cve={panels.cve!} onSearch={q => { setSearchValue(q); handleSearch(q); }} />}
              </div>
              {/* Right column */}
              <div className="panels-col panels-col-right">
                {lastArtifact === 'threat-group' && (hasReputation(panels) || !!panels.mitre) && (
                  <ThreatGroupClassificationPanel rep={panels.reputation} mitre={panels.mitre} />
                )}
                {lastArtifact === 'threat-group' && !!panels.mitre && (
                  <ThreatGroupTargetingPanel mitre={panels.mitre} />
                )}
                {hasTimeline(panels) && <TimelineResultPanel events={panels.timeline} />}
                {lastArtifact === 'cve' && hasCve(panels) && <CveRightPanel cve={panels.cve!} />}
                {(lastArtifact === 'ip' || lastArtifact === 'domain' || lastArtifact === 'url' || lastArtifact === 'hash' || lastArtifact === 'file') && (
                  <ReputationResultPanel rep={panels.reputation} feedMatches={feedMatches} />
                )}
                {lastArtifact === 'ip' && (
                  <AnonResultPanel anon={panels.anon} />
                )}
              </div>
            </div>
          )}
        </main>

      </div>

      {showKeys && <KeysPanel keys={keys} onKeysChange={handleKeysChange} validations={validations} onValidationsChange={handleValidationsChange} onClose={() => setShowKeys(false)} />}
      {showSettings && <SettingsPanel prefs={prefs} onPrefsChange={handlePrefsChange} onClose={() => setShowSettings(false)} onMitreBuildStart={(isUpdate) => setMitreBuildStatus(isUpdate ? 'updating' : 'building')} onMitreBuildEnd={() => setMitreBuildStatus('ready')} mitreCacheState={mitreCacheState} onMitreCacheStateChange={setMitreCacheState} />}
      {showDocs && <DocsHub onClose={() => setShowDocs(false)} />}
      {showFeeds && (
        <ThreatFeeds onClose={() => {
          setShowFeeds(false);
          // Reload feeds so match checking uses the latest set
          loadFeeds().then(f => { feedsRef.current = f; });
        }} />
      )}
    </div>
  );
}

// ── Fetcher helpers ────────────────────────────────────────────────

function isDev(): boolean {
  try {
    const url = (window as unknown as Record<string, unknown>)['CRIBL_API_URL'];
    return typeof url !== 'string' || !url;
  } catch { return true; }
}

// ── Fetchers ───────────────────────────────────────────────────────

import {
  extractVtIp, extractVtDomain, extractVtHash,
  extractAbuseIpDb, extractShodan, extractInternetDb, extractMaxMind,
  extractGreyNoise, extractSpur, extractWhoisRdap,
  extractCirclCve, extractUrlhaus, extractNvd,
  extractApiVoid, extractMalwareBazaar, extractThreatFox, extractSpamhaus,
  extractMalShare, extractHybridAnalysis, extractIpqs,
  extractOtx, extractIpInfo, extractPulsedive, extractRecordedFuture, extractCensys, extractMitreAttack,
} from './panelData';

type Rec2 = Record<string, unknown>;

// ── MITRE ATT&CK KV cache ──────────────────────────────────────────
// Processed data is stored in Cribl KV (falls back to localStorage in dev).
// In-memory session cache avoids repeated KV reads within the same tab.
let mitreSessionCache: MitreCacheEntry | null = null;
let mitreBuildPromise: Promise<MitreCacheEntry> | null = null;

function invalidateMitreSessionCache(): void {
  mitreSessionCache = null;
}

function mitreBase(): string {
  // In dev use the Vite proxy alias; in prod use the full https URL which Cribl's
  // service worker rewrites to /api/v1/a/{appId}/proxy/attack-taxii.mitre.org/...
  try {
    const url = (window as unknown as Record<string, unknown>)['CRIBL_API_URL'];
    return typeof url === 'string' && url ? 'https://attack-taxii.mitre.org' : '/mitre-proxy';
  } catch { return '/mitre-proxy'; }
}

// ── MITRE fetch helpers (module-level so sub-builds can share them) ──

const MITRE_COLLECTION = 'x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019';
const TAXII_HEADERS    = { 'Accept': 'application/taxii+json;version=2.1' };
const mitreFetchDelay  = (ms: number) => new Promise<void>(res => setTimeout(res, ms));

async function mitreFetchPage(url: string, retries = 5): Promise<Record<string, unknown> | null> {
  // Backoffs: immediate, 15s, 30s, 60s, 90s, 120s
  const backoffs = [0, 15000, 30000, 60000, 90000, 120000];
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await mitreFetchDelay(backoffs[attempt] ?? 120000);
    try {
      // 25s timeout — just under most proxy hard limits so we get AbortError instead of a 502
      const r = await fetch(url, { headers: TAXII_HEADERS, signal: AbortSignal.timeout(25000) });
      // 404 here means Cribl's SW proxy failed (not a real not-found) — retry it
      if (r.status === 404 || r.status === 429 || r.status === 502 || r.status === 503 || r.status === 504) continue;
      if (!r.ok) return null;
      return await r.json() as Record<string, unknown>;
    } catch { continue; }
  }
  return null;
}

async function mitreFetchAll(type: string): Promise<Record<string, unknown>[]> {
  const base = mitreBase();
  const all: Record<string, unknown>[] = [];
  let cursor: string | null = null;
  // 200 per page instead of 500 — smaller payloads respond faster, less likely to hit
  // Cribl's proxy timeout before MITRE's TAXII server finishes sending the response
  const limit = 200;
  do {
    const baseUrl = `${base}/api/v21/collections/${MITRE_COLLECTION}/objects/?match%5Btype%5D=${type}&limit=${limit}`;
    const url = cursor ? `${baseUrl}&next=${cursor}` : baseUrl;
    const j = await mitreFetchPage(url);
    if (!j) break; // all retries exhausted for this page — can't advance cursor
    const page = ((j.objects ?? []) as Record<string, unknown>[])
      .filter(o => !(o.revoked as boolean) && !(o.x_mitre_deprecated as boolean));
    all.push(...page);
    cursor = (j.next as string | undefined) ?? null;
    // 10s between pages — MITRE's TAXII is slow and Cribl's proxy times out under load
    if (cursor) await mitreFetchDelay(10000);
  } while (cursor);
  return all;
}

// ── Individual component builds ──

async function buildMitreProfiles(onProgress?: (msg: string) => void, _sharedData?: { intrusionSets: Record<string, unknown>[]; relationships: Record<string, unknown>[] }): Promise<MitreProfileEntry> {
  let intrusionSets: Record<string, unknown>[];
  let relationships: Record<string, unknown>[];

  if (_sharedData) {
    intrusionSets = _sharedData.intrusionSets;
    relationships = _sharedData.relationships;
  } else {
    onProgress?.('Fetching intrusion sets…');
    intrusionSets = await mitreFetchAll('intrusion-set');
    if (!intrusionSets.length) throw new Error('MITRE TAXII returned no intrusion-set objects');
    await mitreFetchDelay(5000);
    onProgress?.('Fetching relationships for targeting & associations…');
    relationships = (await mitreFetchAll('relationship')).filter(r => !(r.revoked as boolean));
    await mitreFetchDelay(5000);
  }

  if (!intrusionSets.length) throw new Error('MITRE TAXII returned no intrusion-set objects');

  onProgress?.('Fetching identity objects…');
  const identities = await mitreFetchAll('identity');

  const identityMap = new Map<string, Record<string, unknown>>();
  for (const o of identities) identityMap.set(o.id as string, o);
  const groupMap = new Map<string, Record<string, unknown>>();
  for (const o of intrusionSets) groupMap.set(o.id as string, o);

  onProgress?.('Building profile index…');
  const now = Date.now();
  const groups: MitreProfileEntry['groups'] = [];
  for (const o of intrusionSets) {
    const extRefs  = o.external_references as Record<string, unknown>[] | undefined;
    const mitreRef = Array.isArray(extRefs) ? extRefs.find(r => r.source_name === 'mitre-attack') : undefined;
    const stixId   = o.id as string;
    const name     = (o.name as string) ?? '';
    const aliases  = (o.aliases as string[] | undefined) ?? [];
    const desc     = ((o.description as string | undefined) ?? '')
      .replace(/\(Citation:[^)]+\)/g, '').replace(/\s{2,}/g, ' ').trim();

    const rels = relationships.filter(r => r.source_ref === stixId || r.target_ref === stixId);
    const sectors: string[] = [];
    const countries: string[] = [];
    const associatedGroups: string[] = [];

    for (const rel of rels) {
      const relType   = rel.relationship_type as string;
      const srcRef    = rel.source_ref as string;
      const targetRef = rel.target_ref as string;

      if (relType === 'targets' && srcRef === stixId) {
        const identity = identityMap.get(targetRef);
        if (identity) {
          const iClass = identity.identity_class as string | undefined;
          const iName  = identity.name as string | undefined;
          if (iName) {
            if (iClass === 'class') sectors.push(iName);
            else if (iClass === 'individual' || iClass === 'organization') countries.push(iName);
            else {
              const sec = identity.sectors as string[] | undefined;
              if (Array.isArray(sec) && sec.length) sec.forEach(s => sectors.push(s));
              else sectors.push(iName);
            }
          }
        }
      } else if (relType === 'related-to') {
        const otherRef = srcRef === stixId ? targetRef : srcRef;
        const other = groupMap.get(otherRef);
        if (other && (other.type as string) === 'intrusion-set') {
          const oName = other.name as string | undefined;
          if (oName && !associatedGroups.includes(oName)) associatedGroups.push(oName);
        }
      }
    }

    groups.push({
      id:              stixId,
      name,
      aliases:         aliases.filter(a => a !== name),
      attackId:        mitreRef ? String(mitreRef.external_id) : '',
      desc:            desc.slice(0, 400),
      sectors,
      countries,
      associatedGroups,
    });
  }

  const entry: MitreProfileEntry = { cachedAt: now, groups };
  await saveMitreProfiles(entry);
  return entry;
}

async function buildMitreTechniques(onProgress?: (msg: string) => void, _sharedData?: { intrusionSets: Record<string, unknown>[]; relationships: Record<string, unknown>[] }): Promise<MitreTechniquesEntry> {
  let intrusionSets: Record<string, unknown>[];
  let relationships: Record<string, unknown>[];

  if (_sharedData) {
    intrusionSets = _sharedData.intrusionSets;
    relationships = _sharedData.relationships;
  } else {
    onProgress?.('Fetching intrusion sets…');
    intrusionSets = await mitreFetchAll('intrusion-set');
    if (!intrusionSets.length) throw new Error('MITRE TAXII returned no intrusion-set objects');
    await mitreFetchDelay(5000);
    onProgress?.('Fetching relationships…');
    relationships = (await mitreFetchAll('relationship')).filter(r => !(r.revoked as boolean));
    await mitreFetchDelay(5000);
  }

  if (!intrusionSets.length) throw new Error('MITRE TAXII returned no intrusion-set objects');

  onProgress?.('Fetching attack patterns…');
  const attackPatterns = await mitreFetchAll('attack-pattern');

  const patternMap = new Map<string, Record<string, unknown>>();
  for (const o of attackPatterns) patternMap.set(o.id as string, o);

  onProgress?.('Building technique index…');
  const byGroup: MitreTechniquesEntry['byGroup'] = {};
  for (const o of intrusionSets) {
    const stixId = o.id as string;
    const rels = relationships.filter(r => r.source_ref === stixId && r.relationship_type === 'uses');
    const techniques: { id: string; name: string; tactic: string }[] = [];
    for (const rel of rels) {
      const target = patternMap.get(rel.target_ref as string);
      if (!target) continue;
      const tExtRefs  = target.external_references as Record<string, unknown>[] | undefined;
      const tMitreRef = Array.isArray(tExtRefs) ? tExtRefs.find(r => r.source_name === 'mitre-attack') : undefined;
      const tId       = tMitreRef ? String(tMitreRef.external_id) : (rel.target_ref as string);
      const phases    = target.kill_chain_phases as Record<string, unknown>[] | undefined;
      const phase     = Array.isArray(phases) ? phases.find(p => p.kill_chain_name === 'mitre-attack') : undefined;
      const tacticSlug = phase ? (phase.phase_name as string) : '';
      const tactic    = tacticSlug.split('-').map((w: string) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
      techniques.push({ id: tId, name: target.name as string, tactic });
    }
    if (techniques.length) byGroup[stixId] = techniques;
  }

  const entry: MitreTechniquesEntry = { cachedAt: Date.now(), byGroup };
  await saveMitreTechniques(entry);
  return entry;
}

async function buildMitreSoftware(onProgress?: (msg: string) => void, _sharedData?: { intrusionSets: Record<string, unknown>[]; relationships: Record<string, unknown>[] }): Promise<MitreSoftwareEntry> {
  let intrusionSets: Record<string, unknown>[];
  let relationships: Record<string, unknown>[];

  if (_sharedData) {
    intrusionSets = _sharedData.intrusionSets;
    relationships = _sharedData.relationships;
  } else {
    onProgress?.('Fetching intrusion sets…');
    intrusionSets = await mitreFetchAll('intrusion-set');
    if (!intrusionSets.length) throw new Error('MITRE TAXII returned no intrusion-set objects');
    await mitreFetchDelay(5000);
    onProgress?.('Fetching relationships…');
    relationships = (await mitreFetchAll('relationship')).filter(r => !(r.revoked as boolean));
    await mitreFetchDelay(5000);
  }

  if (!intrusionSets.length) throw new Error('MITRE TAXII returned no intrusion-set objects');
  onProgress?.('Fetching malware & tools…');
  const malware = await mitreFetchAll('malware');
  await mitreFetchDelay(5000);
  const tools = await mitreFetchAll('tool');
  await mitreFetchDelay(5000);
  onProgress?.('Fetching campaigns & mitigations…');
  const campaigns   = await mitreFetchAll('campaign');
  await mitreFetchDelay(5000);
  const mitigations = await mitreFetchAll('course-of-action');

  const objMap = new Map<string, Record<string, unknown>>();
  for (const o of [...malware, ...tools, ...campaigns, ...mitigations]) objMap.set(o.id as string, o);

  onProgress?.('Building software index…');
  const byGroup: MitreSoftwareEntry['byGroup'] = {};
  for (const o of intrusionSets) {
    const stixId = o.id as string;
    const sw: { id: string; name: string; type: string }[] = [];
    const camp: { id: string; name: string }[] = [];
    const mit:  { id: string; name: string }[] = [];

    for (const rel of relationships) {
      const relType = rel.relationship_type as string;
      const srcRef  = rel.source_ref as string;
      const tgtRef  = rel.target_ref as string;

      // group uses malware/tool
      if (relType === 'uses' && srcRef === stixId) {
        const target = objMap.get(tgtRef);
        if (!target) continue;
        const targetType = target.type as string;
        if (targetType !== 'malware' && targetType !== 'tool') continue;
        const tExtRefs  = target.external_references as Record<string, unknown>[] | undefined;
        const tMitreRef = Array.isArray(tExtRefs) ? tExtRefs.find(r => r.source_name === 'mitre-attack') : undefined;
        const tId       = tMitreRef ? String(tMitreRef.external_id) : tgtRef;
        sw.push({ id: tId, name: target.name as string, type: targetType });
      }
      // campaign attributed-to group (campaign is source, group is target)
      else if (relType === 'attributed-to' && tgtRef === stixId) {
        const src = objMap.get(srcRef);
        if (!src || (src.type as string) !== 'campaign') continue;
        const sExtRefs  = src.external_references as Record<string, unknown>[] | undefined;
        const sMitreRef = Array.isArray(sExtRefs) ? sExtRefs.find(r => r.source_name === 'mitre-attack') : undefined;
        const sId       = sMitreRef ? String(sMitreRef.external_id) : srcRef;
        camp.push({ id: sId, name: src.name as string });
      }
      // course-of-action mitigates technique used by group — link via group's used techniques
      // mitigates goes: course-of-action → attack-pattern, not group → course-of-action
      // Instead look for group → uses → attack-pattern where that pattern has a mitigates rel
    }
    if (sw.length || camp.length || mit.length) {
      byGroup[stixId] = { software: sw, campaigns: camp, mitigations: mit };
    }
  }

  const entry: MitreSoftwareEntry = { cachedAt: Date.now(), byGroup };
  await saveMitreSoftware(entry);
  return entry;
}

// ── Full build (all three) ──
async function buildMitreCache(onProgress?: (msg: string) => void): Promise<MitreCacheEntry> {
  // Fetch shared data once — avoids fetching intrusion-set and relationship 3x each
  onProgress?.('[Shared] Fetching intrusion sets…');
  const intrusionSets = await mitreFetchAll('intrusion-set');
  if (!intrusionSets.length) throw new Error('MITRE TAXII returned no intrusion-set objects');
  await mitreFetchDelay(5000);
  onProgress?.('[Shared] Fetching relationships…');
  const relationships = (await mitreFetchAll('relationship')).filter(r => !(r.revoked as boolean));
  await mitreFetchDelay(5000);
  const shared = { intrusionSets, relationships };

  onProgress?.('[Profiles] Starting…');
  const profiles = await buildMitreProfiles(msg => onProgress?.(`[Profiles] ${msg}`), shared);
  onProgress?.('[Profiles] Done — cooling down 15s before next component…');
  await mitreFetchDelay(15000);
  onProgress?.('[Techniques] Starting…');
  const techniques = await buildMitreTechniques(msg => onProgress?.(`[Techniques] ${msg}`), shared);
  onProgress?.('[Techniques] Done — cooling down 15s before next component…');
  await mitreFetchDelay(15000);
  onProgress?.('[Software] Starting…');
  const software = await buildMitreSoftware(msg => onProgress?.(`[Software] ${msg}`), shared);

  // Assemble session cache from fresh build data
  const groups: MitreCachedGroup[] = profiles.groups.map(p => ({
    id:       p.id,
    name:     p.name,
    aliases:  p.aliases,
    attackId: p.attackId,
    _desc:    p.desc || undefined,
    _related: {
      techniques:      techniques.byGroup[p.id] ?? [],
      software:        software.byGroup[p.id]?.software    ?? [],
      campaigns:       software.byGroup[p.id]?.campaigns   ?? [],
      mitigations:     software.byGroup[p.id]?.mitigations ?? [],
      sectors:         p.sectors,
      countries:       p.countries,
      associatedGroups: p.associatedGroups.map(name => ({ id: '', name })),
    },
  }));
  mitreSessionCache = { cachedAt: profiles.cachedAt, groups };
  return mitreSessionCache;
}

async function getMitreCache(forceReload = false): Promise<MitreCacheEntry | null> {
  if (mitreSessionCache && !forceReload) return mitreSessionCache;
  const stored = await loadMitreCache();
  if (stored) mitreSessionCache = stored;
  return stored ?? null;
}

async function mitreAttackFetch(
  query: string,
  onStatus?: (msg: string | null) => void,
  onColdCache?: () => void,
  onBuildComplete?: () => void,
): Promise<Record<string, unknown> | null> {
  const cache = await getMitreCache();

  // Cache miss — kick off background build and return immediately
  if (!cache) {
    onColdCache?.();
    if (!mitreBuildPromise) {
      mitreBuildPromise = buildMitreCache(onStatus)
        .then(entry => { onBuildComplete?.(); return entry; })
        .catch(e => { throw e; })
        .finally(() => { mitreBuildPromise = null; });
    }
    return null;
  }

  const q = query.trim().toLowerCase();
  const terms = (s: string) => s.toLowerCase();
  // 1. Exact match on name or alias
  let group = cache.groups.find(g =>
    terms(g.name) === q || g.aliases.some(a => terms(a) === q)
  );
  // 2. Prefix match — "Sandworm" matches "Sandworm Team"
  if (!group) group = cache.groups.find(g =>
    terms(g.name).startsWith(q) || g.aliases.some(a => terms(a).startsWith(q))
  );
  // 3. Substring match — "Lazarus" matches "Lazarus Group"
  if (!group) group = cache.groups.find(g =>
    terms(g.name).includes(q) || g.aliases.some(a => terms(a).includes(q))
  );
  if (!group) return null;

  // Reshape to the format extractMitreAttack expects
  return {
    id:          group.id,
    name:        group.name,
    aliases:     [group.name, ...group.aliases],
    description: group._desc ?? '',
    external_references: group.attackId ? [{ source_name: 'mitre-attack', external_id: group.attackId }] : [],
    created:     '',
    modified:    '',
    _related:    group._related,
  };
}

// eslint-disable-next-line react-refresh/only-export-components -- shared non-component logic consumed by BulkSearch.tsx; deeply coupled to this file's MITRE cache subsystem, not worth extracting
export async function fetchProvider(
  providerId: string,
  query: string,
  artifactType: ArtifactType,
  apiKey: string | null,
  onStatus?: (msg: string | null) => void,
  onColdCache?: () => void,
  onBuildComplete?: () => void,
): Promise<QueryResult> {
  const provider = PROVIDERS.find(p => p.id === providerId);
  if (!provider) return { providerId, artifactType, query, status: 'error', data: null, error: 'Unknown provider' };
  if (!provider.supports.includes(artifactType)) return { providerId, artifactType, query, status: 'unsupported', data: null };
  if (provider.requiresKey && !apiKey) return { providerId, artifactType, query, status: 'no-key', data: null };

  // ── NVD (optional key raises rate limit 5→50 req/30s) ────────────
  if (providerId === 'nvd' && artifactType === 'cve') {
    try {
      const isCveId = /^CVE-\d{4}-\d{4,}$/i.test(query.trim());
      const nvdBase = isDev() ? '/nvd-proxy' : 'https://services.nvd.nist.gov';
      const url = isCveId
        ? `${nvdBase}/rest/json/cves/2.0?cveId=${encodeURIComponent(query.trim().toUpperCase())}`
        : `${nvdBase}/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query.trim())}&keywordExactMatch`;
      const headers: Record<string, string> = { 'Accept': 'application/json' };
      if (apiKey) headers['apiKey'] = apiKey;
      const start = performance.now();
      const res = await fetch(url, {
        headers,
        signal: AbortSignal.timeout(12000),
      });
      const latencyMs = Math.round(performance.now() - start);
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const data = await res.json();
      if (!data.totalResults) return { providerId, artifactType, query, status: 'ok', data: { vulnerabilities: [] }, latencyMs };
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── CIRCL CVE (public, no key) ──────────────────────────────────
  if (providerId === 'circl' && artifactType === 'cve') {
    try {
      const isCveId = /^CVE-\d{4}-\d{4,}$/i.test(query.trim());
      const circlBase = isDev() ? '/circl-proxy' : 'https://cve.circl.lu';
      const url = isCveId
        ? `${circlBase}/api/cve/${encodeURIComponent(query.trim().toUpperCase())}`
        : `${circlBase}/api/search/${query.trim().split(/[\s/]+/).map(encodeURIComponent).join('/')}`;
      const start = performance.now();
      const res = await fetch(url, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000),
      });
      const latencyMs = Math.round(performance.now() - start);
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const data = await res.json();
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── APIvoid ────────────────────────────────────────────────────
  if (providerId === 'apivoid' && apiKey) {
    try {
      const base = isDev() ? '/apivoid-proxy' : 'https://api.apivoid.com';
      const headers = { 'X-API-Key': apiKey, 'Content-Type': 'application/json', 'Accept': 'application/json' };
      const start = performance.now();

      if (artifactType === 'ip') {
        const res = await fetch(`${base}/v2/ip-reputation`, {
          method: 'POST', headers, body: JSON.stringify({ ip: query }), signal: AbortSignal.timeout(12000),
        });
        const latencyMs = Math.round(performance.now() - start);
        if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
        return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
      }

      if (artifactType === 'domain') {
        const [repRes, ageRes, sslRes] = await Promise.all([
          fetch(`${base}/v2/domain-reputation`, { method: 'POST', headers, body: JSON.stringify({ host: query }), signal: AbortSignal.timeout(12000) }),
          fetch(`${base}/v2/domain-age`,        { method: 'POST', headers, body: JSON.stringify({ host: query }), signal: AbortSignal.timeout(12000) }),
          fetch(`${base}/v2/ssl-info`,          { method: 'POST', headers, body: JSON.stringify({ host: query }), signal: AbortSignal.timeout(12000) }),
        ]);
        const latencyMs = Math.round(performance.now() - start);
        if (!repRes.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${repRes.status}`, latencyMs };
        const data = {
          reputation: await repRes.json(),
          age:        ageRes.ok  ? await ageRes.json()  : null,
          ssl:        sslRes.ok  ? await sslRes.json()  : null,
        };
        return { providerId, artifactType, query, status: 'ok', data, latencyMs };
      }

      if (artifactType === 'url') {
        const res = await fetch(`${base}/v2/url-reputation`, {
          method: 'POST', headers, body: JSON.stringify({ url: query }), signal: AbortSignal.timeout(30000),
        });
        const latencyMs = Math.round(performance.now() - start);
        if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
        return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
      }

      return { providerId, artifactType, query, status: 'unsupported', data: null };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── Shodan InternetDB (free, no key) ───────────────────────────
  if (providerId === 'internetdb' && artifactType === 'ip') {
    try {
      const url = isDev()
        ? `/internetdb-proxy/${encodeURIComponent(query)}`
        : `https://internetdb.shodan.io/${encodeURIComponent(query)}`;
      const start = performance.now();
      const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
      const latencyMs = Math.round(performance.now() - start);
      if (res.status === 404) return { providerId, artifactType, query, status: 'ok', data: { ports: [], hostnames: [], vulns: [], tags: [], cpes: [] }, latencyMs };
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── MalwareBazaar ───────────────────────────────────────────────
  if (providerId === 'malwarebazaar') {
    if (artifactType !== 'hash') return { providerId, artifactType, query, status: 'unsupported', data: null };
    if (!apiKey) return { providerId, artifactType, query, status: 'no-key', data: null };
    try {
      const base = isDev() ? '/bazaar-proxy' : 'https://mb-api.abuse.ch';
      const start = performance.now();
      const body: Record<string, string> = { query: 'get_info', hash: query };
      const res = await fetch(`${base}/api/v1/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Auth-Key': apiKey },
        body: new URLSearchParams(body).toString(),
        signal: AbortSignal.timeout(10000),
      });
      const latencyMs = Math.round(performance.now() - start);
      if (res.status === 401 || res.status === 403) return { providerId, artifactType, query, status: 'no-key', data: null, latencyMs };
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const data = JSON.parse(await res.text()) as Record<string, unknown>;
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── ThreatFox ────────────────────────────────────────────────────
  if (providerId === 'threatfox') {
    if (!apiKey) return { providerId, artifactType, query, status: 'no-key', data: null };
    try {
      const base = isDev() ? '/threatfox-proxy' : 'https://threatfox-api.abuse.ch';
      const start = performance.now();
      const body: Record<string, unknown> = { query: 'search_ioc', search_term: query };
      const res = await fetch(`${base}/api/v1/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Auth-Key': apiKey },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
      const latencyMs = Math.round(performance.now() - start);
      if (res.status === 401 || res.status === 403) return { providerId, artifactType, query, status: 'no-key', data: null, latencyMs };
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const data = JSON.parse(await res.text()) as Record<string, unknown>;
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── Spamhaus DQS ─────────────────────────────────────────────────
  if (providerId === 'spamhaus' && apiKey) {
    try {
      const base = isDev() ? '/spamhaus-proxy' : 'https://apibl.spamhaus.net';
      const start = performance.now();
      let lists: string[] = [];
      if (artifactType === 'ip') lists = ['sbl', 'xbl', 'pbl', 'css'];
      else if (artifactType === 'domain') lists = ['dbl', 'zrd'];
      const results = await Promise.all(lists.map(async list => {
        try {
          const r = await fetch(`${base}/lookup/v2/${list}/${encodeURIComponent(query)}`, {
            headers: { 'Authorization': `Bearer ${apiKey}` },
            signal: AbortSignal.timeout(8000),
          });
          return { list, status: r.status, data: r.ok ? await r.json() as unknown : null };
        } catch { return { list, status: 0, data: null }; }
      }));
      const latencyMs = Math.round(performance.now() - start);
      return { providerId, artifactType, query, status: 'ok', data: { results }, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── URLhaus (public, no key) ────────────────────────────────────
  if (providerId === 'urlhaus') {
    try {
      let endpoint = '';
      let body = '';
      const urlhausBase = isDev() ? '/urlhaus-proxy' : 'https://urlhaus-api.abuse.ch';
      if (artifactType === 'url') {
        endpoint = `${urlhausBase}/api/v1/url/`;
        body = `url=${encodeURIComponent(query)}`;
      } else if (artifactType === 'domain' || artifactType === 'ip') {
        endpoint = `${urlhausBase}/api/v1/host/`;
        body = `host=${encodeURIComponent(query)}`;
      } else {
        return { providerId, artifactType, query, status: 'unsupported', data: null };
      }
      const start = performance.now();
      const urlhausHeaders: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
      if (apiKey) urlhausHeaders['Auth-Key'] = apiKey;
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: urlhausHeaders,
        body,
        signal: AbortSignal.timeout(8000),
      });
      const latencyMs = Math.round(performance.now() - start);
      if (res.status === 401 || res.status === 403) {
        return { providerId, artifactType, query, status: 'no-key', data: null, latencyMs };
      }
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const text = await res.text();
      const data = JSON.parse(text);
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── GreyNoise (community free, or full context with key) ────────
  if (providerId === 'greynoise' && artifactType === 'ip') {
    try {
      const gnBase = isDev() ? '/greynoise-proxy' : 'https://api.greynoise.io';
      const endpoint = apiKey
        ? `${gnBase}/v3/ip/${encodeURIComponent(query)}`
        : `${gnBase}/v3/community/${encodeURIComponent(query)}`;
      const headers: Record<string, string> = { 'Accept': 'application/json' };
      if (apiKey) headers['key'] = apiKey;
      const start = performance.now();
      const res = await fetch(endpoint, { headers, signal: AbortSignal.timeout(8000) });
      const latencyMs = Math.round(performance.now() - start);
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── WHOIS / RDAP (free, no key) ─────────────────────────────────
  if (providerId === 'whois') {
    try {
      const start = performance.now();
      if (artifactType !== 'domain' && artifactType !== 'ip') {
        return { providerId, artifactType, query, status: 'unsupported', data: null };
      }
      if (artifactType === 'domain') {
        return { providerId, artifactType, query, status: 'unsupported', data: null };
      }
      // rdap.org routes to the correct regional registry server-side.
      // redirect:'follow' lets the SW proxy the redirected request through the allowlisted registry.
      const rdapBase = isDev() ? '/rdap.org' : 'https://rdap.org';
      const rdapUrl = `${rdapBase}/ip/${encodeURIComponent(query)}`;
      const data = await fetch(rdapUrl, { redirect: 'follow', signal: AbortSignal.timeout(8000) })
        .then(res => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json(); })
        .catch(() => null);
      if (!data) throw new Error('No RDAP registry responded');
      const latencyMs = Math.round(performance.now() - start);
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── Censys ─────────────────────────────────────────────────────
  if (providerId === 'censys' && apiKey) {
    try {
      const [apiId, apiSecret] = apiKey.split(':');
      if (!apiId || !apiSecret) return { providerId, artifactType, query, status: 'error', data: null, error: 'Key must be in format api_id:api_secret' };
      const creds = btoa(`${apiId}:${apiSecret}`);
      const headers = { 'Authorization': `Basic ${creds}`, 'Accept': 'application/json' };
      const censysBase = isDev() ? '/censys-proxy' : 'https://search.censys.io';
      const start = performance.now();
      let endpoint = '';
      if (artifactType === 'ip') {
        endpoint = `${censysBase}/api/v2/hosts/${encodeURIComponent(query)}`;
      } else if (artifactType === 'domain') {
        endpoint = `${censysBase}/api/v2/certificates?q=${encodeURIComponent(`parsed.names:${query}`)}&per_page=5`;
      } else {
        return { providerId, artifactType, query, status: 'unsupported', data: null };
      }
      const res = await fetch(endpoint, { headers, signal: AbortSignal.timeout(12000) });
      const latencyMs = Math.round(performance.now() - start);
      if (res.status === 401 || res.status === 403) return { providerId, artifactType, query, status: 'no-key', data: null, latencyMs };
      if (res.status === 404) return { providerId, artifactType, query, status: 'ok', data: null, latencyMs };
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        try { const e = await res.json() as Record<string,unknown>; errMsg = String(e?.message ?? errMsg); } catch { /* ignore */ }
        return { providerId, artifactType, query, status: 'error', data: null, error: errMsg, latencyMs };
      }
      return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── Shodan ─────────────────────────────────────────────────────
  if (providerId === 'shodan' && apiKey) {
    try {
      let endpoint = '';
      const shodanBase = isDev() ? '/shodan-proxy' : 'https://api.shodan.io';
      if (artifactType === 'ip') {
        endpoint = `${shodanBase}/shodan/host/${encodeURIComponent(query)}?key=${encodeURIComponent(apiKey)}`;
      } else if (artifactType === 'domain') {
        endpoint = `${shodanBase}/dns/domain/${encodeURIComponent(query)}?key=${encodeURIComponent(apiKey)}`;
      } else {
        return { providerId, artifactType, query, status: 'unsupported', data: null };
      }
      const start = performance.now();
      const res = await fetch(endpoint, { signal: AbortSignal.timeout(12000) });
      const latencyMs = Math.round(performance.now() - start);
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        try { const e = await res.json(); errMsg = e?.error ?? errMsg; } catch { /* ignore */ }
        return { providerId, artifactType, query, status: 'error', data: null, error: errMsg, latencyMs };
      }
      return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── AbuseIPDB ───────────────────────────────────────────────────
  if (providerId === 'abuseipdb' && apiKey) {
    try {
      const abuseBase = isDev() ? '/abuseipdb-proxy' : 'https://api.abuseipdb.com';
      const endpoint = `${abuseBase}/api/v2/check?ipAddress=${encodeURIComponent(query)}&maxAgeInDays=90&verbose`;
      const start = performance.now();
      const res = await fetch(endpoint, {
        headers: { 'Key': apiKey, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000),
      });
      const latencyMs = Math.round(performance.now() - start);
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const json = await res.json();
      const data = (json?.data ?? json) as Record<string, unknown>;
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── MaxMind GeoIP2 (paid) and GeoLite2 (free) ──────────────────
  if ((providerId === 'maxmind' || providerId === 'maxmind-free') && apiKey) {
    try {
      const [accountId, licenseKey] = apiKey.split(':');
      if (!accountId || !licenseKey) {
        return { providerId, artifactType, query, status: 'error', data: null, error: 'Key must be in format accountId:licenseKey' };
      }
      const creds = btoa(`${accountId}:${licenseKey}`);
      const headers = { 'Authorization': `Basic ${creds}`, 'Accept': 'application/json' };
      const ip = encodeURIComponent(query);
      const isPaid = providerId === 'maxmind';
      // Each variant only tries its own host — no fallback chain so failures are fast.
      const cityBase  = isDev()
        ? (isPaid ? '/maxmind-proxy/geoip/v2.1/city/' : '/geolite-proxy/geoip/v2.1/city/')
        : (isPaid ? '/geoip.maxmind.com/geoip/v2.1/city/' : '/geolite.info/geoip/v2.1/city/');
      const countryBase = isDev()
        ? (isPaid ? '/maxmind-proxy/geoip/v2.1/country/' : '/geolite-proxy/geoip/v2.1/country/')
        : (isPaid ? '/geoip.maxmind.com/geoip/v2.1/country/' : '/geolite.info/geoip/v2.1/country/');
      const start = performance.now();
      let res = await fetch(`${cityBase}${ip}`, { headers, signal: AbortSignal.timeout(8000) });
      if (!res.ok && (res.status === 400 || res.status === 404)) {
        res = await fetch(`${countryBase}${ip}`, { headers, signal: AbortSignal.timeout(8000) });
      }
      const latencyMs = Math.round(performance.now() - start);
      if (res.ok) return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
      let errMsg = `HTTP ${res.status}`;
      try { const e = await res.json() as Record<string, unknown>; errMsg = String(e?.error ?? e?.message ?? errMsg); } catch { /* ignore */ }
      return { providerId, artifactType, query, status: 'error', data: null, error: errMsg, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── VirusTotal ──────────────────────────────────────────────────
  if (providerId === 'virustotal' && apiKey) {
    try {
      let endpoint = '';
      const vtBase = isDev() ? '/vt-proxy' : 'https://www.virustotal.com';
      if (artifactType === 'ip') {
        endpoint = `${vtBase}/api/v3/ip_addresses/${encodeURIComponent(query)}`;
      } else if (artifactType === 'domain') {
        endpoint = `${vtBase}/api/v3/domains/${encodeURIComponent(query)}`;
      } else if (artifactType === 'hash') {
        endpoint = `${vtBase}/api/v3/files/${encodeURIComponent(query)}`;
      } else if (artifactType === 'url') {
        // VT requires a base64url-encoded URL ID
        const id = btoa(query).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        endpoint = `${vtBase}/api/v3/urls/${id}`;
      } else if (artifactType === 'file') {
        endpoint = `${vtBase}/api/v3/files?filter=${encodeURIComponent(`name:"${query}"`)}&limit=10`;
      } else {
        return { providerId, artifactType, query, status: 'unsupported', data: null };
      }
      const start = performance.now();
      const res = await fetch(endpoint, {
        headers: { 'x-apikey': apiKey, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(12000),
      });
      const latencyMs = Math.round(performance.now() - start);
      if (res.status === 401 || res.status === 403) return { providerId, artifactType, query, status: 'no-key', data: null, latencyMs };
      if (res.status === 404) return { providerId, artifactType, query, status: 'ok', data: null, latencyMs };
      // 405 on file search = VT Intelligence not available on this key tier
      if (res.status === 405) return { providerId, artifactType, query, status: 'unsupported', data: null, latencyMs };
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const json = await res.json() as Record<string, unknown>;
      if (artifactType === 'file') {
        const items = json.data as Record<string, unknown>[] | undefined;
        const data = Array.isArray(items) ? { file_results: items.map(i => i.attributes) } : null;
        return { providerId, artifactType, query, status: 'ok', data, latencyMs };
      }
      // VT wraps results under json.data.attributes
      const data = (json?.data as Record<string,unknown>)?.attributes ?? json;
      return { providerId, artifactType, query, status: 'ok', data: data as Record<string, unknown>, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── Hybrid Analysis ───────────────────────────────────────────────
  if (providerId === 'hybrid-analysis' && apiKey) {
    try {
      const haBase = isDev() ? '/hybrid-proxy' : 'https://hybrid-analysis.com';
      const haHeaders = { 'api-key': apiKey, 'User-Agent': 'Falcon', 'Accept': 'application/json' };
      const haPostHeaders = { ...haHeaders, 'Content-Type': 'application/x-www-form-urlencoded' };
      const start = performance.now();
      let res: Response | null = null;

      if (artifactType === 'hash') {
        // GET preferred per API docs (POST deprecated as of v2.35.0)
        res = await fetch(`${haBase}/api/v2/search/hash?hash=${encodeURIComponent(query)}`, {
          method: 'GET', headers: haHeaders,
          signal: AbortSignal.timeout(12000),
        });
      } else if (artifactType === 'url') {
        res = await fetch(`${haBase}/api/v2/search/terms`, {
          method: 'POST', headers: haPostHeaders,
          body: `url=${encodeURIComponent(query)}`,
          signal: AbortSignal.timeout(12000),
        });
      } else if (artifactType === 'domain') {
        res = await fetch(`${haBase}/api/v2/search/terms`, {
          method: 'POST', headers: haPostHeaders,
          body: `domain=${encodeURIComponent(query)}`,
          signal: AbortSignal.timeout(12000),
        });
      } else if (artifactType === 'ip') {
        res = await fetch(`${haBase}/api/v2/search/terms`, {
          method: 'POST', headers: haPostHeaders,
          body: `host=${encodeURIComponent(query)}`,
          signal: AbortSignal.timeout(12000),
        });
      } else if (artifactType === 'file') {
        res = await fetch(`${haBase}/api/v2/search/terms`, {
          method: 'POST', headers: haPostHeaders,
          body: `filename=${encodeURIComponent(query)}`,
          signal: AbortSignal.timeout(12000),
        });
      }

      if (!res) return { providerId, artifactType, query, status: 'unsupported', data: null };
      const latencyMs = Math.round(performance.now() - start);
      if (res.status === 401 || res.status === 403) return { providerId, artifactType, query, status: 'no-key', data: null, latencyMs };
      if (res.status === 404) return { providerId, artifactType, query, status: 'ok', data: null, latencyMs };
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const data = await res.json();
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── IPQS ──────────────────────────────────────────────────────────
  if (providerId === 'ipqs' && apiKey) {
    try {
      const ipqsBase = isDev() ? '/ipqs-proxy' : 'https://www.ipqualityscore.com';
      const start = performance.now();
      let url: string | null = null;

      if (artifactType === 'ip') {
        url = `${ipqsBase}/api/json/ip/${encodeURIComponent(apiKey)}/${encodeURIComponent(query)}?strictness=1`;
      } else if (artifactType === 'url' || artifactType === 'domain') {
        url = `${ipqsBase}/api/json/url/${encodeURIComponent(apiKey)}/${encodeURIComponent(query)}?strictness=0`;
      }

      if (!url) return { providerId, artifactType, query, status: 'unsupported', data: null };
      const res = await fetch(url, { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) });
      const latencyMs = Math.round(performance.now() - start);
      if (res.status === 401 || res.status === 403) return { providerId, artifactType, query, status: 'no-key', data: null, latencyMs };
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const data = await res.json() as Record<string, unknown>;
      if (data.success === false) return { providerId, artifactType, query, status: 'no-key', data: null, latencyMs };
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── MalShare ──────────────────────────────────────────────────────
  if (providerId === 'malshare' && apiKey && artifactType === 'hash') {
    try {
      const msBase = isDev() ? '/malshare-proxy' : 'https://malshare.com';
      const start = performance.now();
      const res = await fetch(
        `${msBase}/api.php?api_key=${encodeURIComponent(apiKey)}&action=details&hash=${encodeURIComponent(query)}`,
        { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) }
      );
      const latencyMs = Math.round(performance.now() - start);
      if (res.status === 401 || res.status === 403 || res.status === 400) return { providerId, artifactType, query, status: 'no-key', data: null, latencyMs };
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      const data = await res.json() as Record<string, unknown>;
      // MalShare returns an error field when hash not found
      if (data.ERROR) return { providerId, artifactType, query, status: 'ok', data: null, latencyMs };
      return { providerId, artifactType, query, status: 'ok', data, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── AlienVault OTX ─────────────────────────────────────────────
  if (providerId === 'otx' && apiKey) {
    try {
      const base = isDev() ? '/otx-proxy' : 'https://otx.alienvault.com';
      const headers = { 'X-OTX-API-KEY': apiKey, 'Accept': 'application/json' };
      const start = performance.now();
      let section = '';
      const indicator = encodeURIComponent(query);
      if (artifactType === 'ip')           { section = `IPv4/${indicator}`; }
      else if (artifactType === 'domain')  { section = `domain/${indicator}`; }
      else if (artifactType === 'url')     { section = `url/${encodeURIComponent(btoa(query))}`; }
      else if (artifactType === 'hash')    { section = `file/${indicator}`; }
      else return { providerId, artifactType, query, status: 'unsupported', data: null };
      const [generalRes, reputationRes] = await Promise.all([
        fetch(`${base}/api/v1/indicators/${section}/general`, { headers, signal: AbortSignal.timeout(20000) }),
        fetch(`${base}/api/v1/indicators/${section}/reputation`, { headers, signal: AbortSignal.timeout(20000) }),
      ]);
      const latencyMs = Math.round(performance.now() - start);
      if (!generalRes.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${generalRes.status}`, latencyMs };
      const general    = await generalRes.json();
      const reputation = reputationRes.ok ? await reputationRes.json() : null;
      return { providerId, artifactType, query, status: 'ok', data: { general, reputation }, latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── IPinfo ──────────────────────────────────────────────────────
  if (providerId === 'ipinfo' && apiKey && artifactType === 'ip') {
    try {
      const base = isDev() ? '/ipinfo-proxy' : 'https://ipinfo.io';
      const start = performance.now();
      const res = await fetch(`${base}/${encodeURIComponent(query)}?token=${encodeURIComponent(apiKey)}`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(8000),
      });
      const latencyMs = Math.round(performance.now() - start);
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── Pulsedive ───────────────────────────────────────────────────
  if (providerId === 'pulsedive' && apiKey) {
    try {
      const base = isDev() ? '/pulsedive-proxy' : 'https://pulsedive.com';
      const start = performance.now();
      const res = await fetch(
        `${base}/api/indicator.php?pretty=1&key=${encodeURIComponent(apiKey)}&indicator=${encodeURIComponent(query)}`,
        { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) }
      );
      const latencyMs = Math.round(performance.now() - start);
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── Recorded Future ─────────────────────────────────────────────
  if (providerId === 'recordedfuture' && apiKey) {
    try {
      const base = isDev() ? '/rf-proxy' : 'https://api.recordedfuture.com';
      const headers = { 'X-RFToken': apiKey, 'Accept': 'application/json' };
      const start = performance.now();
      let endpoint = '';
      const fields = 'fields=risk,intelCard,timestamps,threatLists,relatedEntities,analystNotes';
      if (artifactType === 'ip')         endpoint = `${base}/v2/ip/${encodeURIComponent(query)}?${fields}`;
      else if (artifactType === 'domain') endpoint = `${base}/v2/domain/${encodeURIComponent(query)}?${fields}`;
      else if (artifactType === 'hash')   endpoint = `${base}/v2/hash/${encodeURIComponent(query)}?${fields}`;
      else if (artifactType === 'url')    endpoint = `${base}/v2/url/${encodeURIComponent(query)}?${fields}`;
      else return { providerId, artifactType, query, status: 'unsupported', data: null };
      const res = await fetch(endpoint, { headers, signal: AbortSignal.timeout(12000) });
      const latencyMs = Math.round(performance.now() - start);
      if (!res.ok) return { providerId, artifactType, query, status: 'error', data: null, error: `HTTP ${res.status}`, latencyMs };
      return { providerId, artifactType, query, status: 'ok', data: await res.json(), latencyMs };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  // ── MITRE ATT&CK ────────────────────────────────────────────────
  if (providerId === 'mitre-attack' && artifactType === 'threat-group') {
    try {
      const data = await mitreAttackFetch(query, onStatus, onColdCache, onBuildComplete);
      if (!data) return { providerId, artifactType, query, status: 'ok', data: null, latencyMs: 0 };
      return { providerId, artifactType, query, status: 'ok', data, latencyMs: 0 };
    } catch (e) {
      return { providerId, artifactType, query, status: 'error', data: null, error: e instanceof Error ? e.message : 'Network error' };
    }
  }

  return { providerId, artifactType, query, status: 'pending', data: null };
}

// ── Panel builder: merge all results into the typed panel model ────

// eslint-disable-next-line react-refresh/only-export-components -- shared non-component logic consumed by BulkSearch.tsx
export function buildPanels(results: QueryResult[], artifactType: ArtifactType): PanelData {
  const panels = emptyPanels();

  for (const r of results) {
    if (r.status !== 'ok' || !r.data) continue;
    const d = r.data as Rec2;
    const provider = PROVIDERS.find(p => p.id === r.providerId);
    const name = provider?.shortName ?? r.providerId;

    switch (r.providerId) {
      case 'virustotal':
        if (artifactType === 'ip')     extractVtIp(d, panels, name);
        if (artifactType === 'domain') extractVtDomain(d, panels, name);
        if (artifactType === 'hash')   extractVtHash(d, panels, name);
        if (artifactType === 'url')    extractVtDomain(d, panels, name);
        if (artifactType === 'file') {
          const fileResults = d.file_results as Rec2[] | undefined;
          if (Array.isArray(fileResults)) {
            fileResults.slice(0, 3).forEach(attr => extractVtHash(attr, panels, name));
          }
        }
        break;
      case 'apivoid':     extractApiVoid(d, panels, name, r.artifactType); break;
      case 'abuseipdb':   extractAbuseIpDb(d, panels, name);   break;
      case 'internetdb':  extractInternetDb(d, panels, name);   break;
      case 'shodan':      extractShodan(d, panels, name);       break;
      case 'maxmind':
      case 'maxmind-free': extractMaxMind(d, panels, name);     break;
      case 'greynoise':   extractGreyNoise(d, panels, name);    break;
      case 'spur':        extractSpur(d, panels, name);         break;
      case 'whois':       extractWhoisRdap(d, panels, name);    break;
      case 'nvd':
        if (artifactType === 'cve') extractNvd(r.data, r.query, panels, name);
        break;
      case 'circl':
        if (artifactType === 'cve') extractCirclCve(r.data, r.query, panels, name);
        break;
      case 'urlhaus':        extractUrlhaus(d, panels, name);       break;
      case 'malwarebazaar':  extractMalwareBazaar(d, panels, name); break;
      case 'threatfox':      extractThreatFox(d, panels, name);     break;
      case 'spamhaus':          extractSpamhaus(d, panels, name);          break;
      case 'malshare':          extractMalShare(d, panels, name);                        break;
      case 'hybrid-analysis':   extractHybridAnalysis(d, panels, name);                 break;
      case 'ipqs':              extractIpqs(d, panels, r.artifactType, name);            break;
      case 'censys':            extractCensys(d, panels, artifactType, name);           break;
      case 'mitre-attack':      extractMitreAttack(d, panels, name);                    break;
      case 'otx':               extractOtx(d, panels, name);                            break;
      case 'ipinfo':            extractIpInfo(d, panels, name);                         break;
      case 'pulsedive':         extractPulsedive(d, panels, name);                      break;
      case 'recordedfuture':    extractRecordedFuture(d, panels, name);                 break;
    }
  }

  return panels;
}
