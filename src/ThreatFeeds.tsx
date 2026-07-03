import { useState, useEffect, useRef } from 'react';
import type { FeedConfig, FeedFormat, FeedStatus, IndicatorType, CuratedFeed, FeedAuth, AuthType } from './feedTypes';
import {
  loadFeeds, saveFeed, deleteFeed, syncFeed, deriveFeedStatus, isStale,
  relativeTime, makeFeedConfig, previewFeed, loadFeedIndicators,
  saveFeedAuthKey, loadFeedAuthKey, deleteFeedAuthKey,
} from './feedService';
import { CURATED_FEEDS, CURATED_CATEGORIES } from './feedCurated';

// ── Publish to Stream ─────────────────────────────────────────────────

interface MergedRow {
  indicator: string;
  indicator_type: string;
  feed_names: string;   // semicolon-joined
  trust_score: number;
  tags: string;         // semicolon-joined
}

async function buildMergedLookup(feeds: FeedConfig[]): Promise<MergedRow[]> {
  const synced = feeds.filter(f => f.enabled && f.lastSync && f.lastSyncCount && f.lastSyncCount > 0);
  // Map: indicator → best row so far
  const map = new Map<string, MergedRow>();

  for (const feed of synced) {
    const indicators = await loadFeedIndicators(feed.id);
    for (const raw of indicators) {
      const key = raw.toLowerCase().trim();
      if (!key) continue;
      // Never include CVE IDs in the IOC lookup
      if (/^cve-\d{4}-\d+$/.test(key)) continue;
      const existing = map.get(key);
      if (!existing) {
        map.set(key, {
          indicator: key,
          indicator_type: feed.indicatorType === 'mixed' ? 'unknown' : feed.indicatorType,
          feed_names: feed.name,
          trust_score: feed.trustScore,
          tags: feed.tags.join(';'),
        });
      } else {
        // Keep highest trust score, merge feed names and tags
        const names = new Set(existing.feed_names.split(';'));
        names.add(feed.name);
        const tagSet = new Set(existing.tags ? existing.tags.split(';') : []);
        feed.tags.forEach(t => t && tagSet.add(t));
        map.set(key, {
          ...existing,
          trust_score: Math.max(existing.trust_score, feed.trustScore),
          feed_names: [...names].join(';'),
          tags: [...tagSet].filter(Boolean).join(';'),
        });
      }
    }
  }

  return [...map.values()];
}

function rowsToCsv(rows: MergedRow[]): string {
  const header = 'indicator,indicator_type,feed_names,trust_score,tags';
  const escape = (v: string | number) => {
    const s = String(v);
    return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = rows.map(r =>
    [r.indicator, r.indicator_type, r.feed_names, r.trust_score, r.tags].map(escape).join(',')
  );
  return [header, ...lines].join('\n');
}

function PublishView({ feeds }: { feeds: FeedConfig[] }) {
  const syncedFeeds = feeds.filter(f => f.enabled && f.lastSync && f.lastSyncCount && f.lastSyncCount > 0);

  // Feed selection — all synced feeds selected by default
  const [selectedIds, setSelectedIds] = useState<Set<string>>(
    () => new Set(syncedFeeds.map(f => f.id))
  );
  const [rows, setRows]               = useState<MergedRow[] | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [lookupName, setLookupName]   = useState('nautilus_threat_iocs');

  // Selection changed since the last render — clear rows synchronously for the
  // trivial empty case so we don't flash stale rows before the effect below runs.
  const selectionKey = [...selectedIds].sort().join(',');
  const [prevSelectionKey, setPrevSelectionKey] = useState(selectionKey);
  if (selectionKey !== prevSelectionKey) {
    setPrevSelectionKey(selectionKey);
    if (selectedIds.size === 0) setRows([]);
  }

  // Rebuild preview whenever selection changes. Dedupes on the sorted-id key
  // (via prevIdsRef) rather than the useEffect dependency array, since syncedFeeds
  // gets a new array identity on every render and would otherwise re-trigger a fetch.
  const prevIdsRef = useRef<string>('');
  useEffect(() => {
    const key = [...selectedIds].sort().join(',');
    if (key === prevIdsRef.current) return;
    prevIdsRef.current = key;
    if (selectedIds.size === 0) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- canonical set-loading-before-fetch pattern; deriving loading state would require reshaping `rows` across the component
    setLoadingPreview(true);
    const selected = syncedFeeds.filter(f => selectedIds.has(f.id));
    buildMergedLookup(selected).then(r => { setRows(r); setLoadingPreview(false); });
  }, [selectedIds, syncedFeeds]);

  function toggleFeed(id: string) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function selectAll()  { setSelectedIds(new Set(syncedFeeds.map(f => f.id))); }
  function selectNone() { setSelectedIds(new Set()); }

  // Breakdown by type
  const typeCounts = rows ? rows.reduce<Record<string, number>>((acc, r) => {
    acc[r.indicator_type] = (acc[r.indicator_type] ?? 0) + 1;
    return acc;
  }, {}) : {};

  // Per-feed contribution (only selected)
  const selectedFeeds = syncedFeeds.filter(f => selectedIds.has(f.id));
  const feedCounts = rows ? selectedFeeds.reduce<Record<string, number>>((acc, f) => {
    acc[f.id] = rows.filter(r => r.feed_names.split(';').includes(f.name)).length;
    return acc;
  }, {}) : {};

  function handleExportCsv() {
    if (!rows || rows.length === 0) return;
    const csv = rowsToCsv(rows);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${lookupName}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }


  return (
    <div className="publish-view">
      {/* Feed selection */}
      <div className="publish-section">
        <div className="publish-section-header">
          <span className="publish-section-title">Feeds to Include</span>
          <div className="publish-select-actions">
            <button className="publish-select-btn" onClick={selectAll}>All</button>
            <button className="publish-select-btn" onClick={selectNone}>None</button>
          </div>
        </div>
        {syncedFeeds.length === 0 && (
          <div className="publish-empty">No synced feeds. Sync at least one feed before publishing.</div>
        )}
        {syncedFeeds.map(f => (
          <label key={f.id} className="publish-feed-check">
            <input
              type="checkbox"
              checked={selectedIds.has(f.id)}
              onChange={() => toggleFeed(f.id)}
            />
            <span className="publish-feed-check-name">{f.name}</span>
            <span className={`feed-type-badge feed-type-${f.indicatorType}`}>{f.indicatorType}</span>
            <span className="publish-feed-trust">Trust {f.trustScore}</span>
            {f.lastSyncCount != null && (
              <span className="publish-feed-count">{f.lastSyncCount.toLocaleString()} indicators</span>
            )}
          </label>
        ))}
      </div>

      {/* Preview */}
      <div className="publish-section">
        <div className="publish-section-title">Preview</div>
        {loadingPreview && <div className="publish-loading">Building merged lookup…</div>}
        {!loadingPreview && rows !== null && selectedIds.size === 0 && (
          <div className="publish-empty">Select at least one feed to preview.</div>
        )}
        {!loadingPreview && rows !== null && rows.length === 0 && selectedIds.size > 0 && (
          <div className="publish-empty">No indicators in selected feeds.</div>
        )}
        {!loadingPreview && rows !== null && rows.length > 0 && (
          <>
            <div className="publish-stats">
              <div className="publish-stat-main">
                <span className="publish-stat-num">{rows.length.toLocaleString()}</span>
                <span className="publish-stat-label">unique indicators</span>
              </div>
              <div className="publish-stat-types">
                {Object.entries(typeCounts).sort((a,b) => b[1]-a[1]).map(([type, count]) => (
                  <span key={type} className={`feed-type-badge feed-type-${type}`}>
                    {count.toLocaleString()} {type}
                  </span>
                ))}
              </div>
            </div>
            <div className="publish-feed-breakdown">
              {selectedFeeds.map(f => (
                <div key={f.id} className="publish-feed-row">
                  <span className="publish-feed-name">{f.name}</span>
                  <span className="publish-feed-count">{(feedCounts[f.id] ?? 0).toLocaleString()} rows</span>
                  <span className="publish-feed-trust">Trust {f.trustScore}</span>
                </div>
              ))}
            </div>
            <div className="publish-sample">
              <div className="publish-sample-label">Sample (first 5 rows)</div>
              <table className="publish-sample-table">
                <thead>
                  <tr><th>indicator</th><th>type</th><th>feeds</th><th>trust</th><th>tags</th></tr>
                </thead>
                <tbody>
                  {rows.slice(0, 5).map((r, i) => (
                    <tr key={i}>
                      <td className="publish-sample-ioc">{r.indicator.length > 40 ? r.indicator.slice(0, 38) + '…' : r.indicator}</td>
                      <td><span className={`feed-type-badge feed-type-${r.indicator_type}`}>{r.indicator_type}</span></td>
                      <td className="publish-sample-feeds">{r.feed_names}</td>
                      <td>{r.trust_score}</td>
                      <td className="publish-sample-tags">{r.tags}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      {/* Export config + action */}
      <div className="publish-section">
        <div className="publish-section-title">Export</div>
        <div className="publish-config-row">
          <label className="publish-config-label">File Name</label>
          <input className="publish-config-input" value={lookupName} onChange={e => setLookupName(e.target.value.replace(/[^a-z0-9_]/gi, '_'))} placeholder="nautilus_threat_iocs" />
          <span className="publish-config-hint">.csv</span>
        </div>
        <div className="publish-actions">
          <button className="feed-btn feed-btn-primary" onClick={handleExportCsv} disabled={!rows || rows.length === 0}>
            ↓ Export CSV
          </button>
        </div>
        <div className="publish-export-hint">
          Import into Stream via Knowledge → Lookups → Upload. Commit and deploy after import.
        </div>
      </div>
    </div>
  );
}

// ── Add/Edit Feed Modal ──────────────────────────────────────────────

const FORMAT_OPTIONS: { value: FeedFormat | 'auto'; label: string }[] = [
  { value: 'auto',      label: 'Auto-detect' },
  { value: 'csv',       label: 'CSV'         },
  { value: 'tsv',       label: 'TSV (first column)' },
  { value: 'json',      label: 'JSON'        },
  { value: 'plaintext', label: 'Plaintext'   },
  { value: 'stix',      label: 'STIX Bundle' },
];

const TYPE_OPTIONS: { value: IndicatorType | 'auto'; label: string }[] = [
  { value: 'auto',   label: 'Auto-detect' },
  { value: 'ip',     label: 'IP'          },
  { value: 'domain', label: 'Domain'      },
  { value: 'url',    label: 'URL'         },
  { value: 'hash',   label: 'Hash'        },
  { value: 'mixed',  label: 'Mixed'       },
];

const AUTH_TYPE_OPTIONS: { value: AuthType; label: string; hint: string }[] = [
  { value: 'none',       label: 'None',           hint: '' },
  { value: 'header',     label: 'API Key Header',  hint: 'Attaches a custom request header (e.g. Authorization, X-API-Key)' },
  { value: 'queryparam', label: 'Query Parameter', hint: 'Appends an API key as a URL query parameter (e.g. ?apikey=...)' },
  { value: 'basic',      label: 'HTTP Basic Auth', hint: 'Standard HTTP Basic authentication (username:password)' },
];

function AddFeedModal({
  existing,
  prefill,
  onSave,
  onCancel,
}: {
  existing?: FeedConfig;
  prefill?: Partial<CuratedFeed>;
  onSave: (feed: Omit<FeedConfig, 'id' | 'addedAt' | 'lastSync' | 'lastSyncCount' | 'lastSyncError'>, secretKey?: string) => void;
  onCancel: () => void;
}) {
  const [name, setName]           = useState(existing?.name ?? prefill?.name ?? '');
  const [url, setUrl]             = useState(existing?.url ?? prefill?.url ?? '');
  const [format, setFormat]       = useState<FeedFormat | 'auto'>(existing?.format ?? prefill?.format ?? 'auto');
  const [indicatorField, setField]= useState(existing?.indicatorField ?? prefill?.indicatorField ?? '');
  const [indicatorType, setType]  = useState<IndicatorType | 'auto'>(existing?.indicatorType ?? prefill?.indicatorType ?? 'auto');
  const [ttlDays, setTtlDays]     = useState(existing?.ttlDays ?? 30);
  const [trustScore, setTrust]    = useState(existing?.trustScore ?? prefill?.trustScore ?? 70);
  const [autoSync, setAutoSync]   = useState(existing?.autoSync ?? true);
  const [tags, setTags]           = useState(existing?.tags.join(', ') ?? '');
  const [showPreview, setShowPreview] = useState(false);

  // Auth fields
  const existingAuth = existing?.auth ?? (prefill?.auth ? prefill.auth as FeedAuth : undefined);
  const [authType, setAuthType]       = useState<AuthType>(existingAuth?.type ?? 'none');
  const [authHeaderName, setHeaderName] = useState(existingAuth?.headerName ?? '');
  const [authParamName, setParamName]   = useState(existingAuth?.paramName ?? '');
  const [secretKey, setSecretKey]       = useState('');
  const [secretLoaded, setSecretLoaded] = useState(false);

  // Load existing secret (masked) when editing
  useEffect(() => {
    if (existing?.id && authType !== 'none') {
      loadFeedAuthKey(existing.id).then(val => {
        if (val) { setSecretKey(val); setSecretLoaded(true); }
      });
    }
  }, [existing?.id, authType]);

  const canSave = name.trim().length > 0 && url.trim().length > 0;
  const showField = format === 'csv' || format === 'json' || format === 'tsv';
  const needsAuthFields = authType !== 'none';

  function buildAuth(): FeedAuth | undefined {
    if (authType === 'none') return undefined;
    const base: FeedAuth = { type: authType };
    if (authType === 'header')     base.headerName = authHeaderName.trim() || 'Authorization';
    if (authType === 'queryparam') base.paramName  = authParamName.trim()  || 'apikey';
    if (existing?.id) base.kvKey = existing.id;
    return base;
  }

  function handleSave() {
    const resolvedFormat: FeedFormat = format === 'auto' ? 'plaintext' : format;
    const resolvedType: IndicatorType = indicatorType === 'auto' ? 'mixed' : indicatorType;
    const auth = buildAuth();
    onSave({
      name: name.trim(),
      url: url.trim(),
      format: resolvedFormat,
      indicatorType: resolvedType,
      indicatorField: indicatorField.trim(),
      enabled: existing?.enabled ?? true,
      autoSync,
      ttlDays,
      trustScore,
      tags: tags.split(',').map(t => t.trim()).filter(Boolean),
      auth,
    }, secretKey.trim() || undefined);
  }

  const previewFeedObj: FeedConfig = {
    id: existing?.id ?? 'preview',
    name: name.trim() || 'Preview',
    url: url.trim(),
    format: format === 'auto' ? 'plaintext' : format,
    indicatorField: indicatorField.trim(),
    indicatorType: indicatorType === 'auto' ? 'mixed' : indicatorType,
    enabled: true, autoSync, ttlDays, trustScore,
    tags: [], addedAt: '', lastSync: null, lastSyncCount: null, lastSyncError: null,
    auth: buildAuth(),
  };

  const authHint = AUTH_TYPE_OPTIONS.find(o => o.value === authType)?.hint ?? '';

  return (
    <>
      <div className="overlay" onClick={e => e.target === e.currentTarget && onCancel()}>
        <div className="panel feed-modal">
          <div className="panel-header">
            <span className="panel-title">{existing ? 'Edit Feed' : 'Add Feed'}</span>
            <button className="panel-close" onClick={onCancel}>✕</button>
          </div>
          <div className="feed-modal-body">
            <div className="feed-field">
              <label className="feed-label">Name <span className="feed-required">*</span></label>
              <input className="feed-input" value={name} placeholder="e.g. Feodo Tracker IPs"
                onChange={e => setName(e.target.value)} />
            </div>
            <div className="feed-field">
              <label className="feed-label">Feed URL <span className="feed-required">*</span></label>
              <input className="feed-input" type="url" value={url}
                placeholder="https://example.com/feed.csv"
                onChange={e => setUrl(e.target.value)} />
            </div>
            <div className="feed-field-row">
              <div className="feed-field flex-1">
                <label className="feed-label">Format</label>
                <select className="feed-input" value={format}
                  onChange={e => setFormat(e.target.value as FeedFormat | 'auto')}>
                  {FORMAT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
              <div className="feed-field flex-1">
                <label className="feed-label">Indicator Type</label>
                <select className="feed-input" value={indicatorType}
                  onChange={e => setType(e.target.value as IndicatorType | 'auto')}>
                  {TYPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
              <div className="feed-field flex-1">
                <label className="feed-label">Auth Method</label>
                <select className="feed-input" value={authType}
                  onChange={e => { setAuthType(e.target.value as AuthType); setSecretKey(''); setSecretLoaded(false); }}>
                  {AUTH_TYPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
            </div>
            {showField && (
              <div className="feed-field">
                <label className="feed-label">Column / field name containing the indicator</label>
                <input className="feed-input" value={indicatorField}
                  placeholder="e.g. dst_ip, ioc_value, url"
                  onChange={e => setField(e.target.value)} />
                {format === 'csv' && (
                  <p className="feed-hint">
                    abuse.ch feeds use a <code># "col1",...</code> header — just enter the column name (e.g. <code>ioc_value</code>).
                  </p>
                )}
                {format === 'tsv' && (
                  <p className="feed-hint">
                    Leave blank to use the first column. Enter a column name to find it by header row (e.g. <code>ip</code>).
                  </p>
                )}
              </div>
            )}
            {format === 'stix' && (
              <div className="feed-hint feed-hint-info">
                STIX bundles are parsed automatically — indicator values are extracted from the
                <code> pattern</code> field (e.g. <code>[ipv4-addr:value = '1.2.3.4']</code>).
                No field name needed.
              </div>
            )}

            {/* ── Authentication ─────────────────────────── */}
            {needsAuthFields && (
            <div className="feed-auth-section">
              <div className="feed-auth-header">Authentication</div>
              {authHint && <p className="feed-hint" style={{ marginTop: 0 }}>{authHint}</p>}

              {authType === 'header' && (
                <div className="feed-field">
                  <label className="feed-label">Header Name</label>
                  <input className="feed-input" value={authHeaderName}
                    placeholder="Authorization or X-API-Key"
                    onChange={e => setHeaderName(e.target.value)} />
                </div>
              )}

              {authType === 'queryparam' && (
                <div className="feed-field">
                  <label className="feed-label">Parameter Name</label>
                  <input className="feed-input" value={authParamName}
                    placeholder="apikey"
                    onChange={e => setParamName(e.target.value)} />
                </div>
              )}

              <div className="feed-field">
                <label className="feed-label">
                  {authType === 'basic' ? 'Credentials (user:password)' : 'API Key / Secret'}
                  {secretLoaded && <span className="feed-key-loaded"> — key stored</span>}
                </label>
                <input
                  className="feed-input feed-input-secret"
                  type="password"
                  value={secretKey}
                  placeholder={secretLoaded ? '••••••••  (leave blank to keep current)' : 'Paste your API key here'}
                  onChange={e => setSecretKey(e.target.value)}
                  autoComplete="new-password"
                />
                <p className="feed-hint">
                  Stored securely in Cribl KV — never sent anywhere except the feed host.
                </p>
              </div>
            </div>
            )}

            <div className="feed-field-row">
              <div className="feed-field">
                <label className="feed-label">Stale after (days)</label>
                <input type="number" min={1} max={365} className="feed-input feed-input-sm"
                  value={ttlDays} onChange={e => setTtlDays(Number(e.target.value))} />
              </div>
              <div className="feed-field flex-1">
                <label className="feed-label">Trust Score — <span style={{ color: 'var(--accent)', fontWeight: 600 }}>{trustScore}/100</span></label>
                <input type="range" min={0} max={100} value={trustScore}
                  onChange={e => setTrust(Number(e.target.value))}
                  className="feed-range" />
              </div>
            </div>
            <div className="feed-field">
              <label className="feed-label">Tags (comma-separated)</label>
              <input className="feed-input" value={tags}
                placeholder="e.g. c2, blocklist, abuse.ch"
                onChange={e => setTags(e.target.value)} />
            </div>
            <label className="feed-checkbox-row">
              <input type="checkbox" checked={autoSync} onChange={e => setAutoSync(e.target.checked)} />
              <span>Auto-sync on app load</span>
            </label>
            <button disabled={!url.trim()} onClick={() => setShowPreview(true)}
              className="feed-btn feed-btn-secondary" style={{ width: '100%' }}>
              Test &amp; Preview
            </button>
          </div>
          <div className="feed-modal-footer">
            <button className="feed-btn" onClick={onCancel}>Cancel</button>
            <button className="feed-btn feed-btn-primary" disabled={!canSave} onClick={handleSave}>
              {existing ? 'Save Changes' : 'Save Feed'}
            </button>
          </div>
        </div>
      </div>
      {showPreview && (
        <FeedPreviewModal feed={previewFeedObj} onClose={() => setShowPreview(false)} />
      )}
    </>
  );
}

// ── Auth Key Manager (inline on card) ────────────────────────────────

function AuthKeyManager({
  feed,
  onKeySaved,
}: {
  feed: FeedConfig;
  onKeySaved: () => void;
}) {
  const [key, setKey]       = useState('');
  const [saved, setSaved]   = useState(false);
  const [hasKey, setHasKey] = useState(false);

  useEffect(() => {
    loadFeedAuthKey(feed.id).then(v => setHasKey(!!v));
  }, [feed.id]);

  async function handleSave() {
    if (!key.trim()) return;
    await saveFeedAuthKey(feed.id, key.trim());
    setHasKey(true);
    setSaved(true);
    setKey('');
    setTimeout(() => setSaved(false), 2000);
    onKeySaved();
  }

  async function handleRemove() {
    await deleteFeedAuthKey(feed.id);
    setHasKey(false);
    setKey('');
    onKeySaved();
  }

  const authLabel = feed.auth?.type === 'header'
    ? (feed.auth.headerName ?? 'Authorization')
    : feed.auth?.type === 'queryparam'
    ? `?${feed.auth.paramName ?? 'apikey'}=...`
    : 'API Key';

  return (
    <div className="feed-auth-manager">
      <div className="feed-auth-manager-label">
        {hasKey ? `✓ Key stored (${authLabel})` : `Enter API key for ${authLabel}`}
      </div>
      <div className="feed-auth-manager-row">
        <input
          className="feed-input feed-input-secret feed-input-sm"
          type="password"
          value={key}
          placeholder={hasKey ? '••••••••  (replace)' : 'Paste key…'}
          onChange={e => setKey(e.target.value)}
          autoComplete="new-password"
        />
        <button className="feed-btn feed-btn-primary feed-btn-sm" disabled={!key.trim()} onClick={() => void handleSave()}>
          {saved ? 'Saved ✓' : 'Save'}
        </button>
        {hasKey && (
          <button className="feed-btn feed-btn-danger feed-btn-sm" onClick={() => void handleRemove()}>
            Remove
          </button>
        )}
      </div>
    </div>
  );
}

// ── Preview Modal ─────────────────────────────────────────────────────

function FeedPreviewModal({ feed, onClose }: { feed: FeedConfig; onClose: () => void }) {
  const [preview, setPreview] = useState<import('./feedTypes').FeedPreview | null>(null);
  const [error, setError]     = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    previewFeed(feed.url, feed.format, feed.indicatorField, feed.id, feed.auth)
      .then(r => { if (!cancelled) { setPreview(r); setLoading(false); } })
      .catch(e => { if (!cancelled) { setError(e instanceof Error ? e.message : String(e)); setLoading(false); } });
    return () => { cancelled = true; };
  }, [feed.url, feed.format, feed.indicatorField, feed.id, feed.auth]);

  return (
    <div className="overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="panel feed-modal feed-preview-modal">
        <div className="panel-header">
          <span className="panel-title">Preview — {feed.name}</span>
          <button className="panel-close" onClick={onClose}>✕</button>
        </div>
        <div className="feed-modal-body">
          {loading && <div className="feed-preview-loading">Fetching feed…</div>}
          {error && (
            <div className="feed-error-box">
              <div className="feed-error-label">Fetch / parse error</div>
              <code className="feed-error-msg">{error}</code>
            </div>
          )}
          {preview && (
            <>
              <div className="feed-preview-stats">
                <span className={`feed-type-badge feed-type-${preview.detectedType}`}>{preview.detectedType}</span>
                <span className="feed-format-badge">{preview.detectedFormat}</span>
                <strong>~{preview.estimatedCount.toLocaleString()} indicators</strong>
                <span className="feed-preview-ok">✓ Feed reachable</span>
              </div>
              {preview.sampleIndicators.length > 0 && (
                <div className="feed-preview-section">
                  <div className="feed-preview-section-label">Sample Indicators ({preview.sampleIndicators.length})</div>
                  <div className="feed-preview-samples">
                    {preview.sampleIndicators.map((ind, i) => (
                      <div key={i} className="feed-preview-sample">{ind}</div>
                    ))}
                  </div>
                </div>
              )}
              {preview.rows.length > 0 && (
                <div className="feed-preview-section">
                  <div className="feed-preview-section-label">Raw Content (first {preview.rows.length} lines)</div>
                  <pre className="feed-preview-raw">{preview.rows.join('\n')}</pre>
                </div>
              )}
            </>
          )}
        </div>
        <div className="feed-modal-footer">
          <button className="feed-btn" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

// ── Local Indicators Modal ────────────────────────────────────────────

function LocalLookupModal({ feed, onClose }: { feed: FeedConfig; onClose: () => void }) {
  const [indicators, setIndicators] = useState<string[]>([]);
  const [loading, setLoading]       = useState(true);
  const [search, setSearch]         = useState('');

  useEffect(() => {
    loadFeedIndicators(feed.id).then(inds => {
      setIndicators(inds);
      setLoading(false);
    });
  }, [feed.id]);

  const filtered = search.trim()
    ? indicators.filter(i => i.includes(search.toLowerCase()))
    : indicators;

  return (
    <div className="overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="panel feed-modal feed-preview-modal">
        <div className="panel-header">
          <span className="panel-title">Local KV — {feed.name}</span>
          <button className="panel-close" onClick={onClose}>✕</button>
        </div>
        <div className="feed-modal-body">
          {loading && <div className="feed-preview-loading">Loading…</div>}
          {!loading && (
            <>
              <div className="feed-preview-stats">
                <strong>{indicators.length.toLocaleString()} indicators stored</strong>
                {feed.lastSyncTruncated && (
                  <span style={{ color: 'var(--warn)', fontSize: 11 }}>⚠ Capped at 50,000</span>
                )}
              </div>
              <input
                className="feed-input"
                placeholder="Filter…"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
              <div className="feed-preview-samples">
                {filtered.slice(0, 200).map((ind, i) => (
                  <div key={i} className="feed-preview-sample">{ind}</div>
                ))}
                {filtered.length > 200 && (
                  <div style={{ color: 'var(--text2)', fontSize: 11, padding: '4px 0' }}>
                    …and {(filtered.length - 200).toLocaleString()} more
                  </div>
                )}
              </div>
            </>
          )}
        </div>
        <div className="feed-modal-footer">
          <button className="feed-btn" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

// ── Feed Card ─────────────────────────────────────────────────────────

function StatusLine({ status, stale, feed }: { status: FeedStatus; stale: boolean; feed: FeedConfig }) {
  if (status === 'syncing')      return <span className="feed-status feed-status-syncing">◎ Syncing…</span>;
  if (status === 'synced')       return <span className={`feed-status ${stale ? 'feed-status-warn' : 'feed-status-ok'}`}>● {feed.lastSyncCount?.toLocaleString() ?? 0} indicators · {relativeTime(feed.lastSync)}{stale ? ' (stale)' : ''}</span>;
  if (status === 'never_synced') return <span className="feed-status feed-status-idle">○ Never synced</span>;
  if (status === 'fetch_failed') return <span className="feed-status feed-status-err" title={feed.lastSyncError ?? ''}>✕ Fetch failed — {feed.lastSyncError ?? ''}</span>;
  return <span className="feed-status feed-status-warn">⚠ Parse failed</span>;
}

function FeedCard({
  feed, syncing, onSync, onLookup, onEdit, onPreview, onDelete, onToggle, onFeedUpdate,
}: {
  feed: FeedConfig;
  syncing: boolean;
  onSync: () => void;
  onLookup: () => void;
  onEdit: () => void;
  onPreview: () => void;
  onDelete: () => void;
  onToggle: (v: boolean) => void;
  onFeedUpdate: (f: FeedConfig) => void;
}) {
  const status = deriveFeedStatus(feed, syncing);
  const stale = isStale(feed);
  const hasLocalData = (feed.lastSyncCount ?? 0) > 0 && status !== 'fetch_failed' && status !== 'never_synced';
  const showAuthBanner = feed.needsAuth && (!feed.auth || feed.auth.type === 'none');
  const hasAuthConfigured = feed.auth && feed.auth.type !== 'none';
  const [showKeyManager, setShowKeyManager] = useState(false);

  return (
    <div className={`feed-card ${!feed.enabled ? 'feed-card-disabled' : ''}`}>
      <div className="feed-card-header">
        <span className="feed-card-name">{feed.name}</span>
        <button
          className={`feed-toggle ${feed.enabled ? 'feed-toggle-on' : ''}`}
          onClick={() => onToggle(!feed.enabled)}
          title={feed.enabled ? 'Disable' : 'Enable'}
        >
          <span className="feed-toggle-thumb" />
        </button>
      </div>
      <div className="feed-card-badges">
        <span className={`feed-type-badge feed-type-${feed.indicatorType}`}>{feed.indicatorType}</span>
        <span className="feed-format-badge">{feed.format}</span>
        <span className="feed-trust-badge">Trust {feed.trustScore}</span>
        {hasAuthConfigured && (
          <span className="feed-auth-badge" title={`Auth: ${feed.auth!.type}`}>🔑 {feed.auth!.type}</span>
        )}
        {feed.tags.slice(0, 1).map(t => (
          <span key={t} className="feed-tag">{t}</span>
        ))}
      </div>
      <StatusLine status={status} stale={stale} feed={feed} />

      {showAuthBanner && (
        <div className="feed-needs-auth-banner">
          <span>🔒 401/403 — this feed may require an API key.</span>
          <button className="feed-btn feed-btn-sm" onClick={() => onEdit()}>Configure Auth</button>
        </div>
      )}

      {hasAuthConfigured && (
        <div className="feed-auth-configured">
          <button
            className="feed-btn feed-btn-sm feed-btn-secondary"
            onClick={() => setShowKeyManager(v => !v)}
          >
            {showKeyManager ? 'Hide Key' : 'Manage Key'}
          </button>
        </div>
      )}

      {hasAuthConfigured && showKeyManager && (
        <AuthKeyManager
          feed={feed}
          onKeySaved={() => {
            // Refresh needsAuth flag — after key saved, clear the banner
            const updated: FeedConfig = { ...feed, needsAuth: false };
            onFeedUpdate(updated);
            void saveFeed(updated);
          }}
        />
      )}

      <div className="feed-card-url" title={feed.url}>{feed.url}</div>
      <div className="feed-card-actions">
        <button className="feed-btn feed-btn-primary feed-btn-sm" disabled={syncing} onClick={onSync}>
          {syncing ? 'Syncing…' : 'Sync Now'}
        </button>
        <button className="feed-btn feed-btn-sm" onClick={onEdit}>Edit</button>
        <button className="feed-btn feed-btn-sm" onClick={onPreview}>Preview</button>
        <button className="feed-btn feed-btn-sm" disabled={!hasLocalData}
          title={!hasLocalData ? 'Sync first' : 'View local KV indicators'} onClick={onLookup}>
          Indicators
        </button>
        <button className="feed-btn feed-btn-sm feed-btn-danger" onClick={onDelete}
          style={{ marginLeft: 'auto' }}>Delete</button>
      </div>
    </div>
  );
}

// ── Feed Library ──────────────────────────────────────────────────────

function FeedLibraryView({
  existingFeeds,
  onAdd,
  onDone,
}: {
  existingFeeds: FeedConfig[];
  onAdd: (feed: CuratedFeed) => void;
  onDone: () => void;
}) {
  const existingUrls = new Set(existingFeeds.map(f => f.url));

  return (
    <div className="feed-library">
      <div className="feed-library-header">
        <span className="feed-library-title">Feed Library</span>
        <button className="feed-btn" onClick={onDone}>← Back to My Feeds</button>
      </div>
      {CURATED_CATEGORIES.map((cat, catIdx) => {
        const feeds = CURATED_FEEDS.filter(f => f.category === cat);
        return (
          <div key={cat} className={catIdx > 0 ? 'feed-lib-cat-section' : ''}>
            <div className="feed-lib-cat-label">{cat}</div>
            <div className="feed-lib-grid">
              {feeds.map(feed => {
                const added = existingUrls.has(feed.url);
                const requiresAuth = !!feed.auth && feed.auth.type !== 'none';
                return (
                  <div key={feed.id} className="feed-lib-card">
                    <div className="feed-lib-card-name">
                      {feed.name}
                      {requiresAuth && <span className="feed-lib-lock-badge" title="Requires API key">🔒</span>}
                    </div>
                    <div className="feed-lib-card-source">{feed.source}</div>
                    <div className="feed-lib-card-desc">{feed.description}</div>
                    {requiresAuth && (
                      <div className="feed-lib-auth-note">
                        Requires API key ({feed.auth!.type === 'header' ? feed.auth!.headerName ?? 'Authorization' : feed.auth!.paramName ?? 'apikey'})
                      </div>
                    )}
                    <div className="feed-card-badges">
                      <span className={`feed-type-badge feed-type-${feed.indicatorType}`}>{feed.indicatorType}</span>
                      <span className="feed-format-badge">{feed.updateFrequency}</span>
                      <span className="feed-trust-badge">Trust {feed.trustScore}</span>
                    </div>
                    <div className="feed-lib-card-footer">
                      {added ? (
                        <span className="feed-lib-added">✓ Added</span>
                      ) : (
                        <button className="feed-btn feed-btn-primary feed-btn-sm"
                          onClick={() => onAdd(feed)}>
                          Add Feed
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Main ThreatFeeds Panel ────────────────────────────────────────────

export default function ThreatFeeds({ onClose }: { onClose: () => void }) {
  const [feeds, setFeeds]           = useState<FeedConfig[]>([]);
  const [loading, setLoading]       = useState(true);
  const [syncingIds, setSyncingIds] = useState<Set<string>>(new Set());
  const [view, setView]             = useState<'feeds' | 'library' | 'publish'>('feeds');
  const [addModal, setAddModal]     = useState<{ existing?: FeedConfig; prefill?: Partial<CuratedFeed> } | null>(null);
  const [previewFeedObj, setPreviewFeedObj] = useState<FeedConfig | null>(null);
  const [lookupFeed, setLookupFeed] = useState<FeedConfig | null>(null);

  useEffect(() => {
    loadFeeds().then(f => { setFeeds(f); setLoading(false); });
  }, []);

  async function handleSync(feed: FeedConfig) {
    setSyncingIds(s => new Set(s).add(feed.id));
    const { feed: updated } = await syncFeed(feed);
    setFeeds(prev => prev.map(f => f.id === updated.id ? updated : f));
    setSyncingIds(s => { const next = new Set(s); next.delete(feed.id); return next; });
  }

  async function handleSave(
    partial: Omit<FeedConfig, 'id' | 'addedAt' | 'lastSync' | 'lastSyncCount' | 'lastSyncError'>,
    secretKey?: string,
  ) {
    if (addModal?.existing) {
      const updated: FeedConfig = { ...addModal.existing, ...partial };
      // Attach kvKey to auth referencing this feed's own id
      if (updated.auth && updated.auth.type !== 'none') {
        updated.auth = { ...updated.auth, kvKey: updated.id };
      }
      await saveFeed(updated);
      if (secretKey && updated.auth && updated.auth.type !== 'none') {
        await saveFeedAuthKey(updated.id, secretKey);
      }
      setFeeds(prev => prev.map(f => f.id === updated.id ? updated : f));
    } else {
      const newFeed = makeFeedConfig(partial);
      // Attach kvKey referencing the new feed id
      if (newFeed.auth && newFeed.auth.type !== 'none') {
        newFeed.auth = { ...newFeed.auth, kvKey: newFeed.id };
      }
      await saveFeed(newFeed);
      if (secretKey && newFeed.auth && newFeed.auth.type !== 'none') {
        await saveFeedAuthKey(newFeed.id, secretKey);
      }
      setFeeds(prev => [...prev, newFeed]);
    }
    setAddModal(null);
  }

  async function handleDelete(feedId: string) {
    await deleteFeed(feedId);
    await deleteFeedAuthKey(feedId);
    setFeeds(prev => prev.filter(f => f.id !== feedId));
  }

  async function handleToggle(feed: FeedConfig, enabled: boolean) {
    const updated: FeedConfig = { ...feed, enabled };
    await saveFeed(updated);
    setFeeds(prev => prev.map(f => f.id === updated.id ? updated : f));
  }

  function handleAddCurated(curated: CuratedFeed) {
    setView('feeds');
    setAddModal({
      prefill: {
        name:           curated.name,
        url:            curated.url,
        format:         curated.format,
        indicatorType:  curated.indicatorType,
        indicatorField: curated.indicatorField,
        trustScore:     curated.trustScore,
        auth:           curated.auth,
      },
    });
  }

  return (
    <div className="overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="panel feeds-panel">
        <div className="panel-header">
          <span className="panel-title">Threat Feeds</span>
          <button className="panel-close" onClick={onClose}>✕</button>
        </div>

        {view === 'feeds' && (
          <>
            <div className="feeds-toolbar">
              <button className="feed-btn feed-btn-primary feed-btn-sm"
                onClick={() => setAddModal({})}>
                + Add Custom Feed
              </button>
              <button className="feed-btn feed-btn-sm"
                onClick={() => setView('library')}>
                Feed Library
              </button>
              {feeds.some(f => f.lastSyncCount && f.lastSyncCount > 0) && (
                <button className="feed-btn feed-btn-sm feed-btn-publish"
                  onClick={() => setView('publish')}>
                  ↓ Export Lookup
                </button>
              )}
            </div>

            <div className="feeds-body">
              {loading && <div className="feeds-empty">Loading feeds…</div>}
              {!loading && feeds.length === 0 && (
                <div className="feeds-empty">
                  <div className="feeds-empty-icon">◎</div>
                  <div className="feeds-empty-title">No feeds configured</div>
                  <div className="feeds-empty-sub">
                    Browse the Feed Library to add curated feeds, or add a custom feed URL.
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                    <button className="feed-btn feed-btn-primary" onClick={() => setView('library')}>
                      Browse Feed Library
                    </button>
                    <button className="feed-btn" onClick={() => setAddModal({})}>
                      Add Custom Feed
                    </button>
                  </div>
                </div>
              )}
              {!loading && feeds.length > 0 && (
                <div className="feed-grid">
                  {feeds.map(feed => (
                    <FeedCard
                      key={feed.id}
                      feed={feed}
                      syncing={syncingIds.has(feed.id)}
                      onSync={() => void handleSync(feed)}
                      onLookup={() => setLookupFeed(feed)}
                      onEdit={() => setAddModal({ existing: feed })}
                      onPreview={() => setPreviewFeedObj(feed)}
                      onDelete={() => void handleDelete(feed.id)}
                      onToggle={v => void handleToggle(feed, v)}
                      onFeedUpdate={updated => setFeeds(prev => prev.map(f => f.id === updated.id ? updated : f))}
                    />
                  ))}
                </div>
              )}
            </div>
          </>
        )}

        {view === 'library' && (
          <div className="feeds-body feeds-body-scroll">
            <FeedLibraryView
              existingFeeds={feeds}
              onAdd={handleAddCurated}
              onDone={() => setView('feeds')}
            />
          </div>
        )}

        {view === 'publish' && (
          <div className="feeds-body feeds-body-scroll">
            <div className="feeds-toolbar">
              <button className="feed-btn feed-btn-sm" onClick={() => setView('feeds')}>← Back to My Feeds</button>
            </div>
            <PublishView feeds={feeds} />
          </div>
        )}
      </div>

      {addModal !== null && (
        <AddFeedModal
          existing={addModal.existing}
          prefill={addModal.prefill}
          onSave={(partial, secretKey) => void handleSave(partial, secretKey)}
          onCancel={() => setAddModal(null)}
        />
      )}
      {previewFeedObj && (
        <FeedPreviewModal feed={previewFeedObj} onClose={() => setPreviewFeedObj(null)} />
      )}
      {lookupFeed && (
        <LocalLookupModal feed={lookupFeed} onClose={() => setLookupFeed(null)} />
      )}
    </div>
  );
}

// ── Feed Match Result Panel ───────────────────────────────────────────

export function FeedMatchPanel({ matches }: { matches: import('./feedTypes').FeedMatch[] }) {
  if (matches.length === 0) return null;

  return (
    <div className="result-panel">
      <div className="result-panel-title">
        <span style={{ color: 'var(--warn)' }}>⚠</span> Threat Feed Matches
      </div>
      <div className="feed-match-list">
        {matches.map(m => (
          <div key={m.feedId} className="feed-match-row">
            <span className="feed-match-name">{m.feedName}</span>
            <span className={`feed-type-badge feed-type-${m.indicatorType}`}>{m.indicatorType}</span>
            <span className="feed-trust-badge">Trust {m.trustScore}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
