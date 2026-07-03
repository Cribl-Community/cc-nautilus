import { useState, useRef, useEffect, useCallback } from 'react';
import type { ProviderKey, RoutingPrefs, ArtifactType } from './types';
import { detectArtifact } from './detect';
import { getActiveKey } from './storage';
import { fetchProvider, buildPanels } from './App';
import type { FeedConfig } from './feedTypes';
import { loadFeeds, checkFeedMatches } from './feedService';

// Providers to run in bulk mode
const BULK_PROVIDERS = ['virustotal', 'abuseipdb', 'greynoise', 'internetdb', 'urlhaus', 'threatfox', 'malwarebazaar'];
const CONCURRENCY = 3;
const BATCH_DELAY_MS = 400;

type RowStatus = 'pending' | 'running' | 'done' | 'error';
type VerdictValue = 'malicious' | 'suspicious' | 'clean' | 'unknown';

interface ProviderSignal {
  source: string;
  verdict: VerdictValue;
}

interface BulkRow {
  id: number;
  indicator: string;
  artifactType: ArtifactType;
  status: RowStatus;
  // Consensus: every provider that returned a verdict
  consensus: ProviderSignal[];
  // Worst-case verdict (for row coloring/sorting)
  worstVerdict: VerdictValue;
  // VT engine ratio (hashes / URLs / files)
  vtScore: string;
  // Feed threat intel hits
  feedHits: string[];
  // Type-specific details — rendered differently per artifactType
  details: BulkDetails;
  error?: string;
}

interface BulkDetails {
  // IP
  asnOrg?: string;
  country?: string;
  // Hash / file
  malwareFamily?: string;
  fileType?: string;
  firstSeen?: string;
  // Domain / URL
  categories?: string[];
  // Shared
  tags?: string[];
}

interface BulkSearchProps {
  onSingleSearch: (q: string) => void;
  keys: Record<string, ProviderKey>;
  prefs: RoutingPrefs;
  initialIndicators?: string[];
}

// ── Helpers ─────────────────────────────────────────────────────────

function normaliseVerdict(raw: string): VerdictValue {
  const v = raw.toLowerCase();
  if (v.includes('malicious') || v.includes('blacklisted')) return 'malicious';
  if (v.includes('suspicious')) return 'suspicious';
  if (v.includes('clean') || v.includes('benign') || v.includes('harmless')) return 'clean';
  return 'unknown';
}

function worstOf(signals: ProviderSignal[]): VerdictValue {
  const order: VerdictValue[] = ['malicious', 'suspicious', 'clean', 'unknown'];
  for (const v of order) {
    if (signals.some(s => s.verdict === v)) return v;
  }
  return 'unknown';
}

function verdictColor(v: VerdictValue): string {
  return ({
    malicious: 'var(--danger)',
    suspicious: 'var(--warn)',
    clean: 'var(--success)',
    unknown: 'var(--text2)',
  })[v];
}

function rowClass(v: VerdictValue): string {
  if (v === 'malicious') return 'bulk-row-malicious';
  if (v === 'suspicious') return 'bulk-row-suspicious';
  return '';
}

// ── Pivot links ──────────────────────────────────────────────────────

interface PivotLink { label: string; url: (ioc: string) => string; }

const PIVOT_LINKS: Partial<Record<ArtifactType, PivotLink[]>> = {
  ip: [
    { label: 'Shodan',     url: ioc => `https://www.shodan.io/host/${ioc}` },
    { label: 'Censys',     url: ioc => `https://search.censys.io/hosts/${ioc}` },
    { label: 'GreyNoise',  url: ioc => `https://viz.greynoise.io/ip/${ioc}` },
    { label: 'AbuseIPDB',  url: ioc => `https://www.abuseipdb.com/check/${ioc}` },
    { label: 'BGP.he.net', url: ioc => `https://bgp.he.net/ip/${ioc}` },
    { label: 'IPInfo',     url: ioc => `https://ipinfo.io/${ioc}` },
  ],
  domain: [
    { label: 'VirusTotal',     url: ioc => `https://www.virustotal.com/gui/domain/${ioc}` },
    { label: 'URLScan',        url: ioc => `https://urlscan.io/search/#domain:${ioc}` },
    { label: 'SecurityTrails', url: ioc => `https://securitytrails.com/domain/${ioc}/dns` },
    { label: 'Censys',         url: ioc => `https://search.censys.io/search?resource=hosts&q=${ioc}` },
    { label: 'Shodan',         url: ioc => `https://www.shodan.io/search?query=${ioc}` },
  ],
  url: [
    { label: 'URLScan',    url: ioc => `https://urlscan.io/search/#page.url:${encodeURIComponent(ioc)}` },
    { label: 'VirusTotal', url: ioc => `https://www.virustotal.com/gui/url/${btoa(ioc).replace(/=/g, '')}` },
    { label: 'URLhaus',    url: ioc => `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(ioc)}` },
  ],
  hash: [
    { label: 'VirusTotal',      url: ioc => `https://www.virustotal.com/gui/file/${ioc}` },
    { label: 'MalwareBazaar',   url: ioc => `https://bazaar.abuse.ch/sample/${ioc}` },
    { label: 'Hybrid Analysis', url: ioc => `https://www.hybrid-analysis.com/search?query=${ioc}` },
    { label: 'Any.run',         url: ioc => `https://any.run/malware-trends/?search=${ioc}` },
    { label: 'Intezer',         url: ioc => `https://analyze.intezer.com/search?q=${ioc}` },
  ],
  cve: [
    { label: 'NVD',        url: ioc => `https://nvd.nist.gov/vuln/detail/${ioc}` },
    { label: 'Exploit-DB', url: ioc => `https://www.exploit-db.com/search?cve=${ioc.replace('CVE-', '')}` },
    { label: 'Shodan',     url: ioc => `https://www.shodan.io/search?query=vuln:${ioc}` },
  ],
};

function PivotPopover({ row, onClose }: { row: BulkRow; onClose: () => void }) {
  const links = PIVOT_LINKS[row.artifactType] ?? [];
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [onClose]);

  if (links.length === 0) return null;

  return (
    <div className="pivot-popover" ref={ref}>
      <div className="pivot-popover-header">
        <span className="pivot-popover-ioc" title={row.indicator}>
          {row.indicator.length > 32 ? row.indicator.slice(0, 30) + '…' : row.indicator}
        </span>
        <button className="pivot-popover-close" onClick={onClose}>✕</button>
      </div>
      <div className="pivot-popover-links">
        {links.map(l => (
          <a
            key={l.label}
            className="pivot-link"
            href={l.url(row.indicator)}
            target="_blank"
            rel="noopener noreferrer"
          >
            {l.label} ↗
          </a>
        ))}
      </div>
    </div>
  );
}

// ── Consensus pill ───────────────────────────────────────────────────

function ConsensusPill({ signals }: { signals: ProviderSignal[] }) {
  const withVerdict = signals.filter(s => s.verdict !== 'unknown');
  const flagged = signals.filter(s => s.verdict === 'malicious' || s.verdict === 'suspicious');
  const worst = worstOf(signals);

  const tooltip = signals.length === 0
    ? 'No results yet'
    : signals.map(s => `${s.source}: ${s.verdict}`).join('\n');

  if (signals.length === 0) return null;

  return (
    <span
      className="bulk-consensus-pill"
      title={tooltip}
      style={{ color: verdictColor(worst), borderColor: verdictColor(worst) }}
    >
      <span className="bulk-consensus-flagged">{flagged.length}</span>
      <span className="bulk-consensus-sep">/</span>
      <span className="bulk-consensus-total">{withVerdict.length}</span>
    </span>
  );
}

// ── Adaptive details cell ────────────────────────────────────────────

function DetailsCell({ row }: { row: BulkRow }) {
  const { artifactType, details } = row;

  if (artifactType === 'ip') {
    const parts = [details.asnOrg, details.country].filter(Boolean).join(' · ');
    return (
      <span className="bulk-detail-text" title={parts}>{parts.slice(0, 35)}{parts.length > 35 ? '…' : ''}</span>
    );
  }

  if (artifactType === 'hash') {
    const family = details.malwareFamily ?? '';
    const ftype = details.fileType ? `[${details.fileType}]` : '';
    const parts = [family, ftype].filter(Boolean).join(' ');
    return (
      <span className="bulk-detail-text" title={parts}>{parts.slice(0, 35)}{parts.length > 35 ? '…' : ''}</span>
    );
  }

  if (artifactType === 'domain' || artifactType === 'url') {
    const cats = (details.categories ?? []).slice(0, 2).join(', ');
    const tags = (details.tags ?? []).slice(0, 2).join(', ');
    const parts = [cats, tags].filter(Boolean).join(' · ');
    return (
      <span className="bulk-detail-text" title={parts}>{parts.slice(0, 35)}{parts.length > 35 ? '…' : ''}</span>
    );
  }

  // CVE / file / fallback — show tags
  const tags = (details.tags ?? []).slice(0, 3).join(', ');
  return <span className="bulk-detail-text" title={tags}>{tags.slice(0, 35)}{tags.length > 35 ? '…' : ''}</span>;
}

// ── CSV helpers ──────────────────────────────────────────────────────

function buildCommonRow(r: BulkRow, i: number): string[] {
  const flagged = r.consensus.filter(s => s.verdict === 'malicious' || s.verdict === 'suspicious').length;
  const withVerdict = r.consensus.filter(s => s.verdict !== 'unknown').length;
  const consensusSummary = r.consensus.length > 0 ? `${flagged}/${withVerdict}` : '';
  const consensusDetail = r.consensus.map(s => `${s.source}:${s.verdict}`).join('; ');
  return [String(i + 1), r.indicator, r.artifactType, consensusSummary, consensusDetail, r.vtScore, r.feedHits.join('; ')];
}

function buildCsv(exportRows: BulkRow[], type: ArtifactType | 'all'): string {
  let headers: string[];
  let getRow: (r: BulkRow, i: number) => string[];

  if (type === 'ip') {
    headers = ['#', 'Indicator', 'Consensus', 'Consensus Detail', 'VT Score', 'Feed Hits', 'ASN/Org', 'Country', 'Status'];
    getRow = (r, i) => [...buildCommonRow(r, i).slice(0, 7), r.details.asnOrg ?? '', r.details.country ?? '', r.status];
  } else if (type === 'hash') {
    headers = ['#', 'Indicator', 'Consensus', 'Consensus Detail', 'VT Score', 'Feed Hits', 'Malware Family', 'File Type', 'First Seen', 'Status'];
    getRow = (r, i) => [...buildCommonRow(r, i).slice(0, 7), r.details.malwareFamily ?? '', r.details.fileType ?? '', r.details.firstSeen ?? '', r.status];
  } else if (type === 'domain' || type === 'url') {
    headers = ['#', 'Indicator', 'Type', 'Consensus', 'Consensus Detail', 'VT Score', 'Feed Hits', 'Categories', 'Tags', 'Status'];
    getRow = (r, i) => [...buildCommonRow(r, i), (r.details.categories ?? []).join('; '), (r.details.tags ?? []).join('; '), r.status];
  } else {
    // 'all' or any other type — shared columns + adaptive Details string
    headers = ['#', 'Indicator', 'Type', 'Consensus', 'Consensus Detail', 'VT Score', 'Feed Hits', 'Details', 'Status'];
    getRow = (r, i) => {
      let detail: string;
      if (r.artifactType === 'ip') detail = [r.details.asnOrg, r.details.country].filter(Boolean).join(' · ');
      else if (r.artifactType === 'hash') detail = [r.details.malwareFamily, r.details.fileType].filter(Boolean).join(' · ');
      else detail = [...(r.details.categories ?? []), ...(r.details.tags ?? [])].join('; ');
      return [...buildCommonRow(r, i), detail, r.status];
    };
  }

  const body = exportRows.map((r, i) => getRow(r, i));
  return [headers, ...body]
    .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    .join('\r\n');
}

function downloadCsv(csv: string, filename: string) {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Component ────────────────────────────────────────────────────────

export default function BulkSearch({ onSingleSearch, keys, initialIndicators }: BulkSearchProps) {
  const [inputText, setInputText] = useState(initialIndicators?.join('\n') ?? '');
  const [rows, setRows] = useState<BulkRow[]>([]);
  const [running, setRunning] = useState(false);
  const [paused, setPaused] = useState(false);
  const [done, setDone] = useState(0);
  const [total, setTotal] = useState(0);
  const [started, setStarted] = useState(false);
  const [pivotRowId, setPivotRowId] = useState<number | null>(null);
  const pausedRef = useRef(false);
  const stopRef = useRef(false);
  const feedsRef = useRef<FeedConfig[]>([]);

  useEffect(() => {
    loadFeeds().then(f => { feedsRef.current = f; });
  }, []);

  const [prevInitialIndicators, setPrevInitialIndicators] = useState(initialIndicators);
  if (initialIndicators !== prevInitialIndicators) {
    setPrevInitialIndicators(initialIndicators);
    if (initialIndicators && initialIndicators.length > 0) {
      setInputText(initialIndicators.join('\n'));
    }
  }

  function parseIndicators(): string[] {
    const seen = new Set<string>();
    return inputText
      .split(/\r?\n/)
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'))
      .filter(l => { if (seen.has(l)) return false; seen.add(l); return true; });
  }

  async function sleep(ms: number): Promise<void> {
    return new Promise(res => setTimeout(res, ms));
  }

  function updateRow(id: number, patch: Partial<BulkRow>) {
    setRows(prev => prev.map(r => r.id === id ? { ...r, ...patch } : r));
  }

  async function processIndicator(row: BulkRow): Promise<void> {
    updateRow(row.id, { status: 'running' });
    try {
      const { artifactType } = row;

      const activeProviders = BULK_PROVIDERS.filter(pid => {
        const needsKey = ['virustotal', 'abuseipdb', 'malwarebazaar', 'threatfox'].includes(pid);
        if (needsKey && !getActiveKey(keys, pid)) return false;
        const supportMap: Record<string, ArtifactType[]> = {
          virustotal:    ['ip', 'domain', 'url', 'hash'],
          abuseipdb:     ['ip'],
          greynoise:     ['ip'],
          internetdb:    ['ip'],
          urlhaus:       ['url', 'domain', 'ip'],
          threatfox:     ['ip', 'domain', 'url', 'hash'],
          malwarebazaar: ['hash'],
        };
        return (supportMap[pid] ?? []).includes(artifactType);
      });

      const results = [];
      for (let i = 0; i < activeProviders.length; i++) {
        if (stopRef.current) break;
        if (i > 0) await sleep(BATCH_DELAY_MS);
        const r = await fetchProvider(
          activeProviders[i],
          row.indicator,
          artifactType,
          getActiveKey(keys, activeProviders[i]),
        );
        results.push(r);
      }

      const panels = buildPanels(results, artifactType);

      // Build consensus: one signal per unique source
      const seenSources = new Map<string, VerdictValue>();
      for (const mv of panels.reputation.verdict) {
        const v = normaliseVerdict(mv.value);
        // Keep worst if same source appears multiple times
        const existing = seenSources.get(mv.source);
        if (!existing || worstOf([{ source: mv.source, verdict: existing }, { source: mv.source, verdict: v }]) === v) {
          seenSources.set(mv.source, v);
        }
      }
      const consensus: ProviderSignal[] = [...seenSources.entries()].map(([source, verdict]) => ({ source, verdict }));
      const worstVerdict = worstOf(consensus);

      // VT score
      let vtScore = '';
      if (panels.detection) {
        const { malicious, suspicious, totalEngines } = panels.detection;
        vtScore = `${malicious + suspicious}/${totalEngines}`;
      }

      // Type-specific details
      const details: BulkDetails = {};
      if (artifactType === 'ip') {
        details.asnOrg = panels.geo.org[0]?.value ?? panels.geo.asn[0]?.value ?? '';
        details.country = panels.geo.country[0]?.value ?? '';
      } else if (artifactType === 'hash') {
        details.malwareFamily = panels.reputation.malwareFamily[0]?.value ?? '';
        details.fileType = panels.file.type[0]?.value ?? '';
        details.firstSeen = panels.file.firstSeen[0]?.value ?? '';
      } else {
        details.categories = panels.reputation.categories.map(c => c.value);
        details.tags = panels.reputation.tags.map(t => t.value);
      }

      // Feed hits
      let feedHits: string[] = [];
      if (feedsRef.current.length > 0) {
        const matches = await checkFeedMatches(row.indicator, feedsRef.current);
        feedHits = matches.map(m => m.feedName);
      }

      updateRow(row.id, { status: 'done', consensus, worstVerdict, vtScore, feedHits, details });
    } catch (e) {
      updateRow(row.id, { status: 'error', error: e instanceof Error ? e.message : 'Error' });
    }
    setDone(prev => prev + 1);
  }

  async function startSearch() {
    const indicators = parseIndicators();
    if (!indicators.length) return;

    stopRef.current = false;
    pausedRef.current = false;
    setPaused(false);

    const initialRows: BulkRow[] = indicators.map((ind, i) => ({
      id: i,
      indicator: ind,
      artifactType: detectArtifact(ind),
      status: 'pending',
      consensus: [],
      worstVerdict: 'unknown',
      vtScore: '',
      feedHits: [],
      details: {},
    }));
    setRows(initialRows);
    setTotal(indicators.length);
    setDone(0);
    setRunning(true);
    setStarted(true);

    const queue = [...initialRows];
    let active = 0;
    let queueIdx = 0;

    await new Promise<void>(resolve => {
      function next() {
        while (active < CONCURRENCY && queueIdx < queue.length) {
          if (pausedRef.current) break;
          if (stopRef.current) break;
          const row = queue[queueIdx++];
          active++;
          processIndicator(row).finally(() => {
            active--;
            if (active === 0 && queueIdx >= queue.length) {
              resolve();
            } else {
              next();
            }
          });
        }
      }

      const pollInterval = setInterval(() => {
        if (stopRef.current) { clearInterval(pollInterval); resolve(); return; }
        if (!pausedRef.current) next();
      }, 500);

      next();
      if (active === 0) { clearInterval(pollInterval); resolve(); }
    });

    setRunning(false);
    setPaused(false);
  }

  function handlePauseResume() {
    if (paused) {
      pausedRef.current = false;
      setPaused(false);
    } else {
      pausedRef.current = true;
      setPaused(true);
    }
  }

  function handleStop() {
    stopRef.current = true;
    setPaused(false);
    setRunning(false);
  }

  const exportAll = useCallback(() => {
    const date = new Date().toISOString().slice(0, 10);
    downloadCsv(buildCsv(rows, 'all'), `nautilus-bulk-${date}.csv`);
  }, [rows]);

  const exportByType = useCallback((type: ArtifactType) => {
    const date = new Date().toISOString().slice(0, 10);
    const subset = rows.filter(r => r.artifactType === type);
    downloadCsv(buildCsv(subset, type), `nautilus-bulk-${type}-${date}.csv`);
  }, [rows]);

  const exportFlagged = useCallback(() => {
    const date = new Date().toISOString().slice(0, 10);
    const subset = rows.filter(r => r.worstVerdict === 'malicious' || r.worstVerdict === 'suspicious');
    downloadCsv(buildCsv(subset, 'all'), `nautilus-bulk-flagged-${date}.csv`);
  }, [rows]);

  // Types present in completed rows (for dropdown)
  const presentTypes = [...new Set(rows.filter(r => r.status === 'done').map(r => r.artifactType))] as ArtifactType[];
  const isMixed = presentTypes.length > 1;
  const flaggedCount = rows.filter(r => r.worstVerdict === 'malicious' || r.worstVerdict === 'suspicious').length;

  return (
    <div className="bulk-inline">

      {!started && (
        <div className="bulk-input-section">
          <div className="bulk-input-label">
            Paste indicators — one per line (IPs, domains, hashes, URLs, CVEs)
          </div>
          <textarea
            className="bulk-textarea"
            value={inputText}
            onChange={e => setInputText(e.target.value)}
            placeholder="1.2.3.4&#10;evil.example.com&#10;abc123...sha256...&#10;CVE-2021-44228"
            spellCheck={false}
          />
          <div className="bulk-start-row">
            <button
              className="bulk-start-btn"
              onClick={() => void startSearch()}
              disabled={!inputText.trim()}
            >
              Start Search
            </button>
            <span className="bulk-hint">
              Queries {BULK_PROVIDERS.slice(0, 4).join(', ')} and others with keys &middot; max {CONCURRENCY} parallel
            </span>
          </div>
        </div>
      )}

      {started && (
        <>
          <div className="bulk-controls">
            <div className="bulk-progress-wrap">
              <span className="bulk-progress-label">{done} / {total} complete</span>
              <div className="bulk-progress-bar">
                <div
                  className="bulk-progress-fill"
                  style={{ width: total > 0 ? `${(done / total) * 100}%` : '0%' }}
                />
              </div>
            </div>
            <div className="bulk-control-btns">
              {running && (
                <button className="bulk-pause-btn" onClick={handlePauseResume}>
                  {paused ? 'Resume' : 'Pause'}
                </button>
              )}
              {running && (
                <button className="bulk-stop-btn" onClick={handleStop}>Stop</button>
              )}
              {!running && rows.length > 0 && (
                <>
                  {flaggedCount > 0 && (
                    <button className="bulk-export-flagged-btn" onClick={exportFlagged} title="Export only malicious and suspicious rows">
                      Export Flagged ({flaggedCount})
                    </button>
                  )}
                  {!isMixed ? (
                    <button className="bulk-export-btn" onClick={exportAll}>Export CSV</button>
                  ) : (
                    <div className="bulk-export-menu">
                      <button className="bulk-export-btn" onClick={exportAll}>Export All</button>
                      <div className="bulk-export-divider" />
                      {presentTypes.map(type => (
                        <button key={type} className="bulk-export-type-btn" onClick={() => exportByType(type)}>
                          {type.charAt(0).toUpperCase() + type.slice(1)}s only
                        </button>
                      ))}
                    </div>
                  )}
                  <button
                    className="bulk-start-btn"
                    onClick={() => { setStarted(false); setRows([]); }}
                  >
                    New Search
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="bulk-table-wrap">
            <table className="bulk-results-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Indicator</th>
                  <th>Type</th>
                  <th className="bulk-th-consensus" title="Flagged providers / providers with verdict">Consensus</th>
                  <th>VT Score</th>
                  <th>Feed Hits</th>
                  <th>Details</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, i) => (
                  <tr key={row.id} className={rowClass(row.worstVerdict)}>
                    <td className="bulk-td-num">{i + 1}</td>
                    <td className="bulk-td-indicator">
                      <button
                        className="bulk-indicator-link"
                        onClick={() => onSingleSearch(row.indicator)}
                        title="Search this indicator"
                      >
                        {row.indicator}
                      </button>
                    </td>
                    <td className="bulk-td-type">{row.artifactType !== 'unknown' ? row.artifactType : '?'}</td>
                    <td className="bulk-td-consensus">
                      <ConsensusPill signals={row.consensus} />
                    </td>
                    <td className="bulk-td-vt">{row.vtScore}</td>
                    <td className="bulk-td-feeds">
                      {row.feedHits.length > 0 && (
                        <span className="bulk-feed-badge" title={row.feedHits.join(', ')}>
                          {row.feedHits.length}
                        </span>
                      )}
                    </td>
                    <td className="bulk-td-details">
                      {row.status === 'done' && <DetailsCell row={row} />}
                    </td>
                    <td className="bulk-td-status">
                      {row.status === 'pending' && <span className="bulk-status-pending">&#x25CB;</span>}
                      {row.status === 'running' && <span className="bulk-status-running spinning">&#x25CE;</span>}
                      {row.status === 'done' && <span className="bulk-status-done">&#x2713;</span>}
                      {row.status === 'error' && <span className="bulk-status-error" title={row.error}>&#x2715;</span>}
                    </td>
                    <td className="bulk-td-pivot">
                      {row.status === 'done' && (PIVOT_LINKS[row.artifactType]?.length ?? 0) > 0 && (
                        <div className="pivot-cell">
                          <button
                            className={`pivot-btn${pivotRowId === row.id ? ' active' : ''}`}
                            onClick={() => setPivotRowId(pivotRowId === row.id ? null : row.id)}
                            title="Pivot to external tools"
                          >
                            ↗
                          </button>
                          {pivotRowId === row.id && (
                            <PivotPopover row={row} onClose={() => setPivotRowId(null)} />
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
