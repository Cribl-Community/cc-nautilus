import React, { useState, useCallback } from 'react';

import type { PanelData, MSValue, DetectionSection, CveSection, CvssDetail, TimelineEvent, MitreSection } from './panelData';
import type { FeedMatch } from './feedTypes';
import type { MitreOverlayResult } from './mitreOverlay';
import type { DetectionRule } from './detectionRules';
import { fetchRuleContent } from './detectionRules';

// ── Shared: multi-source field row ────────────────────────────────
// Shows the field label, then each unique value grouped with source tags.
// Values that multiple providers agree on show up once with multiple tags.
// Values only one provider gives show up with a single tag — outliers stand out.

function groupByValue(fields: MSValue[]): { value: string; sources: string[] }[] {
  const map = new Map<string, string[]>();
  for (const f of fields) {
    const existing = map.get(f.value);
    if (existing) { if (!existing.includes(f.source)) existing.push(f.source); }
    else map.set(f.value, [f.source]);
  }
  // Sort: most sources first (consensus at top)
  return [...map.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .map(([value, sources]) => ({ value, sources }));
}

function SourceTag({ name, consensus }: { name: string; consensus: boolean }) {
  return (
    <span className={`src-tag ${consensus ? 'src-consensus' : 'src-solo'}`}>{name}</span>
  );
}

function FieldRow({ label, fields, mono = false }: { label: string; fields: MSValue[]; mono?: boolean }) {
  if (!fields.length) return null;
  const grouped = groupByValue(fields);
  const maxSources = Math.max(...grouped.map(g => g.sources.length));

  return (
    <div className="panel-field-row">
      <span className="panel-field-label">{label}</span>
      <div className="panel-field-values">
        {grouped.map((g, i) => (
          <div key={i} className={`panel-value-group ${g.sources.length === maxSources && maxSources > 1 ? 'value-agreed' : ''}`}>
            <span className={`panel-value-text ${mono ? 'mono' : ''}`}>{g.value}</span>
            <span className="panel-source-tags">
              {g.sources.map(s => (
                <SourceTag key={s} name={s} consensus={g.sources.length > 1} />
              ))}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Panel shell ────────────────────────────────────────────────────

function Panel({ title, icon, accent, children }: {
  title: React.ReactNode;
  icon: string;
  accent: string;
  children: React.ReactNode;
}) {
  return (
    <div className="result-panel" style={{ borderLeftColor: accent }}>
      <div className="result-panel-header" style={{ '--panel-accent': accent } as React.CSSProperties}>
        <span className="result-panel-icon">{icon}</span>
        <span className="result-panel-title">{title}</span>
      </div>
      <div className="result-panel-body">
        {children}
      </div>
    </div>
  );
}

function PanelEmpty() {
  return <div className="panel-empty">No data returned by providers</div>;
}

function PanelSection({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="panel-section">
      <div className="panel-section-label">{label}</div>
      {children}
    </div>
  );
}

// ── Geo panel ─────────────────────────────────────────────────────

function GeoMap({ lat, lon, label }: { lat: number; lon: number; label: string }) {
  const zoom = 10;
  const osmUrl    = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}&zoom=${zoom}`;
  const googleUrl = `https://maps.google.com/?q=${lat},${lon}`;
  return (
    <div className="geo-map-wrap">
      <div className="geo-coords-row">
        <span className="geo-coords-pin">◎</span>
        <span className="geo-coords-label">{label}</span>
        <span className="geo-coords-value">{lat.toFixed(4)}, {lon.toFixed(4)}</span>
        <a className="geo-coords-link" href={osmUrl} target="_blank" rel="noopener noreferrer">OSM ↗</a>
        <a className="geo-coords-link" href={googleUrl} target="_blank" rel="noopener noreferrer">Maps ↗</a>
      </div>
    </div>
  );
}

export function GeoResultPanel({ geo }: { geo: PanelData['geo'] }) {
  const hasLocation = geo.country.length || geo.city.length || geo.region.length || geo.coordinates.length || geo.continent.length;
  const hasNetwork  = geo.asn.length || geo.org.length || geo.isp.length || geo.cidr.length || geo.hostnames.length;
  const hasReg      = geo.registrar.length || geo.registrantCountry.length || geo.created.length || geo.expires.length;

  const coordGroup = geo.coordinates.length ? groupByValue(geo.coordinates)[0] : null;
  const mapCoords = (() => {
    if (!coordGroup) return null;
    const [latStr, lonStr] = coordGroup.value.split(',');
    const lat = parseFloat(latStr);
    const lon = parseFloat(lonStr?.trim());
    if (isNaN(lat) || isNaN(lon)) return null;
    // Build a human-readable label: city + country if available
    const city    = geo.city[0]?.value;
    const country = geo.country[0]?.value;
    const label   = [city, country].filter(Boolean).join(', ') || coordGroup.value;
    return { lat, lon, label };
  })();

  const isEmpty = !hasLocation && !hasNetwork && !hasReg && !mapCoords;

  return (
    <Panel title="Geo & Locality" icon="◎" accent="#58a6ff">
      {isEmpty && <PanelEmpty />}
      {mapCoords && (
        <GeoMap lat={mapCoords.lat} lon={mapCoords.lon} label={mapCoords.label} />
      )}
      {hasLocation && (
        <PanelSection label="Location">
          <FieldRow label="Country"    fields={geo.country} />
          <FieldRow label="Continent"  fields={geo.continent} />
          <FieldRow label="Region"     fields={geo.region} />
          <FieldRow label="City"       fields={geo.city} />
          {coordGroup && (
            <div className="panel-field-row">
              <span className="panel-field-label">Coordinates</span>
              <div className="panel-field-values">
                <div className="panel-value-group">
                  <span className="panel-value-text mono">{coordGroup.value}</span>
                  <span className="panel-source-tags">
                    {coordGroup.sources.map(s => <SourceTag key={s} name={s} consensus={coordGroup.sources.length > 1} />)}
                  </span>
                </div>
              </div>
            </div>
          )}
        </PanelSection>
      )}
      {hasNetwork && (
        <PanelSection label="Network">
          <FieldRow label="ASN"       fields={geo.asn} mono />
          <FieldRow label="Org"       fields={geo.org} />
          <FieldRow label="ISP"       fields={geo.isp} />
          <FieldRow label="CIDR"      fields={geo.cidr} mono />
          <FieldRow label="Hostnames" fields={geo.hostnames} mono />
        </PanelSection>
      )}
      {hasReg && (
        <PanelSection label="Registration">
          <FieldRow label="Registrar"   fields={geo.registrar} />
          <FieldRow label="Registrant Country" fields={geo.registrantCountry} />
          <FieldRow label="Created"     fields={geo.created} />
          <FieldRow label="Expires"     fields={geo.expires} />
        </PanelSection>
      )}
    </Panel>
  );
}

// ── MITRE ATT&CK Software Overlay — standalone panel ─────────────────

export function MitreAttackPanel({ overlay }: { overlay: MitreOverlayResult[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  if (!overlay.length) return null;

  function toggle(id: string) {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <Panel title="ATT&CK Software Overlay" icon="🛡" accent="var(--warn)">
      {overlay.map(result => (
        <div key={result.softwareId} className="mitre-overlay-item">
          <div className="mitre-overlay-item-header" onClick={() => toggle(result.softwareId)}>
            <span className={`mitre-overlay-arrow ${expanded.has(result.softwareId) ? 'open' : ''}`}>&#x25B6;</span>
            <span className="mitre-overlay-name">{result.softwareName}</span>
            <span className="mitre-overlay-id-badge">{result.softwareId}</span>
            <span className={`mitre-overlay-type-badge mitre-overlay-type-${result.softwareType}`}>{result.softwareType}</span>
            {result.techniques.length > 0 && (
              <span className="mitre-overlay-tech-count">{result.techniques.length} technique{result.techniques.length !== 1 ? 's' : ''}</span>
            )}
          </div>
          {expanded.has(result.softwareId) && result.techniques.length > 0 && (
            <div className="mitre-overlay-techniques">
              {result.techniques.map(t => {
                const path = t.id.includes('.')
                  ? `techniques/${t.id.split('.')[0]}/${t.id.split('.')[1]}`
                  : `techniques/${t.id}`;
                return (
                  <div key={t.id} className="mitre-overlay-tech-row">
                    <a href={`https://attack.mitre.org/${path}`} target="_blank" rel="noreferrer" className="mitre-overlay-tech-id">
                      {t.id}
                    </a>
                    <span className="mitre-overlay-tech-name">{t.name}</span>
                    {t.tactic && <span className="mitre-overlay-tactic">{t.tactic}</span>}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ))}
    </Panel>
  );
}

// ── Reputation panel ───────────────────────────────────────────────

export function ReputationResultPanel({ rep, feedMatches = [] }: { rep: PanelData['reputation']; feedMatches?: FeedMatch[] }) {
  const verdictColor = (v: string) =>
    v.toLowerCase() === 'malicious' ? 'var(--danger)' :
    v.toLowerCase() === 'suspicious' ? 'var(--warn)' : 'var(--success)';

  const grouped = groupByValue(rep.verdict);

  const repEmpty = grouped.length === 0 && rep.confidence.length === 0 && rep.score.length === 0 && rep.categories.length === 0 && rep.tags.length === 0 && rep.malwareFamily.length === 0 && rep.threatLabel.length === 0;

  // Multi-feed confidence: weight by trust score, scale by feed count
  const feedScore = feedMatches.length === 0 ? null : (() => {
    const avgTrust = feedMatches.reduce((s, m) => s + m.trustScore, 0) / feedMatches.length;
    // 1 feed = 40% base weight, each additional feed adds ~15%, capped at 95%
    const countWeight = Math.min(0.4 + (feedMatches.length - 1) * 0.15, 0.95);
    return Math.round(avgTrust * countWeight);
  })();

  return (
    <Panel title="Reputation" icon="⚠" accent="#d29922">
      {repEmpty && feedMatches.length === 0 && <PanelEmpty />}

      {feedMatches.length > 0 && (
        <PanelSection label="Feed Intelligence">
          <div className="feed-intel-header">
            <span className="feed-intel-count">
              <span className="feed-intel-dot" />
              {feedMatches.length} feed{feedMatches.length > 1 ? 's' : ''} matched
            </span>
            {feedScore !== null && (
              <span className="feed-intel-score" title="Weighted confidence from matching feeds">
                Confidence {feedScore}
                <span className="feed-intel-score-bar">
                  <span className="feed-intel-score-fill" style={{
                    width: `${feedScore}%`,
                    background: feedScore >= 80 ? 'var(--danger)' : feedScore >= 50 ? 'var(--warn)' : 'var(--accent)',
                  }} />
                </span>
              </span>
            )}
          </div>
          <div className="feed-intel-list">
            {feedMatches.map(m => (
              <div key={m.feedId} className="feed-intel-row">
                <span className="feed-intel-name">{m.feedName}</span>
                <span className={`feed-type-badge feed-type-${m.indicatorType}`}>{m.indicatorType}</span>
                <span className="feed-intel-trust">T{m.trustScore}</span>
              </div>
            ))}
          </div>
        </PanelSection>
      )}

      {grouped.length > 0 && (
        <PanelSection label="Verdict">
          <div className="verdict-row">
            {grouped.map((g, i) => (
              <div key={i} className="verdict-group">
                <span className="verdict-pill" style={{ color: verdictColor(g.value), borderColor: verdictColor(g.value), background: `${verdictColor(g.value)}18` }}>
                  {g.value}
                </span>
                <span className="panel-source-tags">
                  {g.sources.map(s => <SourceTag key={s} name={s} consensus={g.sources.length > 1} />)}
                </span>
              </div>
            ))}
          </div>
        </PanelSection>
      )}
      {(rep.confidence.length > 0 || rep.score.length > 0) && (
        <PanelSection label="Confidence">
          <FieldRow label="Score"      fields={rep.score} />
          <FieldRow label="Confidence" fields={rep.confidence} />
        </PanelSection>
      )}
      {(rep.categories.length > 0 || rep.tags.length > 0 || rep.malwareFamily.length > 0 || rep.threatLabel.length > 0) && (
        <PanelSection label="Threat Context">
          <FieldRow label="Threat label"   fields={rep.threatLabel} />
          <FieldRow label="Malware family" fields={rep.malwareFamily} />
          <FieldRow label="Categories"     fields={rep.categories} />
          <FieldRow label="Tags"           fields={rep.tags} />
        </PanelSection>
      )}
    </Panel>
  );
}

// ── Threat group panels ────────────────────────────────────────────

export function ThreatGroupSummaryPanel({ rep, mitre }: { rep: PanelData['reputation']; mitre?: MitreSection | null; onSearch?: (q: string) => void }) {
  const summaries = groupByValue(rep.summary);
  const labels    = groupByValue(rep.threatLabel);
  const aliases   = groupByValue(rep.categories);
  const isEmpty   = summaries.length === 0 && labels.length === 0 && aliases.length === 0;

  const [fullDesc, setFullDesc]     = useState<string | null>(null);
  const [loadingDesc, setLoading]   = useState(false);
  const [descError, setDescError]   = useState(false);

  const stixId    = mitre?.groupStixId;
  const shortDesc = summaries[0]?.value ?? '';
  const isTruncated = stixId && shortDesc.length >= 390; // near the 400-char storage cap

  async function loadFullDesc() {
    if (!stixId) return;
    setLoading(true);
    setDescError(false);
    try {
      const base = (window as unknown as Record<string, unknown>)['CRIBL_API_URL'];
      const host = typeof base === 'string' && base
        ? 'https://attack-taxii.mitre.org'
        : '/mitre-proxy';
      const collection = 'x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019';
      const url = `${host}/api/v21/collections/${collection}/objects/?match%5Bid%5D=${encodeURIComponent(stixId)}`;
      const r = await fetch(url, { headers: { 'Accept': 'application/taxii+json;version=2.1' }, signal: AbortSignal.timeout(20000) });
      if (!r.ok) { setDescError(true); return; }
      const j = await r.json() as Record<string, unknown>;
      const objs = j.objects as Record<string, unknown>[] | undefined;
      const obj  = objs?.[0];
      if (!obj) { setDescError(true); return; }
      const desc = (obj.description as string | undefined)
        ?.replace(/\(Citation:[^)]+\)/g, '').replace(/\s{2,}/g, ' ').trim() ?? '';
      setFullDesc(desc || shortDesc);
    } catch {
      setDescError(true);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Panel title="Actor Profile" icon="◈" accent="#cf1322">
      {isEmpty && <PanelEmpty />}
      {labels.length > 0 && (
        <PanelSection label="Name">
          {labels.map((g, i) => (
            <div key={i} className="panel-value-group">
              <span className="panel-value-text">{g.value}</span>
              <span className="panel-source-tags">{g.sources.map(s => <SourceTag key={s} name={s} consensus={false} />)}</span>
            </div>
          ))}
        </PanelSection>
      )}
      {aliases.length > 0 && (
        <PanelSection label="Also known as">
          <div className="chip-grid">
            {aliases.map((g, i) => (
              <span key={i} className="tag-chip">{g.value}</span>
            ))}
          </div>
        </PanelSection>
      )}
      {summaries.length > 0 && (
        <PanelSection label="Summary">
          <p className="threat-group-summary">{fullDesc ?? shortDesc}</p>
          {isTruncated && !fullDesc && (
            <button className="desc-more-btn" onClick={loadFullDesc} disabled={loadingDesc}>
              {loadingDesc ? 'Loading…' : descError ? 'Retry' : '…more'}
            </button>
          )}
          {descError && <span className="desc-more-error">Failed to load</span>}
        </PanelSection>
      )}
    </Panel>
  );
}

const PAGE_SIZE = 10;

// Canonical ATT&CK tactic order
const TACTIC_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
];

function tacticSort(a: string, b: string): number {
  const ai = TACTIC_ORDER.indexOf(a.toLowerCase().replace(/ /g, '-'));
  const bi = TACTIC_ORDER.indexOf(b.toLowerCase().replace(/ /g, '-'));
  if (ai === -1 && bi === -1) return a.localeCompare(b);
  if (ai === -1) return 1;
  if (bi === -1) return -1;
  return ai - bi;
}

function TechniqueSubPanel({ tactics }: { tactics: [string, { id: string; name: string }[]][] }) {
  const [activeTab, setActiveTab] = useState(0);
  const [page, setPage] = useState(0);

  const [, techs] = tactics[activeTab] ?? [null, []];
  const totalPages = Math.ceil(techs.length / PAGE_SIZE);
  const slice = techs.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  function switchTab(i: number) { setActiveTab(i); setPage(0); }

  return (
    <div className="technique-subpanel">
      <div className="technique-tabs">
        {tactics.map(([t, items], i) => (
          <button
            key={t}
            className={`technique-tab${i === activeTab ? ' active' : ''}`}
            onClick={() => switchTab(i)}
            title={t}
          >
            {t} <span className="technique-tab-count">{items.length}</span>
          </button>
        ))}
      </div>
      <table className="mitre-technique-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
          </tr>
        </thead>
        <tbody>
          {slice.map(t => {
            const path = t.id.includes('.')
              ? `techniques/${t.id.split('.')[0]}/${t.id.split('.')[1]}`
              : `techniques/${t.id}`;
            return (
              <tr key={t.id}>
                <td className="mitre-technique-id">
                  <a href={`https://attack.mitre.org/${path}`} target="_blank" rel="noreferrer" className="mitre-technique-link">{t.id}</a>
                </td>
                <td className="mitre-technique-name">{t.name}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {totalPages > 1 && (
        <div className="technique-pagination">
          <button className="technique-page-btn" onClick={() => setPage(p => p - 1)} disabled={page === 0}>‹</button>
          <span className="technique-page-info">{page + 1} / {totalPages}</span>
          <button className="technique-page-btn" onClick={() => setPage(p => p + 1)} disabled={page >= totalPages - 1}>›</button>
        </div>
      )}
    </div>
  );
}

export function ThreatGroupTechniquesPanel({ mitre }: { mitre?: MitreSection | null }) {
  const tacticMap = new Map<string, { id: string; name: string }[]>();
  if (mitre) {
    for (const t of mitre.techniques) {
      const tactic = t.tactic || 'Uncategorized';
      const existing = tacticMap.get(tactic);
      if (existing) existing.push({ id: t.id, name: t.name });
      else tacticMap.set(tactic, [{ id: t.id, name: t.name }]);
    }
  }
  const tactics = [...tacticMap.entries()].sort((a, b) => tacticSort(a[0], b[0]));
  if (!tactics.length) return null;
  return (
    <Panel title={`Techniques (${mitre!.techniques.length})`} icon="⬡" accent="#388bfd">
      <TechniqueSubPanel tactics={tactics} />
    </Panel>
  );
}

export function ThreatGroupClassificationPanel({ rep, mitre }: { rep: PanelData['reputation']; mitre?: MitreSection | null }) {
  const ids     = groupByValue(rep.tags);
  const malware = groupByValue(rep.malwareFamily);

  const isEmpty = ids.length === 0 && malware.length === 0 &&
    (!mitre || (mitre.software.length === 0 && mitre.campaigns.length === 0 && mitre.mitigations.length === 0));
  if (isEmpty) return null;

  return (
    <Panel title="Classification" icon="◎" accent="#8957e5">
      {ids.length > 0 && (
        <PanelSection label="ATT&CK ID">
          <div className="chip-grid">
            {ids.map((g, i) => (
              <span key={i} className="tag-chip mono">{g.value}
                <span className="panel-source-tags">{g.sources.map(s => <SourceTag key={s} name={s} consensus={false} />)}</span>
              </span>
            ))}
          </div>
        </PanelSection>
      )}
      {malware.length > 0 && (
        <PanelSection label="Malware families">
          <div className="chip-grid">
            {malware.map((g, i) => (
              <span key={i} className="tag-chip">{g.value}
                <span className="panel-source-tags">{g.sources.map(s => <SourceTag key={s} name={s} consensus={false} />)}</span>
              </span>
            ))}
          </div>
        </PanelSection>
      )}
      {mitre && mitre.software.length > 0 && (
        <PanelSection label="Malware & Tools">
          <div className="chip-grid">
            {mitre.software.map((s, i) => (
              <span key={i} className={`tag-chip mitre-software-${s.type}`} title={`${s.type} · ${s.id}`}>{s.name}</span>
            ))}
          </div>
        </PanelSection>
      )}
      {mitre && mitre.campaigns.length > 0 && (
        <PanelSection label="Campaigns">
          <div className="chip-grid">
            {mitre.campaigns.map((c, i) => (
              <span key={i} className="tag-chip" title={c.id}>{c.name}</span>
            ))}
          </div>
        </PanelSection>
      )}
      {mitre && mitre.mitigations.length > 0 && (
        <PanelSection label="Mitigations">
          <div className="chip-grid">
            {mitre.mitigations.map((m, i) => (
              <span key={i} className="tag-chip mono" title={m.id}>{m.id}<span className="mitre-mitigation-name"> {m.name}</span></span>
            ))}
          </div>
        </PanelSection>
      )}
    </Panel>
  );
}

export function ThreatGroupTargetingPanel({ mitre }: { mitre?: MitreSection | null }) {
  if (!mitre || (mitre.sectors.length === 0 && mitre.countries.length === 0 && mitre.associatedGroups.length === 0)) return null;
  return (
    <Panel title="Targeting & Associations" icon="◈" accent="#e09000">
      <div className="mitre-context-grid">
        {mitre.sectors.length > 0 && (
          <div className="mitre-context-block">
            <div className="mitre-context-label">Target Sectors</div>
            <div className="chip-grid">
              {mitre.sectors.map((s, i) => <span key={i} className="tag-chip mitre-context-sector">{s}</span>)}
            </div>
          </div>
        )}
        {mitre.countries.length > 0 && (
          <div className="mitre-context-block">
            <div className="mitre-context-label">Target Countries / Regions</div>
            <div className="chip-grid">
              {mitre.countries.map((c, i) => <span key={i} className="tag-chip mitre-context-country">{c}</span>)}
            </div>
          </div>
        )}
        {mitre.associatedGroups.length > 0 && (
          <div className="mitre-context-block">
            <div className="mitre-context-label">Associated Groups</div>
            <div className="chip-grid">
              {mitre.associatedGroups.map((g, i) => <span key={i} className="tag-chip mitre-context-group">{g.name}</span>)}
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}

// ── Network panel ──────────────────────────────────────────────────

export function NetworkResultPanel({ network }: { network: PanelData['network'] }) {
  const isEmpty = !network.ports.length && !network.services.length && !network.ssl.length && !network.jarm.length;
  return (
    <Panel title="Network & Services" icon="⬡" accent="#3fb950">
      {isEmpty && <PanelEmpty />}
      {network.ports.length > 0 && (
        <PanelSection label="Open ports">
          <div className="chip-grid">
            {network.ports.map((p, i) => (
              <span key={i} className="port-chip mono">{p.value}<span className="src-tag src-solo">{p.source}</span></span>
            ))}
          </div>
        </PanelSection>
      )}
      {network.services.length > 0 && (
        <PanelSection label="Services">
          <FieldRow label="HTTP" fields={network.services.filter(s => s.value.startsWith('HTTP'))} />
        </PanelSection>
      )}
      {network.ssl.length > 0 && (
        <PanelSection label="TLS / SSL">
          <FieldRow label="TLS Cert CN" fields={network.ssl} mono />
        </PanelSection>
      )}
      {network.jarm.length > 0 && (
        <PanelSection label="Fingerprints">
          <FieldRow label="JARM" fields={network.jarm} mono />
        </PanelSection>
      )}
    </Panel>
  );
}

// ── Anonymization panel ────────────────────────────────────────────

export function AnonResultPanel({ anon }: { anon: PanelData['anon'] }) {
  const isEmpty = !anon.vpn.length && !anon.proxy.length && !anon.tor.length && !anon.hosting.length && !anon.usageType.length;
  return (
    <Panel title="Anonymization" icon="⊘" accent="#f85149">
      {isEmpty ? <PanelEmpty /> : (
        <PanelSection label="Proxying">
          <FieldRow label="VPN"        fields={anon.vpn} />
          <FieldRow label="Proxy"      fields={anon.proxy} />
          <FieldRow label="Tor"        fields={anon.tor} />
          <FieldRow label="Hosting"    fields={anon.hosting} />
          <FieldRow label="Usage type" fields={anon.usageType} />
        </PanelSection>
      )}
    </Panel>
  );
}

// ── File panel ─────────────────────────────────────────────────────

export function FileResultPanel({ file }: { file: PanelData['file'] }) {
  const isEmpty = !file.name.length && !file.type.length && !file.md5.length && !file.sha256.length && !file.firstSeen.length;
  return (
    <Panel title="File Details" icon="◫" accent="#bc8cff">
      {isEmpty && <PanelEmpty />}
      {!isEmpty && <PanelSection label="Identity">
        <FieldRow label="Name"      fields={file.name} />
        <FieldRow label="Type"      fields={file.type} />
        <FieldRow label="Size"      fields={file.size} />
        <FieldRow label="First seen" fields={file.firstSeen} />
        <FieldRow label="Last seen"  fields={file.lastSeen} />
        <FieldRow label="Times submitted" fields={file.timesSubmitted} />
      </PanelSection>}
      {!isEmpty && <PanelSection label="Hashes">
        <FieldRow label="MD5"    fields={file.md5}    mono />
        <FieldRow label="SHA-1"  fields={file.sha1}   mono />
        <FieldRow label="SHA-256" fields={file.sha256} mono />
      </PanelSection>}
    </Panel>
  );
}

// ── Detection panel ────────────────────────────────────────────────

export function DetectionResultPanel({ detection }: { detection: DetectionSection }) {
  const [showAll, setShowAll] = useState(false);
  const { totalEngines, malicious, suspicious, harmless, undetected, engines } = detection;

  const flagged = engines.filter(e => e.category === 'malicious' || e.category === 'suspicious');
  const visible = showAll ? engines : (flagged.length ? flagged : engines.slice(0, 10));

  const verdict = malicious > 0 ? { label: 'Malicious', color: 'var(--danger)' }
    : suspicious > 0            ? { label: 'Suspicious', color: 'var(--warn)' }
                                : { label: 'Clean', color: 'var(--success)' };

  const catColor: Record<string, string> = {
    malicious: 'var(--danger)', suspicious: 'var(--warn)',
    harmless: 'var(--success)', undetected: 'var(--text2)',
  };

  const segs = [
    { key: 'malicious',  v: malicious,  color: 'var(--danger)' },
    { key: 'suspicious', v: suspicious, color: 'var(--warn)' },
    { key: 'harmless',   v: harmless,   color: 'var(--success)' },
    { key: 'undetected', v: undetected, color: 'var(--border)' },
  ].filter(s => s.v > 0);

  return (
    <Panel title="Detection" icon="⊛" accent={verdict.color}>
      <PanelSection label="Summary">
        <div className="detection-verdict-row">
          <span className="detection-verdict" style={{ color: verdict.color, borderColor: verdict.color, background: `${verdict.color}18` }}>
            {verdict.label}
          </span>
          <span className="detection-count" style={{ color: verdict.color }}>
            {malicious + suspicious} / {totalEngines} engines
          </span>
        </div>
        <div className="detection-bar">
          {segs.map(s => (
            <div key={s.key} className="detection-bar-seg"
              style={{ width: `${(s.v / totalEngines) * 100}%`, background: s.color }}
              title={`${s.key}: ${s.v}`}
            />
          ))}
        </div>
        <div className="detection-legend">
          {segs.map(s => (
            <span key={s.key} className="detection-legend-item">
              <span className="detection-legend-dot" style={{ background: s.color }} />
              {s.key} {s.v}
            </span>
          ))}
        </div>
      </PanelSection>
      <PanelSection label={`Engine results · ${detection.source}`}>
        <div className="engine-list">
          {visible.map(e => (
            <div key={e.engine} className="engine-row">
              <span className="engine-name">{e.engine}</span>
              <span className="engine-result" style={{ color: catColor[e.category] ?? 'var(--text2)' }}>
                {e.result ?? e.category}
              </span>
            </div>
          ))}
        </div>
        {!showAll && engines.length > visible.length && (
          <button className="show-all-btn" onClick={() => setShowAll(true)}>
            Show all {engines.length} engines
          </button>
        )}
        {showAll && (
          <button className="show-all-btn" onClick={() => setShowAll(false)}>Collapse</button>
        )}
      </PanelSection>
    </Panel>
  );
}

// ── CVE panel ──────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#f85149',
  HIGH:     '#d29922',
  MEDIUM:   '#58a6ff',
  LOW:      '#3fb950',
  NONE:     '#8b949e',
};

function CvssBar({ score, max = 10 }: { score: number; max?: number }) {
  const pct = Math.min((score / max) * 100, 100);
  const color = score >= 9 ? SEVERITY_COLOR.CRITICAL
    : score >= 7 ? SEVERITY_COLOR.HIGH
    : score >= 4 ? SEVERITY_COLOR.MEDIUM
    : SEVERITY_COLOR.LOW;
  return (
    <div className="cvss-bar-track" title={`CVSS ${score.toFixed(1)}`}>
      <div className="cvss-bar-fill" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function CvssVector({ detail }: { detail: CvssDetail }) {
  const items = [
    { label: 'AV',  value: detail.attackVector },
    { label: 'AC',  value: detail.attackComplexity },
    { label: 'PR',  value: detail.privilegesRequired },
    { label: 'UI',  value: detail.userInteraction },
    { label: 'S',   value: detail.scope },
    { label: 'C',   value: detail.confidentiality },
    { label: 'I',   value: detail.integrity },
    { label: 'A',   value: detail.availability },
  ].filter(i => i.value);
  return (
    <div className="cvss-vector-wrap">
      <div className="cvss-vector-chips">
        {items.map(item => (
          <span key={item.label} className="cvss-chip">
            <span className="cvss-chip-label">{item.label}</span>
            <span className="cvss-chip-value">{(item.value as string)[0].toUpperCase() + (item.value as string).slice(1).toLowerCase()}</span>
          </span>
        ))}
      </div>
      {(detail.exploitabilityScore != null || detail.impactScore != null) && (
        <div className="cvss-subscores">
          {detail.exploitabilityScore != null && <span>Exploitability: <strong>{detail.exploitabilityScore.toFixed(1)}</strong></span>}
          {detail.impactScore != null && <span>Impact: <strong>{detail.impactScore.toFixed(1)}</strong></span>}
        </div>
      )}
    </div>
  );
}



export function CveLeftPanel({ cve, onSearch }: { cve: CveSection; onSearch?: (q: string) => void }) {
  const [showAll, setShowAll] = useState(false);
  const PREVIEW = 5;
  const visible = showAll ? cve.entries : cve.entries.slice(0, PREVIEW);
  const critCount = cve.entries.filter(e => e.severity === 'CRITICAL').length;
  const highCount = cve.entries.filter(e => e.severity === 'HIGH').length;

  return (
    <>
      <Panel title="Vulnerabilities (CVE)" icon="⚡" accent={SEVERITY_COLOR.CRITICAL}>
        <PanelSection label={`${cve.entries.length} result${cve.entries.length !== 1 ? 's' : ''} for "${cve.query}"`}>
          <div className="cve-summary-chips">
            {critCount > 0 && <span className="cve-chip" style={{ color: SEVERITY_COLOR.CRITICAL, borderColor: SEVERITY_COLOR.CRITICAL, background: `${SEVERITY_COLOR.CRITICAL}18` }}>{critCount} Critical</span>}
            {highCount > 0 && <span className="cve-chip" style={{ color: SEVERITY_COLOR.HIGH, borderColor: SEVERITY_COLOR.HIGH, background: `${SEVERITY_COLOR.HIGH}18` }}>{highCount} High</span>}
          </div>
        </PanelSection>
      </Panel>
      {visible.map((e, i) => {
        const color = SEVERITY_COLOR[e.severity] ?? SEVERITY_COLOR.NONE;
        const score = e.cvss3 ?? e.cvss;
        const pubDate = e.published ? new Date(e.published).toLocaleDateString() : '—';
        const modDate = e.modified  ? new Date(e.modified).toLocaleDateString()  : '—';
        const title = (
          <span className="cve-panel-title">
            <span className="cve-id">{e.id}</span>
            <span className="cve-severity-badge" style={{ color, borderColor: color, background: `${color}18` }}>{e.severity}</span>
            {score !== null && <span className="cve-score" style={{ color }}>{score.toFixed(1)}</span>}
            {e.status && <span className="cve-status-badge">{e.status}</span>}
          </span>
        );
        return (
          <Panel key={e.id || i} title={title} icon="⚡" accent={color}>
            <PanelSection label="Summary">
              <p className="cve-summary">{e.summary}</p>
              <div className="cve-meta-row" style={{ marginTop: 8 }}>
                <span className="cve-meta-label">Published</span><span>{pubDate}</span>
                <span className="cve-meta-label">Modified</span><span>{modDate}</span>
                {e.cwe.length > 0 && <>
                  <span className="cve-meta-label">CWE</span>
                  <span>{e.cwe.join(', ')}{e.cweDesc?.length ? ` · ${e.cweDesc.join(', ')}` : ''}</span>
                </>}
                {e.capec.length > 0 && <>
                  <span className="cve-meta-label">CAPEC</span>
                  <span>{e.capec.join(', ')}</span>
                </>}
              </div>
              {score !== null && <CvssBar score={score} />}
              {e.cvssDetail && <CvssVector detail={e.cvssDetail} />}
              {e.relatedCves && e.relatedCves.length > 0 && (
                <div className="cve-related-wrap">
                  <span className="cve-meta-label" style={{ marginBottom: 4, display: 'block' }}>Related CVEs</span>
                  <div className="cve-related-chips">
                    {e.relatedCves.map(id => (
                      <button key={id} className="cve-related-chip" onClick={() => onSearch?.(id)}>{id}</button>
                    ))}
                  </div>
                </div>
              )}
            </PanelSection>
          </Panel>
        );
      })}
      {!showAll && cve.entries.length > PREVIEW && (
        <button className="show-all-btn" onClick={() => setShowAll(true)}>
          Show all {cve.entries.length} CVEs
        </button>
      )}
      {showAll && cve.entries.length > PREVIEW && (
        <button className="show-all-btn" onClick={() => setShowAll(false)}>Collapse</button>
      )}
    </>
  );
}

export function CveRightPanel({ cve }: { cve: CveSection }) {
  const [showAll] = useState(false);
  const PREVIEW = 5;
  const visible = showAll ? cve.entries : cve.entries.slice(0, PREVIEW);

  const hasAffected = visible.some(e => e.affected?.length);
  const hasRefs     = visible.some(e => (e.richRefs?.length ?? e.references.length) > 0);
  if (!hasAffected && !hasRefs) return null;

  return (
    <>
      {visible.map((e) => {
        const color = SEVERITY_COLOR[e.severity] ?? SEVERITY_COLOR.NONE;
        const refs = e.richRefs?.length ? e.richRefs : e.references.map(r => ({ url: r, tags: [] }));
        return (
          <React.Fragment key={e.id}>
            {e.affected && e.affected.length > 0 && (
              <Panel title={`${e.id} — Affected Software (${e.affected.length})`} icon="🖥" accent={color}>
                <PanelSection label="">
                  <div className="cve-affected-list">
                    {e.affected.map((a, i) => (
                      <div key={i} className="cve-affected-row">
                        <span className="cve-affected-product">{a.vendor} / {a.product}</span>
                        {a.versions && <span className="cve-affected-versions">{a.versions}</span>}
                      </div>
                    ))}
                  </div>
                </PanelSection>
              </Panel>
            )}
            {refs.length > 0 && (
              <Panel title={`${e.id} — References (${refs.length})`} icon="🔗" accent={color}>
                <PanelSection label="">
                  <div className="cve-refs">
                    {refs.map((r, i) => (
                      <div key={i} className="cve-ref-row">
                        <a className="cve-ref-link" href={r.url} target="_blank" rel="noopener noreferrer">{r.url}</a>
                        {r.tags.length > 0 && (
                          <span className="cve-ref-tags">
                            {r.tags.map(t => <span key={t} className="cve-ref-tag">{t}</span>)}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </PanelSection>
              </Panel>
            )}
          </React.Fragment>
        );
      })}
    </>
  );
}

const SOURCE_COLORS: Record<string, string> = {
  VirusTotal:   '#3970e8',
  Shodan:       '#e8813a',
  GreyNoise:    '#5cb85c',
  AbuseIPDB:    '#d9534f',
  MalwareBazaar:'#9b59b6',
  ThreatFox:    '#e74c3c',
  URLhaus:      '#c0392b',
  WHOIS:        '#7f8c8d',
};

function sourceColor(source: string): string {
  return SOURCE_COLORS[source] ?? '#58a6ff';
}

export function TimelineResultPanel({ events }: { events: TimelineEvent[] }) {
  const sorted = [...events].sort((a, b) => a.ts - b.ts);
  const first = sorted[0].ts;
  const last  = sorted[sorted.length - 1].ts;
  const spanMs = last - first;
  const spanDays = Math.round(spanMs / 86400000);
  const spanLabel = spanDays < 30
    ? `${spanDays} days`
    : spanDays < 365
    ? `${Math.round(spanDays / 30)} months`
    : `${(spanDays / 365).toFixed(1)} years`;

  function formatDate(ts: number) {
    return new Date(ts).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  return (
    <Panel title="Timeline" icon="⏱" accent="#58a6ff">
      <div className="timeline-span">
        Tracked for <strong>{spanLabel}</strong>
        <span className="timeline-span-range">{formatDate(first)} – {formatDate(last)}</span>
      </div>
      <div className="timeline-list">
        {sorted.map((e, i) => (
          <div key={i} className="timeline-event">
            <div className="timeline-dot" style={{ background: sourceColor(e.source) }} />
            <div className="timeline-date">{formatDate(e.ts)}</div>
            <div className="timeline-body">
              <span className="timeline-label">{e.label}</span>
              {e.detail && <span className="timeline-detail">{e.detail}</span>}
              <span className="timeline-source-tag" style={{ borderColor: sourceColor(e.source), color: sourceColor(e.source) }}>
                {e.source}
              </span>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── Detection Rules Panel ─────────────────────────────────────────────

function RuleCard({ rule }: { rule: DetectionRule & { rawUrl?: string } }) {
  const [expanded, setExpanded] = useState(false);
  const [content, setContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleExpand = useCallback(async () => {
    if (!expanded && content === null) {
      setLoading(true);
      const text = await fetchRuleContent(rule);
      setContent(text);
      setLoading(false);
    }
    setExpanded(v => !v);
  }, [expanded, content, rule]);

  const handleCopy = useCallback(async () => {
    if (!content) return;
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [content]);

  const typeColor = rule.type === 'sigma' ? 'var(--accent)' : 'var(--warn)';

  return (
    <div className="det-rule-card">
      <div className="det-rule-header" onClick={handleExpand}>
        <span className="det-rule-type-badge" style={{ borderColor: typeColor, color: typeColor }}>
          {rule.type.toUpperCase()}
        </span>
        <span className="det-rule-name">{rule.name}</span>
        <span className="det-rule-source">
          <a href={rule.sourceUrl} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}>
            {rule.source} ↗
          </a>
        </span>
        <span className="det-rule-chevron">{expanded ? '▾' : '▸'}</span>
      </div>
      {rule.description && (
        <div className="det-rule-desc">{rule.description}</div>
      )}
      {rule.matchedOn.length > 0 && (
        <div className="det-rule-tags">
          {rule.matchedOn.slice(0, 6).map(t => (
            <span key={t} className="det-rule-match-tag">{t}</span>
          ))}
        </div>
      )}
      {expanded && (
        <div className="det-rule-body">
          {loading && <div className="det-rule-loading">Loading rule…</div>}
          {!loading && content !== null && (
            <>
              <div className="det-rule-actions">
                <button className="det-rule-copy-btn" onClick={handleCopy}>
                  {copied ? '✓ Copied' : 'Copy rule'}
                </button>
              </div>
              <pre className="det-rule-code">{content}</pre>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export function DetectionRulesPanel({ rules, loading }: { rules: DetectionRule[]; loading: boolean }) {
  const sigma = rules.filter(r => r.type === 'sigma');
  const yara  = rules.filter(r => r.type === 'yara');

  return (
    <Panel title="Detection Rules" icon="⚔" accent="var(--accent)">
      {loading && (
        <div className="det-rules-loading">Searching public rule repositories…</div>
      )}
      {!loading && rules.length === 0 && (
        <div className="det-rules-empty">No public rules found for this indicator.</div>
      )}
      {!loading && rules.length > 0 && (
        <div className="det-rules-list">
          {sigma.length > 0 && (
            <div className="det-rules-section">
              <div className="det-rules-section-label">SIGMA ({sigma.length})</div>
              {sigma.map(r => <RuleCard key={r.id} rule={r as DetectionRule & { rawUrl?: string }} />)}
            </div>
          )}
          {yara.length > 0 && (
            <div className="det-rules-section">
              <div className="det-rules-section-label">YARA ({yara.length})</div>
              {yara.map(r => <RuleCard key={r.id} rule={r as DetectionRule & { rawUrl?: string }} />)}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
