import { useState } from 'react';
import type { ArtifactType } from './types';
import { runCriblSearch } from './criblApi';
import type { SearchResult } from './criblApi';
import type { PanelData, MSValue } from './panelData';
import type { MitreOverlayResult } from './mitreOverlay';
import type { DetectionRule } from './detectionRules';
import type { FeedMatch } from './feedTypes';
import type { VtRelations } from './types';

function inCribl(): boolean {
  try {
    const url = (window as unknown as Record<string, unknown>)['CRIBL_API_URL'];
    return typeof url === 'string' && url.length > 0;
  } catch { return false; }
}

// ── Find in logs — compact button in toolbar, results drop below ───

interface FindInLogsProps {
  query: string;
  artifactType: ArtifactType;
}

export function FindInLogs({ query, artifactType }: FindInLogsProps) {
  const [state, setState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle');
  const [events, setEvents] = useState<SearchResult[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState('-24h');
  const [open, setOpen] = useState(false);

  if (!inCribl()) return null;

  function buildQuery(): string {
    const escaped = query.replace(/"/g, '\\"');
    switch (artifactType) {
      case 'ip':     return `dataset="*" | where src_ip=="${escaped}" OR dst_ip=="${escaped}" OR ip=="${escaped}"`;
      case 'domain': return `dataset="*" | where domain=="${escaped}" OR hostname=="${escaped}" OR url like "%${escaped}%"`;
      case 'hash':   return `dataset="*" | where md5=="${escaped}" OR sha1=="${escaped}" OR sha256=="${escaped}" OR hash=="${escaped}"`;
      case 'url':    return `dataset="*" | where url=="${escaped}"`;
      default:       return `dataset="*" | where _raw like "%${escaped}%"`;
    }
  }

  async function search() {
    setState('loading');
    setError(null);
    setEvents([]);
    try {
      const result = await runCriblSearch(buildQuery(), { earliest: timeRange, latest: 'now', limit: 50 });
      setEvents(result.events);
      setTotal(result.totalEventCount);
      setState('done');
      setOpen(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Search failed');
      setState('error');
    }
  }

  return (
    <>
      <div className="find-in-logs-btn-group">
        <select
          className="cribl-time-select"
          value={timeRange}
          onChange={e => setTimeRange(e.target.value)}
          disabled={state === 'loading'}
        >
          <option value="-1h">1h</option>
          <option value="-6h">6h</option>
          <option value="-24h">24h</option>
          <option value="-7d">7d</option>
          <option value="-30d">30d</option>
        </select>
        <button
          className={`cribl-search-btn${state === 'done' ? (total > 0 ? ' has-hits' : ' no-hits') : ''}`}
          onClick={state === 'done' ? () => setOpen(o => !o) : search}
          disabled={state === 'loading'}
          title={error ?? undefined}
        >
          {state === 'loading' ? '…'
            : state === 'error' ? '✗ Search'
            : state === 'done' ? `⌕ ${total > 0 ? total + ' hits' : 'No hits'}`
            : '⌕ Find in Logs'}
        </button>
      </div>

      {state === 'done' && open && (
        <div className="find-in-logs-results">
          <div className="cribl-query-display">
            {buildQuery()}
            <button className="find-logs-close" onClick={() => setOpen(false)}>✕</button>
          </div>
          {events.length === 0 && (
            <div className="cribl-no-results">No events matched in this time range.</div>
          )}
          {events.map((evt, i) => (
            <div key={i} className="cribl-event">
              <span className="cribl-event-time">
                {evt._time ? new Date(Number(evt._time) * 1000).toLocaleString() : '—'}
              </span>
              <span className="cribl-event-raw">{evt._raw ?? JSON.stringify(evt)}</span>
            </div>
          ))}
          {total > events.length && (
            <div className="cribl-more">Showing {events.length} of {total} — open Cribl Search for full results</div>
          )}
        </div>
      )}

      {state === 'error' && open && (
        <div className="find-in-logs-results">
          <div className="cribl-error">{error}</div>
        </div>
      )}
    </>
  );
}

// ── Copy for AI ───────────────────────────────────────────────────

interface CopyForAIProps {
  query: string;
  artifactType: ArtifactType;
  panels: PanelData;
  mitreOverlay: MitreOverlayResult[];
  detectionRules: DetectionRule[];
  feedMatches: FeedMatch[];
  relations: VtRelations | null;
}

function buildMarkdown(props: CopyForAIProps): string {
  const { query, artifactType, panels, mitreOverlay, detectionRules, feedMatches, relations } = props;
  const rep = panels.reputation;
  const lines: string[] = [];

  const typeLabel = artifactType === 'ip' ? 'IP Address'
    : artifactType === 'domain' ? 'Domain'
    : artifactType === 'url' ? 'URL'
    : artifactType === 'hash' ? 'File Hash'
    : artifactType === 'cve' ? 'CVE'
    : artifactType.toUpperCase();

  lines.push(`## IOC Analysis: ${query}`);
  lines.push(`**Type:** ${typeLabel}`);

  // Verdict
  const verdicts = rep.verdict.map((v: MSValue) => v.value);
  const det = panels.detection;
  if (det) {
    lines.push(`**Verdict:** ${verdicts[0] ?? 'Unknown'} (${det.malicious}/${det.totalEngines} engines)`);
  } else if (verdicts.length) {
    lines.push(`**Verdict:** ${[...new Set(verdicts)].join(', ')}`);
  }
  lines.push('');

  // Threat context
  const families = rep.malwareFamily.map((m: MSValue) => m.value);
  const labels = rep.threatLabel.map((m: MSValue) => m.value);
  const tags = rep.tags.map((t: MSValue) => t.value);
  if (families.length || labels.length || tags.length) {
    lines.push('### Threat Context');
    if (families.length) lines.push(`- **Malware Family:** ${families.join(', ')}`);
    if (labels.length)   lines.push(`- **Threat Label:** ${labels.join(', ')}`);
    if (tags.length)     lines.push(`- **Tags:** ${tags.join(', ')}`);
    lines.push('');
  }

  // File info (hashes)
  const file = panels.file;
  const v1 = (arr: Array<{ value: string }>) => arr[0]?.value;
  if (file) {
    const fileLines: string[] = [];
    if (v1(file.md5))   fileLines.push(`- **MD5:** ${v1(file.md5)}`);
    if (v1(file.sha1))  fileLines.push(`- **SHA-1:** ${v1(file.sha1)}`);
    if (v1(file.sha256))fileLines.push(`- **SHA-256:** ${v1(file.sha256)}`);
    if (v1(file.type))  fileLines.push(`- **File Type:** ${v1(file.type)}`);
    if (v1(file.size))  fileLines.push(`- **File Size:** ${v1(file.size)}`);
    if (fileLines.length) {
      lines.push('### File Info');
      lines.push(...fileLines);
      lines.push('');
    }
  }

  // Geo/network (IPs)
  const geo = panels.geo;
  const country = v1(geo.country), city = v1(geo.city), org = v1(geo.org);
  if (country || city || org) {
    lines.push('### Network Context');
    if (country) lines.push(`- **Country:** ${country}`);
    if (city)    lines.push(`- **City:** ${city}`);
    if (org)     lines.push(`- **Org/ASN:** ${org}`);
    lines.push('');
  }

  // MITRE ATT&CK
  if (mitreOverlay.length > 0) {
    lines.push('### ATT&CK Software Overlay');
    for (const sw of mitreOverlay) {
      lines.push(`**${sw.softwareName}** (${sw.softwareId}) — ${sw.softwareType}`);
      for (const t of sw.techniques.slice(0, 10)) {
        lines.push(`- ${t.id} — ${t.name} (${t.tactic})`);
      }
    }
    lines.push('');
  }

  // Feed hits
  if (feedMatches.length > 0) {
    lines.push('### Threat Feed Hits');
    feedMatches.forEach(m => lines.push(`- ${m.feedName} (trust: ${m.trustScore})`));
    lines.push('');
  }

  // Detection rules
  const sigma = detectionRules.filter(r => r.type === 'sigma').slice(0, 5);
  const yara  = detectionRules.filter(r => r.type === 'yara').slice(0, 5);
  if (sigma.length || yara.length) {
    lines.push('### Matched Detection Rules');
    if (sigma.length) {
      lines.push('**SIGMA**');
      sigma.forEach(r => lines.push(`- ${r.name} — ${r.sourceUrl}`));
    }
    if (yara.length) {
      lines.push('**YARA**');
      yara.forEach(r => lines.push(`- ${r.name} — ${r.sourceUrl}`));
    }
    lines.push('');
  }

  // Relations (only if already loaded)
  if (relations && relations.groups.length > 0) {
    const populated = relations.groups.filter(g => g.items.length > 0);
    if (populated.length > 0) {
      lines.push('### Relations');
      for (const group of populated) {
        lines.push(`**${group.label}**`);
        group.items.slice(0, 10).forEach(item => {
          const verdict = item.attributes['last_analysis_stats'] as Record<string, number> | undefined;
          const mal = verdict?.malicious ?? 0;
          const note = mal > 0 ? ` (${mal} malicious detections)` : '';
          lines.push(`- ${item.id}${note}`);
        });
        if (group.items.length > 10) lines.push(`  …and ${group.items.length - 10} more`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

export function CopyForAI(props: CopyForAIProps) {
  const [state, setState] = useState<'idle' | 'copied'>('idle');

  async function handleCopy() {
    const md = buildMarkdown(props);
    try {
      await navigator.clipboard.writeText(md);
      setState('copied');
      setTimeout(() => setState('idle'), 2000);
    } catch {
      // Fallback for browsers that block clipboard
      const ta = document.createElement('textarea');
      ta.value = md;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      setState('copied');
      setTimeout(() => setState('idle'), 2000);
    }
  }

  return (
    <button
      className={`copy-ai-btn${state === 'copied' ? ' copied' : ''}`}
      onClick={() => void handleCopy()}
      title="Copy enrichment summary as markdown for AI assistant"
    >
      {state === 'copied' ? '✓ Copied' : '⎘ Copy for AI'}
    </button>
  );
}
