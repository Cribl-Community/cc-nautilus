import { useState } from 'react';
import { detectArtifact } from './detect';

interface ExtractedIoc {
  value: string;
  type: string;
  checked: boolean;
}

// ── URL detection & page fetching ───────────────────────────────────

const URL_LINE_RE = /^https?:\/\/[^\s]+$/;

function looksLikeUrl(input: string): boolean {
  const trimmed = input.trim();
  const lines = trimmed.split('\n').map(l => l.trim()).filter(Boolean);
  return lines.length === 1 && URL_LINE_RE.test(lines[0]);
}

async function fetchPageText(url: string): Promise<string> {
  const readerUrl = `https://r.jina.ai/${url}`;
  const resp = await fetch(readerUrl, {
    headers: {
      'Accept': 'text/plain',
      'X-Return-Format': 'text',
    },
  });
  if (!resp.ok) {
    throw new Error(`Failed to fetch page (${resp.status}). The URL may be unreachable or blocking extraction.`);
  }
  const text = await resp.text();
  if (!text.trim()) {
    throw new Error('Page returned no extractable content.');
  }
  return text;
}

// ── Defanging ────────────────────────────────────────────────────────

function defang(text: string): string {
  return text
    .replace(/hxxps?/gi, m => m.replace(/xx/, 'tt'))
    .replace(/\[\.]/g, '.')
    .replace(/\[:]g/g, ':')
    .replace(/\[@]/g, '@')
    // spaces around dots in IPs: "1 . 2 . 3 . 4" -> "1.2.3.4"
    .replace(/(\d)\s+\.\s+(\d)/g, '$1.$2');
}

// ── Private IP ranges ────────────────────────────────────────────────

function isPrivateIp(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (ip === '255.255.255.255') return true;
  return false;
}

// ── File-extension false positives for domains ──────────────────────

const FILE_EXTS_SET = new Set([
  'exe','dll','bat','sh','py','rb','pl','php','js','ts','jsx','tsx',
  'doc','docx','xls','xlsx','ppt','pptx','pdf','rtf',
  'zip','gz','tar','rar','7z','iso',
  'cfg','conf','ini','log','tmp','bak','dat',
  'xml','json','yaml','yml','md','csv','tsv','html','htm','css',
  'c','h','cpp','cs','go','rs','java',
  'png','jpg','jpeg','gif','bmp','svg','ico',
]);

// ── IOC extraction ───────────────────────────────────────────────────

function extractIocs(rawText: string): ExtractedIoc[] {
  const text = defang(rawText);
  const results = new Map<string, string>(); // value -> type

  // IPv4 (with optional CIDR)
  const ipv4Re = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/\d+)?\b/g;
  for (const m of text.matchAll(ipv4Re)) {
    const ip = m[1];
    if (!isPrivateIp(ip)) results.set(m[0], 'IP');
  }

  // SHA256
  const sha256Re = /\b([0-9a-fA-F]{64})\b/g;
  for (const m of text.matchAll(sha256Re)) {
    results.set(m[1].toLowerCase(), 'SHA256');
  }

  // SHA1
  const sha1Re = /\b([0-9a-fA-F]{40})\b/g;
  for (const m of text.matchAll(sha1Re)) {
    const v = m[1].toLowerCase();
    if (!results.has(v)) results.set(v, 'SHA1');
  }

  // MD5
  const md5Re = /\b([0-9a-fA-F]{32})\b/g;
  for (const m of text.matchAll(md5Re)) {
    const v = m[1].toLowerCase();
    if (!results.has(v)) results.set(v, 'MD5');
  }

  // URLs
  const urlRe = /https?:\/\/[^\s<>"{}|\\^[\]`]+/g;
  for (const m of text.matchAll(urlRe)) {
    results.set(m[0], 'URL');
  }

  // CVE IDs
  const cveRe = /CVE-\d{4}-\d{4,}/gi;
  for (const m of text.matchAll(cveRe)) {
    results.set(m[0].toUpperCase(), 'CVE');
  }

  // Domains (after URLs, to avoid re-extracting domain from URLs already captured)
  const domainRe = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b/g;
  for (const m of text.matchAll(domainRe)) {
    const domain = m[1].toLowerCase();
    // Skip if already captured as URL or IP
    if ([...results.entries()].some(([v]) => v.includes(domain))) continue;
    // Skip file extensions
    const tld = domain.split('.').pop()?.toLowerCase() ?? '';
    if (FILE_EXTS_SET.has(tld)) continue;
    // Skip if it detects as something other than domain
    const detected = detectArtifact(domain);
    if (detected === 'domain') {
      results.set(domain, 'Domain');
    }
  }

  return [...results.entries()].map(([value, type]) => ({ value, type, checked: true }));
}

// ── Group by type ────────────────────────────────────────────────────

const TYPE_ORDER = ['IP', 'SHA256', 'SHA1', 'MD5', 'URL', 'Domain', 'CVE'];

function groupByType(iocs: ExtractedIoc[]): [string, ExtractedIoc[]][] {
  const map = new Map<string, ExtractedIoc[]>();
  for (const ioc of iocs) {
    const existing = map.get(ioc.type);
    if (existing) existing.push(ioc);
    else map.set(ioc.type, [ioc]);
  }
  const result: [string, ExtractedIoc[]][] = [];
  for (const t of TYPE_ORDER) {
    if (map.has(t)) result.push([t, map.get(t)!]);
  }
  // Any types not in TYPE_ORDER
  for (const [t, iocs] of map) {
    if (!TYPE_ORDER.includes(t)) result.push([t, iocs]);
  }
  return result;
}

// ── Component ────────────────────────────────────────────────────────

interface IocExtractorProps {
  onBulkSearch: (indicators: string[]) => void;
  onSingleSearch: (q: string) => void;
}

export default function IocExtractor({ onBulkSearch, onSingleSearch }: IocExtractorProps) {
  const [inputText, setInputText] = useState('');
  const [iocs, setIocs] = useState<ExtractedIoc[]>([]);
  const [extracted, setExtracted] = useState(false);
  const [fetching, setFetching] = useState(false);
  const [fetchError, setFetchError] = useState('');
  const [fetchedUrl, setFetchedUrl] = useState('');

  async function handleExtract() {
    setFetchError('');
    const trimmed = inputText.trim();

    if (looksLikeUrl(trimmed)) {
      setFetching(true);
      try {
        const pageText = await fetchPageText(trimmed);
        const found = extractIocs(pageText);
        setIocs(found);
        setExtracted(true);
        setFetchedUrl(trimmed);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Failed to fetch page';
        setFetchError(msg);
      } finally {
        setFetching(false);
      }
    } else {
      const found = extractIocs(trimmed);
      setIocs(found);
      setExtracted(true);
      setFetchedUrl('');
    }
  }

  function handleClear() {
    setInputText('');
    setIocs([]);
    setExtracted(false);
    setFetchError('');
    setFetchedUrl('');
  }

  function toggleCheck(value: string) {
    setIocs(prev => prev.map(ioc => ioc.value === value ? { ...ioc, checked: !ioc.checked } : ioc));
  }

  function toggleTypeAll(type: string, checked: boolean) {
    setIocs(prev => prev.map(ioc => ioc.type === type ? { ...ioc, checked } : ioc));
  }

  function handleSearchSelected() {
    const selected = iocs.filter(i => i.checked).map(i => i.value);
    if (selected.length > 0) {
      onBulkSearch(selected);
    }
  }

  const groups = groupByType(iocs);
  const checkedCount = iocs.filter(i => i.checked).length;

  return (
    <div className="ioc-inline">
        <div className="ioc-layout">
          <div className="ioc-input-pane">
            <div className="ioc-input-label">Paste raw text, a report URL, or log snippets</div>
            <textarea
              className="ioc-textarea"
              value={inputText}
              onChange={e => setInputText(e.target.value)}
              placeholder={"Paste text containing IPs, domains, URLs, hashes, CVEs...\n\nOr paste a single URL to a report/blog to fetch and extract IOCs from it."}
              spellCheck={false}
            />
            {fetchError && (
              <div className="ioc-fetch-error">{fetchError}</div>
            )}
            <div className="ioc-input-actions">
              <button className="ioc-extract-btn" onClick={handleExtract} disabled={!inputText.trim() || fetching}>
                {fetching ? 'Fetching page...' : looksLikeUrl(inputText.trim()) ? 'Fetch & Extract' : 'Extract IOCs'}
              </button>
              <button className="ioc-clear-btn" onClick={handleClear}>
                Clear
              </button>
            </div>
          </div>
          <div className="ioc-results-pane">
            {!extracted && (
              <div className="ioc-results-empty">
                <div className="ioc-results-empty-icon">&#9670;</div>
                <div>Extracted IOCs will appear here</div>
                <div className="ioc-results-empty-sub">Defangs hxxp, [.], [:]</div>
              </div>
            )}
            {extracted && iocs.length === 0 && (
              <div className="ioc-results-empty">
                <div>No IOCs found in the pasted text</div>
              </div>
            )}
            {extracted && iocs.length > 0 && (
              <>
                <div className="ioc-results-toolbar">
                  <span className="ioc-total-count">
                    {iocs.length} IOC{iocs.length !== 1 ? 's' : ''} found
                    {fetchedUrl && <span className="ioc-source-badge" title={fetchedUrl}> from URL</span>}
                  </span>
                  {checkedCount > 0 && (
                    <button className="ioc-bulk-btn" onClick={handleSearchSelected}>
                      Search {checkedCount} selected in bulk
                    </button>
                  )}
                </div>
                {groups.map(([type, items]) => {
                  const allChecked = items.every(i => i.checked);
                  const anyChecked = items.some(i => i.checked);
                  return (
                    <div key={type} className="ioc-type-group">
                      <div className="ioc-type-header">
                        <input
                          type="checkbox"
                          checked={allChecked}
                          ref={el => { if (el) el.indeterminate = anyChecked && !allChecked; }}
                          onChange={e => toggleTypeAll(type, e.target.checked)}
                          title={`Toggle all ${type}`}
                        />
                        <span className="ioc-type-label">{type}</span>
                        <span className="ioc-type-count">{items.length}</span>
                      </div>
                      {items.map(ioc => (
                        <div key={ioc.value} className="ioc-item-row">
                          <input
                            type="checkbox"
                            checked={ioc.checked}
                            onChange={() => toggleCheck(ioc.value)}
                          />
                          <span className="ioc-item-value mono">{ioc.value}</span>
                          <span className={`ioc-type-badge ioc-type-badge-${type.toLowerCase()}`}>{ioc.type}</span>
                          <button
                            className="ioc-single-search-btn"
                            onClick={() => onSingleSearch(ioc.value)}
                            title="Search this IOC"
                          >
                            Search
                          </button>
                        </div>
                      ))}
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </div>
    </div>
  );
}
