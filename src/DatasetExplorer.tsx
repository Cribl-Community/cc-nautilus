import { useState } from 'react';
import { runCriblSearch } from './criblApi';
import type { SearchResult } from './criblApi';

export default function DatasetExplorer() {
  const [dataset, setDataset] = useState('');
  const [query, setQuery] = useState('');
  const [timeRange, setTimeRange] = useState('-24h');
  const [limit, setLimit] = useState(50);
  const [state, setState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle');
  const [events, setEvents] = useState<SearchResult[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const [columns, setColumns] = useState<string[]>([]);

  function buildQuery(): string {
    const base = dataset.trim() ? `dataset="${dataset.trim()}"` : 'dataset="*"';
    const filter = query.trim();
    return filter ? `${base} | ${filter}` : base;
  }

  async function handleSearch() {
    setState('loading');
    setError('');
    setEvents([]);
    setColumns([]);
    try {
      const result = await runCriblSearch(buildQuery(), { earliest: timeRange, latest: 'now', limit });
      setEvents(result.events);
      setTotal(result.totalEventCount);
      setState('done');

      // Derive columns from results
      const cols = new Set<string>();
      for (const evt of result.events.slice(0, 20)) {
        for (const key of Object.keys(evt)) {
          cols.add(key);
        }
      }
      const ordered = ['_time', ...Array.from(cols).filter(c => c !== '_time' && c !== '_raw').sort(), '_raw'].filter(c => cols.has(c));
      setColumns(ordered);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Search failed');
      setState('error');
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && dataset.trim()) {
      handleSearch();
    }
  }

  function formatCell(value: unknown): string {
    if (value == null) return '';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }

  function formatTime(value: unknown): string {
    if (!value) return '';
    const num = Number(value);
    if (!isNaN(num)) {
      const ms = num > 1e12 ? num : num * 1000;
      return new Date(ms).toLocaleString();
    }
    return String(value);
  }

  return (
    <div className="dataset-explorer">
      <div className="dataset-controls">
        <div className="dataset-input-row">
          <input
            className="dataset-name-input"
            type="text"
            value={dataset}
            onChange={e => setDataset(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Dataset name (e.g. main, stix_intel)"
          />
          <select
            className="dataset-time-select"
            value={timeRange}
            onChange={e => setTimeRange(e.target.value)}
          >
            <option value="-1h">1h</option>
            <option value="-6h">6h</option>
            <option value="-24h">24h</option>
            <option value="-7d">7d</option>
            <option value="-30d">30d</option>
            <option value="-90d">90d</option>
          </select>
          <select
            className="dataset-limit-select"
            value={limit}
            onChange={e => setLimit(Number(e.target.value))}
          >
            <option value={10}>10</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={500}>500</option>
          </select>
        </div>
        <div className="dataset-query-row">
          <input
            className="dataset-query-input"
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={'Optional filter (e.g. where type=="indicator" | head 10)'}
          />
          <button
            className="dataset-search-btn"
            onClick={handleSearch}
            disabled={!dataset.trim() || state === 'loading'}
          >
            {state === 'loading' ? 'Searching...' : 'Query'}
          </button>
        </div>
        <div className="dataset-full-query">
          {buildQuery()}
        </div>
      </div>

      {state === 'error' && (
        <div className="dataset-error">{error}</div>
      )}

      {state === 'done' && events.length === 0 && (
        <div className="dataset-empty">No results found in this time range.</div>
      )}

      {state === 'done' && events.length > 0 && (
        <div className="dataset-results">
          <div className="dataset-results-toolbar">
            <span className="dataset-results-count">
              {events.length} of {total} event{total !== 1 ? 's' : ''}
            </span>
          </div>
          <div className="dataset-table-wrap">
            <table className="dataset-table">
              <thead>
                <tr>
                  {columns.map(col => (
                    <th key={col}>{col}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((evt, i) => (
                  <tr key={i}>
                    {columns.map(col => (
                      <td key={col} className={col === '_raw' ? 'dataset-cell-raw' : 'dataset-cell'}>
                        {col === '_time' ? formatTime(evt[col]) : formatCell(evt[col])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {total > events.length && (
            <div className="dataset-more">Showing {events.length} of {total} — increase limit or narrow the query</div>
          )}
        </div>
      )}
    </div>
  );
}
