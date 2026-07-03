export type FeedFormat = 'csv' | 'json' | 'plaintext' | 'tsv' | 'stix';
export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'mixed';
export type AuthType = 'none' | 'header' | 'queryparam' | 'basic';

export type SyncStage = 'fetch_failed' | 'parse_failed';

export type FeedStatus =
  | 'never_synced'
  | 'syncing'
  | 'synced'
  | 'fetch_failed'
  | 'parse_failed';

export interface FeedAuth {
  type: AuthType;
  /** Header name for type='header' (e.g. 'Authorization', 'X-API-Key') */
  headerName?: string;
  /** Query param name for type='queryparam' (e.g. 'apikey', 'token') */
  paramName?: string;
  /** KV key reference — points to an entry in the existing provider key store */
  kvKey?: string;
}

export interface FeedConfig {
  id: string;
  name: string;
  url: string;
  format: FeedFormat;
  indicatorType: IndicatorType;
  indicatorField: string;
  enabled: boolean;
  autoSync: boolean;
  ttlDays: number;
  trustScore: number;
  tags: string[];
  addedAt: string;
  lastSync: string | null;
  lastSyncCount: number | null;
  lastSyncError: string | null;
  lastSyncStage?: SyncStage;
  lastSyncTruncated?: boolean;
  auth?: FeedAuth;
  /** Set by the service when a 401/403 is returned and no auth is configured */
  needsAuth?: boolean;
}

export interface FeedPreview {
  rows: string[];
  detectedFormat: FeedFormat;
  detectedType: IndicatorType;
  estimatedCount: number;
  sampleIndicators: string[];
}

export interface CuratedFeed {
  id: string;
  name: string;
  description: string;
  url: string;
  format: FeedFormat;
  indicatorType: IndicatorType;
  indicatorField: string;
  trustScore: number;
  updateFrequency: string;
  category: string;
  source: string;
  /** When set, this feed requires authentication to sync */
  auth?: Pick<FeedAuth, 'type' | 'headerName' | 'paramName'>;
}

export interface SyncLogEntry {
  id: string;
  timestamp: string;
  feedId: string;
  feedName: string;
  success: boolean;
  indicatorCount?: number;
  error?: string;
  durationMs?: number;
}

export interface FeedMatch {
  feedId: string;
  feedName: string;
  indicatorType: IndicatorType;
  trustScore: number;
}
