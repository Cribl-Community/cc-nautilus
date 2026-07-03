export type ArtifactType = 'ip' | 'domain' | 'url' | 'hash' | 'threat-group' | 'file' | 'cve' | 'unknown';

export type ProviderTier = 'free' | 'community' | 'trial' | 'enterprise';

export interface KeyValidation {
  status:    'valid' | 'invalid' | 'rate-limited' | 'unknown';
  checkedAt: number;
  plan?:     string;
  credits?:  string;
  expires?:  string;
  detail?:   string;
}

export type ProviderStatus = 'idle' | 'loading' | 'ok' | 'error' | 'no-key' | 'unsupported' | 'pending';

export interface Provider {
  id: string;
  name: string;
  shortName: string;
  description: string;
  docsUrl: string;
  supports: ArtifactType[];
  authType: 'api-key' | 'basic' | 'none';
  keyLabel: string;
  keyPlaceholder: string;
  requiresKey: boolean;
  tags: string[];
  notes?: string;
  freeTierNote?: string;
  tier: ProviderTier;          // highest available tier (free → community → trial → enterprise)
  upgradeTo?: string;          // URL to upgrade/sign up
  canValidate: boolean;        // true if we have a quota/ping endpoint
  portalUrl?: string;          // for providers where validation is portal-only (option B)
  enterpriseTypes?: ArtifactType[];  // types only available on a paid/enterprise key tier
}

export interface ProviderKey {
  providerId: string;
  keys: string[];         // list of keys; first is active
  activeIndex: number;
}

// Which providers are enabled per artifact type.
// Structure: { [providerId]: { [artifactType]: boolean } }
// A missing key means "use the default" (enabled if provider supports that type).
export type RoutingPrefs = Record<string, Partial<Record<ArtifactType, boolean>>>;

export interface VtRelationItem {
  id:    string;
  type:  string;
  attributes: Record<string, unknown>;
}

export interface VtRelationGroup {
  name:    string;
  label:   string;
  items:   VtRelationItem[];
  error?:  string;
}

export interface VtRelations {
  artifactType: ArtifactType;
  query:        string;
  groups:       VtRelationGroup[];
}

export interface QueryResult {
  providerId: string;
  artifactType: ArtifactType;
  query: string;
  status: ProviderStatus;
  data: unknown;
  error?: string;
  latencyMs?: number;
  fetchedAt?: number;
}
