// Unified multi-source panel data model.
// Each field is MSValue[] — many providers can contribute the same or
// different values. The UI groups by unique value so analysts can see
// consensus vs. outliers across tools.

export interface MSValue {
  value: string;
  source: string;   // provider shortName for display
}

export interface TimelineEvent {
  ts:     number;   // Unix ms
  label:  string;   // e.g. "First seen", "Last report"
  source: string;   // provider shortName
  detail?: string;  // optional extra context
}

// ── Section schemas ────────────────────────────────────────────────

export interface GeoSection {
  country:           MSValue[];
  city:              MSValue[];
  region:            MSValue[];
  continent:         MSValue[];
  coordinates:       MSValue[];   // "lat, lon"
  asn:               MSValue[];
  org:               MSValue[];
  isp:               MSValue[];
  cidr:              MSValue[];
  hostnames:         MSValue[];
  registrar:         MSValue[];
  registrantCountry: MSValue[];
  created:           MSValue[];
  expires:           MSValue[];
}

export interface ReputationSection {
  verdict:       MSValue[];   // "Malicious" | "Suspicious" | "Clean"
  score:         MSValue[];   // reputation score (numeric string)
  confidence:    MSValue[];   // e.g. "85% abuse confidence"
  summary:       MSValue[];   // prose description (threat group profiles)
  categories:    MSValue[];   // threat / content categories
  tags:          MSValue[];
  malwareFamily: MSValue[];
  threatLabel:   MSValue[];   // suggested_threat_label from VT etc.
}

export interface NetworkSection {
  ports:    MSValue[];   // "22/tcp · SSH"
  services: MSValue[];
  ssl:      MSValue[];   // cert CN / issuer
  jarm:     MSValue[];
}

export interface AnonSection {
  vpn:       MSValue[];   // "Yes – <operator>" or "No"
  proxy:     MSValue[];
  tor:       MSValue[];
  hosting:   MSValue[];
  usageType: MSValue[];
}

export interface FileSection {
  name:           MSValue[];
  type:           MSValue[];
  size:           MSValue[];
  md5:            MSValue[];
  sha1:           MSValue[];
  sha256:         MSValue[];
  firstSeen:      MSValue[];
  lastSeen:       MSValue[];
  timesSubmitted: MSValue[];
}

export interface EngineResult {
  engine:   string;
  category: string;
  result:   string | null;
  source:   string;
}

export interface DetectionSection {
  totalEngines: number;
  malicious:    number;
  suspicious:   number;
  harmless:     number;
  undetected:   number;
  engines:      EngineResult[];
  source:       string;
}

export interface CveReference {
  url:   string;
  tags:  string[];   // e.g. 'Exploit', 'Vendor Advisory', 'Third Party Advisory'
}

export interface CvssDetail {
  version:             string;   // '3.1' | '3.0' | '2.0'
  vectorString:        string;
  attackVector?:       string;
  attackComplexity?:   string;
  privilegesRequired?: string;
  userInteraction?:    string;
  scope?:              string;
  confidentiality?:    string;
  integrity?:          string;
  availability?:       string;
  exploitabilityScore?: number;
  impactScore?:        number;
}

export interface AffectedVersion {
  vendor:   string;
  product:  string;
  versions: string;  // human-readable range, e.g. "< 8.3p1"
}

export interface CveEntry {
  id:          string;
  summary:     string;
  cvss:        number | null;
  cvss3:       number | null;
  severity:    string;          // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
  published:   string;
  modified:    string;
  status?:     string;          // e.g. 'Modified', 'Analyzed'
  references:  string[];        // legacy flat list — kept for CIRCL compat
  richRefs?:   CveReference[];  // NVD refs with tags
  cvssDetail?: CvssDetail;
  affected?:   AffectedVersion[];
  cwe:         string[];
  cweDesc?:    string[];        // human-readable CWE descriptions
  capec:       string[];
  vulnerable:  string[];        // CPE strings (legacy)
  relatedCves?: string[];       // CVE IDs extracted from description/references
  source:      string;
}

export interface CveSection {
  query:   string;              // the original vendor/product or CVE ID searched
  entries: CveEntry[];
}

export interface MitreTechnique {
  id:     string;   // e.g. "T1566.001"
  name:   string;
  tactic: string;   // e.g. "Initial Access"
}

export interface MitreSoftware {
  id:   string;   // e.g. "S0002"
  name: string;
  type: string;   // "malware" | "tool"
}

export interface MitreCampaign {
  id:   string;   // e.g. "C0001"
  name: string;
}

export interface MitreMitigation {
  id:   string;   // e.g. "M1049"
  name: string;
}

export interface MitreSection {
  groupStixId:     string;
  techniques:      MitreTechnique[];
  software:        MitreSoftware[];
  campaigns:       MitreCampaign[];
  mitigations:     MitreMitigation[];
  sectors:         string[];
  countries:       string[];
  associatedGroups: { id: string; name: string }[];
}

export interface PanelData {
  geo:        GeoSection;
  reputation: ReputationSection;
  network:    NetworkSection;
  anon:       AnonSection;
  file:       FileSection;
  detection:  DetectionSection | null;
  cve:        CveSection | null;
  mitre:      MitreSection | null;
  timeline:   TimelineEvent[];
}

// ── Builder helpers ────────────────────────────────────────────────

export function emptyPanels(): PanelData {
  return {
    geo:        { country: [], city: [], region: [], continent: [], coordinates: [], asn: [], org: [], isp: [], cidr: [], hostnames: [], registrar: [], registrantCountry: [], created: [], expires: [] },
    reputation: { verdict: [], score: [], confidence: [], summary: [], categories: [], tags: [], malwareFamily: [], threatLabel: [] },
    network:    { ports: [], services: [], ssl: [], jarm: [] },
    anon:       { vpn: [], proxy: [], tor: [], hosting: [], usageType: [] },
    file:       { name: [], type: [], size: [], md5: [], sha1: [], sha256: [], firstSeen: [], lastSeen: [], timesSubmitted: [] },
    detection:  null,
    cve:        null,
    mitre:      null,
    timeline:   [],
  };
}

function push(list: MSValue[], value: string | number | null | undefined, source: string) {
  if (value === null || value === undefined) return;
  const s = String(value).trim();
  if (!s) return;
  if (!list.some(v => v.value === s && v.source === source)) {
    list.push({ value: s, source });
  }
}

// Parse a date string or Unix timestamp (seconds or ms) to Unix ms, or null.
function toMs(raw: string | number | null | undefined): number | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'number') {
    // Heuristic: values < 1e10 are Unix seconds, larger are already ms
    return raw < 1e10 ? raw * 1000 : raw;
  }
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d.getTime();
}

function pushEvent(
  panels: PanelData,
  raw: string | number | null | undefined,
  label: string,
  source: string,
  detail?: string,
) {
  const ts = toMs(raw);
  if (!ts) return;
  // Dedupe same label+source
  if (!panels.timeline.some(e => e.label === label && e.source === source)) {
    panels.timeline.push({ ts, label, source, detail });
  }
}

// ── Per-provider extractors ────────────────────────────────────────

type Rec = Record<string, unknown>;

export function extractVtIp(attr: Rec, panels: PanelData, sourceName = 'VirusTotal'): void {
  push(panels.geo.country,   attr.country as string,   sourceName);
  push(panels.geo.continent, attr.continent as string, sourceName);
  push(panels.geo.asn,       attr.asn ? `AS${attr.asn}` : null, sourceName);
  push(panels.geo.org,       attr.as_owner as string,  sourceName);
  push(panels.geo.cidr,      attr.network as string,   sourceName);
  push(panels.network.jarm,  attr.jarm as string,      sourceName);

  const rep = attr.reputation as number | undefined;
  if (rep !== undefined) push(panels.reputation.score, String(rep), sourceName);

  const votes = attr.total_votes as Rec | undefined;
  if (votes) {
    const mal = votes.malicious as number ?? 0;
    const ok  = votes.harmless  as number ?? 0;
    push(panels.reputation.verdict, mal > 0 ? 'Malicious' : 'Clean', sourceName);
    push(panels.reputation.confidence, `${mal} malicious / ${ok} harmless votes`, sourceName);
  }

  if (Array.isArray(attr.tags)) {
    (attr.tags as string[]).forEach(t => push(panels.reputation.tags, t, sourceName));
  }

  pushEvent(panels, attr.last_analysis_date as number, 'Last analysis', sourceName);

  const stats = attr.last_analysis_stats as Rec | undefined;
  const results = attr.last_analysis_results as Record<string, Rec> | undefined;
  if (stats && results && !panels.detection) {
    panels.detection = {
      totalEngines: Object.values(stats).reduce((a: number, b) => a + (b as number), 0),
      malicious:    (stats.malicious  as number) ?? 0,
      suspicious:   (stats.suspicious as number) ?? 0,
      harmless:     (stats.harmless   as number) ?? 0,
      undetected:   (stats.undetected as number) ?? 0,
      engines: Object.entries(results).map(([engine, r]) => ({
        engine,
        category: r.category as string,
        result:   r.result as string | null,
        source:   sourceName,
      })),
      source: sourceName,
    };
  }
}

export function extractVtDomain(attr: Rec, panels: PanelData, sourceName = 'VirusTotal'): void {
  push(panels.geo.registrar, attr.registrar as string, sourceName);
  push(panels.geo.created,
    attr.creation_date ? new Date((attr.creation_date as number) * 1000).toLocaleDateString() : null,
    sourceName);
  push(panels.geo.expires,
    attr.expiration_date ? new Date((attr.expiration_date as number) * 1000).toLocaleDateString() : null,
    sourceName);
  pushEvent(panels, attr.creation_date as number, 'Domain registered', sourceName);
  pushEvent(panels, attr.last_analysis_date as number, 'Last analysis', sourceName);

  const cats = attr.categories as Record<string, string> | undefined;
  if (cats) Object.values(cats).forEach(c => push(panels.reputation.categories, c, sourceName));

  if (Array.isArray(attr.tags)) {
    (attr.tags as string[]).forEach(t => push(panels.reputation.tags, t, sourceName));
  }

  const rep = attr.reputation as number | undefined;
  if (rep !== undefined) push(panels.reputation.score, String(rep), sourceName);

  const stats = attr.last_analysis_stats as Rec | undefined;
  const results = attr.last_analysis_results as Record<string, Rec> | undefined;
  if (stats && results && !panels.detection) {
    panels.detection = {
      totalEngines: Object.values(stats).reduce((a: number, b) => a + (b as number), 0),
      malicious:    (stats.malicious  as number) ?? 0,
      suspicious:   (stats.suspicious as number) ?? 0,
      harmless:     (stats.harmless   as number) ?? 0,
      undetected:   (stats.undetected as number) ?? 0,
      engines: Object.entries(results).map(([engine, r]) => ({
        engine,
        category: r.category as string,
        result:   r.result as string | null,
        source:   sourceName,
      })),
      source: sourceName,
    };
  }
}

export function extractVtHash(attr: Rec, panels: PanelData, sourceName = 'VirusTotal'): void {
  push(panels.file.name,           attr.meaningful_name as string, sourceName);
  push(panels.file.type,           attr.type_description as string, sourceName);
  push(panels.file.size,           attr.size ? `${(attr.size as number).toLocaleString()} bytes` : null, sourceName);
  push(panels.file.md5,            attr.md5 as string,  sourceName);
  push(panels.file.sha1,           attr.sha1 as string, sourceName);
  push(panels.file.sha256,         attr.sha256 as string, sourceName);
  push(panels.file.timesSubmitted, attr.times_submitted as number, sourceName);
  push(panels.file.firstSeen,
    attr.first_submission_date ? new Date((attr.first_submission_date as number) * 1000).toLocaleDateString() : null,
    sourceName);
  pushEvent(panels, attr.first_submission_date as number, 'First submission', sourceName);
  pushEvent(panels, attr.last_submission_date as number, 'Last submission', sourceName);
  pushEvent(panels, attr.last_analysis_date as number, 'Last analysis', sourceName);

  const threat = attr.popular_threat_classification as Rec | undefined;
  if (threat) {
    push(panels.reputation.threatLabel, threat.suggested_threat_label as string, sourceName);
    const cats = threat.popular_threat_category as { value: string }[] | undefined;
    cats?.forEach(c => push(panels.reputation.categories, c.value, sourceName));
    const names = threat.popular_threat_name as { value: string }[] | undefined;
    names?.forEach(n => push(panels.reputation.malwareFamily, n.value, sourceName));
  }

  if (Array.isArray(attr.names)) {
    (attr.names as string[]).slice(0, 5).forEach(n => push(panels.file.name, n, sourceName));
  }
  if (Array.isArray(attr.tags)) {
    (attr.tags as string[]).forEach(t => push(panels.reputation.tags, t, sourceName));
  }

  const stats = attr.last_analysis_stats as Rec | undefined;
  const results = attr.last_analysis_results as Record<string, Rec> | undefined;
  if (stats && results && !panels.detection) {
    panels.detection = {
      totalEngines: Object.values(stats).reduce((a: number, b) => a + (b as number), 0),
      malicious:    (stats.malicious  as number) ?? 0,
      suspicious:   (stats.suspicious as number) ?? 0,
      harmless:     (stats.harmless   as number) ?? 0,
      undetected:   (stats.undetected as number) ?? 0,
      engines: Object.entries(results).map(([engine, r]) => ({
        engine,
        category: r.category as string,
        result:   r.result as string | null,
        source:   sourceName,
      })),
      source: sourceName,
    };
  }
}

export function extractAbuseIpDb(data: Rec, panels: PanelData, sourceName = 'AbuseIPDB'): void {
  push(panels.geo.country,   data.countryCode as string, sourceName);
  push(panels.geo.isp,       data.isp as string,         sourceName);
  push(panels.geo.org,       data.domain as string,      sourceName);
  push(panels.anon.usageType, data.usageType as string,  sourceName);
  if (Array.isArray(data.hostnames)) {
    (data.hostnames as string[]).forEach(h => push(panels.geo.hostnames, h, sourceName));
  }
  const conf = data.abuseConfidenceScore as number | undefined;
  if (conf !== undefined) {
    push(panels.reputation.confidence, `${conf}% abuse confidence`, sourceName);
    push(panels.reputation.verdict, conf > 50 ? 'Malicious' : conf > 10 ? 'Suspicious' : 'Clean', sourceName);
  }
  push(panels.anon.hosting,
    (data.isPublic === false) ? 'Private' : (data.usageType as string ?? ''),
    sourceName);
  pushEvent(panels, data.lastReportedAt as string, 'Last abuse report', sourceName,
    data.totalReports ? `${data.totalReports} total reports` : undefined);
}

export function extractShodan(data: Rec, panels: PanelData, sourceName = 'Shodan'): void {
  push(panels.geo.country,   data.country_name as string, sourceName);
  push(panels.geo.city,      data.city as string,         sourceName);
  push(panels.geo.region,    data.region_code as string,  sourceName);
  if (data.latitude && data.longitude) {
    push(panels.geo.coordinates, `${data.latitude}, ${data.longitude}`, sourceName);
  }
  push(panels.geo.org,       data.org as string,          sourceName);
  push(panels.geo.isp,       data.isp as string,          sourceName);
  push(panels.geo.asn,       data.asn as string,          sourceName);
  if (Array.isArray(data.hostnames)) {
    (data.hostnames as string[]).forEach(h => push(panels.geo.hostnames, h, sourceName));
  }
  if (Array.isArray(data.domains)) {
    (data.domains as string[]).forEach(d => push(panels.geo.hostnames, d, sourceName));
  }
  pushEvent(panels, data.last_update as string, 'Last seen', sourceName);
  if (Array.isArray(data.data)) {
    (data.data as Rec[]).slice(0, 8).forEach(svc => {
      const port = svc.port as number;
      const transport = svc.transport as string ?? 'tcp';
      const product = svc.product as string ?? '';
      push(panels.network.ports, `${port}/${transport}${product ? ` · ${product}` : ''}`, sourceName);
      if (svc.http) {
        const http = svc.http as Rec;
        push(panels.network.services, `HTTP ${(http.title as string) ?? ''}`.trim(), sourceName);
      }
      const ssl = svc.ssl as Rec | undefined;
      if (ssl?.cert) {
        const cert = ssl.cert as Rec;
        const subject = cert.subject as Rec | undefined;
        if (subject?.CN) push(panels.network.ssl, `CN=${subject.CN}`, sourceName);
      }
    });
  }
}

export function extractInternetDb(data: Rec, panels: PanelData, sourceName = 'InternetDB'): void {
  if (Array.isArray(data.hostnames)) {
    (data.hostnames as string[]).forEach(h => push(panels.geo.hostnames, h, sourceName));
  }
  if (Array.isArray(data.ports)) {
    (data.ports as number[]).forEach(p => push(panels.network.ports, `${p}/tcp`, sourceName));
  }
  if (Array.isArray(data.tags)) {
    (data.tags as string[]).forEach(t => {
      if (t === 'tor')    push(panels.anon.tor,     'Yes', sourceName);
      else if (t === 'vpn')   push(panels.anon.vpn,     'Yes', sourceName);
      else if (t === 'proxy') push(panels.anon.proxy,   'Yes', sourceName);
      else if (t === 'cdn' || t === 'cloud' || t === 'hosting') push(panels.anon.hosting, t, sourceName);
      else push(panels.network.services, t, sourceName);
    });
  }
  if (Array.isArray(data.cpes)) {
    (data.cpes as string[]).forEach(c => push(panels.network.services, c, sourceName));
  }
  if (Array.isArray(data.vulns) && (data.vulns as string[]).length > 0) {
    (data.vulns as string[]).forEach(cve => {
      push(panels.reputation.tags, `CVE: ${cve}`, sourceName);
    });
  }
}

export function extractApiVoid(data: Rec, panels: PanelData, sourceName = 'APIvoid', artifactType?: string): void {
  // APIvoid wraps all responses: { data: { report: { ... } } }
  const report = ((data.data as Rec | undefined)?.report ?? data) as Rec;

  // IP reputation response
  if (artifactType === 'ip') {
    const info = report.information as Rec | undefined;
    const bl   = report.blacklists as Rec | undefined;
    const anon = report.anonymity  as Rec | undefined;
    const risk = report.risk_score as Rec | undefined;
    const asn  = report.asn        as Rec | undefined;

    if (info) {
      push(panels.geo.country,     info.country_name  as string, sourceName);
      push(panels.geo.city,        info.city_name     as string, sourceName);
      push(panels.geo.region,      info.region_name   as string, sourceName);
      push(panels.geo.isp,         info.isp           as string, sourceName);
      push(panels.geo.org,         info.reverse_dns   as string, sourceName);
      if (info.latitude && info.longitude) {
        push(panels.geo.coordinates, `${info.latitude}, ${info.longitude}`, sourceName);
      } else if (info.coordinates) {
        push(panels.geo.coordinates, info.coordinates as string, sourceName);
      }
    }
    if (asn) {
      push(panels.geo.asn, `${asn.number ?? ''} ${asn.organization ?? ''}`.trim(), sourceName);
    }
    if (bl) {
      const det  = bl.detections  as number ?? 0;
      const tot  = bl.engines_count as number ?? 0;
      const rate = bl.detection_rate as string ?? '';
      if (tot > 0) push(panels.reputation.score, `${det}/${tot} blacklists (${rate})`, sourceName);
    }
    if (risk) push(panels.reputation.score, `Risk: ${risk.result}/100`, sourceName);
    if (anon) {
      if (anon.is_vpn)   push(panels.anon.vpn,     'Yes', sourceName);
      if (anon.is_proxy) push(panels.anon.proxy,   'Yes', sourceName);
      if (anon.is_tor)   push(panels.anon.tor,     'Yes', sourceName);
      if (anon.is_hosting || anon.is_relay) push(panels.anon.hosting, 'Yes', sourceName);
    }
    return;
  }

  // Domain reputation response (wrapped object: { reputation, age, ssl })
  if (artifactType === 'domain') {
    const rep = data.reputation as Rec | undefined;  // composite shape passed directly from fetcher
    const age = data.age        as Rec | undefined;
    const ssl = data.ssl        as Rec | undefined;

    if (rep) {
      const bl   = rep.blacklists   as Rec | undefined;
      const srv  = rep.server_details as Rec | undefined;
      const risk = rep.risk_score   as Rec | undefined;
      const cat  = rep.category     as Rec | undefined;
      if (bl) {
        const det  = bl.detections   as number ?? 0;
        const tot  = bl.engines_count as number ?? 0;
        const rate = bl.detection_rate as string ?? '';
        if (tot > 0) push(panels.reputation.score, `${det}/${tot} blacklists (${rate})`, sourceName);
      }
      if (risk) push(panels.reputation.score, `Risk: ${risk.result}/100`, sourceName);
      if (srv) {
        push(panels.geo.country, srv.country_name as string, sourceName);
        push(panels.geo.city,    srv.city_name    as string, sourceName);
        push(panels.geo.isp,     srv.isp          as string, sourceName);
        push(panels.geo.asn,     srv.asn          as string, sourceName);
      }
      if (cat) {
        if (cat.is_free_hosting)    push(panels.anon.hosting,  'Free Hosting',    sourceName);
        if (cat.is_anonymizer)      push(panels.anon.proxy,    'Yes',             sourceName);
        if (cat.is_url_shortener)   push(panels.network.services, 'URL Shortener', sourceName);
        if (cat.is_free_dynamic_dns) push(panels.network.services, 'Dynamic DNS',  sourceName);
        if (cat.is_pastebin)        push(panels.network.services, 'Pastebin',      sourceName);
      }
    }
    if (age?.domain_age_found) {
      push(panels.network.services, `Domain age: ${age.domain_age_in_years}y (${age.domain_creation_date})`, sourceName);
    }
    if (ssl) {
      const cert = ssl.certificate as Rec | undefined;
      if (cert?.found) {
        const det  = cert.details  as Rec | undefined;
        const subj = det?.subject  as Rec | undefined;
        const val  = det?.validity as Rec | undefined;
        if (subj?.common_name) push(panels.network.ssl, `CN=${subj.common_name}`, sourceName);
        if (val?.valid_to)     push(panels.network.ssl, `Expires: ${val.valid_to}`, sourceName);
        if (cert.expired)      push(panels.reputation.tags, 'SSL expired', sourceName);
        if (cert.revoked)      push(panels.reputation.tags, 'SSL revoked', sourceName);
      }
    }
    return;
  }

  // URL reputation response
  if (artifactType === 'url') {
    const bl   = report.domain_blacklist as Rec | undefined;
    const risk = report.risk_score       as Rec | undefined;
    const redir = report.redirection     as Rec | undefined;
    const srv  = report.server_details   as Rec | undefined;
    if (bl) {
      const det  = bl.detections   as number ?? 0;
      const tot  = bl.engines_count as number ?? 0;
      const rate = bl.detection_rate as string ?? '';
      if (tot > 0) push(panels.reputation.score, `${det}/${tot} blacklists (${rate})`, sourceName);
    }
    if (risk) push(panels.reputation.score, `Risk: ${risk.result}/100`, sourceName);
    if (redir?.detected) push(panels.network.services, `Redirects to: ${redir.url}`, sourceName);
    if (srv) {
      push(panels.geo.country, srv.country_name as string, sourceName);
      push(panels.geo.isp,     srv.isp          as string, sourceName);
    }
  }
}

export function extractMaxMind(data: Rec, panels: PanelData, sourceName = 'MaxMind'): void {
  const city       = data.city       as Rec | undefined;
  const country    = data.country    as Rec | undefined;
  const location   = data.location   as Rec | undefined;
  const traits     = data.traits     as Rec | undefined;
  const subs       = data.subdivisions as Rec[] | undefined;

  push(panels.geo.country,     (country?.names  as Rec)?.en as string, sourceName);
  push(panels.geo.city,        (city?.names     as Rec)?.en as string, sourceName);
  push(panels.geo.region,      subs?.[0] ? ((subs[0].names as Rec)?.en as string) : null, sourceName);
  if (location?.latitude && location?.longitude) {
    push(panels.geo.coordinates, `${location.latitude}, ${location.longitude}`, sourceName);
  }
  push(panels.geo.isp,         traits?.isp          as string, sourceName);
  push(panels.geo.org,         traits?.organization as string, sourceName);
  push(panels.geo.asn,         traits?.autonomous_system_number ? `AS${traits.autonomous_system_number}` : null, sourceName);

  if (traits?.is_anonymous_vpn)     push(panels.anon.vpn,     'Yes', sourceName);
  if (traits?.is_anonymous_proxy)   push(panels.anon.proxy,   'Yes', sourceName);
  if (traits?.is_hosting_provider)  push(panels.anon.hosting, 'Yes', sourceName);
}

export function extractGreyNoise(data: Rec, panels: PanelData, sourceName = 'GreyNoise'): void {
  // Geo (paid context tier)
  push(panels.geo.country,  data.country      as string, sourceName);
  push(panels.geo.city,     data.city         as string, sourceName);
  push(panels.geo.org,      data.organization as string, sourceName);
  push(panels.geo.asn,      data.asn          as string, sourceName);

  // Reputation — paid classification
  const classification = data.classification as string | undefined;
  if (classification) {
    push(panels.reputation.verdict,
      classification === 'malicious' ? 'Malicious' :
      classification === 'benign'    ? 'Clean'     : 'Unknown',
      sourceName);
  }

  // Tags (paid)
  if (Array.isArray(data.tags)) {
    (data.tags as string[]).forEach(t => push(panels.reputation.tags, t, sourceName));
  }

  // Anonymization (paid)
  if (data.vpn) push(panels.anon.vpn, `Yes${data.vpn_service ? ` – ${data.vpn_service}` : ''}`, sourceName);
  if (data.tor) push(panels.anon.tor, 'Yes', sourceName);

  // Metadata (paid)
  const meta = data.metadata as Rec | undefined;
  if (meta) {
    push(panels.geo.country, meta.country as string, sourceName);
    push(panels.geo.city,    meta.city    as string, sourceName);
    push(panels.geo.org,     meta.organization as string, sourceName);
    push(panels.geo.asn,     meta.asn     as string, sourceName);
    if (meta.tor) push(panels.anon.tor, 'Yes', sourceName);
  }

  pushEvent(panels, data.first_seen as string, 'First seen', sourceName);
  pushEvent(panels, data.last_seen  as string, 'Last seen',  sourceName);

  // Community tier fallback fields
  if (data.riot)  push(panels.reputation.tags, 'RIOT – known benign service', sourceName);
  if (data.noise) push(panels.reputation.tags, 'Internet background noise / scanner', sourceName);
  const msg = data.message as string | undefined;
  if (msg && !classification) {
    push(panels.reputation.tags, `GreyNoise: ${msg}`, sourceName);
  }
}

export function extractSpur(data: Rec, panels: PanelData, sourceName = 'Spur'): void {
  const as = data.as as Rec | undefined;
  if (as) {
    push(panels.geo.asn, as.number ? `AS${as.number}` : null, sourceName);
    push(panels.geo.org, as.organization as string, sourceName);
  }
  const client = data.client as Rec | undefined;
  if (client?.countries) {
    (client.countries as string[]).slice(0, 2).forEach(c => push(panels.geo.country, c, sourceName));
  }
  const tunnels = data.tunnels as Rec[] | undefined;
  tunnels?.forEach(t => {
    const type = (t.type as string)?.toLowerCase();
    const op   = t.operator as string ?? '';
    if (type === 'vpn')      push(panels.anon.vpn,   `Yes${op ? ` – ${op}` : ''}`, sourceName);
    if (type === 'proxy')    push(panels.anon.proxy,  `Yes${op ? ` – ${op}` : ''}`, sourceName);
    if (type === 'tor')      push(panels.anon.tor,    'Yes', sourceName);
    if (type === 'hosting')  push(panels.anon.hosting,'Yes', sourceName);
  });
}

export function extractWhoisRdap(data: Rec, panels: PanelData, sourceName = 'WHOIS'): void {
  const events = data.events as Rec[] | undefined;
  if (events) {
    const reg = events.find(e => e.eventAction === 'registration');
    const exp = events.find(e => e.eventAction === 'expiration');
    const upd = events.find(e => e.eventAction === 'last changed');
    if (reg) { push(panels.geo.created, new Date(reg.eventDate as string).toLocaleDateString(), sourceName); pushEvent(panels, reg.eventDate as string, 'Registered', sourceName); }
    if (exp) { push(panels.geo.expires, new Date(exp.eventDate as string).toLocaleDateString(), sourceName); pushEvent(panels, exp.eventDate as string, 'Expires', sourceName); }
    if (upd) pushEvent(panels, upd.eventDate as string, 'Last updated', sourceName);
  }

  // Domain: nameservers
  const ns = data.nameservers as Rec[] | undefined;
  if (ns) ns.slice(0, 4).forEach(n => push(panels.geo.hostnames, n.ldhName as string, sourceName));

  const entities = data.entities as Rec[] | undefined;
  entities?.forEach(e => {
    const roles = e.roles as string[] | undefined;

    // Domain: registrar
    if (roles?.includes('registrar')) {
      const publicIds = e.publicIds as Rec[] | undefined;
      if (publicIds?.length) push(panels.geo.registrar, publicIds[0].identifier as string, sourceName);
      else push(panels.geo.registrar, e.handle as string, sourceName);
    }

    // IP: registrant org name from vCard
    if (roles?.includes('registrant')) {
      const vcard = e.vcardArray as [string, unknown[][]] | undefined;
      if (vcard?.[1]) {
        const fn = (vcard[1] as unknown[]).find((f: unknown) => Array.isArray(f) && (f as unknown[])[0] === 'fn') as unknown[] | undefined;
        if (fn) push(panels.geo.org, fn[3] as string, sourceName);
      }
    }
  });

  // IP: CIDR block
  const cidrs = data.cidr0_cidrs as Rec[] | undefined;
  cidrs?.slice(0, 2).forEach(c => {
    if (c.v4prefix && c.length) push(panels.geo.cidr, `${c.v4prefix}/${c.length}`, sourceName);
    if (c.v6prefix && c.length) push(panels.geo.cidr, `${c.v6prefix}/${c.length}`, sourceName);
  });

  // IP: country from handle or name
  if (data.country) push(panels.geo.country, data.country as string, sourceName);
}

export function extractUrlhaus(data: Rec, panels: PanelData, sourceName = 'URLhaus'): void {
  const status = data.query_status as string | undefined;
  if (!status || status === 'no_results') return;

  // URL lookup
  const urlStatus = data.url_status as string | undefined;
  const threat    = data.threat    as string | undefined;
  if (urlStatus) {
    push(panels.reputation.verdict,
      urlStatus === 'online' ? 'Malicious' : 'Suspicious',
      sourceName);
  }
  if (threat) push(panels.reputation.categories, threat.replace(/_/g, ' '), sourceName);

  const tags = data.tags as string[] | undefined;
  if (Array.isArray(tags)) tags.forEach(t => push(panels.reputation.tags, t, sourceName));

  // Host lookup — aggregate across URLs
  const urls = data.urls as Rec[] | undefined;
  if (Array.isArray(urls) && urls.length > 0) {
    const online = urls.filter(u => (u.url_status as string) === 'online').length;
    push(panels.reputation.verdict, online > 0 ? 'Malicious' : 'Suspicious', sourceName);
    push(panels.reputation.confidence, `${online} of ${urls.length} URLs currently online`, sourceName);
    urls.slice(0, 3).forEach(u => {
      const t = u.threat as string | undefined;
      if (t) push(panels.reputation.categories, t.replace(/_/g, ' '), sourceName);
      const utags = u.tags as string[] | undefined;
      if (Array.isArray(utags)) utags.forEach(tag => push(panels.reputation.tags, tag, sourceName));
    });
  }

  // Hash (payload) lookup
  const fileType = data.file_type as string | undefined;
  const fileSize = data.file_size as number | undefined;
  const sig      = data.signature as string | undefined;
  const firstseen = data.firstseen as string | undefined;
  if (fileType) push(panels.file.type, fileType, sourceName);
  if (fileSize) push(panels.file.size, `${fileSize.toLocaleString()} bytes`, sourceName);
  if (sig)      push(panels.reputation.malwareFamily, sig, sourceName);
  if (firstseen) push(panels.file.firstSeen, new Date(firstseen).toLocaleDateString(), sourceName);
  pushEvent(panels, firstseen, 'First seen', sourceName);
  pushEvent(panels, data.date_added as string, 'Added to URLhaus', sourceName);
  if (data.md5_hash)    push(panels.file.md5,    data.md5_hash    as string, sourceName);
  if (data.sha256_hash) push(panels.file.sha256, data.sha256_hash as string, sourceName);
}

export function extractMalwareBazaar(data: Rec, panels: PanelData, sourceName = 'MalwareBazaar'): void {
  const status = data.query_status as string | undefined;
  if (!status || status === 'hash_not_found') return;

  const items = data.data as Rec[] | undefined;
  const item = Array.isArray(items) ? items[0] : undefined;
  if (!item) return;

  const fileType = item.file_type as string | undefined;
  const fileSize = item.file_size as number | undefined;
  const sig      = item.signature as string | undefined;
  const firstseen = item.first_seen as string | undefined;
  const lastSeen  = item.last_seen  as string | undefined;

  if (fileType) push(panels.file.type,     fileType, sourceName);
  if (fileSize) push(panels.file.size,     `${fileSize.toLocaleString()} bytes`, sourceName);
  if (sig)      push(panels.reputation.malwareFamily, sig, sourceName);
  if (firstseen) push(panels.file.firstSeen, new Date(firstseen).toLocaleDateString(), sourceName);
  if (lastSeen)  push(panels.file.lastSeen,  new Date(lastSeen).toLocaleDateString(),  sourceName);
  pushEvent(panels, firstseen, 'First seen', sourceName);
  pushEvent(panels, lastSeen,  'Last seen',  sourceName);

  if (item.md5_hash)    push(panels.file.md5,    item.md5_hash    as string, sourceName);
  if (item.sha1_hash)   push(panels.file.sha1,   item.sha1_hash   as string, sourceName);
  if (item.sha256_hash) push(panels.file.sha256, item.sha256_hash as string, sourceName);

  const tags = item.tags as string[] | undefined;
  if (Array.isArray(tags)) tags.forEach(t => push(panels.reputation.tags, t, sourceName));

  push(panels.reputation.verdict, 'Malicious', sourceName);

  const deliveries = item.delivery_method as string | undefined;
  if (deliveries) push(panels.reputation.categories, deliveries, sourceName);

  const originCountry = item.origin_country as string | undefined;
  if (originCountry) push(panels.geo.country, originCountry, sourceName);

  const intelligence = item.intelligence as Rec | undefined;
  if (intelligence) {
    const downloads = intelligence.downloads as number | undefined;
    const uploads   = intelligence.uploads   as number | undefined;
    if (downloads != null) push(panels.reputation.confidence, `${downloads} downloads`, sourceName);
    if (uploads   != null) push(panels.reputation.confidence, `${uploads} uploads`,   sourceName);
  }
}

export function extractThreatFox(data: Rec, panels: PanelData, sourceName = 'ThreatFox'): void {
  const status = data.query_status as string | undefined;
  if (!status || status === 'no_results') return;

  const items = data.data as Rec[] | undefined;
  if (!Array.isArray(items) || items.length === 0) return;

  push(panels.reputation.verdict, 'Malicious', sourceName);

  const seen = new Set<string>();
  for (const ioc of items.slice(0, 5)) {
    const malware   = ioc.malware      as string | undefined;
    const mwAlias   = ioc.malware_alias as string | undefined;
    const threat    = ioc.threat_type  as string | undefined;
    const confidence = ioc.confidence_level as number | undefined;
    const firstseen = ioc.first_seen   as string | undefined;
    const lastseen  = ioc.last_seen    as string | undefined;
    const tags      = ioc.tags         as string[] | undefined;
    const reporter  = ioc.reporter     as string | undefined;

    if (malware && !seen.has(malware)) {
      seen.add(malware);
      push(panels.reputation.malwareFamily, mwAlias ? `${malware} (${mwAlias})` : malware, sourceName);
    }
    if (threat)      push(panels.reputation.categories, threat,                  sourceName);
    if (confidence)  push(panels.reputation.confidence, `${confidence}% confidence`, sourceName);
    if (firstseen)   push(panels.file.firstSeen, new Date(firstseen).toLocaleDateString(), sourceName);
    if (lastseen)    push(panels.file.lastSeen,  new Date(lastseen).toLocaleDateString(),  sourceName);
    pushEvent(panels, firstseen, 'First seen', sourceName, malware ?? undefined);
    pushEvent(panels, lastseen,  'Last seen',  sourceName, malware ?? undefined);
    if (reporter)    push(panels.reputation.tags, `Reported by: ${reporter}`, sourceName);
    if (Array.isArray(tags)) tags.forEach(t => push(panels.reputation.tags, t, sourceName));
  }
}

export function extractSpamhaus(data: Rec, panels: PanelData, sourceName = 'Spamhaus'): void {
  const results = data.results as Array<{ list: string; status: number; data: unknown }> | undefined;
  if (!Array.isArray(results)) return;

  const listLabels: Record<string, string> = {
    sbl: 'SBL (spam source)',
    xbl: 'XBL (exploited)',
    pbl: 'PBL (policy block)',
    css: 'CSS (snowshoe spam)',
    dbl: 'DBL (domain block)',
    zrd: 'ZRD (zero-reputation domain)',
  };

  const hits = results.filter(r => r.status === 200);
  const clean = results.filter(r => r.status === 404);

  if (hits.length > 0) {
    push(panels.reputation.verdict, 'Blacklisted', sourceName);
    hits.forEach(r => push(panels.reputation.categories, listLabels[r.list] ?? r.list, sourceName));
  } else if (clean.length > 0) {
    push(panels.reputation.verdict, 'Clean', sourceName);
  }

  const total = results.filter(r => r.status === 200 || r.status === 404).length;
  if (total > 0) {
    push(panels.reputation.confidence, `${hits.length}/${total} Spamhaus lists matched`, sourceName);
  }
}

// ── Panel presence helpers ─────────────────────────────────────────

export function hasGeo(p: PanelData): boolean {
  const g = p.geo;
  return !!(g.country.length || g.city.length || g.asn.length || g.org.length ||
            g.registrar.length || g.created.length || g.hostnames.length);
}
export function hasReputation(p: PanelData): boolean {
  const r = p.reputation;
  return !!(r.verdict.length || r.confidence.length || r.categories.length || r.tags.length || r.malwareFamily.length || r.threatLabel.length);
}
export function hasNetwork(p: PanelData): boolean {
  return !!(p.network.ports.length || p.network.services.length || p.network.ssl.length || p.network.jarm.length);
}
export function hasAnon(p: PanelData): boolean {
  const a = p.anon;
  return !!(a.vpn.length || a.proxy.length || a.tor.length || a.hosting.length || a.usageType.length);
}
export function hasFile(p: PanelData): boolean {
  const f = p.file;
  return !!(f.name.length || f.type.length || f.md5.length || f.sha256.length);
}
export function hasCve(p: PanelData): boolean {
  return !!(p.cve && p.cve.entries.length > 0);
}
export function hasTimeline(p: PanelData): boolean {
  return p.timeline.length >= 2;
}

// ── CIRCL CVE extractor ────────────────────────────────────────────
// Handles two response shapes:
//   1. Array of CVE objects  — from /api/search/vendor/product
//   2. Single CVE object     — from /api/cve/CVE-ID

function parseCveEntry(raw: Rec, sourceName: string): CveEntry {
  // Detect CVE 5.x format (containers/cveMetadata) vs legacy v4 format
  const isV5 = !!(raw.cveMetadata || raw.containers);

  let id: string;
  let summary: string;
  let cvss: number | null = null;
  let cvss3: number | null = null;
  let published: string;
  let modified: string;
  let refs: string[] = [];
  let cweList: string[] = [];
  let capecList: string[] = [];
  const vulnerable: string[] = [];

  if (isV5) {
    const meta       = raw.cveMetadata as Rec | undefined;
    const containers = raw.containers  as Rec | undefined;
    const cna        = containers?.cna as Rec | undefined;
    const adpArr     = (containers?.adp as Rec[] | undefined) ?? [];

    id        = (meta?.cveId as string) ?? '';
    published = (meta?.datePublished as string) ?? '';
    modified  = (meta?.dateUpdated   as string) ?? '';

    const descs = cna?.descriptions as Rec[] | undefined;
    summary = (descs?.[0]?.value as string) ?? '';

    // CVSS: look in adp first, then cna
    const allMetrics: Rec[] = [];
    adpArr.forEach(a => { if (Array.isArray(a.metrics)) allMetrics.push(...(a.metrics as Rec[])); });
    if (Array.isArray(cna?.metrics)) allMetrics.push(...((cna!.metrics as Rec[])));

    for (const m of allMetrics) {
      const v3 = (m.cvssV3_1 ?? m.cvssV3_0) as Rec | undefined;
      const v2 = m.cvssV2_0 as Rec | undefined;
      if (v3?.baseScore) { cvss3 = v3.baseScore as number; break; }
      if (v2?.baseScore && cvss === null) cvss = v2.baseScore as number;
    }

    // References
    const cnaRefs = cna?.references as Rec[] | undefined;
    if (cnaRefs) refs = cnaRefs.slice(0, 8).map(r => r.url as string).filter(Boolean);

    // CWE from adp problemTypes
    adpArr.forEach(a => {
      const pts = a.problemTypes as Rec[] | undefined;
      pts?.forEach(pt => {
        const descs2 = pt.descriptions as Rec[] | undefined;
        descs2?.forEach(d => { if (d.cweId) cweList.push(d.cweId as string); });
      });
    });

    // Vulnerable configurations from affected
    const affected = cna?.affected as Rec[] | undefined;
    affected?.slice(0, 4).forEach(a => {
      const vendor  = a.vendor  as string ?? '';
      const product = a.product as string ?? '';
      if (vendor && product) vulnerable.push(`${vendor}:${product}`);
    });

    // Fall back to x_legacyV4Record for richer legacy data if nothing above
    const legacy = cna?.x_legacyV4Record as Rec | undefined;
    if (legacy) {
      if (!summary) summary = ((legacy.description as Rec)?.description_data as Rec[])?.[0]?.value as string ?? '';
      if (cweList.length === 0) {
        const ptd = (legacy.problemtype as Rec)?.problemtype_data as Rec[] | undefined;
        ptd?.forEach(p => (p.description as Rec[])?.forEach(d => { if (d.value) cweList.push(String(d.value)); }));
      }
    }
  } else {
    // Legacy v4 flat format (older CIRCL API responses)
    id        = (raw.id ?? raw['cve-id'] ?? '') as string;
    summary   = (raw.summary ?? '') as string;
    cvss      = raw.cvss  as number ?? null;
    cvss3     = (raw.cvss3 as Rec | undefined)?.['base_score'] as number ?? null;
    published = (raw.Published ?? raw.published ?? '') as string;
    modified  = (raw.Modified  ?? raw.modified  ?? '') as string;

    refs = Array.isArray(raw.references) ? (raw.references as string[]).slice(0, 6) : [];
    cweList = Array.isArray(raw.cwe) ? (raw.cwe as string[]) : raw.cwe ? [String(raw.cwe)] : [];
    capecList = Array.isArray(raw.capec)
      ? (raw.capec as Rec[]).map(c => `CAPEC-${c.id ?? ''}`)
      : [];
    const configs = raw.vulnerable_configuration as Rec[] | undefined;
    configs?.slice(0, 5).forEach(c => { if (c.id) vulnerable.push(c.id as string); });
  }

  const score = cvss3 ?? cvss;
  const severity = score === null ? 'NONE'
    : score >= 9.0 ? 'CRITICAL'
    : score >= 7.0 ? 'HIGH'
    : score >= 4.0 ? 'MEDIUM'
    : 'LOW';

  return {
    id, summary, cvss, cvss3, severity,
    published, modified,
    references: refs,
    cwe:        cweList,
    capec:      capecList,
    vulnerable,
    source: sourceName,
  };
}

export function extractCirclCve(
  data: unknown,
  query: string,
  panels: PanelData,
  sourceName = 'CIRCL'
): void {
  const entries: CveEntry[] = [];

  if (Array.isArray(data)) {
    // /api/search response — array of CVE objects
    (data as Rec[]).forEach(raw => entries.push(parseCveEntry(raw, sourceName)));
  } else if (data && typeof data === 'object') {
    const d = data as Rec;
    // CVE 5.x format, legacy v4 flat format, or wrapped { data: [...] }
    if (d.id || d['cve-id'] || d.cveMetadata || d.containers) {
      entries.push(parseCveEntry(d, sourceName));
    } else if (d.data && Array.isArray(d.data)) {
      (d.data as Rec[]).forEach(raw => entries.push(parseCveEntry(raw, sourceName)));
    }
  }

  if (entries.length) {
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };
    entries.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    panels.cve = { query, entries };
  }
}

// ── NVD extractor ──────────────────────────────────────────────────
// Handles NVD API v2 response: { totalResults, vulnerabilities: [{ cve: {...} }] }

export function extractNvd(
  data: unknown,
  query: string,
  panels: PanelData,
  sourceName = 'NVD'
): void {
  const d = data as Rec;
  const vulns = d.vulnerabilities as Rec[] | undefined;
  if (!vulns?.length) return;

  const entries: CveEntry[] = vulns.map(v => {
    const cve = v.cve as Rec;
    const id = cve.id as string ?? '';

    const descs = cve.descriptions as Rec[] | undefined;
    const summary = descs?.find(d => d.lang === 'en')?.value as string ?? '';

    const published = cve.published as string ?? '';
    const modified  = cve.lastModified as string ?? '';

    // CVSS — prefer v3.1, fall back to v3.0, then v2
    let cvss3: number | null = null;
    let cvss: number | null = null;
    const metricsV31 = (cve.metrics as Rec)?.cvssMetricV31 as Rec[] | undefined;
    const metricsV30 = (cve.metrics as Rec)?.cvssMetricV30 as Rec[] | undefined;
    const metricsV2  = (cve.metrics as Rec)?.cvssMetricV2  as Rec[] | undefined;
    const v31 = metricsV31?.[0]?.cvssData as Rec | undefined;
    const v30 = metricsV30?.[0]?.cvssData as Rec | undefined;
    const v2  = metricsV2?.[0]?.cvssData  as Rec | undefined;
    if (v31?.baseScore) cvss3 = v31.baseScore as number;
    else if (v30?.baseScore) cvss3 = v30.baseScore as number;
    if (v2?.baseScore) cvss = v2.baseScore as number;

    const score = cvss3 ?? cvss;
    const severity = score === null ? 'NONE'
      : score >= 9.0 ? 'CRITICAL'
      : score >= 7.0 ? 'HIGH'
      : score >= 4.0 ? 'MEDIUM'
      : 'LOW';

    const status = cve.vulnStatus as string | undefined;

    // Rich references with tags
    const richRefs: CveReference[] = (cve.references as Rec[] | undefined)?.slice(0, 12).map(r => ({
      url:  r.url as string ?? '',
      tags: Array.isArray(r.tags) ? (r.tags as string[]) : [],
    })).filter(r => r.url) ?? [];
    const refs = richRefs.map(r => r.url);

    // Weaknesses
    const weaknesses = cve.weaknesses as Rec[] | undefined;
    const cweList: string[] = [];
    const cweDescList: string[] = [];
    weaknesses?.forEach(w => {
      (w.description as Rec[] | undefined)?.forEach(d => {
        const val = d.value as string;
        if (val?.startsWith('CWE-')) cweList.push(val);
        else if (val) cweDescList.push(val);
      });
    });

    // CVSS detail from best available metric
    const bestMetric = metricsV31?.[0] ?? metricsV30?.[0];
    const bestData = bestMetric?.cvssData as Rec | undefined;
    const cvssDetail: CvssDetail | undefined = bestData ? {
      version:             bestData.version as string ?? '',
      vectorString:        bestData.vectorString as string ?? '',
      attackVector:        bestData.attackVector as string | undefined,
      attackComplexity:    bestData.attackComplexity as string | undefined,
      privilegesRequired:  bestData.privilegesRequired as string | undefined,
      userInteraction:     bestData.userInteraction as string | undefined,
      scope:               bestData.scope as string | undefined,
      confidentiality:     bestData.confidentialityImpact as string | undefined,
      integrity:           bestData.integrityImpact as string | undefined,
      availability:        bestData.availabilityImpact as string | undefined,
      exploitabilityScore: bestMetric?.exploitabilityScore as number | undefined,
      impactScore:         bestMetric?.impactScore as number | undefined,
    } : undefined;

    // Affected versions — configurations lives on v, not v.cve
    const affected: AffectedVersion[] = [];
    const configs = (v.configurations ?? cve.configurations) as Rec[] | undefined;
    configs?.forEach(cfg => {
      (cfg.nodes as Rec[] | undefined)?.forEach(node => {
        (node.cpeMatch as Rec[] | undefined)?.filter(m => m.vulnerable).forEach(m => {
          const cpe = m.criteria as string ?? '';
          const parts = cpe.split(':');
          const vendor  = parts[3] ?? '';
          const product = parts[4] ?? '';
          const ranges: string[] = [];
          if (m.versionStartIncluding) ranges.push(`>= ${m.versionStartIncluding}`);
          if (m.versionStartExcluding) ranges.push(`> ${m.versionStartExcluding}`);
          if (m.versionEndIncluding)   ranges.push(`<= ${m.versionEndIncluding}`);
          if (m.versionEndExcluding)   ranges.push(`< ${m.versionEndExcluding}`);
          if (!ranges.length && parts[5] && parts[5] !== '*') ranges.push(`= ${parts[5]}`);
          const versions = ranges.join(', ') || 'all versions';
          if (vendor && product) {
            const existing = affected.find(a => a.vendor === vendor && a.product === product && a.versions === versions);
            if (!existing) affected.push({ vendor, product, versions });
          }
        });
      });
    });

    // CISA KEV fields — surface as structured data
    const cisaName    = cve.cisaVulnerabilityName as string | undefined;
    const cisaAdded   = cve.cisaExploitAdd        as string | undefined;
    const cisaDue     = cve.cisaActionDue          as string | undefined;
    const cisaRequired = cve.cisaRequiredAction   as string | undefined;

    const summaryFull = [
      summary,
      cisaName    ? `CISA KEV: ${cisaName}`          : '',
      cisaAdded   ? `KEV added: ${cisaAdded}`         : '',
      cisaDue     ? `Remediation due: ${cisaDue}`     : '',
      cisaRequired ? `Action: ${cisaRequired}`        : '',
    ].filter(Boolean).join(' · ');

    // Extract related CVE IDs mentioned in description or reference URLs
    const cvePattern = /CVE-\d{4}-\d{4,}/g;
    const relatedSet = new Set<string>();
    [...(summary.matchAll(cvePattern))].forEach(m => relatedSet.add(m[0]));
    richRefs.forEach(r => [...(r.url.matchAll(cvePattern))].forEach(m => relatedSet.add(m[0])));
    relatedSet.delete(id); // don't include self
    const relatedCves = [...relatedSet];

    return {
      id, summary: summaryFull, cvss, cvss3, severity,
      published, modified, status,
      references: refs, richRefs,
      cvssDetail, affected,
      cwe: cweList, cweDesc: cweDescList, capec: [], vulnerable: [],
      relatedCves: relatedCves.length ? relatedCves : undefined,
      source: sourceName,
    };
  });

  if (entries.length) {
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };
    entries.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    if (panels.cve) {
      // Merge with existing entries from CIRCL, dedup by id
      const existing = new Set(panels.cve.entries.map(e => e.id));
      panels.cve.entries.push(...entries.filter(e => !existing.has(e.id)));
      panels.cve.entries.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    } else {
      panels.cve = { query, entries };
    }
  }
}

// ── MalShare extractor ─────────────────────────────────────────────
// Response shape: { md5, sha1, sha256, filetype, sources: string[], yarahits: string[] }
export function extractMalShare(data: Rec, panels: PanelData, sourceName = 'MalShare'): void {
  if (!data || typeof data !== 'object') return;

  if (data.md5)      push(panels.file.md5,    data.md5    as string, sourceName);
  if (data.sha1)     push(panels.file.sha1,   data.sha1   as string, sourceName);
  if (data.sha256)   push(panels.file.sha256, data.sha256 as string, sourceName);
  if (data.filetype) push(panels.file.type,   data.filetype as string, sourceName);

  push(panels.reputation.verdict, 'Malicious', sourceName);

  const sources = data.sources as string[] | undefined;
  if (Array.isArray(sources)) {
    sources.forEach(s => push(panels.reputation.tags, `Source: ${s}`, sourceName));
  }

  const yarahits = data.yarahits as string[] | undefined;
  if (Array.isArray(yarahits)) {
    yarahits.forEach(y => push(panels.reputation.tags, `YARA: ${y}`, sourceName));
  }
}

// ── Hybrid Analysis extractor ──────────────────────────────────────
// Response from /api/v2/search/hash or /api/v2/search/terms:
// { count, result: [{ verdict, threat_score, threat_level, sha256, md5, type, type_short,
//                     submit_name, file_type, file_size, analysis_start_time,
//                     tags, vx_family, threat_metadata, ... }] }
export function extractHybridAnalysis(data: Rec, panels: PanelData, sourceName = 'Hybrid Analysis'): void {
  const results = data.result as Rec[] | undefined;
  if (!Array.isArray(results) || results.length === 0) return;

  const item = results[0];

  const verdict     = item.verdict      as string | undefined;
  const threatScore = item.threat_score as number | undefined;
  const vxFamily    = item.vx_family    as string | undefined;
  const submitName  = item.submit_name  as string | undefined;
  const fileType    = item.file_type    as string | undefined;
  const fileSize    = item.file_size    as number | undefined;
  const sha256      = item.sha256       as string | undefined;
  const md5         = item.md5          as string | undefined;
  const analysisTs  = item.analysis_start_time as string | undefined;
  const tags        = item.tags         as string[] | undefined;

  if (verdict)     push(panels.reputation.verdict, verdict.charAt(0).toUpperCase() + verdict.slice(1), sourceName);
  if (threatScore != null) push(panels.reputation.score, `${threatScore}/100`, sourceName);
  if (vxFamily)    push(panels.reputation.malwareFamily, vxFamily, sourceName);
  if (submitName)  push(panels.file.name, submitName, sourceName);
  if (fileType)    push(panels.file.type, fileType, sourceName);
  if (fileSize)    push(panels.file.size, `${fileSize.toLocaleString()} bytes`, sourceName);
  if (sha256)      push(panels.file.sha256, sha256, sourceName);
  if (md5)         push(panels.file.md5, md5, sourceName);

  if (analysisTs) {
    pushEvent(panels, analysisTs, 'Sandbox analysis', sourceName, vxFamily ?? undefined);
  }

  if (Array.isArray(tags)) {
    tags.forEach(t => push(panels.reputation.tags, t, sourceName));
  }

  // Pull threat metadata from additional result entries if present
  const meta = item.threat_metadata as Rec | undefined;
  if (meta) {
    const threatName = meta.threat_name as string | undefined;
    if (threatName) push(panels.reputation.malwareFamily, threatName, sourceName);
  }
}

// ── IPQS extractor ─────────────────────────────────────────────────
// Handles both Proxy Detection (IP) and Malicious URL Scanner (URL/domain)
export function extractIpqs(data: Rec, panels: PanelData, artifactType: string, sourceName = 'IPQS'): void {
  if (!data || typeof data !== 'object') return;
  if (data.success === false) return;

  const fraudScore = data.fraud_score as number | undefined;
  if (fraudScore != null) push(panels.reputation.score, `${fraudScore}/100 fraud score`, sourceName);

  if (artifactType === 'ip') {
    // Proxy Detection API fields
    const vpn   = data.vpn   as boolean | undefined;
    const proxy = data.proxy as boolean | undefined;
    const tor   = data.tor   as boolean | undefined;
    const bot   = data.bot_status as boolean | undefined;
    const connType    = data.connection_type as string | undefined;
    const abuseVel    = data.abuse_velocity  as string | undefined;
    const isp         = data.ISP             as string | undefined;
    const org         = data.organization    as string | undefined;
    const country     = data.country_code    as string | undefined;
    const city        = data.city            as string | undefined;
    const region      = data.region          as string | undefined;

    if (vpn)   push(panels.anon.vpn,     'Yes (VPN detected)',   sourceName);
    if (proxy) push(panels.anon.proxy,   'Yes (proxy detected)', sourceName);
    if (tor)   push(panels.anon.tor,     'Yes (Tor exit node)',  sourceName);
    if (bot)   push(panels.reputation.tags, 'Bot traffic', sourceName);
    if (connType)  push(panels.anon.usageType, connType, sourceName);
    if (abuseVel)  push(panels.reputation.confidence, `Abuse velocity: ${abuseVel}`, sourceName);
    if (isp)       push(panels.geo.isp, isp, sourceName);
    if (org)       push(panels.geo.org, org, sourceName);
    if (country)   push(panels.geo.country, country, sourceName);
    if (city)      push(panels.geo.city, city, sourceName);
    if (region)    push(panels.geo.region, region, sourceName);

    if (fraudScore != null) {
      const verdict = fraudScore >= 75 ? 'Malicious' : fraudScore >= 40 ? 'Suspicious' : 'Clean';
      push(panels.reputation.verdict, verdict, sourceName);
    }
  } else {
    // Malicious URL Scanner API fields
    const unsafe    = data.unsafe    as boolean | undefined;
    const phishing  = data.phishing  as boolean | undefined;
    const malware   = data.malware   as boolean | undefined;
    const spamming  = data.spamming  as boolean | undefined;
    const parking   = data.parking   as boolean | undefined;
    const riskScore = data.risk_score as number | undefined;
    const category  = data.category  as string | undefined;
    const domainAge = data.domain_age as Rec | undefined;
    const ipAddress = data.ip_address as string | undefined;
    const country   = data.country_code as string | undefined;
    const server    = data.server    as string | undefined;

    if (unsafe !== undefined) {
      push(panels.reputation.verdict, unsafe ? 'Malicious' : 'Clean', sourceName);
    }
    if (phishing) push(panels.reputation.categories, 'Phishing', sourceName);
    if (malware)  push(panels.reputation.categories, 'Malware',  sourceName);
    if (spamming) push(panels.reputation.categories, 'Spam',     sourceName);
    if (parking)  push(panels.reputation.tags, 'Parked domain',  sourceName);
    if (riskScore != null) push(panels.reputation.score, `${riskScore}/100 risk score`, sourceName);
    if (category)  push(panels.reputation.categories, category, sourceName);
    if (ipAddress) push(panels.geo.org, ipAddress, sourceName);
    if (country)   push(panels.geo.country, country, sourceName);
    if (server)    push(panels.network.services, `Server: ${server}`, sourceName);

    const created = domainAge?.human as string | undefined;
    if (created) push(panels.geo.created, `Domain created: ${created}`, sourceName);
  }
}

// ── AlienVault OTX ─────────────────────────────────────────────────
export function extractOtx(data: Rec, panels: PanelData, sourceName = 'OTX'): void {
  const general    = data.general    as Rec | undefined;
  const reputation = data.reputation as Rec | undefined;

  if (general) {
    // Pulse count as a confidence signal
    const pulseCount = general.pulse_info as Rec | undefined;
    const count = pulseCount?.count as number | undefined;
    if (count != null) push(panels.reputation.confidence, `${count} pulse${count !== 1 ? 's' : ''}`, sourceName);

    // Malware families
    const malware = general.malware_families as unknown[] | undefined;
    if (Array.isArray(malware)) {
      malware.forEach((m: unknown) => {
        const mRec = m as Rec;
        const name = mRec.display_name as string ?? mRec.id as string;
        if (name) push(panels.reputation.malwareFamily, name, sourceName);
      });
    }

    // Threat labels / adversary
    const adversary = general.adversary as string | undefined;
    if (adversary) push(panels.reputation.threatLabel, adversary, sourceName);

    // Tags
    const tags = general.tags as string[] | undefined;
    if (Array.isArray(tags)) tags.forEach(t => push(panels.reputation.tags, t, sourceName));

    // Geo (IP indicators)
    push(panels.geo.country,  general.country_name as string, sourceName);
    push(panels.geo.city,     general.city         as string, sourceName);
    push(panels.geo.asn,      general.asn          as string, sourceName);

    pushEvent(panels, general.first_seen as string, 'First seen', sourceName);
  }

  if (reputation) {
    const score = reputation.reputation as number | undefined;
    if (score != null) {
      push(panels.reputation.score, `${score}`, sourceName);
      const verdict = score < -2 ? 'Malicious' : score < 0 ? 'Suspicious' : 'Clean';
      push(panels.reputation.verdict, verdict, sourceName);
    }
  }
}

// ── IPinfo ─────────────────────────────────────────────────────────
export function extractIpInfo(data: Rec, panels: PanelData, sourceName = 'IPinfo'): void {
  push(panels.geo.country,  data.country  as string, sourceName);
  push(panels.geo.city,     data.city     as string, sourceName);
  push(panels.geo.region,   data.region   as string, sourceName);

  const loc = data.loc as string | undefined;
  if (loc && loc.includes(',')) push(panels.geo.coordinates, loc, sourceName);

  push(panels.geo.org,      data.org      as string, sourceName);

  const asn = data.asn as Rec | undefined;
  if (asn) {
    push(panels.geo.asn, asn.asn as string, sourceName);
    push(panels.geo.org, asn.name as string, sourceName);
  }

  const hostname = data.hostname as string | undefined;
  if (hostname) push(panels.geo.hostnames, hostname, sourceName);

  // Privacy detection (paid)
  const privacy = data.privacy as Rec | undefined;
  if (privacy) {
    if (privacy.vpn)     push(panels.anon.vpn,     'Yes (VPN)', sourceName);
    if (privacy.proxy)   push(panels.anon.proxy,   'Yes (proxy)', sourceName);
    if (privacy.tor)     push(panels.anon.tor,      'Yes (Tor)', sourceName);
    if (privacy.hosting) push(panels.anon.hosting,  'Yes (hosting)', sourceName);
  }

  // Abuse contact (paid)
  const abuse = data.abuse as Rec | undefined;
  if (abuse?.email) push(panels.geo.registrar, `Abuse: ${abuse.email}`, sourceName);
}

// ── Pulsedive ──────────────────────────────────────────────────────
export function extractPulsedive(data: Rec, panels: PanelData, sourceName = 'Pulsedive'): void {
  const risk = data.risk as string | undefined;
  if (risk) {
    const verdict = risk === 'high' || risk === 'critical' ? 'Malicious'
      : risk === 'medium' ? 'Suspicious' : 'Clean';
    push(panels.reputation.verdict, verdict, sourceName);
    push(panels.reputation.score, `${risk} risk`, sourceName);
  }

  // Threat associations
  const threats = data.threats as unknown[] | undefined;
  if (Array.isArray(threats)) {
    threats.forEach((t: unknown) => {
      const tr = t as Rec;
      if (tr.name) push(panels.reputation.threatLabel, tr.name as string, sourceName);
    });
  }

  // Feed associations
  const feeds = data.feeds as unknown[] | undefined;
  if (Array.isArray(feeds)) {
    feeds.slice(0, 5).forEach((f: unknown) => {
      const fr = f as Rec;
      if (fr.name) push(panels.reputation.tags, `Feed: ${fr.name}`, sourceName);
    });
  }

  // Attributes
  const attributes = data.attributes as Rec | undefined;
  if (attributes) {
    const ports = attributes.port as unknown[] | undefined;
    if (Array.isArray(ports)) ports.forEach((p: unknown) => push(panels.network.ports, String(p), sourceName));

    const protocols = attributes.protocol as unknown[] | undefined;
    if (Array.isArray(protocols)) protocols.forEach((p: unknown) => push(panels.network.services, String(p), sourceName));
  }

  // Geo
  push(panels.geo.country, data.country as string, sourceName);

  pushEvent(panels, data.stamp_seen as string,       'Last seen',  sourceName);
  pushEvent(panels, data.stamp_probed as string,     'Last probed', sourceName);
}

// ── Recorded Future ────────────────────────────────────────────────
export function extractRecordedFuture(data: Rec, panels: PanelData, sourceName = 'Rec Future'): void {
  const d = data.data as Rec | undefined;
  if (!d) return;

  const risk = d.risk as Rec | undefined;
  if (risk) {
    const score = risk.score as number | undefined;
    if (score != null) {
      push(panels.reputation.score, `${score}/99 risk score`, sourceName);
      const verdict = score >= 65 ? 'Malicious' : score >= 25 ? 'Suspicious' : 'Clean';
      push(panels.reputation.verdict, verdict, sourceName);
    }

    const rules = risk.evidenceDetails as unknown[] | undefined;
    if (Array.isArray(rules)) {
      rules.forEach((r: unknown) => {
        const rule = r as Rec;
        if (rule.rule) push(panels.reputation.tags, rule.rule as string, sourceName);
      });
    }
  }

  // Threat lists
  const threatLists = d.threatLists as unknown[] | undefined;
  if (Array.isArray(threatLists)) {
    threatLists.slice(0, 5).forEach((tl: unknown) => {
      const t = tl as Rec;
      if (t.name) push(panels.reputation.categories, t.name as string, sourceName);
    });
  }

  // Related entities (malware, threat actors)
  const related = d.relatedEntities as unknown[] | undefined;
  if (Array.isArray(related)) {
    related.forEach((group: unknown) => {
      const g = group as Rec;
      const type = g.type as string | undefined;
      const entities = g.entities as unknown[] | undefined;
      if (!Array.isArray(entities)) return;
      entities.slice(0, 3).forEach((e: unknown) => {
        const ent = e as Rec;
        const name = ent.name as string | undefined;
        if (!name) return;
        if (type === 'RelatedMalware')      push(panels.reputation.malwareFamily, name, sourceName);
        else if (type === 'RelatedThreatActor') push(panels.reputation.threatLabel, name, sourceName);
      });
    });
  }

  const timestamps = d.timestamps as Rec | undefined;
  pushEvent(panels, timestamps?.firstSeen as string, 'First seen', sourceName);
  pushEvent(panels, timestamps?.lastSeen  as string, 'Last seen',  sourceName);
}

export function extractCensys(data: Rec, panels: PanelData, _artifactType: string, sourceName = 'Censys'): void {
  // Censys v2 host response is wrapped under result
  const result = (data.result ?? data) as Rec;

  // IP host lookup
  const ip = result.ip as string | undefined;
  if (ip) {
    // Geo
    const location = result.location as Rec | undefined;
    if (location) {
      const country = location.country as string | undefined;
      const city    = location.city    as string | undefined;
      const locCoords = location.coordinates as Rec | undefined;
      const lat = locCoords?.latitude  as number | undefined;
      const lon = locCoords?.longitude as number | undefined;
      if (country) push(panels.geo.country, country, sourceName);
      if (city)    push(panels.geo.city,    city,    sourceName);
      if (lat !== undefined && lon !== undefined) {
        push(panels.geo.coordinates, `${lat}, ${lon}`, sourceName);
      }
    }
    // ASN / Network
    const as_ = result.autonomous_system as Rec | undefined;
    if (as_) {
      if (as_.asn)        push(panels.geo.asn,  `AS${as_.asn}`,               sourceName);
      if (as_.name)       push(panels.geo.asn,  String(as_.name),             sourceName);
      if (as_.bgp_prefix) push(panels.geo.cidr, String(as_.bgp_prefix),       sourceName);
    }
    // Services / open ports
    const services = result.services as unknown[] | undefined;
    if (Array.isArray(services)) {
      services.forEach((svc: unknown) => {
        const s = svc as Rec;
        const port    = s.port    as number | undefined;
        const proto   = s.transport_protocol as string | undefined;
        const service = s.service_name as string | undefined;
        const banner  = (s.banner ?? s.extended_service_name) as string | undefined;
        if (port) {
          const label = [port, proto?.toLowerCase(), service ?? banner].filter(Boolean).join('/');
          push(panels.network.ports, label, sourceName);
        }
        // TLS cert subject
        const tls = s.tls as Rec | undefined;
        const certData = (tls as Rec | undefined)?.certificates as Rec | undefined;
        const leafData = certData?.leaf_data as Rec | undefined;
        const subjectRec = leafData?.subject as Rec | undefined;
        const cn = subjectRec?.common_name as string | undefined;
        if (cn) push(panels.network.ssl, `CN=${cn}`, sourceName);
      });
    }
    // Hostnames / DNS names
    const dnsRec = result.dns as Rec | undefined;
    const revDns = dnsRec?.reverse_dns as Rec | undefined;
    const hostnames = revDns?.names as string[] | undefined;
    if (Array.isArray(hostnames)) {
      hostnames.slice(0, 5).forEach(h => push(panels.geo.hostnames, h, sourceName));
    }
    // Last updated
    const lastUpdated = result.last_updated_at as string | undefined;
    if (lastUpdated) pushEvent(panels, lastUpdated, 'Last seen', sourceName);
  }

  // Domain / certificate search
  const resultOuter = data.result as Rec | undefined;
  const hits = resultOuter?.hits as unknown[] | undefined;
  if (Array.isArray(hits)) {
    hits.forEach((hit: unknown) => {
      const h = hit as Rec;
      const parsed = h.parsed as Rec | undefined;
      const subject = parsed?.subject_dn as string | undefined;
      if (subject) push(panels.network.ssl, subject, sourceName);
      const issuer = parsed?.issuer_dn as string | undefined;
      if (issuer) push(panels.geo.registrar, issuer, sourceName);
    });
  }
}

// ── MITRE ATT&CK extractor ─────────────────────────────────────────
export function extractMitreAttack(data: Rec, panels: PanelData, sourceName = 'MITRE ATT&CK'): void {
  const name = data.name as string | undefined;
  if (name) push(panels.reputation.threatLabel, name, sourceName);

  const extRefs = data.external_references as Rec[] | undefined;
  if (Array.isArray(extRefs)) {
    const mitreRef = extRefs.find(r => r.source_name === 'mitre-attack');
    if (mitreRef?.external_id) push(panels.reputation.tags, String(mitreRef.external_id), sourceName);
  }

  const aliases = data.aliases as string[] | undefined;
  if (Array.isArray(aliases)) {
    aliases.forEach(a => {
      if (a !== name) push(panels.reputation.categories, a, sourceName);
    });
  }

  const desc = (data.description as string | undefined)?.replace(/\(Citation:[^)]+\)/g, '').replace(/\s{2,}/g, ' ').trim();
  if (desc) push(panels.reputation.summary, desc, sourceName);

  pushEvent(panels, data.created  as string, 'ATT&CK record created', sourceName);
  pushEvent(panels, data.modified as string, 'ATT&CK record updated', sourceName);

  // Relationship data (techniques, software, campaigns, mitigations)
  const related = data._related as Rec | undefined;
  if (!related) return;
  if (!panels.mitre) {
    panels.mitre = { groupStixId: (data.id as string) ?? '', techniques: [], software: [], campaigns: [], mitigations: [], sectors: [], countries: [], associatedGroups: [] };
  }
  const m = panels.mitre;

  const techniques      = related.techniques      as Rec[] | undefined;
  const software        = related.software        as Rec[] | undefined;
  const campaigns       = related.campaigns       as Rec[] | undefined;
  const mitigations     = related.mitigations     as Rec[] | undefined;
  const sectors         = related.sectors         as string[] | undefined;
  const countries       = related.countries       as string[] | undefined;
  const associatedGroups = related.associatedGroups as Rec[] | undefined;

  if (Array.isArray(techniques)) {
    for (const t of techniques) {
      const id     = t.id     as string | undefined;
      const tname  = t.name   as string | undefined;
      const tactic = t.tactic as string | undefined;
      if (id && tname && !m.techniques.some(x => x.id === id)) {
        m.techniques.push({ id, name: tname, tactic: tactic ?? '' });
      }
    }
  }
  if (Array.isArray(software)) {
    for (const s of software) {
      const id    = s.id   as string | undefined;
      const sname = s.name as string | undefined;
      const stype = s.type as string | undefined;
      if (id && sname && !m.software.some(x => x.id === id)) {
        m.software.push({ id, name: sname, type: stype ?? 'malware' });
      }
    }
  }
  if (Array.isArray(campaigns)) {
    for (const c of campaigns) {
      const id    = c.id   as string | undefined;
      const cname = c.name as string | undefined;
      if (id && cname && !m.campaigns.some(x => x.id === id)) {
        m.campaigns.push({ id, name: cname });
      }
    }
  }
  if (Array.isArray(mitigations)) {
    for (const mit of mitigations) {
      const id    = mit.id   as string | undefined;
      const mname = mit.name as string | undefined;
      if (id && mname && !m.mitigations.some(x => x.id === id)) {
        m.mitigations.push({ id, name: mname });
      }
    }
  }
  if (Array.isArray(sectors)) {
    for (const s of sectors) {
      if (s && !m.sectors.includes(s)) m.sectors.push(s);
    }
  }
  if (Array.isArray(countries)) {
    for (const c of countries) {
      if (c && !m.countries.includes(c)) m.countries.push(c);
    }
  }
  if (Array.isArray(associatedGroups)) {
    for (const g of associatedGroups) {
      const id    = g.id   as string | undefined;
      const gname = g.name as string | undefined;
      if (id && gname && !m.associatedGroups.some(x => x.id === id)) {
        m.associatedGroups.push({ id, name: gname });
      }
    }
  }
}
