import type { ArtifactType } from './types';

// File extensions that look like TLDs but are not domain suffixes.
const FILE_EXTENSIONS = new Set([
  'exe','dll','bat','cmd','sh','bash','zsh','ps1','psm1','psd1',
  'py','pyc','pyo','rb','pl','php','jar','class','war','ear',
  'js','ts','jsx','tsx','mjs','cjs',
  'vbs','vbe','wsf','wsh','hta',
  'doc','docx','xls','xlsx','ppt','pptx','pdf','rtf','odt','ods',
  'zip','gz','tar','rar','7z','bz2','xz','cab','iso','img','dmg',
  'apk','ipa','msi','deb','rpm',
  'elf','so','dylib','sys','drv',
  'lnk','url','scr','cpl','ocx',
  'cfg','conf','ini','log','tmp','bak',
  'sql','db','sqlite','mdb',
  'csv','tsv','xml','json','yaml','yml','toml',
  'html','htm','css','scss','sass',
  'c','cpp','h','hpp','cs','go','rs','swift','kt','java',
  'png','jpg','jpeg','gif','bmp','svg','ico','tiff','webp',
  'mp3','mp4','avi','mov','mkv','wav','flac',
  'pem','crt','cer','key','pfx','p12',
]);

// Country-code and well-known generic TLDs that are definitely domain suffixes.
// Two-letter codes are all valid ccTLDs; we also explicitly list common gTLDs.
// Anything not in FILE_EXTENSIONS and matching the domain regex is treated as a domain.
function isDomainLike(s: string): boolean {
  const m = s.match(/\.([a-z0-9]+)$/i);
  if (!m) return false;
  const ext = m[1].toLowerCase();

  // Block known file extensions
  if (FILE_EXTENSIONS.has(ext)) return false;

  // All two-letter suffixes are valid ccTLDs (us, uk, de, cn, ru, io, co, etc.)
  if (ext.length === 2) return true;

  // Common three-letter+ gTLDs and ccSLDs
  const KNOWN_GTLD = new Set([
    'com','net','org','gov','mil','edu','int',
    'info','biz','name','pro','aero','coop','museum',
    'app','dev','web','api','cdn','aws','azure','cloud',
    'onion','local','internal','lan',
    'shop','store','online','site','tech','media','news',
    'gov','mil', // repeated for clarity
  ]);
  if (KNOWN_GTLD.has(ext)) return true;

  // 3–6 letter extensions not in file list — treat as domain (covers new gTLDs like .ninja, .click)
  if (ext.length >= 3 && ext.length <= 6) return true;

  return false;
}

export function detectArtifact(raw: string): ArtifactType {
  const s = raw.trim();
  if (!s) return 'unknown';

  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return 'ip';
  // IPv6
  if (/^[0-9a-f:]{7,39}$/i.test(s) && s.includes(':')) return 'ip';
  // MD5 / SHA1 / SHA256 / SHA512
  if (/^[0-9a-f]{32}$/i.test(s)) return 'hash';
  if (/^[0-9a-f]{40}$/i.test(s)) return 'hash';
  if (/^[0-9a-f]{64}$/i.test(s)) return 'hash';
  if (/^[0-9a-f]{128}$/i.test(s)) return 'hash';
  // URL
  if (/^https?:\/\//i.test(s)) return 'url';
  // CVE ID
  if (/^CVE-\d{4}-\d{4,}$/i.test(s)) return 'cve';
  // vendor/product CVE search (e.g. "microsoft/office", "apache/log4j")
  if (/^[a-z0-9][\w\s-]{2,}\/[a-z0-9][\w\s-]{1,}$/i.test(s)) return 'cve';
  // Threat group — numbered designations (APT28, TA505, UNC2452, FIN7, G0016…)
  if (/^(apt|ta|unc|fin|g\d{4}|threat)\s*\d+/i.test(s)) return 'threat-group';
  // Threat group — well-known named actors (single or multi-word, no dots/slashes)
  const NAMED_ACTORS = new Set([
    'lazarus','lazarusgroup',
    'cozybear','cozyfancy','cozydukes',
    'fancybear','sandworm','trickbot','carbanak',
    'turla','equation','darkhotel','menupass',
    'oceanlotus','apt1','comment crew',
    'axiom','deep panda','stone panda',
    'dragonfly','energeticbear','berserkbear',
    'sidewinder','muddywater','magic hound',
    'charming kitten','phosphorus','lotus blossom',
    'winnti','barium','doublespider',
    'navigator','nomadic octopus','gamaredon',
    'callisto','star kitten','iron liberty',
    'blacktech','bronze butler','tick',
    'volatile cedar','transparent tribe','sidewinder',
    'andariel','bluenoroff','kimsuky',
    'scarlet mimic','naikon','temp.periscope',
    'leviathan','tropic trooper','keyboy',
    'anunak','cobalt group','fin6','fin8',
    'revil','darkside','conti','lapsus',
    'scattered spider','alphv','blackcat',
  ]);
  const normalized = s.toLowerCase().replace(/\s+/g, '');
  if (NAMED_ACTORS.has(normalized) || NAMED_ACTORS.has(s.toLowerCase())) return 'threat-group';
  // Multi-word with no dots or slashes — likely a named actor if it looks like a proper noun phrase
  if (/^[A-Z][a-zA-Z]+(\s[A-Z][a-zA-Z]+){1,3}$/.test(s) && !isDomainLike(s)) return 'threat-group';
  // Domain — must look like a domain AND not be a filename
  if (/^[a-z0-9][a-z0-9._-]+\.[a-z0-9]{2,}$/i.test(s) && !s.includes('/') && !s.includes(' ') && isDomainLike(s)) return 'domain';

  // Filename — anything with a known file extension (with or without a path)
  const fileExt = s.match(/\.([a-z0-9]+)$/i)?.[1]?.toLowerCase();
  if (fileExt && FILE_EXTENSIONS.has(fileExt)) return 'file';

  return 'unknown';
}

export const ARTIFACT_LABELS: Record<ArtifactType, string> = {
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  hash: 'File Hash',
  'threat-group': 'Threat Group',
  file: 'File',
  cve: 'CVE / Vulnerability',
  unknown: 'Unknown',
};

export const ARTIFACT_COLORS: Record<ArtifactType, { bg: string; color: string; border: string }> = {
  ip:            { bg: '#e6f7ff', color: '#0958d9', border: '#91d5ff' },
  domain:        { bg: '#f6ffed', color: '#389e0d', border: '#b7eb8f' },
  url:           { bg: '#fff7e6', color: '#d46b08', border: '#ffd591' },
  hash:          { bg: '#f9f0ff', color: '#722ed1', border: '#d3adf7' },
  'threat-group':{ bg: '#fff1f0', color: '#cf1322', border: '#ffa39e' },
  file:          { bg: '#e6fffb', color: '#08979c', border: '#87e8de' },
  cve:           { bg: '#fff7e6', color: '#d4380d', border: '#ffbb96' },
  unknown:       { bg: '#fafafa', color: '#8c8c8c', border: '#d9d9d9' },
};
