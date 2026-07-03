// Looks up malware/tool names in the MITRE software+techniques KV cache
// Returns ATT&CK technique IDs associated with those names (via the groups that use them)

import { loadMitreSoftware, loadMitreTechniques } from './storage';

export interface MitreOverlayResult {
  softwareName: string;
  softwareId: string;   // e.g. S0002
  softwareType: string; // malware | tool
  techniques: { id: string; name: string; tactic: string }[];
}

interface SoftwareIndex {
  // name (lowercase) -> { softwareId, softwareType, groupStixIds[] }
  byName: Map<string, { softwareId: string; softwareType: string; originalName: string; groupStixIds: string[] }>;
}

let cachedIndex: SoftwareIndex | null = null;

async function buildIndex(): Promise<SoftwareIndex | null> {
  if (cachedIndex) return cachedIndex;

  const software = await loadMitreSoftware();
  if (!software) return null;

  const byName = new Map<string, { softwareId: string; softwareType: string; originalName: string; groupStixIds: string[] }>();

  for (const [groupStixId, groupData] of Object.entries(software.byGroup)) {
    for (const sw of groupData.software) {
      const key = sw.name.toLowerCase();
      const existing = byName.get(key);
      if (existing) {
        if (!existing.groupStixIds.includes(groupStixId)) {
          existing.groupStixIds.push(groupStixId);
        }
      } else {
        byName.set(key, {
          softwareId: sw.id,
          softwareType: sw.type,
          originalName: sw.name,
          groupStixIds: [groupStixId],
        });
      }
    }
  }

  cachedIndex = { byName };
  return cachedIndex;
}

export async function lookupMitreOverlay(names: string[]): Promise<MitreOverlayResult[]> {
  if (!names.length) return [];

  const [index, techniquesEntry] = await Promise.all([buildIndex(), loadMitreTechniques()]);
  if (!index || !techniquesEntry) return [];

  // Separate into exact and substring matches so exact come first
  const exactMatches: MitreOverlayResult[] = [];
  const substringMatches: MitreOverlayResult[] = [];
  const seenSoftwareIds = new Set<string>();

  for (const queryName of names) {
    const q = queryName.toLowerCase().trim();
    if (!q) continue;

    // Try exact match first
    let entry = index.byName.get(q);
    let isExact = true;

    if (!entry) {
      // Substring match: find first entry where either the sw name contains the query
      // or the query contains the sw name
      isExact = false;
      for (const [key, val] of index.byName) {
        if (key.includes(q) || q.includes(key)) {
          entry = val;
          break;
        }
      }
    }

    if (!entry) continue;
    if (seenSoftwareIds.has(entry.softwareId)) continue;
    seenSoftwareIds.add(entry.softwareId);

    // Collect all techniques from all groups that use this software
    const techMap = new Map<string, { id: string; name: string; tactic: string }>();
    for (const groupStixId of entry.groupStixIds) {
      const groupTechs = techniquesEntry.byGroup[groupStixId] ?? [];
      for (const t of groupTechs) {
        if (!techMap.has(t.id)) {
          techMap.set(t.id, t);
        }
      }
    }

    const techniques = [...techMap.values()].slice(0, 20);

    const result: MitreOverlayResult = {
      softwareName: entry.originalName,
      softwareId: entry.softwareId,
      softwareType: entry.softwareType,
      techniques,
    };

    if (isExact) exactMatches.push(result);
    else substringMatches.push(result);
  }

  return [...exactMatches, ...substringMatches].slice(0, 5);
}
