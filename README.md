# Nautilus

Nautilus is a [Cribl App](https://docs.cribl.io/) for cyber threat intelligence (CTI) artifact search. It lets an analyst query an indicator — an IP, domain, URL, file hash, or CVE — against dozens of threat intel sources at once and see the results merged into one consistent view, without leaving Cribl.

## What it does

- **Multi-provider artifact search.** Enter an IP, domain, URL, hash, or CVE and Nautilus fans the query out to the providers that support that artifact type (reputation/blocklist services, sandboxes, WHOIS/RDAP, geolocation, vulnerability databases, and more), then normalizes the responses into unified reputation, geo, network, file, CVE, and timeline panels. Supported providers include VirusTotal, AbuseIPDB, GreyNoise, Shodan, Censys, URLhaus, ThreatFox, MalwareBazaar, Hybrid Analysis, MalShare, IPQualityScore, APIvoid, MaxMind (GeoIP2/GeoLite2), OTX, Pulsedive, Recorded Future, NVD, CIRCL, Spamhaus DQS, IPinfo, WHOIS/RDAP, and MITRE ATT&CK, among others. Most providers work with a user-supplied API key; a handful (URLhaus, ThreatFox, MalwareBazaar, CIRCL, Shodan InternetDB, WHOIS) work key-free.
- **MITRE ATT&CK overlay.** Search results are cross-referenced against a locally-built MITRE ATT&CK cache to surface related threat groups, techniques, software, and campaigns.
- **Detection rule matching.** Indicators are matched against known detection rule sources to show whether existing signatures already cover a given artifact.
- **IOC extraction.** Paste unstructured text (a report, an email, log output) and Nautilus pulls out IPs, domains, URLs, hashes, and CVE IDs for follow-up lookup.
- **Bulk search.** Run the same lookup workflow across a list of indicators in parallel, then export results to CSV.
- **Threat feed management.** Configure and sync external threat feeds (Feodo Tracker, ThreatFox, URLhaus, Spamhaus, Emerging Threats, CISA, PhishTank, Tor exit list, and others), merge them into a deduplicated indicator lookup, and publish that lookup for use in Cribl Stream pipelines.
- **Cribl integration.** Pivot straight from a search result into a Cribl Search job scoped to the artifact ("Find in Logs"), or copy a structured summary of the findings for use with an AI assistant ("Copy for AI").
- **Per-user query routing.** Analysts can enable/disable individual providers per artifact type, and API keys are stored per-user in the app's scoped Cribl KV store.

## Installation

1. Download the tgz file from the [Releases](https://github.com/Cribl-Community/CC-nautilus/releases) page.
2. Log into Cribl Cloud
2. Go to **App Platform > Add App > Import from File**
3. Select the downloaded tgz file and click **Open**
4. Click **Import**
5. Click on the app in the list of installed apps


## Development

Clone this repo.
Install dependencies and start the app.
```bash
npm install
npm run dev 
```
1. Log into Cribl Cloud
2. Go to **App Platform > Development > Live Preview**