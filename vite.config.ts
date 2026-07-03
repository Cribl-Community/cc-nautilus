import { defineConfig, type IndexHtmlTransformContext, type IndexHtmlTransformResult, type ViteDevServer } from 'vite'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readFileSync } from 'node:fs'
import { join } from 'path'
import react from '@vitejs/plugin-react'
// @ts-expect-error - pkgutil.mjs has no type declarations
import { servePackageTgz } from './scripts/pkgutil.mjs'

// Cribl's sandboxed iframe throws "Cannot redefine property: get" when Rolldown's
// CJS interop helper calls Object.defineProperty(ns, propName, {get: ...}).
// This plugin rewrites the generated s() helper to use plain value assignment instead.
const patchCjsInteropPlugin = () => ({
  name: 'patch-cjs-interop',
  enforce: 'post' as const,
  generateBundle(_opts: unknown, bundle: Record<string, { type: string; code?: string; fileName: string }>) {
    for (const chunk of Object.values(bundle)) {
      if (chunk.type !== 'chunk' || !chunk.code) continue;
      // Replace the getter-based namespace copy helper:
      //   d=c[l], !a.call(e,d) && d!==o && t(e,d,{get:(e=>i[e]).bind(null,d), enumerable:...})
      // with a plain assignment:
      //   d=c[l], !a.call(e,d) && d!==o && (e[d]=i[d])
      // Pattern: DEFPROP(TGT, KEY, {get:(X=>SRC[X]).bind(null,KEY), enumerable:...})
      // Replace: TGT[KEY] = SRC[KEY]
      chunk.code = chunk.code.replace(
        /([a-z])\(([a-z]),([a-z]),\{get:\([a-z]=>([a-z])\[[a-z]\]\)\.bind\(null,\3\),enumerable:[^}]+\}\)/g,
        '($2[$3]=$4[$3])'
      );
    }
  },
})

const packageEndpointPlugin = () => ({
  name: 'vite-plugin-package-endpoint',
  configureServer(server: ViteDevServer) {
    server.middlewares.use('/package.tgz', (req: IncomingMessage, res: ServerResponse) => {
      void servePackageTgz(req, res, server.config.root)
    })
  },
})

const injectScriptFromQueryPlugin = () => {
  let initScriptUrl: string | null = null;
  return {
    name: 'inject-script-from-query',
    configureServer(server: ViteDevServer) {
      const root = server.config.root;
      server.watcher.add([
        join(root, 'package.json'),
        join(root, 'config', 'proxies.yml'),
      ]);
      server.watcher.on('change', (file) => {
        if (file === join(root, 'package.json') || file === join(root, 'config', 'proxies.yml')) {
          server.ws.send({ type: 'full-reload' });
        }
      });
    },
    transformIndexHtml(html: string, ctx: IndexHtmlTransformContext): IndexHtmlTransformResult{
      const url = new URL(ctx.originalUrl ?? '/', 'https://localhost');
      initScriptUrl = initScriptUrl || url.searchParams.get('init');
      const root = process.cwd();
      let appName;
      try {
        const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf-8')) as { name?: string };
        appName = pkg.name;
      } catch {
        /* ignore missing or invalid package.json */
      }
      appName = appName || 'unknown';
      const tags: Array<{ tag: string; attrs?: Record<string, string>; children?: string; injectTo: 'head-prepend' }> = [];
      tags.push({
        tag: 'script',
        children: `window.CRIBL_APP_ID = '__dev__${appName}';`,
        injectTo: 'head-prepend' as const,
      });
      if (initScriptUrl) {
        tags.push({
          tag: 'script',
          attrs: { src: initScriptUrl, type: 'text/javascript' },
          injectTo: 'head-prepend' as const,
        });
      }
      return { html, tags };
    },
  };
};

export default defineConfig({
  plugins: [react(), patchCjsInteropPlugin(), packageEndpointPlugin(), injectScriptFromQueryPlugin()],
  base: './',
  server: {
    cors: true,
    proxy: {
      '/apivoid-proxy':    { target: 'https://api.apivoid.com',          changeOrigin: true, rewrite: p => p.replace(/^\/apivoid-proxy/, '') },
      '/circl-proxy':      { target: 'https://cve.circl.lu',             changeOrigin: true, rewrite: p => p.replace(/^\/circl-proxy/, '') },
      '/nvd-proxy':        { target: 'https://services.nvd.nist.gov',    changeOrigin: true, rewrite: p => p.replace(/^\/nvd-proxy/, '') },
      '/urlhaus-proxy':    { target: 'https://urlhaus-api.abuse.ch',     changeOrigin: true, rewrite: p => p.replace(/^\/urlhaus-proxy/, '') },
      '/bazaar-proxy':     { target: 'https://mb-api.abuse.ch',          changeOrigin: true, rewrite: p => p.replace(/^\/bazaar-proxy/, '') },
      '/threatfox-proxy':  { target: 'https://threatfox-api.abuse.ch',   changeOrigin: true, rewrite: p => p.replace(/^\/threatfox-proxy/, '') },
      '/spamhaus-proxy':   { target: 'https://apibl.spamhaus.net',       changeOrigin: true, rewrite: p => p.replace(/^\/spamhaus-proxy/, '') },
      '/greynoise-proxy':  { target: 'https://api.greynoise.io',         changeOrigin: true, rewrite: p => p.replace(/^\/greynoise-proxy/, '') },
      '/vt-proxy':         { target: 'https://www.virustotal.com',       changeOrigin: true, rewrite: p => p.replace(/^\/vt-proxy/, '') },
      '/internetdb-proxy': { target: 'https://internetdb.shodan.io',      changeOrigin: true, rewrite: p => p.replace(/^\/internetdb-proxy/, '') },
      '/shodan-proxy':     { target: 'https://api.shodan.io',            changeOrigin: true, rewrite: p => p.replace(/^\/shodan-proxy/, '') },
      '/abuseipdb-proxy':  { target: 'https://api.abuseipdb.com',        changeOrigin: true, rewrite: p => p.replace(/^\/abuseipdb-proxy/, '') },
      '/maxmind-proxy':    { target: 'https://geoip.maxmind.com',        changeOrigin: true, rewrite: p => p.replace(/^\/maxmind-proxy/, '') },
      '/geolite-proxy':    { target: 'https://geolite.info',             changeOrigin: true, rewrite: p => p.replace(/^\/geolite-proxy/, '') },
      '/censys-proxy':     { target: 'https://search.censys.io',         changeOrigin: true, rewrite: p => p.replace(/^\/censys-proxy/, '') },
      '/hybrid-proxy':     { target: 'https://hybrid-analysis.com',         changeOrigin: true, rewrite: p => p.replace(/^\/hybrid-proxy/, '') },
      '/malshare-proxy':   { target: 'https://malshare.com',              changeOrigin: true, rewrite: p => p.replace(/^\/malshare-proxy/, '') },
      '/ipqs-proxy':       { target: 'https://www.ipqualityscore.com',   changeOrigin: true, rewrite: p => p.replace(/^\/ipqs-proxy/, '') },
      '/osm-proxy-a':      { target: 'https://a.tile.openstreetmap.org', changeOrigin: true, rewrite: p => p.replace(/^\/osm-proxy-a/, '') },
      '/osm-proxy-b':      { target: 'https://b.tile.openstreetmap.org', changeOrigin: true, rewrite: p => p.replace(/^\/osm-proxy-b/, '') },
      '/osm-proxy-c':      { target: 'https://c.tile.openstreetmap.org', changeOrigin: true, rewrite: p => p.replace(/^\/osm-proxy-c/, '') },
      '/otx-proxy':        { target: 'https://otx.alienvault.com',       changeOrigin: true, rewrite: p => p.replace(/^\/otx-proxy/, '') },
      '/ipinfo-proxy':     { target: 'https://ipinfo.io',                changeOrigin: true, rewrite: p => p.replace(/^\/ipinfo-proxy/, '') },
      '/pulsedive-proxy':  { target: 'https://pulsedive.com',            changeOrigin: true, rewrite: p => p.replace(/^\/pulsedive-proxy/, '') },
      '/rf-proxy':         { target: 'https://api.recordedfuture.com',   changeOrigin: true, rewrite: p => p.replace(/^\/rf-proxy/, '') },
      '/mitre-proxy':      { target: 'https://attack-taxii.mitre.org',   changeOrigin: true, rewrite: p => p.replace(/^\/mitre-proxy/, '') },
      // Threat feed sources
      '/feed-proxy/feodotracker':  { target: 'https://feodotracker.abuse.ch',                       changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/feodotracker/, '') },
      '/feed-proxy/threatfox':     { target: 'https://threatfox.abuse.ch',                          changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/threatfox/, '') },
      '/feed-proxy/urlhaus':       { target: 'https://urlhaus.abuse.ch',                            changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/urlhaus/, '') },
      '/feed-proxy/spamhaus':      { target: 'https://www.spamhaus.org',                            changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/spamhaus/, '') },
      '/feed-proxy/et':            { target: 'https://rules.emergingthreats.net',                   changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/et/, '') },
      '/feed-proxy/cisa':          { target: 'https://www.cisa.gov',                                changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/cisa/, '') },
      '/feed-proxy/github':        { target: 'https://raw.githubusercontent.com',                   changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/github/, '') },
      '/feed-proxy/torproject':    { target: 'https://check.torproject.org',                        changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/torproject/, '') },
      '/feed-proxy/blocklistde':   { target: 'https://lists.blocklist.de',                          changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/blocklistde/, '') },
      '/feed-proxy/phishtank':     { target: 'https://data.phishtank.com',                          changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/phishtank/, '') },
      '/feed-proxy/bazaar':        { target: 'https://bazaar.abuse.ch',                             changeOrigin: true, rewrite: p => p.replace(/^\/feed-proxy\/bazaar/, '') },
    },
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        // Cribl's sandbox blocks Object.defineProperty with getter descriptors.
        // This switches CJS interop from {get: () => ...} to plain value assignment.
        externalLiveBindings: false,
      },
    },
  }
})

