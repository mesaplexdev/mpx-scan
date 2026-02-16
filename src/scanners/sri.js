/**
 * Subresource Integrity (SRI) Scanner
 * 
 * Checks that external scripts and stylesheets use integrity attributes
 * to prevent supply-chain attacks (e.g., compromised CDNs).
 */

const https = require('https');
const http = require('http');

async function scanSRI(parsedUrl, options = {}) {
  const checks = [];
  let score = 0;
  let maxScore = 0;

  const html = await fetchBody(parsedUrl, options);
  
  if (!html) {
    checks.push({ name: 'Subresource Integrity', status: 'error', message: 'Could not fetch page HTML' });
    return { score: 0, maxScore: 1, checks };
  }

  // Find external scripts
  const scriptRegex = /<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>/gi;
  const linkRegex = /<link[^>]+href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["']stylesheet["'][^>]*>|<link[^>]*rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["']([^"']+)["'][^>]*>/gi;

  const externalScripts = [];
  const externalStyles = [];
  let match;

  while ((match = scriptRegex.exec(html)) !== null) {
    const src = match[1];
    const fullTag = match[0];
    if (isExternal(src, parsedUrl.hostname)) {
      externalScripts.push({ src, tag: fullTag, hasIntegrity: /integrity\s*=\s*["']/i.test(fullTag) });
    }
  }

  while ((match = linkRegex.exec(html)) !== null) {
    const href = match[1] || match[2];
    const fullTag = match[0];
    if (href && isExternal(href, parsedUrl.hostname)) {
      externalStyles.push({ src: href, tag: fullTag, hasIntegrity: /integrity\s*=\s*["']/i.test(fullTag) });
    }
  }

  const allExternal = [...externalScripts, ...externalStyles];

  if (allExternal.length === 0) {
    checks.push({ name: 'Subresource Integrity', status: 'pass', message: 'No external scripts or stylesheets found (self-hosted resources)' });
    return { score: 1, maxScore: 1, checks };
  }

  maxScore = allExternal.length;
  let withSRI = 0;
  let withoutSRI = 0;

  // Group by domain for cleaner output
  const byDomain = {};
  for (const resource of [...externalScripts, ...externalStyles]) {
    const isScript = externalScripts.includes(resource);
    let domain;
    try { domain = new URL(resource.src.startsWith('//') ? 'https:' + resource.src : resource.src).hostname; } 
    catch { domain = 'unknown'; }
    if (!byDomain[domain]) byDomain[domain] = { scripts: 0, styles: 0, withSRI: 0, withoutSRI: 0 };
    if (isScript) byDomain[domain].scripts++; else byDomain[domain].styles++;
    if (resource.hasIntegrity) { byDomain[domain].withSRI++; withSRI++; score += 1; }
    else { byDomain[domain].withoutSRI++; withoutSRI++; if (!isScript) score += 0.25; }
  }

  // Output per-domain summary (max 10 domains shown)
  const domains = Object.entries(byDomain).sort((a, b) => b[1].withoutSRI - a[1].withoutSRI);
  for (const [domain, counts] of domains.slice(0, 10)) {
    const total = counts.withSRI + counts.withoutSRI;
    if (counts.withoutSRI === 0) {
      checks.push({ name: `SRI: ${domain}`, status: 'pass', message: `All ${total} resources have integrity attributes` });
    } else if (counts.scripts > 0 && counts.withoutSRI > 0) {
      checks.push({ name: `SRI: ${domain}`, status: 'fail', message: `${counts.withoutSRI} of ${total} resources missing integrity (${counts.scripts} scripts)`, recommendation: 'Add integrity="sha384-..." and crossorigin="anonymous" to external script/link tags' });
    } else {
      checks.push({ name: `SRI: ${domain}`, status: 'warn', message: `${counts.withoutSRI} of ${total} stylesheets missing integrity`, recommendation: 'Add integrity="sha384-..." attribute' });
    }
  }
  if (domains.length > 10) {
    checks.push({ name: 'SRI', status: 'info', message: `...and ${domains.length - 10} more external domains` });
  }

  // Summary check at top
  if (withoutSRI === 0) {
    checks.unshift({ name: 'Subresource Integrity', status: 'pass', message: `All ${allExternal.length} external resources have integrity attributes` });
  } else {
    checks.unshift({ name: 'Subresource Integrity', status: withoutSRI > withSRI ? 'fail' : 'warn', message: `${withoutSRI} of ${allExternal.length} external resources missing integrity (${Object.keys(byDomain).length} domains)` });
  }

  return { score, maxScore, checks };
}

function isExternal(url, hostname) {
  if (url.startsWith('//')) url = 'https:' + url;
  if (url.startsWith('http://') || url.startsWith('https://')) {
    try {
      const parsed = new URL(url);
      return parsed.hostname !== hostname;
    } catch { return false; }
  }
  return false; // Relative URLs are same-origin
}

function shortenUrl(url) {
  try {
    const parsed = new URL(url.startsWith('//') ? 'https:' + url : url);
    const path = parsed.pathname.split('/').pop() || parsed.pathname;
    return `${parsed.hostname}/.../${path}`.substring(0, 60);
  } catch { return url.substring(0, 60); }
}

function fetchBody(parsedUrl, options = {}) {
  return new Promise((resolve) => {
    const timeout = options.timeout || 10000;
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    let resolved = false;
    const done = (val) => { if (!resolved) { resolved = true; resolve(val); } };
    const timer = setTimeout(() => done(''), timeout + 2000);

    const req = protocol.request(parsedUrl.href, {
      method: 'GET',
      timeout,
      headers: { 
        'User-Agent': 'SiteGuard/0.1 Security Scanner',
        'Accept': 'text/html'
      },
      rejectUnauthorized: false,
    }, (res) => {
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        clearTimeout(timer);
        const redirectUrl = new URL(res.headers.location, parsedUrl.href);
        fetchBody(redirectUrl, options).then(done);
        res.resume();
        return;
      }
      
      let body = '';
      res.setEncoding('utf-8');
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 500000) { // 500KB max
          res.destroy();
          clearTimeout(timer);
          done(body);
        }
      });
      res.on('end', () => { clearTimeout(timer); done(body); });
      res.on('error', () => { clearTimeout(timer); done(body); });
    });

    req.on('error', () => { clearTimeout(timer); done(''); });
    req.on('timeout', () => { clearTimeout(timer); req.destroy(); done(''); });
    req.end();
  });
}

module.exports = { scanSRI, fetchBody };
