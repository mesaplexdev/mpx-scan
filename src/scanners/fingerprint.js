/**
 * Technology Fingerprinting Scanner
 * 
 * Identifies the CMS, framework, server software, and libraries
 * used by the target. Useful for:
 * - Understanding attack surface
 * - Checking for known vulnerable versions
 * - General security posture awareness
 */

const https = require('https');
const http = require('http');
const { fetchBody } = require('./sri');

// Fingerprint signatures — checked against headers, HTML, and cookies
const SIGNATURES = {
  // CMS
  'WordPress': {
    html: [/wp-content\//i, /wp-includes\//i, /wp-json\//i, /<meta\s+name="generator"\s+content="WordPress[^"]*"/i],
    headers: { 'x-powered-by': /WordPress/i },
    cookies: ['wordpress_', 'wp-settings'],
    paths: ['/wp-login.php', '/wp-admin/'],
    category: 'CMS',
    risk: 'medium',
    note: 'Popular CMS — ensure plugins and core are updated'
  },
  'Drupal': {
    html: [/Drupal\.settings/i, /sites\/default\/files/i, /<meta\s+name="generator"\s+content="Drupal/i],
    headers: { 'x-generator': /Drupal/i, 'x-drupal-cache': /./ },
    category: 'CMS',
    risk: 'medium',
    note: 'Enterprise CMS — keep core and modules updated'
  },
  'Joomla': {
    html: [/\/media\/jui\//i, /\/components\/com_/i, /<meta\s+name="generator"\s+content="Joomla/i],
    category: 'CMS',
    risk: 'medium',
    note: 'CMS with history of plugin vulnerabilities'
  },
  'Shopify': {
    html: [/cdn\.shopify\.com/i, /Shopify\.theme/i],
    headers: { 'x-shopify-stage': /./ },
    category: 'E-commerce',
    risk: 'low',
    note: 'Managed platform — security handled by Shopify'
  },
  'Squarespace': {
    html: [/squarespace\.com/i, /static\.squarespace\.com/i],
    category: 'CMS',
    risk: 'low',
    note: 'Managed platform'
  },
  'Wix': {
    html: [/wix\.com/i, /static\.parastorage\.com/i, /wixstatic\.com/i],
    category: 'CMS',
    risk: 'low',
    note: 'Managed platform'
  },

  // Frameworks
  'React': {
    html: [/data-reactroot/i, /react\.production\.min\.js/i, /__NEXT_DATA__/i, /_next\//i],
    category: 'Framework',
    risk: 'info'
  },
  'Next.js': {
    html: [/__NEXT_DATA__/i, /_next\/static/i],
    headers: { 'x-powered-by': /Next\.js/i },
    category: 'Framework',
    risk: 'info'
  },
  'Vue.js': {
    html: [/vue\.min\.js/i, /vue\.runtime/i, /data-v-[a-f0-9]/i, /__vue/i],
    category: 'Framework',
    risk: 'info'
  },
  'Nuxt.js': {
    html: [/__nuxt/i, /_nuxt\//i],
    category: 'Framework',
    risk: 'info'
  },
  'Angular': {
    html: [/ng-version/i, /angular\.min\.js/i, /ng-app/i],
    category: 'Framework',
    risk: 'info'
  },
  'Ruby on Rails': {
    headers: { 'x-powered-by': /Phusion Passenger/i, 'server': /Phusion/i },
    cookies: ['_session_id'],
    html: [/csrf-token/i],
    category: 'Framework',
    risk: 'info'
  },
  'Django': {
    cookies: ['django_language', 'sessionid'],
    html: [/csrfmiddlewaretoken/i, /django/i],
    category: 'Framework',
    risk: 'info'
  },
  'Laravel': {
    cookies: ['laravel_session', 'XSRF-TOKEN'],
    html: [/laravel/i],
    category: 'Framework',
    risk: 'info'
  },
  'Express.js': {
    headers: { 'x-powered-by': /Express/i },
    category: 'Framework',
    risk: 'info',
    note: 'Remove X-Powered-By header in production'
  },

  // Servers
  'Nginx': {
    headers: { 'server': /nginx/i },
    category: 'Server',
    risk: 'info'
  },
  'Apache': {
    headers: { 'server': /Apache/i },
    category: 'Server',
    risk: 'info'
  },
  'Cloudflare': {
    headers: { 'server': /cloudflare/i, 'cf-ray': /./ },
    category: 'CDN/WAF',
    risk: 'low',
    note: 'Protected by Cloudflare WAF'
  },
  'AWS CloudFront': {
    headers: { 'server': /CloudFront/i, 'x-amz-cf-id': /./ },
    category: 'CDN',
    risk: 'low'
  },
  'Vercel': {
    headers: { 'server': /Vercel/i, 'x-vercel-id': /./ },
    category: 'Platform',
    risk: 'low'
  },
  'Netlify': {
    headers: { 'server': /Netlify/i },
    category: 'Platform',
    risk: 'low'
  },

  // Security
  'Akamai': {
    headers: { 'server': /AkamaiGHost/i, 'x-akamai-session-info': /./ },
    category: 'CDN/WAF',
    risk: 'low',
    note: 'Protected by Akamai WAF'
  },

  // Analytics/Libraries
  'jQuery': {
    html: [/jquery[-.][\d.]*\.min\.js/i, /jquery\.min\.js/i],
    category: 'Library',
    risk: 'info',
    note: 'Check for outdated versions with known XSS vulnerabilities'
  },
  'Bootstrap': {
    html: [/bootstrap[-.][\d.]*\.min\.(js|css)/i, /bootstrap\.min\.(js|css)/i],
    category: 'Library',
    risk: 'info'
  },
  'Google Analytics': {
    html: [/google-analytics\.com\/analytics/i, /googletagmanager\.com/i, /gtag\(/i],
    category: 'Analytics',
    risk: 'info'
  },
  'Google Tag Manager': {
    html: [/googletagmanager\.com\/gtm\.js/i],
    category: 'Analytics',
    risk: 'info'
  },
};

async function scanFingerprint(parsedUrl, options = {}) {
  const checks = [];
  let score = 0;
  let maxScore = 3; // Based on information exposure

  // Fetch headers and body
  const [headers, html] = await Promise.all([
    fetchHeaders(parsedUrl, options),
    fetchBody(parsedUrl, options)
  ]);

  const detected = [];

  for (const [tech, sig] of Object.entries(SIGNATURES)) {
    let found = false;
    let evidence = '';

    // Check headers
    if (sig.headers && headers) {
      for (const [header, pattern] of Object.entries(sig.headers)) {
        if (headers[header] && pattern.test(headers[header])) {
          found = true;
          evidence = `Header: ${header}: ${headers[header]}`;
          break;
        }
      }
    }

    // Check HTML patterns
    if (!found && sig.html && html) {
      for (const pattern of sig.html) {
        if (pattern.test(html)) {
          found = true;
          evidence = 'HTML content match';
          break;
        }
      }
    }

    // Check cookies
    if (!found && sig.cookies && headers && headers['set-cookie']) {
      const cookieStr = Array.isArray(headers['set-cookie']) ? headers['set-cookie'].join(' ') : headers['set-cookie'];
      for (const cookieName of sig.cookies) {
        if (cookieStr.toLowerCase().includes(cookieName.toLowerCase())) {
          found = true;
          evidence = `Cookie: ${cookieName}`;
          break;
        }
      }
    }

    if (found) {
      detected.push({ name: tech, ...sig, evidence });
    }
  }

  // Check for version leaks in Server header
  const serverHeader = headers?.server || '';
  const versionMatch = serverHeader.match(/([\w.-]+)\/([\d.]+)/);
  let leaksVersion = false;

  if (versionMatch) {
    leaksVersion = true;
    checks.push({ name: 'Server Version Exposure', status: 'warn', 
      message: `Server header reveals: ${versionMatch[0]}. Attackers can target version-specific exploits.`,
      value: serverHeader,
      recommendation: 'Remove version numbers from Server header'
    });
  }

  // Check X-Powered-By
  const poweredBy = headers?.['x-powered-by'];
  if (poweredBy) {
    leaksVersion = true;
    checks.push({ name: 'X-Powered-By Exposure', status: 'warn',
      message: `Reveals technology: "${poweredBy}". Aids attacker reconnaissance.`,
      value: poweredBy,
      recommendation: 'Remove X-Powered-By header entirely'
    });
  }

  // Score based on information exposure
  if (!leaksVersion && detected.filter(d => d.risk !== 'info').length === 0) {
    score = 3;
    checks.unshift({ name: 'Technology Fingerprint', status: 'pass', message: 'Minimal technology exposure — good operational security' });
  } else if (!leaksVersion) {
    score = 2;
    checks.unshift({ name: 'Technology Fingerprint', status: 'pass', message: 'No version information leaked in headers' });
  } else {
    score = 1;
    checks.unshift({ name: 'Technology Fingerprint', status: 'warn', message: 'Server exposes technology/version information' });
  }

  // List detected technologies
  if (detected.length > 0) {
    const byCategory = {};
    for (const tech of detected) {
      if (!byCategory[tech.category]) byCategory[tech.category] = [];
      byCategory[tech.category].push(tech);
    }

    for (const [category, techs] of Object.entries(byCategory)) {
      const names = techs.map(t => t.name).join(', ');
      checks.push({ name: `Detected: ${category}`, status: 'info', message: names, value: names });
      
      // Add notes for notable detections
      for (const tech of techs) {
        if (tech.note) {
          checks.push({ name: tech.name, status: tech.risk === 'medium' ? 'warn' : 'info', message: tech.note });
        }
      }
    }
  } else {
    checks.push({ name: 'Technologies', status: 'info', message: 'No technologies confidently identified from external scan' });
  }

  return { score, maxScore, checks };
}

function fetchHeaders(parsedUrl, options = {}) {
  return new Promise((resolve) => {
    const timeout = options.timeout || 10000;
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    let resolved = false;
    const done = (val) => { if (!resolved) { resolved = true; resolve(val); } };
    const timer = setTimeout(() => done(null), timeout + 2000);

    const req = protocol.request(parsedUrl.href, {
      method: 'HEAD', timeout,
      headers: { 'User-Agent': 'SiteGuard/0.1 Security Scanner' },
      rejectUnauthorized: false,
    }, (res) => {
      clearTimeout(timer);
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const redirectUrl = new URL(res.headers.location, parsedUrl.href);
        fetchHeaders(redirectUrl, options).then(done);
        return;
      }
      done(res.headers);
    });
    req.on('error', () => { clearTimeout(timer); done(null); });
    req.on('timeout', () => { clearTimeout(timer); req.destroy(); done(null); });
    req.end();
  });
}

module.exports = { scanFingerprint };
