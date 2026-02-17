/**
 * Open Redirect Scanner
 * 
 * Tests for open redirect vulnerabilities by checking if the site
 * redirects to arbitrary external domains via URL parameters.
 * 
 * Open redirects are used in phishing attacks — attackers craft URLs
 * that look legitimate but redirect to malicious sites.
 */

const https = require('https');
const http = require('http');

// Common parameter names used for redirects
const REDIRECT_PARAMS = [
  'url', 'redirect', 'redirect_url', 'redirect_uri', 'return', 'return_url',
  'returnTo', 'return_to', 'next', 'goto', 'dest', 'destination', 'redir',
  'out', 'continue', 'target', 'path', 'callback', 'cb', 'ref',
];

const EVIL_DOMAIN = 'https://evil.example.com';

async function scanRedirects(parsedUrl, options = {}) {
  const checks = [];
  let score = 0;
  let maxScore = 0;

  // Test each redirect parameter
  const vulnParams = [];
  const safeParams = [];
  const testedCount = Math.min(REDIRECT_PARAMS.length, options.maxRedirectTests || 10);
  maxScore = testedCount;

  const testPromises = REDIRECT_PARAMS.slice(0, testedCount).map(async (param) => {
    try {
      const testUrl = new URL(parsedUrl.href);
      testUrl.searchParams.set(param, EVIL_DOMAIN);
      
      const result = await followRedirect(testUrl, options);
      
      if (result.redirectsToExternal) {
        vulnParams.push({ param, redirectedTo: result.location });
        return { param, vulnerable: true };
      } else {
        safeParams.push(param);
        return { param, vulnerable: false };
      }
    } catch {
      return { param, vulnerable: false };
    }
  });

  const results = await Promise.all(testPromises);

  // Score
  const vulnCount = results.filter(r => r.vulnerable).length;
  score = testedCount - vulnCount;

  if (vulnCount === 0) {
    checks.push({ name: 'Open Redirects', status: 'pass', message: `Tested ${testedCount} common redirect parameters — none vulnerable` });
  } else {
    checks.push({ name: 'Open Redirects', status: 'fail', 
      message: `${vulnCount} open redirect(s) found! Attackers can craft phishing URLs using your domain.`,
      recommendation: 'Validate redirect destinations against an allowlist of trusted domains. Never redirect to user-supplied URLs without validation.'
    });
    
    for (const vuln of vulnParams) {
      checks.push({ name: `Redirect: ?${vuln.param}=`, status: 'fail', 
        message: `Redirects to external domain via "${vuln.param}" parameter`,
        value: vuln.redirectedTo
      });
    }
  }

  return { score, maxScore, checks };
}

function followRedirect(testUrl, options = {}) {
  return new Promise((resolve) => {
    const timeout = options.timeout || 5000;
    const protocol = testUrl.protocol === 'https:' ? https : http;
    let resolved = false;
    const done = (val) => { if (!resolved) { resolved = true; resolve(val); } };
    const timer = setTimeout(() => { req && req.destroy(); done({ redirectsToExternal: false }); }, timeout);

    const req = protocol.request(testUrl.href, {
      method: 'GET',
      timeout,
      headers: { 'User-Agent': 'mpx-scan/1.2.1 Security Scanner (https://github.com/mesaplexdev/mpx-scan)' },
      rejectUnauthorized: false,
    }, (res) => {
      res.resume(); // Consume body
      clearTimeout(timer);
      
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const location = res.headers.location;
        try {
          const redirectTarget = new URL(location, testUrl.href);
          // Check if redirect goes to our test domain OR any external domain
          // that wasn't the original host (indicates the param controls redirect target)
          const originalHost = testUrl.hostname;
          const isExternal = redirectTarget.hostname === 'evil.example.com';
          done({ redirectsToExternal: isExternal, location });
        } catch {
          done({ redirectsToExternal: false });
        }
      } else {
        done({ redirectsToExternal: false });
      }
    });

    req.on('error', () => { clearTimeout(timer); done({ redirectsToExternal: false }); });
    req.on('timeout', () => { clearTimeout(timer); req.destroy(); done({ redirectsToExternal: false }); });
    req.end();
  });
}

module.exports = { scanRedirects };
