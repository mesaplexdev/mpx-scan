/**
 * Security Headers Scanner
 * 
 * Checks for presence and configuration of security headers:
 * - Strict-Transport-Security (HSTS)
 * - Content-Security-Policy (CSP)
 * - X-Content-Type-Options
 * - X-Frame-Options
 * - Referrer-Policy
 * - Permissions-Policy
 * - X-XSS-Protection (deprecated but still checked)
 * - Cross-Origin-Opener-Policy
 * - Cross-Origin-Resource-Policy
 * - Cross-Origin-Embedder-Policy
 */

const https = require('https');
const http = require('http');

async function scanHeaders(parsedUrl, options = {}) {
  const headers = await fetchHeaders(parsedUrl, options);
  const checks = [];
  let score = 0;
  let maxScore = 0;

  // ==============================================
  // CRITICAL HEADERS (fail if missing, full points)
  // ==============================================

  // --- Strict-Transport-Security (4 pts) ---
  maxScore += 4;
  const hsts = headers['strict-transport-security'];
  if (hsts) {
    const maxAge = parseInt((hsts.match(/max-age=(\d+)/) || [])[1] || '0');
    const includesSubs = /includesubdomains/i.test(hsts);
    const preload = /preload/i.test(hsts);
    
    if (maxAge >= 31536000 && includesSubs && preload) {
      checks.push({ name: 'Strict-Transport-Security', status: 'pass', message: `Excellent. max-age=${maxAge}, includeSubDomains, preload`, value: hsts });
      score += 4;
    } else if (maxAge >= 31536000) {
      checks.push({ name: 'Strict-Transport-Security', status: 'pass', message: `Good. max-age=${maxAge}${includesSubs ? ', includeSubDomains' : ''}${preload ? ', preload' : ''}`, value: hsts });
      score += 3;
    } else if (maxAge > 0) {
      checks.push({ name: 'Strict-Transport-Security', status: 'warn', message: `max-age=${maxAge} is low. Recommend >= 31536000 (1 year)`, value: hsts });
      score += 1;
    }
  } else {
    checks.push({ name: 'Strict-Transport-Security', status: 'fail', message: 'Missing. Allows downgrade attacks to HTTP.', recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' });
  }

  // --- X-Content-Type-Options (3 pts) ---
  maxScore += 3;
  const xcto = headers['x-content-type-options'];
  if (xcto && xcto.toLowerCase() === 'nosniff') {
    checks.push({ name: 'X-Content-Type-Options', status: 'pass', message: 'nosniff — prevents MIME-type sniffing', value: xcto });
    score += 3;
  } else {
    checks.push({ name: 'X-Content-Type-Options', status: 'fail', message: 'Missing or incorrect. Browsers may MIME-sniff responses.', recommendation: 'Add: X-Content-Type-Options: nosniff' });
  }

  // ==============================================
  // IMPORTANT HEADERS (fail if missing, fewer pts)
  // ==============================================

  // --- X-Frame-Options (2 pts) ---
  maxScore += 2;
  const csp = headers['content-security-policy'];
  const xfo = headers['x-frame-options'];
  if (xfo) {
    const val = xfo.toUpperCase();
    if (val === 'DENY' || val === 'SAMEORIGIN') {
      checks.push({ name: 'X-Frame-Options', status: 'pass', message: `${val} — prevents clickjacking`, value: xfo });
      score += 2;
    } else {
      checks.push({ name: 'X-Frame-Options', status: 'warn', message: `Unusual value: ${xfo}`, value: xfo });
      score += 1;
    }
  } else {
    // Check if CSP has frame-ancestors
    if (csp && /frame-ancestors/i.test(csp)) {
      checks.push({ name: 'X-Frame-Options', status: 'pass', message: 'Not set, but CSP frame-ancestors provides equivalent protection', value: 'via CSP' });
      score += 2;
    } else {
      checks.push({ name: 'X-Frame-Options', status: 'fail', message: 'Missing. Page can be embedded in iframes (clickjacking risk).', recommendation: 'Add: X-Frame-Options: DENY (or SAMEORIGIN)' });
    }
  }

  // --- Referrer-Policy (2 pts) ---
  maxScore += 2;
  const rp = headers['referrer-policy'];
  const goodPolicies = ['no-referrer', 'strict-origin-when-cross-origin', 'strict-origin', 'same-origin', 'no-referrer-when-downgrade'];
  if (rp && goodPolicies.some(p => rp.toLowerCase().includes(p))) {
    checks.push({ name: 'Referrer-Policy', status: 'pass', message: `${rp}`, value: rp });
    score += 2;
  } else if (rp) {
    checks.push({ name: 'Referrer-Policy', status: 'warn', message: `Set to "${rp}" — may leak referrer data`, value: rp });
    score += 1;
  } else {
    checks.push({ name: 'Referrer-Policy', status: 'fail', message: 'Missing. Browser defaults may leak URL paths in referrer.', recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin' });
  }

  // ==============================================
  // NICE-TO-HAVE HEADERS (warn if missing, no pts)
  // ==============================================

  // --- Content-Security-Policy (bonus: 2 pts if present, warn if missing, no deduction) ---
  maxScore += 2;
  if (csp) {
    const hasDefaultSrc = /default-src/i.test(csp);
    const hasUnsafeInline = /unsafe-inline/i.test(csp);
    const hasUnsafeEval = /unsafe-eval/i.test(csp);
    
    if (hasDefaultSrc && !hasUnsafeInline && !hasUnsafeEval) {
      checks.push({ name: 'Content-Security-Policy', status: 'pass', message: 'Strong policy without unsafe directives', value: csp.substring(0, 200) + (csp.length > 200 ? '...' : '') });
      score += 2;
    } else if (hasDefaultSrc) {
      const issues = [];
      if (hasUnsafeInline) issues.push('unsafe-inline');
      if (hasUnsafeEval) issues.push('unsafe-eval');
      checks.push({ name: 'Content-Security-Policy', status: 'warn', message: `Present but uses ${issues.join(', ')}`, value: csp.substring(0, 200) });
      score += 1;
    } else {
      checks.push({ name: 'Content-Security-Policy', status: 'warn', message: 'Present but missing default-src directive', value: csp.substring(0, 200) });
      score += 1;
    }
  } else {
    // Warn instead of fail — CSP is hard to implement correctly
    checks.push({ name: 'Content-Security-Policy', status: 'warn', message: 'Missing. Consider adding to protect against XSS and data injection.', recommendation: "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'" });
    score += 0; // No deduction for missing CSP
  }

  // --- Permissions-Policy (bonus: 1 pt if present) ---
  maxScore += 1;
  const pp = headers['permissions-policy'] || headers['feature-policy'];
  if (pp) {
    checks.push({ name: 'Permissions-Policy', status: 'pass', message: 'Controls browser feature access', value: pp.substring(0, 200) });
    score += 1;
  } else {
    checks.push({ name: 'Permissions-Policy', status: 'warn', message: 'Missing. Browser features (camera, mic, geolocation) unrestricted.', recommendation: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()' });
  }

  // --- Cross-Origin-Opener-Policy (bonus: 0.5 pts if present) ---
  maxScore += 0.5;
  const coop = headers['cross-origin-opener-policy'];
  if (coop) {
    checks.push({ name: 'Cross-Origin-Opener-Policy', status: 'pass', message: coop, value: coop });
    score += 0.5;
  } else {
    checks.push({ name: 'Cross-Origin-Opener-Policy', status: 'info', message: 'Not set. Consider adding for cross-origin isolation.' });
  }

  // --- Cross-Origin-Resource-Policy (bonus: 0.5 pts if present) ---
  maxScore += 0.5;
  const corp = headers['cross-origin-resource-policy'];
  if (corp) {
    checks.push({ name: 'Cross-Origin-Resource-Policy', status: 'pass', message: corp, value: corp });
    score += 0.5;
  } else {
    checks.push({ name: 'Cross-Origin-Resource-Policy', status: 'info', message: 'Not set. Consider adding to control resource sharing.' });
  }

  // --- Deprecated but notable ---
  const xxss = headers['x-xss-protection'];
  if (xxss && xxss !== '0') {
    checks.push({ name: 'X-XSS-Protection', status: 'info', message: `Set to "${xxss}". This header is deprecated; CSP is the modern replacement.`, value: xxss });
  }

  // --- Server header leak ---
  const server = headers['server'];
  if (server && /\d/.test(server)) {
    checks.push({ name: 'Server Header', status: 'warn', message: `Leaks version info: "${server}". Remove version numbers.`, value: server });
  }

  // --- X-Powered-By leak ---
  const powered = headers['x-powered-by'];
  if (powered) {
    checks.push({ name: 'X-Powered-By', status: 'warn', message: `Leaks technology: "${powered}". Remove this header.`, value: powered });
  }

  return { score, maxScore, checks };
}

function fetchHeaders(parsedUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 10000;
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    const req = protocol.request(parsedUrl.href, {
      method: 'HEAD',
      timeout,
      headers: {
        'User-Agent': 'mpx-scan/1.2.0 Security Scanner (https://github.com/mesaplexdev/mpx-scan)'
      },
      rejectUnauthorized: false // We check SSL separately
    }, (res) => {
      // Follow redirects (up to 5)
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const redirectUrl = new URL(res.headers.location, parsedUrl.href);
        if ((options._redirectCount || 0) >= 5) {
          reject(new Error('Too many redirects'));
          return;
        }
        fetchHeaders(redirectUrl, { ...options, _redirectCount: (options._redirectCount || 0) + 1 })
          .then(resolve).catch(reject);
        return;
      }
      resolve(res.headers);
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Connection timeout')); });
    req.end();
  });
}

module.exports = { scanHeaders };
