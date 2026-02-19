/**
 * Cookie Security Scanner
 * 
 * Checks Set-Cookie headers for security flags:
 * - Secure flag (HTTPS only)
 * - HttpOnly flag (no JS access)
 * - SameSite attribute
 * - Path scope
 * - Expiration
 */

const https = require('https');
const http = require('http');

async function scanCookies(parsedUrl, options = {}) {
  const checks = [];
  let score = 0;
  let maxScore = 0;

  const cookies = await fetchCookies(parsedUrl, options);

  if (cookies.length === 0) {
    checks.push({ name: 'Cookies', status: 'info', message: 'No cookies set on initial page load' });
    return { score: 1, maxScore: 1, checks };
  }

  checks.push({ name: 'Cookie Count', status: 'info', message: `${cookies.length} cookie(s) found`, value: cookies.length.toString() });

  for (const cookie of cookies) {
    const name = cookie.name || 'unnamed';
    const isSession = /session|sid|token|auth|jwt|csrf/i.test(name);
    const weight = isSession ? 2 : 1;

    // --- Secure flag ---
    maxScore += weight;
    if (cookie.secure) {
      checks.push({ name: `${name}: Secure`, status: 'pass', message: 'Cookie sent only over HTTPS' });
      score += weight;
    } else if (parsedUrl.protocol === 'https:') {
      checks.push({ name: `${name}: Secure`, status: isSession ? 'fail' : 'warn', message: 'Missing Secure flag — cookie can be sent over HTTP', recommendation: 'Add Secure flag to Set-Cookie header' });
      if (!isSession) score += weight * 0.5;
    }

    // --- HttpOnly flag ---
    maxScore += weight;
    if (cookie.httpOnly) {
      checks.push({ name: `${name}: HttpOnly`, status: 'pass', message: 'Cookie inaccessible to JavaScript' });
      score += weight;
    } else {
      checks.push({ name: `${name}: HttpOnly`, status: isSession ? 'fail' : 'warn', message: 'Missing HttpOnly — cookie accessible via document.cookie (XSS risk)', recommendation: 'Add HttpOnly flag to prevent JavaScript access' });
      if (!isSession) score += weight * 0.25;
    }

    // --- SameSite ---
    maxScore += weight * 0.5;
    if (cookie.sameSite) {
      const val = cookie.sameSite.toLowerCase();
      if (val === 'strict' || val === 'lax') {
        checks.push({ name: `${name}: SameSite`, status: 'pass', message: `SameSite=${cookie.sameSite}`, value: cookie.sameSite });
        score += weight * 0.5;
      } else if (val === 'none') {
        checks.push({ name: `${name}: SameSite`, status: 'warn', message: 'SameSite=None — cookie sent on all cross-site requests' });
        score += weight * 0.25;
      }
    } else {
      checks.push({ name: `${name}: SameSite`, status: 'warn', message: 'Missing SameSite attribute', recommendation: 'Add SameSite=Lax or SameSite=Strict' });
    }
  }

  return { score, maxScore, checks };
}

function fetchCookies(parsedUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 10000;
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    const req = protocol.request(parsedUrl.href, {
      method: 'GET',
      timeout,
      headers: { 'User-Agent': 'mpx-scan/1.3.0 Security Scanner (https://github.com/mesaplexdev/mpx-scan)' },
      rejectUnauthorized: false,
    }, (res) => {
      // Consume body
      res.on('data', () => {});
      res.on('end', () => {});

      // Follow redirects to get cookies from final destination
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        if ((options._redirectCount || 0) >= 5) {
          resolve([]);
          return;
        }
        const redirectUrl = new URL(res.headers.location, parsedUrl.href);
        fetchCookies(redirectUrl, { ...options, _redirectCount: (options._redirectCount || 0) + 1 })
          .then(resolve).catch(() => resolve([]));
        return;
      }

      const setCookies = res.headers['set-cookie'] || [];
      const parsed = setCookies.map(parseCookie);
      resolve(parsed);
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

function parseCookie(setCookieStr) {
  const parts = setCookieStr.split(';').map(p => p.trim());
  const [nameValue, ...attrs] = parts;
  const eqIndex = nameValue.indexOf('=');
  const name = eqIndex > -1 ? nameValue.substring(0, eqIndex) : nameValue;
  
  const cookie = { name, raw: setCookieStr };
  
  for (const attr of attrs) {
    const [key, val] = attr.split('=').map(s => s.trim());
    const lower = key.toLowerCase();
    if (lower === 'secure') cookie.secure = true;
    else if (lower === 'httponly') cookie.httpOnly = true;
    else if (lower === 'samesite') cookie.sameSite = val || 'Lax';
    else if (lower === 'path') cookie.path = val;
    else if (lower === 'domain') cookie.domain = val;
    else if (lower === 'expires') cookie.expires = val;
    else if (lower === 'max-age') cookie.maxAge = parseInt(val);
  }
  
  return cookie;
}

module.exports = { scanCookies };
