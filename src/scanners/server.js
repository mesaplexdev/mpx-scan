/**
 * Server Configuration Scanner
 * 
 * Checks server-level security:
 * - HTTP to HTTPS redirect
 * - Server information leakage
 * - CORS configuration
 * - HTTP methods allowed
 */

const https = require('https');
const http = require('http');

async function scanServer(parsedUrl, options = {}) {
  const checks = [];
  let score = 0;
  let maxScore = 0;

  // --- HTTP to HTTPS redirect ---
  maxScore += 2;
  if (parsedUrl.protocol === 'https:') {
    try {
      const httpUrl = new URL(parsedUrl.href);
      httpUrl.protocol = 'http:';
      const redirectsToHttps = await checkRedirectToHttps(httpUrl, options);
      if (redirectsToHttps) {
        checks.push({ name: 'HTTP → HTTPS Redirect', status: 'pass', message: 'HTTP requests redirect to HTTPS' });
        score += 2;
      } else {
        checks.push({ name: 'HTTP → HTTPS Redirect', status: 'warn', message: 'HTTP does not redirect to HTTPS. Users can access insecure version.', recommendation: 'Configure server to redirect all HTTP traffic to HTTPS (301 redirect)' });
      }
    } catch {
      checks.push({ name: 'HTTP → HTTPS Redirect', status: 'info', message: 'Could not test HTTP redirect (port 80 may be closed)' });
      score += 1; // Benefit of doubt — port 80 closed is actually fine
    }
  } else {
    checks.push({ name: 'HTTPS', status: 'fail', message: 'Site served over HTTP. All traffic is unencrypted.' });
  }

  // --- CORS headers ---
  maxScore += 1;
  try {
    const corsHeaders = await fetchWithOrigin(parsedUrl, options);
    const acao = corsHeaders['access-control-allow-origin'];
    if (!acao) {
      checks.push({ name: 'CORS Policy', status: 'pass', message: 'No Access-Control-Allow-Origin header (default same-origin policy)' });
      score += 1;
    } else if (acao === '*') {
      checks.push({ name: 'CORS Policy', status: 'warn', message: 'Access-Control-Allow-Origin: * — allows any origin to read responses', value: acao });
      score += 0.25;
    } else {
      checks.push({ name: 'CORS Policy', status: 'pass', message: `CORS restricted to: ${acao}`, value: acao });
      score += 1;
    }
  } catch {
    checks.push({ name: 'CORS Policy', status: 'info', message: 'Could not test CORS configuration' });
  }

  // --- Allowed HTTP methods ---
  maxScore += 1;
  try {
    const methods = await checkMethods(parsedUrl, options);
    if (methods.length === 0) {
      checks.push({ name: 'HTTP Methods', status: 'info', message: 'Server did not disclose allowed methods (OPTIONS returned no Allow header)' });
      score += 0.5; // Benefit of doubt
    } else {
      const dangerous = methods.filter(m => ['PUT', 'DELETE', 'TRACE', 'TRACK'].includes(m));
      if (dangerous.length > 0) {
        checks.push({ name: 'HTTP Methods', status: 'warn', message: `Potentially dangerous methods enabled: ${dangerous.join(', ')}`, value: methods.join(', ') });
        score += 0.5;
      } else {
        checks.push({ name: 'HTTP Methods', status: 'pass', message: `Allowed: ${methods.join(', ')}`, value: methods.join(', ') });
        score += 1;
      }
    }
  } catch {
    checks.push({ name: 'HTTP Methods', status: 'info', message: 'Could not determine allowed methods' });
    score += 0.5;
  }

  return { score, maxScore, checks };
}

function checkRedirectToHttps(httpUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 5000;
    const method = options._useGet ? 'GET' : 'HEAD';
    const req = http.request(httpUrl.href, {
      method,
      timeout,
      headers: { 'User-Agent': 'mpx-scan/1.2.1 Security Scanner (https://github.com/mesaplexdev/mpx-scan)' },
    }, (res) => {
      if (method === 'GET') { res.resume(); }
      if (res.statusCode >= 300 && res.statusCode < 400) {
        const location = res.headers.location || '';
        resolve(location.startsWith('https://'));
      } else if (!options._useGet && res.statusCode >= 400) {
        checkRedirectToHttps(httpUrl, { ...options, _useGet: true }).then(resolve).catch(reject);
      } else {
        resolve(false);
      }
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

function fetchWithOrigin(parsedUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 5000;
    const method = options._useGet ? 'GET' : 'HEAD';
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    const req = protocol.request(parsedUrl.href, {
      method,
      timeout,
      headers: {
        'User-Agent': 'mpx-scan/1.2.1 Security Scanner (https://github.com/mesaplexdev/mpx-scan)',
        'Origin': 'https://evil.example.com'
      },
      rejectUnauthorized: false,
    }, (res) => {
      if (method === 'GET') { res.resume(); }
      // HEAD returned error — retry with GET
      if (!options._useGet && res.statusCode >= 400) {
        fetchWithOrigin(parsedUrl, { ...options, _useGet: true }).then(resolve).catch(reject);
        return;
      }
      resolve(res.headers);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

function checkMethods(parsedUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 5000;
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    const req = protocol.request(parsedUrl.href, {
      method: 'OPTIONS',
      timeout,
      headers: { 'User-Agent': 'mpx-scan/1.2.1 Security Scanner (https://github.com/mesaplexdev/mpx-scan)' },
      rejectUnauthorized: false,
    }, (res) => {
      const allow = res.headers.allow || '';
      const methods = allow ? allow.split(',').map(m => m.trim().toUpperCase()) : [];
      resolve(methods);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

module.exports = { scanServer };
