/**
 * mpx-scan — Professional Website Security Scanner
 * 
 * Core engine. Runs all security checks against a target URL
 * and returns a structured report with grades and recommendations.
 * 
 * Zero external dependencies for scanning (only chalk/commander for CLI)
 */

const https = require('https');
const http = require('http');
const { scanHeaders } = require('./scanners/headers');
const { scanSSL } = require('./scanners/ssl');
const { scanCookies } = require('./scanners/cookies');
const { scanExposedFiles } = require('./scanners/exposed-files');
const { scanDNS } = require('./scanners/dns');
const { scanServer } = require('./scanners/server');
const { scanSRI } = require('./scanners/sri');
const { scanMixedContent } = require('./scanners/mixed-content');
const { scanRedirects } = require('./scanners/redirects');

const GRADES = ['A+', 'A', 'B', 'C', 'D', 'F'];

const SCANNER_TIERS = {
  free: ['headers', 'ssl', 'server'],
  pro: ['headers', 'ssl', 'cookies', 'server', 'exposedFiles', 'dns', 'sri', 'mixedContent', 'redirects']
};

/**
 * Run a full security scan on the target URL
 * @param {string} url - Target URL to scan
 * @param {object} options - Scan options
 * @returns {object} Structured scan report
 */
/**
 * Quick connectivity check — throws a network error if the host is unreachable.
 * Used to provide exit code 4 (NETWORK_ERROR) early instead of silently returning error checks.
 */
function checkConnectivity(parsedUrl, timeoutMs) {
  return new Promise((resolve, reject) => {
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    const timer = setTimeout(() => {
      req && req.destroy();
      const err = new Error(`ETIMEDOUT: Connection to ${parsedUrl.hostname} timed out`);
      err.code = 'ETIMEDOUT';
      reject(err);
    }, timeoutMs);

    const req = protocol.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname || '/',
      method: 'HEAD',
      timeout: timeoutMs,
      headers: { 'User-Agent': 'mpx-scan/1.3.0 Security Scanner' },
      rejectUnauthorized: false,
    }, (res) => {
      clearTimeout(timer);
      res.resume();
      resolve();
    });

    req.on('error', (err) => {
      clearTimeout(timer);
      if (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN' || err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' || err.code === 'ECONNRESET') {
        reject(err);
      } else {
        resolve(); // Other errors (like SSL) are fine — host is reachable
      }
    });

    req.on('timeout', () => {
      req.destroy();
      clearTimeout(timer);
      const err = new Error(`ETIMEDOUT: Connection to ${parsedUrl.hostname} timed out`);
      err.code = 'ETIMEDOUT';
      reject(err);
    });

    req.end();
  });
}

async function scan(url, options = {}) {
  const startTime = Date.now();
  const timeoutMs = options.timeout || 10000;
  
  // Normalize URL
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  
  const parsedUrl = new URL(url);
  
  // BUG-02: Pre-scan connectivity check — throws network error → CLI maps to exit 4
  await checkConnectivity(parsedUrl, Math.min(timeoutMs, 10000));
  const results = {
    url: parsedUrl.href,
    hostname: parsedUrl.hostname,
    scannedAt: new Date().toISOString(),
    scanDuration: 0,
    grade: 'F',
    score: 0,
    maxScore: 0,
    sections: {},
    summary: {
      passed: 0,
      warnings: 0,
      failed: 0,
      info: 0
    },
    tier: options.tier || 'free'
  };

  const allScanners = [
    { name: 'headers', fn: scanHeaders, weight: 15 },
    { name: 'ssl', fn: scanSSL, weight: 20 },
    { name: 'cookies', fn: scanCookies, weight: 10 },
    { name: 'server', fn: scanServer, weight: 8 },
    { name: 'exposedFiles', fn: scanExposedFiles, weight: 10 },
    { name: 'dns', fn: scanDNS, weight: 7 },
    { name: 'sri', fn: scanSRI, weight: 5 },
    { name: 'mixedContent', fn: scanMixedContent, weight: 5 },
    { name: 'redirects', fn: scanRedirects, weight: 5 },
  ];

  // Determine which scanners to run based on tier and options
  const tier = options.tier || 'free';
  const allowedScanners = options.full ? SCANNER_TIERS.pro : (SCANNER_TIERS[tier] || SCANNER_TIERS.free);
  
  const enabledScanners = allScanners.filter(s => allowedScanners.includes(s.name));

  // BUG-05: Wrap each scanner in a timeout race to prevent hanging on closed ports
  const scannerTimeout = timeoutMs + 5000; // Give scanners a bit extra beyond the connect timeout

  // Run scanners concurrently
  const scanPromises = enabledScanners.map(async (scanner) => {
    try {
      // BUG-05: Race scanner against timeout to prevent indefinite hang on closed ports
      const timeoutPromise = new Promise((_, reject) => {
        const t = setTimeout(() => {
          reject(new Error(`Scanner timed out after ${scannerTimeout}ms`));
        }, scannerTimeout);
        // Allow process to exit even if timer is pending
        if (t.unref) t.unref();
      });
      const result = await Promise.race([scanner.fn(parsedUrl, options), timeoutPromise]);
      return { name: scanner.name, weight: scanner.weight, result };
    } catch (err) {
      return { 
        name: scanner.name, 
        weight: scanner.weight,
        result: {
          score: 0,
          maxScore: scanner.weight,
          checks: [{ 
            name: `${scanner.name} scan`, 
            status: 'error', 
            message: err.message 
          }]
        }
      };
    }
  });

  const scanResults = await Promise.all(scanPromises);

  // Aggregate results
  let totalScore = 0;
  let totalMax = 0;

  for (const { name, weight, result } of scanResults) {
    // Normalize scores to weight
    const normalizedScore = result.maxScore > 0 
      ? (result.score / result.maxScore) * weight 
      : 0;
    
    totalScore += normalizedScore;
    totalMax += weight;

    results.sections[name] = {
      score: Math.round(normalizedScore * 10) / 10,
      maxScore: weight,
      grade: calculateGrade(normalizedScore / weight),
      checks: result.checks || []
    };

    // Count statuses
    for (const check of (result.checks || [])) {
      if (check.status === 'pass') results.summary.passed++;
      else if (check.status === 'warn') results.summary.warnings++;
      else if (check.status === 'fail') results.summary.failed++;
      else if (check.status === 'info') results.summary.info++;
    }
  }

  results.score = Math.round(totalScore * 10) / 10;
  results.maxScore = totalMax;
  results.grade = calculateGrade(totalScore / totalMax);
  results.scanDuration = Date.now() - startTime;

  return results;
}

function calculateGrade(ratio) {
  if (ratio >= 0.95) return 'A+';
  if (ratio >= 0.85) return 'A';
  if (ratio >= 0.70) return 'B';
  if (ratio >= 0.55) return 'C';
  if (ratio >= 0.40) return 'D';
  return 'F';
}

function scoreToPercentage(score, maxScore) {
  if (maxScore === 0) return 0;
  return Math.round((score / maxScore) * 100);
}

module.exports = { scan, calculateGrade, scoreToPercentage, SCANNER_TIERS };
