/**
 * mpx-scan — Professional Website Security Scanner
 * 
 * Core engine. Runs all security checks against a target URL
 * and returns a structured report with grades and recommendations.
 * 
 * Zero external dependencies for scanning (only chalk/commander for CLI)
 */

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
async function scan(url, options = {}) {
  const startTime = Date.now();
  
  // Normalize URL
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  
  const parsedUrl = new URL(url);
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

  // Run scanners concurrently
  const scanPromises = enabledScanners.map(async (scanner) => {
    try {
      const result = await scanner.fn(parsedUrl, options);
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
