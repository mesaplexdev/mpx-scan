/**
 * JSON Reporter
 * 
 * Machine-readable output for CI/CD pipelines
 */

const pkg = require('../../package.json');

function formatJSON(results, pretty = false) {
  const output = {
    mpxScan: {
      version: pkg.version,
      scannedAt: results.scannedAt,
      scanDuration: results.scanDuration
    },
    target: {
      url: results.url,
      hostname: results.hostname
    },
    score: {
      grade: results.grade,
      numeric: results.score,
      maxScore: results.maxScore,
      percentage: Math.round((results.score / results.maxScore) * 100)
    },
    summary: results.summary,
    sections: results.sections,
    tier: results.tier
  };
  
  return JSON.stringify(output, null, pretty ? 2 : 0);
}

module.exports = { formatJSON };
