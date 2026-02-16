/**
 * Mixed Content Scanner
 * 
 * Detects HTTP resources loaded on HTTPS pages.
 * Mixed content can be blocked by browsers and indicates security gaps.
 * 
 * Active mixed content (scripts, iframes) = high risk
 * Passive mixed content (images, video) = medium risk
 */

const { fetchBody } = require('./sri');

async function scanMixedContent(parsedUrl, options = {}) {
  const checks = [];
  let score = 0;
  let maxScore = 2;

  if (parsedUrl.protocol !== 'https:') {
    checks.push({ name: 'Mixed Content', status: 'info', message: 'Site served over HTTP — mixed content check not applicable' });
    return { score: 0, maxScore: 0, checks };
  }

  const html = await fetchBody(parsedUrl, options);
  
  if (!html) {
    checks.push({ name: 'Mixed Content', status: 'error', message: 'Could not fetch page HTML' });
    return { score: 0, maxScore: 2, checks };
  }

  // Active mixed content (high risk — blocked by most browsers)
  const activePatterns = [
    { regex: /<script[^>]+src\s*=\s*["'](http:\/\/[^"']+)["']/gi, type: 'script' },
    { regex: /<iframe[^>]+src\s*=\s*["'](http:\/\/[^"']+)["']/gi, type: 'iframe' },
    { regex: /<link[^>]+href\s*=\s*["'](http:\/\/[^"']+)["'][^>]*rel\s*=\s*["']stylesheet["']/gi, type: 'stylesheet' },
    { regex: /<object[^>]+data\s*=\s*["'](http:\/\/[^"']+)["']/gi, type: 'object' },
  ];

  // Passive mixed content (medium risk — may show warnings)
  const passivePatterns = [
    { regex: /<img[^>]+src\s*=\s*["'](http:\/\/[^"']+)["']/gi, type: 'image' },
    { regex: /<video[^>]+src\s*=\s*["'](http:\/\/[^"']+)["']/gi, type: 'video' },
    { regex: /<audio[^>]+src\s*=\s*["'](http:\/\/[^"']+)["']/gi, type: 'audio' },
    { regex: /<source[^>]+src\s*=\s*["'](http:\/\/[^"']+)["']/gi, type: 'media source' },
  ];

  // Also check CSS url() references
  const cssUrlPattern = /url\(\s*["']?(http:\/\/[^"')]+)["']?\s*\)/gi;

  const activeIssues = [];
  const passiveIssues = [];

  for (const { regex, type } of activePatterns) {
    let match;
    while ((match = regex.exec(html)) !== null) {
      activeIssues.push({ url: match[1], type });
    }
  }

  for (const { regex, type } of passivePatterns) {
    let match;
    while ((match = regex.exec(html)) !== null) {
      passiveIssues.push({ url: match[1], type });
    }
  }

  let cssMatch;
  while ((cssMatch = cssUrlPattern.exec(html)) !== null) {
    passiveIssues.push({ url: cssMatch[1], type: 'css-url' });
  }

  // Score
  if (activeIssues.length === 0 && passiveIssues.length === 0) {
    checks.push({ name: 'Mixed Content', status: 'pass', message: 'No HTTP resources detected on HTTPS page' });
    score = 2;
  } else {
    if (activeIssues.length > 0) {
      checks.push({ name: 'Active Mixed Content', status: 'fail', 
        message: `${activeIssues.length} active HTTP resource(s) — scripts/styles loaded over HTTP on HTTPS page. Blocked by modern browsers.`,
        recommendation: 'Change all resource URLs from http:// to https:// or use protocol-relative URLs (//)' 
      });
      // List first 5
      activeIssues.slice(0, 5).forEach(issue => {
        checks.push({ name: `HTTP ${issue.type}`, status: 'fail', message: issue.url.substring(0, 100), value: issue.url });
      });
      if (activeIssues.length > 5) {
        checks.push({ name: 'Active Mixed Content', status: 'info', message: `...and ${activeIssues.length - 5} more` });
      }
    } else {
      score += 1;
    }

    if (passiveIssues.length > 0) {
      checks.push({ name: 'Passive Mixed Content', status: 'warn',
        message: `${passiveIssues.length} passive HTTP resource(s) — images/media loaded over HTTP. May show browser warnings.`,
        recommendation: 'Update resource URLs to HTTPS'
      });
      passiveIssues.slice(0, 3).forEach(issue => {
        checks.push({ name: `HTTP ${issue.type}`, status: 'warn', message: issue.url.substring(0, 100), value: issue.url });
      });
      score += 0.5;
    } else {
      score += 1;
    }
  }

  return { score, maxScore, checks };
}

module.exports = { scanMixedContent };
