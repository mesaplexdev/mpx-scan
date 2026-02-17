/**
 * Exposed Files Scanner
 * 
 * Checks for files/paths that should not be publicly accessible:
 * - .env, .git, .htaccess
 * - wp-admin, phpinfo
 * - Backup files, config files
 * - Directory listings
 */

const https = require('https');
const http = require('http');

const SENSITIVE_PATHS = [
  { path: '/.env', name: '.env file', severity: 'critical', description: 'Environment variables (may contain secrets, API keys, passwords)' },
  { path: '/.git/HEAD', name: '.git directory', severity: 'critical', description: 'Git repository exposed — full source code and history accessible' },
  { path: '/.git/config', name: '.git config', severity: 'critical', description: 'Git configuration with potential remote URLs and credentials' },
  { path: '/.svn/entries', name: '.svn directory', severity: 'high', description: 'Subversion repository exposed' },
  { path: '/.htaccess', name: '.htaccess', severity: 'medium', description: 'Apache configuration file — reveals server setup' },
  { path: '/wp-admin/', name: 'WordPress Admin', severity: 'medium', description: 'WordPress admin panel exposed' },
  { path: '/wp-login.php', name: 'WordPress Login', severity: 'low', description: 'WordPress login page' },
  { path: '/phpinfo.php', name: 'PHP Info', severity: 'high', description: 'PHP configuration disclosure' },
  { path: '/server-status', name: 'Server Status', severity: 'high', description: 'Apache server status page' },
  { path: '/elmah.axd', name: 'ELMAH Log', severity: 'high', description: '.NET error log viewer' },
  { path: '/backup.sql', name: 'SQL Backup', severity: 'critical', description: 'Database backup file' },
  { path: '/dump.sql', name: 'SQL Dump', severity: 'critical', description: 'Database dump file' },
  { path: '/db.sql', name: 'Database File', severity: 'critical', description: 'Database file' },
  { path: '/.DS_Store', name: '.DS_Store', severity: 'low', description: 'macOS directory metadata — reveals file/folder names' },
  { path: '/crossdomain.xml', name: 'crossdomain.xml', severity: 'low', description: 'Flash cross-domain policy (may be overly permissive)' },
  { path: '/composer.json', name: 'composer.json', severity: 'high', description: 'PHP dependency manifest — reveals packages and versions' },
  { path: '/package.json', name: 'package.json', severity: 'medium', description: 'Node.js dependency manifest — reveals packages and versions' },
  { path: '/Gruntfile.js', name: 'Gruntfile.js', severity: 'medium', description: 'Build tool configuration exposed' },
  { path: '/Dockerfile', name: 'Dockerfile', severity: 'high', description: 'Docker configuration — reveals infrastructure details' },
  { path: '/docker-compose.yml', name: 'docker-compose.yml', severity: 'critical', description: 'Docker Compose — may contain service passwords and configs' },
  { path: '/.dockerenv', name: '.dockerenv', severity: 'medium', description: 'Running inside Docker container' },
  { path: '/web.config', name: 'web.config', severity: 'high', description: 'IIS configuration — reveals server setup and potential credentials' },
  { path: '/config.php', name: 'config.php', severity: 'critical', description: 'PHP configuration file — likely contains database credentials' },
  { path: '/wp-config.php.bak', name: 'wp-config.php.bak', severity: 'critical', description: 'WordPress config backup — contains database credentials in plaintext' },
  { path: '/.npmrc', name: '.npmrc', severity: 'critical', description: 'npm config — may contain auth tokens' },
  { path: '/.aws/credentials', name: 'AWS credentials', severity: 'critical', description: 'AWS credential file exposed' },
  { path: '/debug.log', name: 'debug.log', severity: 'high', description: 'Debug log — may contain stack traces and sensitive data' },
  { path: '/error.log', name: 'error.log', severity: 'high', description: 'Error log — may contain stack traces and paths' },
  { path: '/access.log', name: 'access.log', severity: 'medium', description: 'Access log — reveals visitor IPs and paths' },
  { path: '/.vscode/settings.json', name: 'VS Code settings', severity: 'low', description: 'IDE settings exposed — reveals development environment' },
  { path: '/adminer.php', name: 'Adminer', severity: 'critical', description: 'Database admin tool exposed to the internet' },
  { path: '/phpmyadmin/', name: 'phpMyAdmin', severity: 'critical', description: 'Database admin panel exposed to the internet' },
  { path: '/.well-known/security.txt', name: 'security.txt', severity: 'info', description: 'Security contact information' },
  { path: '/robots.txt', name: 'robots.txt', severity: 'info', description: 'Robots exclusion — may reveal hidden paths' },
  { path: '/sitemap.xml', name: 'sitemap.xml', severity: 'info', description: 'Site map — reveals site structure' },
  { path: '/humans.txt', name: 'humans.txt', severity: 'info', description: 'Team information file' },
];

async function scanExposedFiles(parsedUrl, options = {}) {
  const checks = [];
  let score = 0;
  let maxScore = 0;

  // Score critical, high, and medium severity paths (not low/info)
  const scoredPaths = SENSITIVE_PATHS.filter(p => ['critical', 'high', 'medium'].includes(p.severity));
  maxScore = scoredPaths.length;
  // Note: low severity items are reported but NOT scored

  // Check paths concurrently (in batches to be polite)
  const batchSize = options.concurrency || 5;
  const results = [];
  
  for (let i = 0; i < SENSITIVE_PATHS.length; i += batchSize) {
    const batch = SENSITIVE_PATHS.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (entry) => {
        try {
          const status = await checkPath(parsedUrl, entry.path, options);
          return { ...entry, status };
        } catch {
          return { ...entry, status: 0 };
        }
      })
    );
    results.push(...batchResults);
  }

  let exposedCritical = 0;
  let exposedHigh = 0;

  // Track connection failures to detect unreachable hosts
  let connectionFailures = 0;
  
  for (const result of results) {
    // Only 200-299 is truly exposed. 3xx redirects are NOT exposures.
    // Status 0 = connection failed
    const isExposed = result.status >= 200 && result.status < 300;
    if (result.status === 0) connectionFailures++;
    
    if (result.severity === 'info') {
      if (isExposed) {
        checks.push({ name: result.name, status: 'info', message: `Found (${result.status}) — ${result.description}`, value: result.path });
      }
      continue;
    }

    if (result.severity === 'low') {
      // Low severity: report if found, but don't affect score
      if (isExposed) {
        checks.push({ name: result.name, status: 'info', message: `Found (${result.status}) — ${result.description}`, value: result.path });
      }
      continue;
    }

    if (isExposed) {
      if (result.severity === 'critical') {
        checks.push({ name: result.name, status: 'fail', message: `🚨 EXPOSED (${result.status}) — ${result.description}`, value: result.path });
        exposedCritical++;
      } else if (result.severity === 'high') {
        checks.push({ name: result.name, status: 'fail', message: `⚠️ EXPOSED (${result.status}) — ${result.description}`, value: result.path });
        exposedHigh++;
      } else if (result.severity === 'medium') {
        checks.push({ name: result.name, status: 'warn', message: `Accessible (${result.status}) — ${result.description}`, value: result.path });
        score += 0.5;
      }
    } else if (result.status > 0) {
      score += 1;
    }
  }
  
  // If most checks failed to connect, report as error
  const totalScored = results.filter(r => !['info'].includes(r.severity)).length;
  if (connectionFailures > totalScored * 0.8) {
    checks.unshift({ name: 'Exposed Files', status: 'error', message: 'Most path checks failed to connect — results may be unreliable' });
  }

  if (exposedCritical === 0 && exposedHigh === 0) {
    checks.unshift({ name: 'Sensitive Files', status: 'pass', message: 'No critical or high-severity files exposed' });
  } else {
    checks.unshift({ name: 'Sensitive Files', status: 'fail', message: `${exposedCritical} critical, ${exposedHigh} high-severity files exposed!` });
  }

  return { score, maxScore, checks };
}

function checkPath(parsedUrl, pathStr, options = {}) {
  return new Promise((resolve) => {
    const timeout = options.timeout || 5000;
    const url = new URL(pathStr, parsedUrl.href);
    const protocol = url.protocol === 'https:' ? https : http;
    let resolved = false;
    const done = (val) => { if (!resolved) { resolved = true; resolve(val); } };
    
    // Hard timeout fallback
    const timer = setTimeout(() => done(0), timeout + 2000);
    
    const req = protocol.request(url.href, {
      method: 'GET',
      timeout,
      headers: { 'User-Agent': 'mpx-scan/1.2.1 Security Scanner (https://github.com/mesaplexdev/mpx-scan)' },
      rejectUnauthorized: false,
    }, (res) => {
      let body = '';
      res.setEncoding('utf-8');
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 2000) {
          res.destroy();
          clearTimeout(timer);
          done(validateResponse(res.statusCode, body, pathStr));
        }
      });
      res.on('end', () => {
        clearTimeout(timer);
        done(validateResponse(res.statusCode, body, pathStr));
      });
      res.on('error', () => { clearTimeout(timer); done(0); });
      res.on('close', () => { clearTimeout(timer); done(res.statusCode); });
    });

    req.on('error', () => { clearTimeout(timer); done(0); });
    req.on('timeout', () => { clearTimeout(timer); req.destroy(); done(0); });
    req.end();
  });
}

/**
 * Validate if a response is actually the sensitive file or a generic page.
 * Returns the effective status code (404 for false positives).
 */
function validateResponse(statusCode, body, pathStr) {
  if (statusCode < 200 || statusCode >= 300) return statusCode;
  if (!body || body.length < 5) return 404; // Empty response
  
  // Soft 404 detection — generic error pages
  if (/<title>.*(?:404|not found|page not found|error|oops|doesn't exist).*<\/title>/i.test(body)) return 404;
  if (/<h1>.*(?:404|not found|page not found).*<\/h1>/i.test(body)) return 404;
  
  // If the body is HTML but the file shouldn't be HTML, it's likely a catch-all route
  const isHtmlResponse = /<(!DOCTYPE|html|head|body)/i.test(body);
  const nonHtmlFiles = ['/.env', '/.git/HEAD', '/.git/config', '/.htaccess', '/backup.sql', 
    '/dump.sql', '/db.sql', '/.DS_Store', '/composer.json', '/package.json', '/Gruntfile.js',
    '/Dockerfile', '/docker-compose.yml', '/.dockerenv', '/config.php', '/wp-config.php.bak',
    '/.npmrc', '/.aws/credentials', '/debug.log', '/error.log', '/access.log',
    '/.vscode/settings.json'];
  
  if (isHtmlResponse && nonHtmlFiles.includes(pathStr)) {
    // HTML response for a non-HTML file = probably a catch-all/SPA router
    return 404;
  }
  
  // For admin panel paths that return HTML, check if it's actually the admin panel
  // or just a generic page / catch-all route
  const adminPaths = ['/wp-admin/', '/wp-login.php', '/phpmyadmin/', '/adminer.php', '/server-status', '/elmah.axd'];
  if (isHtmlResponse && adminPaths.includes(pathStr)) {
    // Check for actual admin panel indicators
    if (pathStr.includes('wp-admin') && !/wp-login|wordpress/i.test(body)) return 404;
    if (pathStr.includes('wp-login') && !/<form[^>]*wp-login/i.test(body)) return 404;
    if (pathStr.includes('phpmyadmin') && !/phpMyAdmin|pma_/i.test(body)) return 404;
    if (pathStr.includes('adminer') && !/adminer/i.test(body)) return 404;
    if (pathStr.includes('server-status') && !/Server Version|Apache/i.test(body)) return 404;
    if (pathStr.includes('elmah') && !/ELMAH|Error Log/i.test(body)) return 404;
  }
  
  // Content validation for specific files
  if (pathStr === '/.env' && !/[A-Z_]+=/.test(body)) return 404;
  if (pathStr === '/.git/HEAD' && !/ref:/.test(body)) return 404;
  if (pathStr === '/.git/config' && !/\[core\]|\[remote/.test(body)) return 404;
  if (pathStr === '/composer.json' && !/"require"/.test(body)) return 404;
  if (pathStr === '/package.json' && !/"name"|"version"/.test(body)) return 404;
  if (pathStr === '/Dockerfile' && !/FROM |RUN |CMD /i.test(body)) return 404;
  if (pathStr === '/docker-compose.yml' && !/services:|version:/i.test(body)) return 404;
  
  return statusCode;
}

module.exports = { scanExposedFiles };
