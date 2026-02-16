/**
 * Fix Generator
 * 
 * Generates copy-paste configuration snippets for fixing security issues
 * Supports: nginx, apache, caddy, cloudflare
 */

const chalk = require('chalk');

const PLATFORMS = ['nginx', 'apache', 'caddy', 'cloudflare'];

function generateFixes(platform, results) {
  if (!PLATFORMS.includes(platform)) {
    throw new Error(`Unknown platform: ${platform}. Supported: ${PLATFORMS.join(', ')}`);
  }
  
  const lines = [];
  
  lines.push('');
  lines.push(chalk.bold.cyan('═'.repeat(70)));
  lines.push(chalk.bold.cyan(`  Security Fix Configuration — ${platform.toUpperCase()}`));
  lines.push(chalk.bold.cyan('═'.repeat(70)));
  lines.push('');
  
  // Collect all failed/warned checks with recommendations
  const issues = [];
  
  for (const [sectionName, section] of Object.entries(results.sections)) {
    for (const check of section.checks) {
      if ((check.status === 'fail' || check.status === 'warn') && check.recommendation) {
        issues.push({ section: sectionName, check });
      }
    }
  }
  
  if (issues.length === 0) {
    lines.push(chalk.green('✓ No security issues found! Your site is well-configured.'));
    lines.push('');
    return lines.join('\n');
  }
  
  lines.push(chalk.yellow(`Found ${issues.length} issue(s) to fix:\n`));
  
  // Generate platform-specific configs
  switch (platform) {
    case 'nginx':
      lines.push(...generateNginxConfig(issues));
      break;
    case 'apache':
      lines.push(...generateApacheConfig(issues));
      break;
    case 'caddy':
      lines.push(...generateCaddyConfig(issues));
      break;
    case 'cloudflare':
      lines.push(...generateCloudflareConfig(issues));
      break;
  }
  
  lines.push('');
  lines.push(chalk.gray('─'.repeat(70)));
  lines.push(chalk.gray('After applying these changes:'));
  lines.push(chalk.gray('1. Test your configuration'));
  lines.push(chalk.gray(`2. Reload/restart your ${platform} server`));
  lines.push(chalk.gray('3. Run mpx-scan again to verify'));
  lines.push(chalk.gray('─'.repeat(70)));
  lines.push('');
  
  return lines.join('\n');
}

function generateNginxConfig(issues) {
  const lines = [];
  
  lines.push(chalk.bold('Add these headers to your nginx config:'));
  lines.push(chalk.gray('# Location: /etc/nginx/sites-available/your-site'));
  lines.push(chalk.gray('# Inside the server {} block:\n'));
  
  lines.push(chalk.cyan('server {'));
  lines.push(chalk.cyan('    # ... your existing config ...\n'));
  
  const headers = extractHeaders(issues);
  
  for (const [header, value] of Object.entries(headers)) {
    lines.push(chalk.green(`    add_header ${header} "${value}" always;`));
  }
  
  // SSL-specific recommendations
  if (hasSSLIssues(issues)) {
    lines.push('');
    lines.push(chalk.gray('    # SSL/TLS Configuration'));
    lines.push(chalk.green('    ssl_protocols TLSv1.2 TLSv1.3;'));
    lines.push(chalk.green('    ssl_prefer_server_ciphers on;'));
    lines.push(chalk.green('    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";'));
  }
  
  lines.push(chalk.cyan('}'));
  lines.push('');
  lines.push(chalk.gray('# Then reload nginx:'));
  lines.push(chalk.yellow('sudo nginx -t && sudo systemctl reload nginx'));
  lines.push('');
  
  return lines;
}

function generateApacheConfig(issues) {
  const lines = [];
  
  lines.push(chalk.bold('Add these headers to your Apache config:'));
  lines.push(chalk.gray('# Location: /etc/apache2/sites-available/your-site.conf'));
  lines.push(chalk.gray('# Or .htaccess in your document root\n'));
  
  lines.push(chalk.cyan('<IfModule mod_headers.c>'));
  
  const headers = extractHeaders(issues);
  
  for (const [header, value] of Object.entries(headers)) {
    lines.push(chalk.green(`    Header always set ${header} "${value}"`));
  }
  
  lines.push(chalk.cyan('</IfModule>'));
  lines.push('');
  
  if (hasSSLIssues(issues)) {
    lines.push(chalk.gray('# SSL/TLS Configuration'));
    lines.push(chalk.cyan('<IfModule mod_ssl.c>'));
    lines.push(chalk.green('    SSLProtocol -all +TLSv1.2 +TLSv1.3'));
    lines.push(chalk.green('    SSLCipherSuite HIGH:!aNULL:!MD5'));
    lines.push(chalk.green('    SSLHonorCipherOrder on'));
    lines.push(chalk.cyan('</IfModule>'));
    lines.push('');
  }
  
  lines.push(chalk.gray('# Then reload Apache:'));
  lines.push(chalk.yellow('sudo apachectl configtest && sudo systemctl reload apache2'));
  lines.push('');
  
  return lines;
}

function generateCaddyConfig(issues) {
  const lines = [];
  
  lines.push(chalk.bold('Add these headers to your Caddyfile:'));
  lines.push(chalk.gray('# Location: /etc/caddy/Caddyfile\n'));
  
  lines.push(chalk.cyan('your-domain.com {'));
  lines.push(chalk.gray('    # ... your existing config ...\n'));
  
  const headers = extractHeaders(issues);
  
  lines.push(chalk.green('    header {'));
  for (const [header, value] of Object.entries(headers)) {
    lines.push(chalk.green(`        ${header} "${value}"`));
  }
  lines.push(chalk.green('    }'));
  
  lines.push(chalk.cyan('}'));
  lines.push('');
  lines.push(chalk.gray('# Caddy automatically handles TLS 1.2/1.3'));
  lines.push(chalk.gray('# Then reload Caddy:'));
  lines.push(chalk.yellow('sudo systemctl reload caddy'));
  lines.push('');
  
  return lines;
}

function generateCloudflareConfig(issues) {
  const lines = [];
  
  lines.push(chalk.bold('Configure Cloudflare security headers:'));
  lines.push(chalk.gray('Dashboard → Rules → Transform Rules → Modify Response Header\n'));
  
  const headers = extractHeaders(issues);
  
  lines.push(chalk.yellow('Create these Transform Rules:'));
  lines.push('');
  
  for (const [header, value] of Object.entries(headers)) {
    lines.push(chalk.green(`• Set "${header}" to "${value}"`));
  }
  
  lines.push('');
  lines.push(chalk.gray('Or use Cloudflare Workers:'));
  lines.push('');
  lines.push(chalk.cyan('addEventListener("fetch", event => {'));
  lines.push(chalk.cyan('  event.respondWith(handleRequest(event.request));'));
  lines.push(chalk.cyan('});'));
  lines.push('');
  lines.push(chalk.cyan('async function handleRequest(request) {'));
  lines.push(chalk.cyan('  const response = await fetch(request);'));
  lines.push(chalk.cyan('  const newHeaders = new Headers(response.headers);'));
  lines.push('');
  
  for (const [header, value] of Object.entries(headers)) {
    lines.push(chalk.green(`  newHeaders.set("${header}", "${value}");`));
  }
  
  lines.push('');
  lines.push(chalk.cyan('  return new Response(response.body, {'));
  lines.push(chalk.cyan('    status: response.status,'));
  lines.push(chalk.cyan('    statusText: response.statusText,'));
  lines.push(chalk.cyan('    headers: newHeaders'));
  lines.push(chalk.cyan('  });'));
  lines.push(chalk.cyan('}'));
  lines.push('');
  
  if (hasSSLIssues(issues)) {
    lines.push(chalk.gray('# Also check:'));
    lines.push(chalk.yellow('• SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2'));
    lines.push('');
  }
  
  return lines;
}

function extractHeaders(issues) {
  const headers = {};
  
  for (const { check } of issues) {
    const rec = check.recommendation;
    
    if (rec.includes('Strict-Transport-Security')) {
      headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
    }
    if (rec.includes('Content-Security-Policy')) {
      headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'";
    }
    if (rec.includes('X-Content-Type-Options')) {
      headers['X-Content-Type-Options'] = 'nosniff';
    }
    if (rec.includes('X-Frame-Options')) {
      headers['X-Frame-Options'] = 'DENY';
    }
    if (rec.includes('Referrer-Policy')) {
      headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
    }
    if (rec.includes('Permissions-Policy')) {
      headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()';
    }
    if (rec.includes('Cross-Origin-Opener-Policy')) {
      headers['Cross-Origin-Opener-Policy'] = 'same-origin';
    }
    if (rec.includes('Cross-Origin-Resource-Policy')) {
      headers['Cross-Origin-Resource-Policy'] = 'same-origin';
    }
  }
  
  return headers;
}

function hasSSLIssues(issues) {
  return issues.some(({ section }) => section === 'ssl');
}

module.exports = { generateFixes, PLATFORMS };
