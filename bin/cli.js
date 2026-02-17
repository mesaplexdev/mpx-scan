#!/usr/bin/env node

/**
 * mpx-scan CLI
 * 
 * Professional website security scanner
 * Part of the Mesaplex developer toolchain
 */

const { Command } = require('commander');
const chalk = require('chalk');
const { scan } = require('../src/index');
const { formatReport, formatBrief } = require('../src/reporters/terminal');
const { formatJSON } = require('../src/reporters/json');
const { generateFixes, PLATFORMS } = require('../src/generators/fixes');
const { getSchema } = require('../src/schema');
const { 
  getLicense, 
  activateLicense, 
  deactivateLicense, 
  checkRateLimit, 
  recordScan,
  FREE_DAILY_LIMIT 
} = require('../src/license');

const pkg = require('../package.json');

// Exit codes per AI-native spec
const EXIT = {
  SUCCESS: 0,           // Success, no issues found
  ISSUES_FOUND: 1,      // Success, issues found
  BAD_ARGS: 2,          // Invalid arguments
  CONFIG_ERROR: 3,      // Configuration error
  NETWORK_ERROR: 4      // Network/connectivity error
};

// Auto-detect non-interactive mode
const isInteractive = process.stdout.isTTY && !process.env.CI;

const program = new Command();

program
  .name('mpx-scan')
  .description('Professional website security scanner — check headers, SSL, DNS, and more')
  .version(pkg.version)
  .argument('[url]', 'URL to scan')
  .option('--full', 'Run all checks (Pro only)')
  .option('--json', 'Output as JSON (machine-readable)')
  .option('--brief', 'Brief output (one-line summary)')
  .option('-q, --quiet', 'Minimal output (results only, no banners)')
  .option('--no-color', 'Disable colored output')
  .option('--batch', 'Batch mode: read URLs from stdin (one per line)')
  .option('--schema', 'Output JSON schema describing all commands and flags')
  .option('--fix <platform>', `Generate fix config for platform (${PLATFORMS.join(', ')})`)
  .option('--timeout <seconds>', 'Connection timeout', '10')
  .option('--ci', 'CI/CD mode: exit 1 if score below threshold')
  .option('--min-score <score>', 'Minimum score for CI mode (default: 70)', '70')
  .action(async (url, options) => {
    // Handle --schema flag
    if (options.schema) {
      console.log(JSON.stringify(getSchema(), null, 2));
      process.exit(EXIT.SUCCESS);
      return;
    }

    // Handle --batch mode (read URLs from stdin)
    if (options.batch) {
      await runBatchMode(options);
      return;
    }

    // Show help if no URL provided
    if (!url) {
      program.help();
      return;
    }
    
    const exitCode = await runSingleScan(url, options);
    process.exit(exitCode);
  });

async function runSingleScan(url, options) {
  const jsonMode = options.json;
  const quietMode = options.quiet || options.Q;
  
  // Disable chalk if --no-color or non-TTY
  if (options.color === false || !process.stdout.isTTY) {
    chalk.level = 0;
  }

  try {
    // Validate timeout
    const timeoutVal = parseInt(options.timeout);
    if (isNaN(timeoutVal) || timeoutVal < 0) {
      if (jsonMode) {
        console.log(JSON.stringify({ error: 'Invalid --timeout value. Must be a non-negative number.', code: 'ERR_BAD_ARGS' }, null, 2));
      } else {
        console.error(chalk.red.bold('\n❌ Invalid --timeout value. Must be a non-negative number.'));
      }
      return EXIT.BAD_ARGS;
    }
    
    // Check license and rate limits
    const license = getLicense();
    const rateLimit = checkRateLimit();
    
    // Handle rate limiting
    if (!rateLimit.allowed) {
      if (jsonMode) {
        console.log(JSON.stringify({
          error: 'Daily scan limit reached',
          code: 'ERR_RATE_LIMIT',
          resetsAt: new Date(rateLimit.resetsAt).toISOString(),
          limit: FREE_DAILY_LIMIT,
          upgrade: 'https://mesaplex.com/mpx-scan'
        }, null, 2));
      } else {
        console.error(chalk.red.bold('\n❌ Daily scan limit reached'));
        console.error(chalk.yellow(`Free tier: ${FREE_DAILY_LIMIT} scans/day`));
        console.error(chalk.gray(`Resets: ${new Date(rateLimit.resetsAt).toLocaleString()}\n`));
        console.error(chalk.blue('Upgrade to Pro for unlimited scans:'));
        console.error(chalk.blue('  https://mesaplex.com/mpx-scan\n'));
      }
      return EXIT.CONFIG_ERROR;
    }
    
    // Check for Pro-only features
    if (options.full && license.tier !== 'pro') {
      if (jsonMode) {
        console.log(JSON.stringify({
          error: '--full flag requires Pro license',
          code: 'ERR_PRO_REQUIRED',
          upgrade: 'https://mesaplex.com/mpx-scan'
        }, null, 2));
      } else {
        console.error(chalk.red.bold('\n❌ --full flag requires Pro license'));
        console.error(chalk.yellow('Free tier includes: headers, SSL, server checks'));
        console.error(chalk.yellow('Pro includes: all checks (DNS, cookies, SRI, exposed files, etc.)\n'));
        console.error(chalk.blue('Upgrade: https://mesaplex.com/mpx-scan\n'));
      }
      return EXIT.CONFIG_ERROR;
    }
    
    // Show scan info (unless quiet/json/brief)
    if (!jsonMode && !options.brief && !quietMode) {
      console.error(chalk.bold.cyan('🔍 Scanning...'));
      if (license.tier === 'free') {
        console.error(chalk.gray(`Free tier: ${rateLimit.remaining} scan(s) remaining today`));
      }
    }
    
    // Run scan
    const results = await scan(url, {
      timeout: parseInt(options.timeout) * 1000,
      tier: license.tier,
      full: options.full
    });
    
    // Record scan for rate limiting
    recordScan();
    
    // Output results
    if (options.fix) {
      console.log(generateFixes(options.fix, results));
    } else if (jsonMode) {
      console.log(formatJSON(results, true));
    } else if (options.brief) {
      console.log(formatBrief(results));
    } else {
      console.log(formatReport(results, { ...options, quiet: quietMode }));
    }
    
    // Check if core scanners errored with network issues (DNS failure, connection refused, etc.)
    const coreScanners = ['headers', 'ssl'];
    const coreErrored = coreScanners.every(name => {
      const section = results.sections[name];
      if (!section) return false;
      return section.checks.some(c => c.status === 'error' && 
        /ENOTFOUND|ECONNREFUSED|ETIMEDOUT|ECONNRESET|network/i.test(c.message || ''));
    });
    if (coreErrored) {
      return EXIT.NETWORK_ERROR;
    }
    
    // Determine exit code based on findings
    if (options.ci) {
      const minScore = parseInt(options.minScore);
      if (isNaN(minScore)) {
        if (jsonMode) {
          console.log(JSON.stringify({ error: 'Invalid --min-score value', code: 'ERR_BAD_ARGS' }, null, 2));
        } else {
          console.error(chalk.red.bold('\n❌ Invalid --min-score value. Must be a number.'));
        }
        return EXIT.BAD_ARGS;
      }
      const percentage = Math.round((results.score / results.maxScore) * 100);
      if (percentage < minScore) {
        if (!jsonMode && !options.brief && !quietMode) {
          console.error(chalk.yellow(`\n⚠️  CI mode: Score ${percentage}/100 below minimum ${minScore}`));
        }
        return EXIT.ISSUES_FOUND;
      }
      return EXIT.SUCCESS;
    }
    
    // Exit 1 if there are failures, 0 if clean
    if (results.summary.failed > 0) {
      return EXIT.ISSUES_FOUND;
    }
    return EXIT.SUCCESS;
    
  } catch (err) {
    if (jsonMode) {
      const code = isNetworkError(err) ? 'ERR_NETWORK' : 'ERR_SCAN';
      console.log(JSON.stringify({ error: err.message, code }, null, 2));
    } else {
      console.error(chalk.red.bold('\n❌ Error:'), err.message);
      console.error('');
    }
    return isNetworkError(err) ? EXIT.NETWORK_ERROR : EXIT.ISSUES_FOUND;
  }
}

async function runBatchMode(options) {
  const jsonMode = options.json;

  // Read URLs from stdin
  const input = await readStdin();
  if (!input.trim()) {
    if (jsonMode) {
      console.log(JSON.stringify({ error: 'No URLs provided on stdin', code: 'ERR_NO_INPUT' }, null, 2));
    } else {
      console.error(chalk.red('No URLs provided. Pipe URLs via stdin:'));
      console.error(chalk.gray('  cat urls.txt | mpx-scan --batch --json'));
    }
    process.exit(EXIT.BAD_ARGS);
    return;
  }

  const urls = input.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  
  if (urls.length === 0) {
    if (jsonMode) {
      console.log(JSON.stringify({ error: 'No valid URLs found in input', code: 'ERR_NO_INPUT' }, null, 2));
    } else {
      console.error(chalk.red('No valid URLs found in input.'));
    }
    process.exit(EXIT.BAD_ARGS);
    return;
  }

  let hasIssues = false;
  let hasErrors = false;

  for (const url of urls) {
    try {
      const license = getLicense();
      const rateLimit = checkRateLimit();
      
      if (!rateLimit.allowed) {
        if (jsonMode) {
          console.log(JSON.stringify({
            url,
            error: 'Rate limit reached',
            code: 'ERR_RATE_LIMIT'
          }));
        }
        hasErrors = true;
        continue;
      }

      const results = await scan(url, {
        timeout: parseInt(options.timeout) * 1000,
        tier: license.tier,
        full: options.full
      });
      
      recordScan();
      
      if (results.summary.failed > 0) hasIssues = true;

      if (jsonMode) {
        // JSONL: one JSON object per line
        console.log(formatJSON(results, false));
      } else if (options.brief) {
        console.log(formatBrief(results));
      } else {
        console.log(formatReport(results, options));
      }
    } catch (err) {
      hasErrors = true;
      if (jsonMode) {
        console.log(JSON.stringify({ url, error: err.message, code: isNetworkError(err) ? 'ERR_NETWORK' : 'ERR_SCAN' }));
      } else {
        console.error(chalk.red(`Error scanning ${url}: ${err.message}`));
      }
    }
  }

  if (hasErrors) process.exit(EXIT.NETWORK_ERROR);
  if (hasIssues) process.exit(EXIT.ISSUES_FOUND);
  process.exit(EXIT.SUCCESS);
}

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      resolve('');
      return;
    }
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => data += chunk);
    process.stdin.on('end', () => resolve(data));
  });
}

function isNetworkError(err) {
  const msg = (err.message || '').toLowerCase();
  return msg.includes('econnrefused') || msg.includes('enotfound') || 
         msg.includes('timeout') || msg.includes('network') ||
         msg.includes('dns') || msg.includes('econnreset') ||
         err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || 
         err.code === 'ETIMEDOUT';
}

// License management subcommands
program
  .command('license')
  .description('Manage your mpx-scan license')
  .action(() => {
    const license = getLicense();
    
    console.log('');
    console.log(chalk.bold('License Status:'));
    console.log(chalk.gray('─'.repeat(50)));
    console.log(chalk.bold('Tier:    ') + (license.tier === 'pro' ? chalk.green('Pro ✓') : chalk.yellow('Free')));
    
    if (license.tier === 'pro') {
      console.log(chalk.bold('Key:     ') + chalk.gray(license.key));
      if (license.email) {
        console.log(chalk.bold('Email:   ') + chalk.gray(license.email));
      }
    } else {
      console.log(chalk.bold('Limit:   ') + chalk.yellow(`${FREE_DAILY_LIMIT} scans/day`));
      const rateLimit = checkRateLimit();
      console.log(chalk.bold('Today:   ') + chalk.cyan(`${FREE_DAILY_LIMIT - rateLimit.remaining}/${FREE_DAILY_LIMIT} used`));
    }
    
    console.log(chalk.gray('─'.repeat(50)));
    
    if (license.tier === 'free') {
      console.log('');
      console.log(chalk.blue('Upgrade to Pro:'));
      console.log(chalk.blue('  https://mesaplex.com/mpx-scan'));
      console.log('');
      console.log(chalk.gray('Activate with: mpx-scan activate <license-key>'));
    }
    
    console.log('');
  });

program
  .command('activate')
  .description('Activate a Pro license')
  .argument('<key>', 'License key')
  .option('--email <email>', 'Your email address')
  .action((key, options) => {
    try {
      activateLicense(key, options.email);
      console.log('');
      console.log(chalk.green.bold('✓ License activated!'));
      console.log(chalk.gray('You now have access to:'));
      console.log(chalk.gray('  • Unlimited scans'));
      console.log(chalk.gray('  • All security checks'));
      console.log(chalk.gray('  • JSON/CSV export'));
      console.log(chalk.gray('  • Batch scanning'));
      console.log('');
    } catch (err) {
      console.error(chalk.red.bold('\n❌ Activation failed:'), err.message);
      console.error('');
      process.exit(EXIT.CONFIG_ERROR);
    }
  });

program
  .command('deactivate')
  .description('Deactivate license and return to free tier')
  .action(() => {
    deactivateLicense();
    console.log('');
    console.log(chalk.yellow('License deactivated'));
    console.log(chalk.gray('You are now on the free tier (3 scans/day)'));
    console.log('');
  });

// Update subcommand
program
  .command('update')
  .description('Check for updates and optionally install the latest version')
  .option('--check', 'Only check for updates (do not install)')
  .option('--json', 'Machine-readable JSON output')
  .action(async (options, cmd) => {
    const { checkForUpdate, performUpdate } = require('../src/update');
    const jsonMode = options.json || cmd.parent?.opts()?.json;

    try {
      const info = checkForUpdate();

      if (jsonMode) {
        const output = {
          current: info.current,
          latest: info.latest,
          updateAvailable: info.updateAvailable,
          isGlobal: info.isGlobal
        };

        if (!options.check && info.updateAvailable) {
          try {
            const result = performUpdate(info.isGlobal);
            output.updated = true;
            output.newVersion = result.version;
          } catch (err) {
            output.updated = false;
            output.error = err.message;
          }
        }

        console.log(JSON.stringify(output, null, 2));
        process.exit(EXIT.SUCCESS);
        return;
      }

      // Human-readable output
      if (!info.updateAvailable) {
        console.log('');
        console.log(chalk.green.bold(`✓ mpx-scan v${info.current} is up to date`));
        console.log('');
        process.exit(EXIT.SUCCESS);
        return;
      }

      console.log('');
      console.log(chalk.yellow.bold(`⬆ Update available: v${info.current} → v${info.latest}`));

      if (options.check) {
        console.log(chalk.gray(`Run ${chalk.cyan('mpx-scan update')} to install`));
        console.log('');
        process.exit(EXIT.SUCCESS);
        return;
      }

      console.log(chalk.gray(`Installing v${info.latest}${info.isGlobal ? ' (global)' : ''}...`));

      const result = performUpdate(info.isGlobal);
      console.log(chalk.green.bold(`✓ Updated to v${result.version}`));
      console.log('');
      process.exit(EXIT.SUCCESS);
    } catch (err) {
      if (jsonMode) {
        console.log(JSON.stringify({ error: err.message, code: 'ERR_UPDATE' }, null, 2));
      } else {
        console.error(chalk.red.bold('\n❌ Update check failed:'), err.message);
        console.error('');
      }
      process.exit(EXIT.NETWORK_ERROR);
    }
  });

// MCP subcommand
program
  .command('mcp')
  .description('Start MCP (Model Context Protocol) stdio server')
  .action(async () => {
    try {
      const { startMCPServer } = require('../src/mcp');
      await startMCPServer();
    } catch (err) {
      console.error(JSON.stringify({ error: err.message, code: 'ERR_MCP_START' }));
      process.exit(EXIT.CONFIG_ERROR);
    }
  });

// Examples
program.addHelpText('after', `
${chalk.bold('Examples:')}
  ${chalk.cyan('mpx-scan https://example.com')}           Quick security scan
  ${chalk.cyan('mpx-scan example.com --full')}            Deep scan (Pro only)
  ${chalk.cyan('mpx-scan example.com --json')}            JSON output
  ${chalk.cyan('mpx-scan example.com --fix nginx')}       Generate nginx config
  ${chalk.cyan('mpx-scan example.com --brief')}           One-line summary
  ${chalk.cyan('mpx-scan --schema')}                      Show tool schema (JSON)
  ${chalk.cyan('cat urls.txt | mpx-scan --batch --json')} Batch scan from stdin
  ${chalk.cyan('mpx-scan mcp')}                           Start MCP server
  ${chalk.cyan('mpx-scan license')}                       Check license status

${chalk.bold('Exit Codes:')}
  0  Success, no issues found
  1  Success, issues found
  2  Invalid arguments
  3  Configuration error (license, rate limit)
  4  Network/connectivity error

${chalk.bold('Free vs Pro:')}
  ${chalk.yellow('Free:')}  3 scans/day, basic checks (headers, SSL, server)
  ${chalk.green('Pro:')}   Unlimited scans, all checks, batch mode, CI/CD integration

  ${chalk.blue('Upgrade: https://mesaplex.com/mpx-scan')}
`);

program.parse();
