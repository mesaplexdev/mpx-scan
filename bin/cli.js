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
const { 
  getLicense, 
  activateLicense, 
  deactivateLicense, 
  checkRateLimit, 
  recordScan,
  FREE_DAILY_LIMIT 
} = require('../src/license');

const pkg = require('../package.json');

const program = new Command();

program
  .name('mpx-scan')
  .description('Professional website security scanner — check headers, SSL, DNS, and more')
  .version(pkg.version)
  .argument('[url]', 'URL to scan')
  .option('--full', 'Run all checks (Pro only)')
  .option('--json', 'Output as JSON')
  .option('--brief', 'Brief output (one-line summary)')
  .option('--fix <platform>', `Generate fix config for platform (${PLATFORMS.join(', ')})`)
  .option('--timeout <seconds>', 'Connection timeout', '10')
  .option('--ci', 'CI/CD mode: exit 1 if score below threshold')
  .option('--min-score <score>', 'Minimum score for CI mode (default: 70)', '70')
  .action(async (url, options) => {
    // Show help if no URL provided
    if (!url) {
      program.help();
      return;
    }
    
    try {
      // Check license and rate limits
      const license = getLicense();
      const rateLimit = checkRateLimit();
      
      // Handle rate limiting
      if (!rateLimit.allowed) {
        console.error(chalk.red.bold('\n❌ Daily scan limit reached'));
        console.error(chalk.yellow(`Free tier: ${FREE_DAILY_LIMIT} scans/day`));
        console.error(chalk.gray(`Resets: ${new Date(rateLimit.resetsAt).toLocaleString()}\n`));
        console.error(chalk.blue('Upgrade to Pro for unlimited scans:'));
        console.error(chalk.blue('  https://mesaplex.com/mpx-scan\n'));
        process.exit(1);
      }
      
      // Check for Pro-only features
      if (options.full && license.tier !== 'pro') {
        console.error(chalk.red.bold('\n❌ --full flag requires Pro license'));
        console.error(chalk.yellow('Free tier includes: headers, SSL, server checks'));
        console.error(chalk.yellow('Pro includes: all checks (DNS, cookies, SRI, exposed files, etc.)\n'));
        console.error(chalk.blue('Upgrade: https://mesaplex.com/mpx-scan\n'));
        process.exit(1);
      }
      
      if (options.json && license.tier !== 'pro') {
        console.error(chalk.red.bold('\n❌ --json output requires Pro license\n'));
        console.error(chalk.blue('Upgrade: https://mesaplex.com/mpx-scan\n'));
        process.exit(1);
      }
      
      // Show scan info
      if (!options.json && !options.brief) {
        console.log('');
        console.log(chalk.bold.cyan('🔍 Scanning...'));
        if (license.tier === 'free') {
          console.log(chalk.gray(`Free tier: ${rateLimit.remaining} scan(s) remaining today\n`));
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
      } else if (options.json) {
        console.log(formatJSON(results, true));
      } else if (options.brief) {
        console.log(formatBrief(results));
      } else {
        console.log(formatReport(results, options));
      }
      
      // Exit code logic:
      // - Exit 0: scan completed successfully (default)
      // - Exit 1: only in --ci mode if score below threshold
      if (options.ci) {
        const minScore = parseInt(options.minScore);
        const percentage = Math.round((results.score / results.maxScore) * 100);
        if (percentage < minScore) {
          if (!options.json && !options.brief) {
            console.error(chalk.yellow(`\n⚠️  CI mode: Score ${percentage}/100 below minimum ${minScore}`));
          }
          process.exit(1);
        }
      }
      
      process.exit(0);
      
    } catch (err) {
      if (options.json) {
        console.log(JSON.stringify({ error: err.message }, null, 2));
      } else {
        console.error(chalk.red.bold('\n❌ Error:'), err.message);
        console.error('');
      }
      process.exit(1);
    }
  });

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
      process.exit(1);
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

// Examples
program.addHelpText('after', `
${chalk.bold('Examples:')}
  ${chalk.cyan('mpx-scan https://example.com')}           Quick security scan
  ${chalk.cyan('mpx-scan example.com --full')}            Deep scan (Pro only)
  ${chalk.cyan('mpx-scan example.com --json')}            JSON output (Pro only)
  ${chalk.cyan('mpx-scan example.com --fix nginx')}       Generate nginx config
  ${chalk.cyan('mpx-scan example.com --brief')}           One-line summary
  ${chalk.cyan('mpx-scan license')}                       Check license status
  ${chalk.cyan('mpx-scan activate MPX-PRO-XXX')}          Activate Pro license

${chalk.bold('Free vs Pro:')}
  ${chalk.yellow('Free:')}  3 scans/day, basic checks (headers, SSL, server)
  ${chalk.green('Pro:')}   Unlimited scans, all checks, JSON export, CI/CD integration

  ${chalk.blue('Upgrade: https://mesaplex.com/mpx-scan')}
`);

program.parse();
