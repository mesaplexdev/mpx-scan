/**
 * Terminal Reporter
 * 
 * Beautiful colored output for CLI with chalk
 */

const chalk = require('chalk');

const STATUS_ICONS = {
  pass: '✓',
  warn: '⚠',
  fail: '✗',
  error: '⚠',
  info: 'ℹ'
};

const STATUS_COLORS = {
  pass: 'green',
  warn: 'yellow',
  fail: 'red',
  error: 'red',
  info: 'blue'
};

const GRADE_COLORS = {
  'A+': 'greenBright',
  'A': 'green',
  'B': 'cyan',
  'C': 'yellow',
  'D': 'magenta',
  'F': 'red'
};

function formatReport(results, options = {}) {
  const lines = [];
  
  // Header
  lines.push('');
  lines.push(chalk.bold.cyan('┌─────────────────────────────────────────────────────────────┐'));
  lines.push(chalk.bold.cyan('│') + chalk.bold('         mpx-scan — Website Security Report          ') + chalk.bold.cyan('│'));
  lines.push(chalk.bold.cyan('└─────────────────────────────────────────────────────────────┘'));
  lines.push('');
  
  // URL and basic info
  lines.push(chalk.bold('Target:     ') + chalk.cyan(results.url));
  lines.push(chalk.bold('Scanned:    ') + chalk.gray(new Date(results.scannedAt).toLocaleString()));
  lines.push(chalk.bold('Duration:   ') + chalk.gray(`${results.scanDuration}ms`));
  lines.push('');
  
  // Overall score
  const gradeColor = GRADE_COLORS[results.grade] || 'gray';
  const percentage = Math.round((results.score / results.maxScore) * 100);
  const barLength = 40;
  const filledLength = Math.round((percentage / 100) * barLength);
  const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);
  
  lines.push(chalk.bold('Overall Score:'));
  lines.push('  ' + chalk[gradeColor](bar));
  lines.push('  ' + chalk.bold[gradeColor](`${results.grade}`) + chalk.gray(` (${percentage}/100)`));
  lines.push('');
  
  // Summary
  lines.push(chalk.bold('Summary:'));
  lines.push('  ' + chalk.green(`${STATUS_ICONS.pass} ${results.summary.passed} passed`) + 
             chalk.gray(' │ ') +
             chalk.yellow(`${STATUS_ICONS.warn} ${results.summary.warnings} warnings`) +
             chalk.gray(' │ ') +
             chalk.red(`${STATUS_ICONS.fail} ${results.summary.failed} failed`));
  lines.push('');
  
  // Sections
  const sections = Object.entries(results.sections);
  
  for (const [name, section] of sections) {
    const sectionGrade = section.grade;
    const sectionColor = GRADE_COLORS[sectionGrade] || 'gray';
    const sectionPercentage = Math.round((section.score / section.maxScore) * 100);
    
    lines.push(chalk.bold.underline(`\n${capitalize(name)}`));
    lines.push(chalk.gray(`  Score: ${section.score}/${section.maxScore} (${sectionPercentage}%) — Grade: `) + chalk.bold[sectionColor](sectionGrade));
    lines.push('');
    
    for (const check of section.checks) {
      const icon = STATUS_ICONS[check.status] || '•';
      const color = STATUS_COLORS[check.status] || 'white';
      
      lines.push('  ' + chalk[color](`${icon} ${check.name}`));
      
      if (check.message) {
        lines.push('    ' + chalk.gray(check.message));
      }
      
      if (check.value && !options.brief) {
        const value = String(check.value).length > 100 
          ? String(check.value).substring(0, 100) + '...'
          : check.value;
        lines.push('    ' + chalk.dim(`→ ${value}`));
      }
      
      if (check.recommendation && !options.brief) {
        lines.push('    ' + chalk.cyan(`💡 ${check.recommendation}`));
      }
    }
  }
  
  // Free tier upgrade message
  if (results.tier === 'free') {
    lines.push('');
    lines.push(chalk.yellow('─'.repeat(63)));
    lines.push(chalk.yellow.bold('🔓 Upgrade to Pro for:'));
    lines.push(chalk.yellow('  • Unlimited scans (free tier: 3/day)'));
    lines.push(chalk.yellow('  • All security checks (DNS, cookies, SRI, exposed files)'));
    lines.push(chalk.yellow('  • JSON/CSV export for CI/CD integration'));
    lines.push(chalk.yellow('  • Batch scanning'));
    lines.push('');
    lines.push(chalk.blue('Learn more: https://mesaplex.com/mpx-scan'));
    lines.push(chalk.yellow('─'.repeat(63)));
  }
  
  lines.push('');
  
  return lines.join('\n');
}

function formatBrief(results) {
  const gradeColor = GRADE_COLORS[results.grade] || 'gray';
  const percentage = Math.round((results.score / results.maxScore) * 100);
  
  return `${results.url} — ${chalk.bold[gradeColor](results.grade)} (${percentage}/100) — ` +
         `${chalk.green(results.summary.passed + ' ✓')} ${chalk.yellow(results.summary.warnings + ' ⚠')} ${chalk.red(results.summary.failed + ' ✗')}`;
}

function capitalize(str) {
  return str
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, s => s.toUpperCase())
    .trim();
}

module.exports = { formatReport, formatBrief };
