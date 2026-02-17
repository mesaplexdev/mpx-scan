/**
 * Update Command
 * 
 * Checks npm for the latest version of mpx-scan and offers to update.
 */

const { execSync } = require('child_process');
const pkg = require('../package.json');

/**
 * Check npm registry for latest version
 * @returns {object} { current, latest, updateAvailable, isGlobal }
 */
function checkForUpdate() {
  const current = pkg.version;
  
  let latest;
  try {
    latest = execSync('npm view mpx-scan version', { encoding: 'utf8', timeout: 10000 }).trim();
  } catch (err) {
    throw new Error('Failed to check npm registry: ' + (err.message || 'unknown error'));
  }
  
  const updateAvailable = latest !== current && compareVersions(latest, current) > 0;
  
  // Detect if installed globally
  let isGlobal = false;
  try {
    const globalDir = execSync('npm root -g', { encoding: 'utf8', timeout: 5000 }).trim();
    isGlobal = __dirname.startsWith(globalDir) || process.argv[1]?.includes('node_modules/.bin');
  } catch {
    // Can't determine, assume local
  }
  
  return { current, latest, updateAvailable, isGlobal };
}

/**
 * Perform the update
 * @param {boolean} isGlobal - Install globally
 * @returns {object} { success, version }
 */
function performUpdate(isGlobal) {
  const cmd = isGlobal ? 'npm install -g mpx-scan@latest' : 'npm install mpx-scan@latest';
  try {
    execSync(cmd, { encoding: 'utf8', timeout: 60000, stdio: 'pipe' });
    // Verify
    const newVersion = execSync('npm view mpx-scan version', { encoding: 'utf8', timeout: 10000 }).trim();
    return { success: true, version: newVersion };
  } catch (err) {
    throw new Error('Update failed: ' + (err.message || 'unknown error'));
  }
}

/**
 * Compare semver strings. Returns >0 if a > b, <0 if a < b, 0 if equal.
 */
function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
}

module.exports = { checkForUpdate, performUpdate, compareVersions };
