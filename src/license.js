/**
 * License Management
 * 
 * Free tier: 3 scans/day, basic checks only
 * Pro tier: unlimited scans, all checks, JSON export
 * 
 * Simple file-based license tracking (can be upgraded to LemonSqueezy API later)
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const LICENSE_DIR = path.join(os.homedir(), '.mpx-scan');
const LICENSE_FILE = path.join(LICENSE_DIR, 'license.json');
const USAGE_FILE = path.join(LICENSE_DIR, 'usage.json');

const FREE_DAILY_LIMIT = 3;

function ensureDir() {
  if (!fs.existsSync(LICENSE_DIR)) {
    fs.mkdirSync(LICENSE_DIR, { recursive: true });
  }
}

/**
 * Get current license status
 * @returns {object} { tier: 'free'|'pro', key: string|null }
 */
function getLicense() {
  ensureDir();
  
  try {
    if (fs.existsSync(LICENSE_FILE)) {
      const data = JSON.parse(fs.readFileSync(LICENSE_FILE, 'utf8'));
      
      // Validate license key format (simple check for now)
      if (data.key && data.key.startsWith('MPX-PRO-')) {
        return { tier: 'pro', key: data.key, email: data.email || null };
      }
    }
  } catch (err) {
    // Invalid license file, treat as free
  }
  
  return { tier: 'free', key: null, email: null };
}

/**
 * Activate a pro license
 * @param {string} key - License key
 * @param {string} email - User email (optional)
 */
function activateLicense(key, email = null) {
  ensureDir();
  
  // TODO: Validate with LemonSqueezy API
  // For now, just check format
  if (!key.startsWith('MPX-PRO-')) {
    throw new Error('Invalid license key format. Pro keys start with MPX-PRO-');
  }
  
  const licenseData = {
    key,
    email,
    activatedAt: new Date().toISOString()
  };
  
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(licenseData, null, 2));
  
  return { success: true, tier: 'pro' };
}

/**
 * Check if user can perform a scan (rate limiting for free tier)
 * @returns {object} { allowed: boolean, remaining: number, resetsAt: string }
 */
function checkRateLimit() {
  const license = getLicense();
  
  // Pro users have unlimited scans
  if (license.tier === 'pro') {
    return { allowed: true, remaining: -1, resetsAt: null };
  }
  
  ensureDir();
  
  // Free tier: check daily usage
  let usage = { scans: [], lastReset: null };
  
  try {
    if (fs.existsSync(USAGE_FILE)) {
      usage = JSON.parse(fs.readFileSync(USAGE_FILE, 'utf8'));
    }
  } catch (err) {
    // Invalid usage file, reset
  }
  
  const now = new Date();
  const today = now.toISOString().split('T')[0];
  
  // Reset if it's a new day
  if (usage.lastReset !== today) {
    usage = { scans: [], lastReset: today };
  }
  
  // Filter scans from today
  const todayScans = usage.scans.filter(s => s.startsWith(today));
  
  if (todayScans.length >= FREE_DAILY_LIMIT) {
    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);
    
    return {
      allowed: false,
      remaining: 0,
      resetsAt: tomorrow.toISOString()
    };
  }
  
  return {
    allowed: true,
    remaining: FREE_DAILY_LIMIT - todayScans.length,
    resetsAt: null
  };
}

/**
 * Record a scan (for free tier rate limiting)
 */
function recordScan() {
  const license = getLicense();
  
  // No need to track pro scans
  if (license.tier === 'pro') {
    return;
  }
  
  ensureDir();
  
  let usage = { scans: [], lastReset: null };
  
  try {
    if (fs.existsSync(USAGE_FILE)) {
      usage = JSON.parse(fs.readFileSync(USAGE_FILE, 'utf8'));
    }
  } catch (err) {
    // Invalid usage file, reset
  }
  
  const now = new Date();
  const today = now.toISOString().split('T')[0];
  
  // Reset if it's a new day
  if (usage.lastReset !== today) {
    usage = { scans: [], lastReset: today };
  }
  
  usage.scans.push(now.toISOString());
  
  // Keep only last 10 scans for privacy
  if (usage.scans.length > 10) {
    usage.scans = usage.scans.slice(-10);
  }
  
  fs.writeFileSync(USAGE_FILE, JSON.stringify(usage, null, 2));
}

/**
 * Deactivate license
 */
function deactivateLicense() {
  if (fs.existsSync(LICENSE_FILE)) {
    fs.unlinkSync(LICENSE_FILE);
  }
  return { success: true, tier: 'free' };
}

module.exports = {
  getLicense,
  activateLicense,
  deactivateLicense,
  checkRateLimit,
  recordScan,
  FREE_DAILY_LIMIT
};
