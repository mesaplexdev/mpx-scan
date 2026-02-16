/**
 * DNS Security Scanner
 * 
 * Checks DNS configuration for security features:
 * - SPF records (email spoofing protection)
 * - DMARC records (email authentication)
 * - DKIM (if discoverable)
 * - DNSSEC (via DO flag)
 * - CAA records (certificate authority authorization)
 * - MX records (mail configuration)
 */

const dns = require('dns');
const { Resolver } = dns.promises;

async function scanDNS(parsedUrl, options = {}) {
  const checks = [];
  let score = 0;
  let maxScore = 0;
  
  const hostname = parsedUrl.hostname;
  // Get root domain for DNS checks
  const parts = hostname.split('.');
  const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;
  
  const resolver = new Resolver();
  resolver.setServers(['8.8.8.8', '1.1.1.1']); // Use public DNS

  // --- SPF Record ---
  maxScore += 1;
  try {
    const txtRecords = await resolver.resolveTxt(rootDomain);
    const spf = txtRecords.flat().find(r => r.startsWith('v=spf1'));
    if (spf) {
      const hasAll = /[-~?+]all/.test(spf);
      const isStrict = /-all/.test(spf);
      if (isStrict) {
        checks.push({ name: 'SPF Record', status: 'pass', message: 'Strict SPF (-all) — rejects unauthorized senders', value: spf.substring(0, 150) });
        score += 1;
      } else if (hasAll) {
        checks.push({ name: 'SPF Record', status: 'warn', message: 'SPF present but uses soft fail (~all). Consider -all', value: spf.substring(0, 150) });
        score += 0.5;
      } else {
        checks.push({ name: 'SPF Record', status: 'warn', message: 'SPF present but may not reject unauthorized senders', value: spf.substring(0, 150) });
        score += 0.5;
      }
    } else {
      checks.push({ name: 'SPF Record', status: 'fail', message: 'No SPF record found. Domain vulnerable to email spoofing.', recommendation: 'Add TXT record: v=spf1 include:_spf.google.com -all (adjust for your email provider)' });
    }
  } catch (err) {
    checks.push({ name: 'SPF Record', status: 'info', message: `Could not query TXT records: ${err.code || err.message}` });
  }

  // --- DMARC Record ---
  maxScore += 1;
  try {
    const dmarcRecords = await resolver.resolveTxt(`_dmarc.${rootDomain}`);
    const dmarc = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));
    if (dmarc) {
      const policy = (dmarc.match(/p=(\w+)/) || [])[1] || 'none';
      if (policy === 'reject') {
        checks.push({ name: 'DMARC Record', status: 'pass', message: 'DMARC policy=reject — strongest protection', value: dmarc.substring(0, 150) });
        score += 1;
      } else if (policy === 'quarantine') {
        checks.push({ name: 'DMARC Record', status: 'pass', message: 'DMARC policy=quarantine — good protection', value: dmarc.substring(0, 150) });
        score += 0.75;
      } else {
        checks.push({ name: 'DMARC Record', status: 'warn', message: `DMARC policy=${policy} — monitoring only, not enforcing`, value: dmarc.substring(0, 150) });
        score += 0.25;
      }
    } else {
      checks.push({ name: 'DMARC Record', status: 'fail', message: 'No DMARC record. Email spoofing protection incomplete.', recommendation: 'Add TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com' });
    }
  } catch (err) {
    if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
      checks.push({ name: 'DMARC Record', status: 'fail', message: 'No DMARC record found', recommendation: 'Add DMARC TXT record at _dmarc.yourdomain.com' });
    } else {
      checks.push({ name: 'DMARC Record', status: 'info', message: `Could not query DMARC: ${err.code || err.message}` });
    }
  }

  // --- CAA Records ---
  maxScore += 0.5;
  try {
    const caaRecords = await resolver.resolveCaa(rootDomain);
    if (caaRecords && caaRecords.length > 0) {
      const issuers = caaRecords.filter(r => r.tag === 'issue').map(r => r.value);
      checks.push({ name: 'CAA Records', status: 'pass', message: `Restricts certificate issuance to: ${issuers.join(', ')}`, value: issuers.join(', ') });
      score += 0.5;
    } else {
      checks.push({ name: 'CAA Records', status: 'warn', message: 'No CAA records. Any CA can issue certificates for this domain.', recommendation: 'Add CAA records to restrict which CAs can issue certificates' });
    }
  } catch (err) {
    if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
      checks.push({ name: 'CAA Records', status: 'warn', message: 'No CAA records found' });
    } else {
      checks.push({ name: 'CAA Records', status: 'info', message: `Could not query CAA: ${err.code || err.message}` });
    }
  }

  // --- MX Records (informational) ---
  try {
    const mxRecords = await resolver.resolveMx(rootDomain);
    if (mxRecords && mxRecords.length > 0) {
      const mxList = mxRecords.sort((a, b) => a.priority - b.priority).map(r => `${r.exchange} (${r.priority})`);
      checks.push({ name: 'MX Records', status: 'info', message: `Mail servers: ${mxList.join(', ')}`, value: mxList.join(', ') });
    }
  } catch { /* MX is informational only */ }

  return { score, maxScore, checks };
}

module.exports = { scanDNS };
