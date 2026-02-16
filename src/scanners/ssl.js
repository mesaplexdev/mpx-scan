/**
 * SSL/TLS Scanner
 * 
 * Checks certificate validity, protocol support, and configuration.
 * Uses Node.js tls module — zero external dependencies.
 */

const tls = require('tls');
const https = require('https');

async function scanSSL(parsedUrl, options = {}) {
  const checks = [];
  let score = 0;
  let maxScore = 0;

  if (parsedUrl.protocol !== 'https:') {
    checks.push({ name: 'HTTPS', status: 'fail', message: 'Site does not use HTTPS. All data transmitted in cleartext.' });
    return { score: 0, maxScore: 5, checks };
  }

  const hostname = parsedUrl.hostname;
  const port = parsedUrl.port || 443;

  try {
    const certInfo = await getCertificateInfo(hostname, port, options);

    // --- Certificate validity ---
    maxScore += 2;
    const now = new Date();
    const validFrom = new Date(certInfo.valid_from);
    const validTo = new Date(certInfo.valid_to);
    const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

    if (daysRemaining < 0) {
      checks.push({ name: 'Certificate Validity', status: 'fail', message: `EXPIRED ${Math.abs(daysRemaining)} days ago`, value: validTo.toISOString().split('T')[0] });
    } else if (daysRemaining < 7) {
      checks.push({ name: 'Certificate Validity', status: 'fail', message: `Expires in ${daysRemaining} days!`, value: validTo.toISOString().split('T')[0] });
      score += 0.5;
    } else if (daysRemaining < 30) {
      checks.push({ name: 'Certificate Validity', status: 'warn', message: `Expires in ${daysRemaining} days`, value: validTo.toISOString().split('T')[0] });
      score += 1;
    } else {
      checks.push({ name: 'Certificate Validity', status: 'pass', message: `Valid for ${daysRemaining} more days (expires ${validTo.toISOString().split('T')[0]})`, value: `${daysRemaining} days` });
      score += 2;
    }

    // --- Certificate issuer ---
    maxScore += 0.5;
    const issuer = certInfo.issuer?.O || certInfo.issuer?.CN || 'Unknown';
    const isSelfSigned = certInfo.issuer?.CN === certInfo.subject?.CN && !certInfo.issuer?.O;
    if (isSelfSigned) {
      checks.push({ name: 'Certificate Issuer', status: 'warn', message: `Self-signed certificate (${issuer})`, value: issuer });
    } else {
      checks.push({ name: 'Certificate Issuer', status: 'pass', message: `Issued by ${issuer}`, value: issuer });
      score += 0.5;
    }

    // --- Subject match ---
    maxScore += 1;
    const altNames = (certInfo.subjectaltname || '').split(',').map(s => s.trim().replace('DNS:', ''));
    const subjectCN = certInfo.subject?.CN || '';
    const matchesHostname = altNames.some(name => matchesDomain(name, hostname)) || matchesDomain(subjectCN, hostname);
    
    if (matchesHostname) {
      checks.push({ name: 'Hostname Match', status: 'pass', message: `Certificate covers ${hostname}`, value: altNames.slice(0, 5).join(', ') });
      score += 1;
    } else {
      checks.push({ name: 'Hostname Match', status: 'fail', message: `Certificate does NOT match ${hostname}. Subject: ${subjectCN}`, value: altNames.slice(0, 5).join(', ') });
    }

    // --- TLS version ---
    maxScore += 1.5;
    const tlsVersion = certInfo.protocol;
    if (tlsVersion === 'TLSv1.3') {
      checks.push({ name: 'TLS Version', status: 'pass', message: 'TLS 1.3 — latest and most secure', value: tlsVersion });
      score += 1.5;
    } else if (tlsVersion === 'TLSv1.2') {
      checks.push({ name: 'TLS Version', status: 'pass', message: 'TLS 1.2 — acceptable', value: tlsVersion });
      score += 1;
    } else {
      checks.push({ name: 'TLS Version', status: 'fail', message: `${tlsVersion || 'Unknown'} — outdated and insecure`, value: tlsVersion });
    }

    // --- Cipher suite ---
    maxScore += 1;
    const cipher = certInfo.cipher;
    if (cipher) {
      const isStrong = /AES.*(256|GCM)|CHACHA20/i.test(cipher.name || '');
      if (isStrong) {
        checks.push({ name: 'Cipher Suite', status: 'pass', message: cipher.name, value: `${cipher.name} (${cipher.standardName || ''})` });
        score += 1;
      } else {
        checks.push({ name: 'Cipher Suite', status: 'warn', message: `${cipher.name} — consider stronger cipher`, value: cipher.name });
        score += 0.5;
      }
    }

  } catch (err) {
    maxScore = 5;
    if (err.code === 'CERT_HAS_EXPIRED') {
      checks.push({ name: 'Certificate', status: 'fail', message: 'Certificate has expired' });
    } else if (err.code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
      checks.push({ name: 'Certificate', status: 'fail', message: 'Certificate hostname mismatch' });
    } else {
      checks.push({ name: 'SSL/TLS Connection', status: 'error', message: `Failed: ${err.message}` });
    }
  }

  return { score, maxScore, checks };
}

function getCertificateInfo(hostname, port, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 10000;
    
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: false, // We want to inspect even bad certs
      timeout,
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      
      socket.destroy();
      resolve({
        ...cert,
        protocol,
        cipher,
        authorized: socket.authorized
      });
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('TLS connection timeout'));
    });
  });
}

function matchesDomain(pattern, hostname) {
  if (!pattern) return false;
  pattern = pattern.toLowerCase();
  hostname = hostname.toLowerCase();
  if (pattern === hostname) return true;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    return hostname.endsWith(suffix) && hostname.split('.').length === pattern.split('.').length;
  }
  return false;
}

module.exports = { scanSSL };
