# mpx-scan 🔍

**Professional website security scanner for developers**

Check your site's security headers, SSL/TLS configuration, DNS settings, and get actionable fix suggestions — all from your terminal.

Part of the [Mesaplex](https://mesaplex.com) developer toolchain.

[![npm version](https://img.shields.io/npm/v/mpx-scan.svg)](https://www.npmjs.com/package/mpx-scan)
[![License](https://img.shields.io/badge/license-Dual-blue.svg)](LICENSE)

## ✨ Features

- **Zero-config security scanning** — just point it at a URL
- **Beautiful terminal output** with color-coded results
- **Actionable fix suggestions** — copy-paste config for nginx, Apache, Caddy, Cloudflare
- **Fast** — scans complete in seconds
- **Zero native dependencies** — installs cleanly everywhere
- **CI/CD ready** — JSON output and exit codes for automated testing

### Security Checks

- ✅ HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- ✅ SSL/TLS certificate validity, expiration, protocol version
- ✅ Cookie security flags (Secure, HttpOnly, SameSite)
- ✅ Server information leakage
- ✅ CORS misconfiguration
- ✅ Mixed content detection
- ✅ DNS security (DNSSEC, CAA records) — *Pro only*
- ✅ Subresource Integrity (SRI) — *Pro only*
- ✅ Open redirect detection — *Pro only*
- ✅ Exposed sensitive files — *Pro only*

## 🚀 Quick Start

```bash
# Run once without installing
npx mpx-scan https://example.com

# Or install globally
npm install -g mpx-scan
mpx-scan https://example.com
```

## 📖 Usage

### Basic Scan

```bash
mpx-scan https://example.com
```

![Example output](https://example.com/mpx-scan-demo.gif)

### Get Fix Suggestions

```bash
mpx-scan https://example.com --fix nginx
mpx-scan https://example.com --fix apache
mpx-scan https://example.com --fix caddy
mpx-scan https://example.com --fix cloudflare
```

Generates copy-paste configuration snippets for your platform.

### Deep Scan (Pro)

```bash
mpx-scan https://example.com --full
```

Runs all security checks including DNS, cookies, SRI, exposed files.

### JSON Output (Pro)

```bash
mpx-scan https://example.com --json
```

Perfect for CI/CD pipelines:

```json
{
  "mpxScan": {
    "version": "1.0.0",
    "scannedAt": "2026-02-15T22:00:00.000Z"
  },
  "target": {
    "url": "https://example.com",
    "hostname": "example.com"
  },
  "score": {
    "grade": "B",
    "numeric": 72.5,
    "maxScore": 100,
    "percentage": 73
  },
  "summary": {
    "passed": 12,
    "warnings": 3,
    "failed": 2
  }
}
```

### Brief Output

```bash
mpx-scan https://example.com --brief
```

One-line summary — great for monitoring multiple sites.

## 🎯 Use Cases

### Local Development

```bash
mpx-scan http://localhost:3000 --fix nginx
```

Check your security before deploying.

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - run: npx mpx-scan https://mysite.com --json
```

### Batch Scanning (Pro)

```bash
for site in site1.com site2.com site3.com; do
  mpx-scan $site --json >> security-report.jsonl
done
```

## 📊 Free vs Pro

| Feature | Free | Pro |
|---------|------|-----|
| **Daily scans** | 3 | Unlimited |
| **Security headers** | ✅ | ✅ |
| **SSL/TLS checks** | ✅ | ✅ |
| **Server info checks** | ✅ | ✅ |
| **DNS security** | ❌ | ✅ |
| **Cookie security** | ❌ | ✅ |
| **SRI checks** | ❌ | ✅ |
| **Exposed files** | ❌ | ✅ |
| **Mixed content** | ❌ | ✅ |
| **JSON export** | ❌ | ✅ |
| **Batch scanning** | ❌ | ✅ |
| **CI/CD integration** | ❌ | ✅ |

**Upgrade to Pro:** [https://mesaplex.com/mpx-scan](https://mesaplex.com/mpx-scan)

## 🔐 License Management

### Check License Status

```bash
mpx-scan license
```

### Activate Pro License

```bash
mpx-scan activate MPX-PRO-XXXXXXXXXXXXXXXX
```

### Deactivate

```bash
mpx-scan deactivate
```

## 🛠️ CLI Options

```
Usage: mpx-scan [url] [options]

Arguments:
  url                      URL to scan

Options:
  -V, --version            output the version number
  --full                   Run all checks (Pro only)
  --json                   Output as JSON (Pro only)
  --brief                  Brief output (one-line summary)
  --fix <platform>         Generate fix config (nginx, apache, caddy, cloudflare)
  --timeout <seconds>      Connection timeout (default: "10")
  -h, --help               display help for command

Commands:
  license                  Manage your mpx-scan license
  activate <key>           Activate a Pro license
  deactivate               Deactivate license
```

## 📦 Installation

### Global Install

```bash
npm install -g mpx-scan
```

### Project Dependency

```bash
npm install --save-dev mpx-scan
```

Add to `package.json`:

```json
{
  "scripts": {
    "security": "mpx-scan https://mysite.com"
  }
}
```

### Requirements

- Node.js 18.0.0 or higher
- No other dependencies required for scanning
- Works on macOS, Linux, Windows

## 🧪 Testing

```bash
npm test
```

Runs the built-in test suite for core scanning logic.

## 🤝 Contributing

This is a commercial product with a free tier. Security improvements and bug fixes are welcome!

## 📄 License

Dual License: Free tier for personal use, Pro license for commercial use and advanced features.

See [LICENSE](LICENSE) for full terms.

## 🔗 Links

- **Website:** [https://mesaplex.com/mpx-scan](https://mesaplex.com/mpx-scan)
- **Documentation:** [https://docs.mesaplex.com/mpx-scan](https://docs.mesaplex.com/mpx-scan)
- **Support:** support@mesaplex.com
- **Twitter:** [@mesaplex](https://twitter.com/mesaplex)

## 🐛 Known Issues

None currently! Report issues via email: support@mesaplex.com

## 📚 Related Tools

Part of the Mesaplex developer toolchain:

- **mpx-scan** — Security scanner (you are here)
- **mpx-api** — API testing toolkit *(coming soon)*
- **mpx-perf** — Performance profiler *(coming soon)*
- **mpx-deploy** — Deployment automation *(coming soon)*

---

**Made with ❤️ by [Mesaplex](https://mesaplex.com)**
