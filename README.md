# mpx-scan 🔍

**Professional website security scanner for developers and AI agents**

Check your site's security headers, SSL/TLS configuration, DNS settings, and get actionable fix suggestions — all from your terminal.

Part of the [Mesaplex](https://mesaplex.com) developer toolchain.

[![npm version](https://img.shields.io/npm/v/mpx-scan.svg)](https://www.npmjs.com/package/mpx-scan)
[![License](https://img.shields.io/badge/license-Dual-blue.svg)](LICENSE)

## ✨ Features

- **Zero-config security scanning** — just point it at a URL
- **Beautiful terminal output** with color-coded results
- **Structured JSON output** — `--json` for CI/CD and AI agent consumption
- **MCP server** — integrates with any MCP-compatible AI agent (Claude, GPT, Cursor, etc.)
- **Actionable fix suggestions** — copy-paste config for nginx, Apache, Caddy, Cloudflare
- **Batch scanning** — pipe URLs from stdin
- **Self-documenting** — `--schema` returns machine-readable tool description
- **Fast** — scans complete in seconds
- **Zero native dependencies** — installs cleanly everywhere
- **CI/CD ready** — predictable exit codes and JSON output

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

### JSON Output

```bash
mpx-scan https://example.com --json
```

Returns structured JSON to stdout (progress/status goes to stderr):

```json
{
  "mpxScan": {
    "version": "1.1.0",
    "scannedAt": "2026-02-16T22:00:00.000Z",
    "scanDuration": 350
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
    "failed": 2,
    "info": 0
  },
  "sections": { ... },
  "tier": "free"
}
```

### Get Fix Suggestions

```bash
mpx-scan https://example.com --fix nginx
mpx-scan https://example.com --fix apache
mpx-scan https://example.com --fix caddy
mpx-scan https://example.com --fix cloudflare
```

### Deep Scan (Pro)

```bash
mpx-scan https://example.com --full
```

### Brief Output

```bash
mpx-scan https://example.com --brief
```

### Batch Scanning

```bash
cat urls.txt | mpx-scan --batch --json
```

Reads one URL per line from stdin, outputs one JSON result per line (JSONL format). Lines starting with `#` are ignored.

### Tool Schema

```bash
mpx-scan --schema
```

Returns a JSON schema describing all commands, flags, inputs, and outputs — designed for AI agent tool discovery.

## 🤖 AI Agent Usage

mpx-scan is designed to be used by AI agents as well as humans.

### MCP Integration

Add to your MCP client configuration (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "mpx-scan": {
      "command": "npx",
      "args": ["mpx-scan", "mcp"]
    }
  }
}
```

The MCP server exposes these tools:
- **`scan`** — Scan a URL and return structured results
- **`generate_fixes`** — Scan and generate platform-specific fix config
- **`get_schema`** — Get full tool schema

### Programmatic Usage

```bash
# JSON output for parsing
mpx-scan https://example.com --json

# Batch processing
cat urls.txt | mpx-scan --batch --json

# Schema discovery
mpx-scan --schema

# Quiet mode (no banners, progress goes to stderr)
mpx-scan https://example.com --json --quiet
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no security issues found |
| 1 | Scan complete, security issues found |
| 2 | Invalid arguments |
| 3 | Configuration error (license, rate limit) |
| 4 | Network/connectivity error |

### Error Responses (JSON mode)

When `--json` is used, errors return structured JSON:

```json
{
  "error": "Description of what went wrong",
  "code": "ERR_NETWORK"
}
```

Error codes: `ERR_NETWORK`, `ERR_SCAN`, `ERR_RATE_LIMIT`, `ERR_PRO_REQUIRED`, `ERR_NO_INPUT`

### Automation Tips

- Use `--json` for machine-parseable output (stdout only, no ANSI)
- Use `--no-color` to strip ANSI codes from human-readable output
- Use `--quiet` to suppress banners and progress info
- Pipe `--batch --json` for JSONL (one result per line) processing
- Check exit codes for pass/fail decisions in CI/CD

## 🎯 Use Cases

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - run: npx mpx-scan https://mysite.com --ci --min-score 70 --json
```

### Monitoring Script

```bash
#!/bin/bash
for site in site1.com site2.com site3.com; do
  result=$(npx mpx-scan "$site" --json 2>/dev/null)
  grade=$(echo "$result" | jq -r '.score.grade')
  echo "$site: $grade"
done
```

## 📊 Free vs Pro

| Feature | Free | Pro |
|---------|------|-----|
| **Daily scans** | 3 | Unlimited |
| **Security headers** | ✅ | ✅ |
| **SSL/TLS checks** | ✅ | ✅ |
| **Server info checks** | ✅ | ✅ |
| **JSON output** | ✅ | ✅ |
| **Batch scanning** | ✅ | ✅ |
| **MCP server** | ✅ | ✅ |
| **DNS security** | ❌ | ✅ |
| **Cookie security** | ❌ | ✅ |
| **SRI checks** | ❌ | ✅ |
| **Exposed files** | ❌ | ✅ |
| **Mixed content** | ❌ | ✅ |
| **Full scan (--full)** | ❌ | ✅ |

**Upgrade to Pro:** [https://mesaplex.com/mpx-scan](https://mesaplex.com/mpx-scan)

## 🔐 License Management

```bash
mpx-scan license                         # Check status
mpx-scan activate MPX-PRO-XXXXXXXX      # Activate Pro
mpx-scan deactivate                      # Return to free tier
```

## 🛠️ CLI Reference

```
Usage: mpx-scan [url] [options]

Arguments:
  url                      URL to scan

Options:
  -V, --version            Output version number
  --json                   Output as structured JSON
  --full                   Run all checks (Pro only)
  --brief                  Brief one-line output
  --quiet, -q              Minimal output (no banners)
  --no-color               Disable ANSI color codes
  --batch                  Read URLs from stdin (one per line)
  --schema                 Output JSON schema for tool discovery
  --fix <platform>         Generate fix config (nginx, apache, caddy, cloudflare)
  --timeout <seconds>      Connection timeout (default: 10)
  --ci                     CI mode: exit 1 if below --min-score
  --min-score <score>      Minimum score for CI mode (default: 70)
  -h, --help               Display help

Commands:
  license                  Show license status
  activate <key>           Activate Pro license
  deactivate               Return to free tier
  mcp                      Start MCP stdio server
```

## 📦 Installation

```bash
# Global
npm install -g mpx-scan

# Project dependency
npm install --save-dev mpx-scan

# One-off with npx
npx mpx-scan https://example.com
```

### Requirements

- Node.js 18.0.0 or higher
- No native dependencies
- Works on macOS, Linux, Windows

## 🧪 Testing

```bash
npm test
```

## 🤝 Contributing

Security improvements and bug fixes are welcome!

## 📄 License

Dual License: Free tier for personal use, Pro license for commercial use and advanced features.

See [LICENSE](LICENSE) for full terms.

## 🔗 Links

- **Website:** [https://mesaplex.com/mpx-scan](https://mesaplex.com/mpx-scan)
- **npm:** [https://www.npmjs.com/package/mpx-scan](https://www.npmjs.com/package/mpx-scan)
- **GitHub:** [https://github.com/mesaplexdev/mpx-scan](https://github.com/mesaplexdev/mpx-scan)
- **Support:** support@mesaplex.com

## 📚 Related Tools

- **mpx-scan** — Security scanner (you are here)
- **[mpx-api](https://www.npmjs.com/package/mpx-api)** — API testing toolkit
- **[mpx-db](https://www.npmjs.com/package/mpx-db)** — Database toolkit

---

**Made with ❤️ by [Mesaplex](https://mesaplex.com)**
