/**
 * Schema Module
 * 
 * Returns a machine-readable JSON schema describing all commands,
 * flags, inputs, and outputs for AI agent discovery.
 */

const pkg = require('../package.json');
const { PLATFORMS } = require('./generators/fixes');
const { SCANNER_TIERS } = require('./index');

function getSchema() {
  return {
    tool: 'mpx-scan',
    version: pkg.version,
    description: pkg.description,
    homepage: pkg.homepage,
    commands: {
      scan: {
        description: 'Scan a URL for security issues',
        usage: 'mpx-scan <url> [options]',
        arguments: {
          url: {
            type: 'string',
            required: true,
            description: 'URL to scan (https:// prefix added automatically if missing)'
          }
        },
        flags: {
          '--json': {
            type: 'boolean',
            default: false,
            description: 'Output results as structured JSON'
          },
          '--full': {
            type: 'boolean',
            default: false,
            description: 'Run all security checks (Pro license required)'
          },
          '--brief': {
            type: 'boolean',
            default: false,
            description: 'One-line summary output'
          },
          '--quiet': {
            type: 'boolean',
            default: false,
            description: 'Minimal output (no banners or progress)'
          },
          '--no-color': {
            type: 'boolean',
            default: false,
            description: 'Disable ANSI color codes in output'
          },
          '--batch': {
            type: 'boolean',
            default: false,
            description: 'Read URLs from stdin (one per line), output JSONL with --json'
          },
          '--fix': {
            type: 'string',
            enum: PLATFORMS,
            description: 'Generate fix configuration for specified platform'
          },
          '--timeout': {
            type: 'number',
            default: 10,
            description: 'Connection timeout in seconds'
          },
          '--ci': {
            type: 'boolean',
            default: false,
            description: 'CI/CD mode: exit 1 if score below --min-score'
          },
          '--min-score': {
            type: 'number',
            default: 70,
            description: 'Minimum score threshold for --ci mode (0-100)'
          },
          '--schema': {
            type: 'boolean',
            default: false,
            description: 'Output this schema as JSON'
          }
        },
        output: {
          json: {
            description: 'Structured scan results when --json is used',
            schema: {
              type: 'object',
              properties: {
                mpxScan: {
                  type: 'object',
                  properties: {
                    version: { type: 'string' },
                    scannedAt: { type: 'string', format: 'date-time' },
                    scanDuration: { type: 'number', description: 'Duration in milliseconds' }
                  }
                },
                target: {
                  type: 'object',
                  properties: {
                    url: { type: 'string' },
                    hostname: { type: 'string' }
                  }
                },
                score: {
                  type: 'object',
                  properties: {
                    grade: { type: 'string', enum: ['A+', 'A', 'B', 'C', 'D', 'F'] },
                    numeric: { type: 'number' },
                    maxScore: { type: 'number' },
                    percentage: { type: 'number', minimum: 0, maximum: 100 }
                  }
                },
                summary: {
                  type: 'object',
                  properties: {
                    passed: { type: 'number' },
                    warnings: { type: 'number' },
                    failed: { type: 'number' },
                    info: { type: 'number' }
                  }
                },
                sections: { type: 'object', description: 'Per-scanner results keyed by scanner name' },
                tier: { type: 'string', enum: ['free', 'pro'] }
              }
            }
          },
          error: {
            description: 'Error response when scan fails',
            schema: {
              type: 'object',
              properties: {
                error: { type: 'string' },
                code: { type: 'string', enum: ['ERR_NETWORK', 'ERR_SCAN', 'ERR_RATE_LIMIT', 'ERR_PRO_REQUIRED', 'ERR_NO_INPUT'] }
              }
            }
          }
        },
        exitCodes: {
          0: 'Success, no security issues found',
          1: 'Success, security issues found',
          2: 'Invalid arguments',
          3: 'Configuration error (license, rate limit)',
          4: 'Network/connectivity error'
        },
        examples: [
          { command: 'mpx-scan https://example.com --json', description: 'Scan with JSON output' },
          { command: 'mpx-scan https://example.com --json --full', description: 'Full scan with JSON (Pro)' },
          { command: 'cat urls.txt | mpx-scan --batch --json', description: 'Batch scan from stdin' },
          { command: 'mpx-scan https://example.com --fix nginx', description: 'Get nginx fix config' }
        ]
      },
      mcp: {
        description: 'Start MCP (Model Context Protocol) stdio server for AI agent integration',
        usage: 'mpx-scan mcp',
        arguments: {},
        flags: {},
        examples: [
          { command: 'mpx-scan mcp', description: 'Start MCP stdio server' }
        ]
      },
      license: {
        description: 'Show current license status',
        usage: 'mpx-scan license'
      },
      activate: {
        description: 'Activate a Pro license key',
        usage: 'mpx-scan activate <key>',
        arguments: {
          key: { type: 'string', required: true, description: 'License key (MPX-PRO-...)' }
        }
      },
      deactivate: {
        description: 'Deactivate Pro license and return to free tier',
        usage: 'mpx-scan deactivate'
      },
      update: {
        description: 'Check for updates and optionally install the latest version',
        usage: 'mpx-scan update [--check] [--json]',
        flags: {
          '--check': { description: 'Only check for updates (do not install)', default: false },
          '--json': { description: 'Machine-readable JSON output', default: false }
        },
        examples: [
          { command: 'mpx-scan update', description: 'Check and install updates' },
          { command: 'mpx-scan update --check', description: 'Just check for updates' },
          { command: 'mpx-scan update --check --json', description: 'Check for updates (JSON output)' }
        ]
      }
    },
    scanners: {
      free: SCANNER_TIERS.free,
      pro: SCANNER_TIERS.pro
    },
    mcpConfig: {
      description: 'Add to your MCP client configuration to use mpx-scan as an AI tool',
      config: {
        mcpServers: {
          'mpx-scan': {
            command: 'npx',
            args: ['mpx-scan', 'mcp']
          }
        }
      }
    }
  };
}

module.exports = { getSchema };
