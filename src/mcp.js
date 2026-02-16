/**
 * MCP (Model Context Protocol) Server
 * 
 * Exposes mpx-scan capabilities as MCP tools for AI agent integration.
 * Runs over stdio transport.
 */

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const {
  ListToolsRequestSchema,
  CallToolRequestSchema
} = require('@modelcontextprotocol/sdk/types.js');

const { scan } = require('./index');
const { formatJSON } = require('./reporters/json');
const { getSchema } = require('./schema');
const { getLicense, checkRateLimit, recordScan } = require('./license');
const { generateFixes, PLATFORMS } = require('./generators/fixes');
const pkg = require('../package.json');

async function startMCPServer() {
  const server = new Server(
    { name: 'mpx-scan', version: pkg.version },
    { capabilities: { tools: {} } }
  );

  // List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: 'scan',
          description: 'Scan a website for security issues. Returns structured results with grade, score, and per-check details.',
          inputSchema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'URL to scan (https:// added automatically if missing)'
              },
              full: {
                type: 'boolean',
                description: 'Run all security checks (Pro license required)',
                default: false
              },
              timeout: {
                type: 'number',
                description: 'Connection timeout in seconds',
                default: 10
              }
            },
            required: ['url']
          }
        },
        {
          name: 'generate_fixes',
          description: 'Generate platform-specific configuration to fix security issues found by a scan.',
          inputSchema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'URL to scan and generate fixes for'
              },
              platform: {
                type: 'string',
                enum: PLATFORMS,
                description: 'Target platform for fix configuration'
              },
              timeout: {
                type: 'number',
                description: 'Connection timeout in seconds',
                default: 10
              }
            },
            required: ['url', 'platform']
          }
        },
        {
          name: 'get_schema',
          description: 'Get the full JSON schema describing all mpx-scan commands, flags, and output formats.',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        }
      ]
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case 'scan': {
          const license = getLicense();
          const rateLimit = checkRateLimit();
          
          if (!rateLimit.allowed) {
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  error: 'Daily scan limit reached',
                  code: 'ERR_RATE_LIMIT',
                  resetsAt: new Date(rateLimit.resetsAt).toISOString()
                }, null, 2)
              }],
              isError: true
            };
          }

          const results = await scan(args.url, {
            timeout: (args.timeout || 10) * 1000,
            tier: license.tier,
            full: args.full || false
          });
          
          recordScan();

          return {
            content: [{
              type: 'text',
              text: formatJSON(results, true)
            }]
          };
        }

        case 'generate_fixes': {
          const license = getLicense();
          const rateLimit2 = checkRateLimit();
          
          if (!rateLimit2.allowed) {
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  error: 'Daily scan limit reached',
                  code: 'ERR_RATE_LIMIT',
                  resetsAt: new Date(rateLimit2.resetsAt).toISOString()
                }, null, 2)
              }],
              isError: true
            };
          }

          const fixResults = await scan(args.url, {
            timeout: (args.timeout || 10) * 1000,
            tier: license.tier,
            full: false
          });
          
          recordScan();

          // Collect issues and generate structured fix data
          const issues = [];
          for (const [sectionName, section] of Object.entries(fixResults.sections)) {
            for (const check of section.checks) {
              if ((check.status === 'fail' || check.status === 'warn') && check.recommendation) {
                issues.push({
                  section: sectionName,
                  name: check.name,
                  status: check.status,
                  recommendation: check.recommendation
                });
              }
            }
          }

          // Extract headers from issues
          const headers = {};
          for (const issue of issues) {
            const rec = issue.recommendation;
            if (rec.includes('Strict-Transport-Security')) headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
            if (rec.includes('Content-Security-Policy')) headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'";
            if (rec.includes('X-Content-Type-Options')) headers['X-Content-Type-Options'] = 'nosniff';
            if (rec.includes('X-Frame-Options')) headers['X-Frame-Options'] = 'DENY';
            if (rec.includes('Referrer-Policy')) headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
            if (rec.includes('Permissions-Policy')) headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()';
            if (rec.includes('Cross-Origin-Opener-Policy')) headers['Cross-Origin-Opener-Policy'] = 'same-origin';
            if (rec.includes('Cross-Origin-Resource-Policy')) headers['Cross-Origin-Resource-Policy'] = 'same-origin';
          }

          const hasSSL = issues.some(i => i.section === 'ssl');

          // Build platform-specific config snippet
          let configSnippet = '';
          const p = args.platform;
          if (p === 'nginx') {
            const headerLines = Object.entries(headers).map(([h, v]) => `    add_header ${h} "${v}" always;`).join('\n');
            configSnippet = `server {\n    # ... your existing config ...\n\n${headerLines}\n}`;
            if (hasSSL) configSnippet += '\n\n# SSL/TLS\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;';
          } else if (p === 'apache') {
            const headerLines = Object.entries(headers).map(([h, v]) => `    Header always set ${h} "${v}"`).join('\n');
            configSnippet = `<IfModule mod_headers.c>\n${headerLines}\n</IfModule>`;
          } else if (p === 'caddy') {
            const headerLines = Object.entries(headers).map(([h, v]) => `        ${h} "${v}"`).join('\n');
            configSnippet = `header {\n${headerLines}\n}`;
          } else if (p === 'cloudflare') {
            configSnippet = Object.entries(headers).map(([h, v]) => `Set "${h}" to "${v}"`).join('\n');
          }

          const fixData = {
            url: args.url,
            platform: args.platform,
            issueCount: issues.length,
            issues: issues.map(i => ({ section: i.section, name: i.name, status: i.status, recommendation: i.recommendation })),
            headers,
            hasSSLIssues: hasSSL,
            configSnippet,
            instructions: {
              nginx: 'Add to server {} block, then: sudo nginx -t && sudo systemctl reload nginx',
              apache: 'Add to .htaccess or site config, then: sudo apachectl configtest && sudo systemctl reload apache2',
              caddy: 'Add to Caddyfile site block, then: sudo systemctl reload caddy',
              cloudflare: 'Dashboard → Rules → Transform Rules → Modify Response Header'
            }[args.platform]
          };

          return {
            content: [{
              type: 'text',
              text: JSON.stringify(fixData, null, 2)
            }]
          };
        }

        case 'get_schema': {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify(getSchema(), null, 2)
            }]
          };
        }

        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true
          };
      }
    } catch (err) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ error: err.message, code: 'ERR_SCAN' }, null, 2)
        }],
        isError: true
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

module.exports = { startMCPServer };
