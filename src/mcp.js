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
          const results = await scan(args.url, {
            timeout: (args.timeout || 10) * 1000,
            tier: license.tier,
            full: false
          });
          
          recordScan();

          // Strip ANSI for MCP output
          const chalk = require('chalk');
          const origLevel = chalk.level;
          chalk.level = 0;
          const fixes = generateFixes(args.platform, results);
          chalk.level = origLevel;

          return {
            content: [{
              type: 'text',
              text: fixes
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
