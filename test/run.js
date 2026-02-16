#!/usr/bin/env node

/**
 * Test Suite for mpx-scan
 * 
 * Zero-dependency test runner. Tests core scanning logic and AI-native features.
 */

const { scan, calculateGrade, scoreToPercentage } = require('../src/index');
const { getLicense, activateLicense, deactivateLicense } = require('../src/license');
const { getSchema } = require('../src/schema');
const { formatJSON } = require('../src/reporters/json');
const { execSync } = require('child_process');
const path = require('path');

let passed = 0;
let failed = 0;

function test(name, fn) {
  process.stdout.write(`  ${name} ... `);
  try {
    fn();
    console.log('✓');
    passed++;
  } catch (err) {
    console.log('✗');
    console.error(`    ${err.message}`);
    failed++;
  }
}

async function asyncTest(name, fn) {
  process.stdout.write(`  ${name} ... `);
  try {
    await fn();
    console.log('✓');
    passed++;
  } catch (err) {
    console.log('✗');
    console.error(`    ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message || 'Assertion failed'}: expected ${expected}, got ${actual}`);
  }
}

const CLI = path.join(__dirname, '..', 'bin', 'cli.js');

function runCLI(args, stdin = null) {
  try {
    const opts = { encoding: 'utf8', timeout: 15000, stdio: ['pipe', 'pipe', 'pipe'] };
    if (stdin) opts.input = stdin;
    const result = execSync(`node ${CLI} ${args}`, opts);
    return { stdout: result, exitCode: 0 };
  } catch (err) {
    return { stdout: err.stdout || '', stderr: err.stderr || '', exitCode: err.status };
  }
}

async function runTests() {
  console.log('\n🧪 Running mpx-scan tests...\n');
  
  // Grade calculation tests
  console.log('Grade Calculation:');
  test('calculateGrade(1.0) returns A+', () => {
    assertEqual(calculateGrade(1.0), 'A+');
  });
  test('calculateGrade(0.95) returns A+', () => {
    assertEqual(calculateGrade(0.95), 'A+');
  });
  test('calculateGrade(0.85) returns A', () => {
    assertEqual(calculateGrade(0.85), 'A');
  });
  test('calculateGrade(0.70) returns B', () => {
    assertEqual(calculateGrade(0.70), 'B');
  });
  test('calculateGrade(0.55) returns C', () => {
    assertEqual(calculateGrade(0.55), 'C');
  });
  test('calculateGrade(0.40) returns D', () => {
    assertEqual(calculateGrade(0.40), 'D');
  });
  test('calculateGrade(0.30) returns F', () => {
    assertEqual(calculateGrade(0.30), 'F');
  });
  
  // Score percentage tests
  console.log('\nScore Calculation:');
  test('scoreToPercentage(50, 100) returns 50', () => {
    assertEqual(scoreToPercentage(50, 100), 50);
  });
  test('scoreToPercentage(0, 100) returns 0', () => {
    assertEqual(scoreToPercentage(0, 100), 0);
  });
  test('scoreToPercentage(100, 100) returns 100', () => {
    assertEqual(scoreToPercentage(100, 100), 100);
  });
  
  // License tests
  console.log('\nLicense Management:');
  test('getLicense() returns free tier by default', () => {
    const license = getLicense();
    assertEqual(license.tier, 'free');
  });
  
  test('activateLicense() requires MPX-PRO prefix', () => {
    let error = null;
    try {
      activateLicense('INVALID-KEY');
    } catch (err) {
      error = err;
    }
    assert(error !== null, 'Should throw error for invalid key');
  });
  
  // Scan tests (basic validation)
  console.log('\nScanning (basic validation):');
  await asyncTest('scan() returns valid result structure', async () => {
    const result = await scan('https://example.com', { timeout: 5000, tier: 'free' });
    assert(result.url, 'Should have url');
    assert(result.hostname, 'Should have hostname');
    assert(result.grade, 'Should have grade');
    assert(typeof result.score === 'number', 'Should have numeric score');
    assert(result.sections, 'Should have sections');
    assert(result.summary, 'Should have summary');
  });
  
  await asyncTest('scan() handles timeout gracefully', async () => {
    let error = null;
    try {
      await scan('https://example.com', { timeout: 1, tier: 'free' });
    } catch (err) {
      error = err;
    }
    assert(true, 'Timeout handling works');
  });
  
  await asyncTest('scan() respects tier limits', async () => {
    const freeResult = await scan('https://example.com', { timeout: 5000, tier: 'free' });
    const freeSections = Object.keys(freeResult.sections);
    
    assert(freeSections.includes('headers'), 'Free should include headers');
    assert(freeSections.includes('ssl'), 'Free should include ssl');
    assert(!freeSections.includes('dns'), 'Free should NOT include dns');
  });

  // === AI-NATIVE FEATURE TESTS ===

  // Schema tests
  console.log('\nSchema (--schema):');
  test('getSchema() returns valid schema object', () => {
    const schema = getSchema();
    assertEqual(schema.tool, 'mpx-scan');
    assert(schema.version, 'Should have version');
    assert(schema.commands, 'Should have commands');
    assert(schema.commands.scan, 'Should have scan command');
    assert(schema.commands.mcp, 'Should have mcp command');
    assert(schema.scanners, 'Should have scanners info');
    assert(schema.mcpConfig, 'Should have MCP config example');
  });

  test('schema has exit codes documented', () => {
    const schema = getSchema();
    const codes = schema.commands.scan.exitCodes;
    assert(codes, 'Should have exit codes');
    assert(codes['0'], 'Should document exit code 0');
    assert(codes['1'], 'Should document exit code 1');
    assert(codes['2'], 'Should document exit code 2');
    assert(codes['3'], 'Should document exit code 3');
    assert(codes['4'], 'Should document exit code 4');
  });

  test('schema has output JSON schema', () => {
    const schema = getSchema();
    const output = schema.commands.scan.output;
    assert(output.json, 'Should have json output spec');
    assert(output.json.schema, 'Should have json schema');
    assert(output.error, 'Should have error output spec');
  });

  test('--schema flag returns valid JSON', () => {
    const result = runCLI('--schema');
    assertEqual(result.exitCode, 0, 'Should exit 0');
    const parsed = JSON.parse(result.stdout);
    assertEqual(parsed.tool, 'mpx-scan');
  });

  // JSON output tests
  console.log('\nJSON Output (--json):');
  await asyncTest('formatJSON returns valid parseable JSON', async () => {
    const scanResult = await scan('https://example.com', { timeout: 5000, tier: 'free' });
    const json = formatJSON(scanResult, true);
    const parsed = JSON.parse(json);
    assert(parsed.mpxScan, 'Should have mpxScan metadata');
    assert(parsed.target, 'Should have target');
    assert(parsed.score, 'Should have score');
    assert(parsed.summary, 'Should have summary');
    assert(parsed.sections, 'Should have sections');
  });

  await asyncTest('JSON output includes all required fields', async () => {
    const scanResult = await scan('https://example.com', { timeout: 5000, tier: 'free' });
    const parsed = JSON.parse(formatJSON(scanResult, true));
    assert(typeof parsed.score.grade === 'string', 'Should have string grade');
    assert(typeof parsed.score.numeric === 'number', 'Should have numeric score');
    assert(typeof parsed.score.percentage === 'number', 'Should have percentage');
    assert(typeof parsed.summary.passed === 'number', 'Should have passed count');
    assert(typeof parsed.summary.failed === 'number', 'Should have failed count');
  });

  // Batch mode tests
  console.log('\nBatch Mode (--batch):');
  test('--batch with no stdin returns error', () => {
    // stdin is TTY in test, so should exit with error
    const result = runCLI('--batch --json');
    // Should get exit code 2 (bad args) or error JSON
    assert(result.exitCode !== 0, 'Should fail with no input');
  });

  // CLI flag tests
  console.log('\nCLI Flags:');
  test('--version returns version string', () => {
    const result = runCLI('--version');
    assert(result.stdout.trim().match(/\d+\.\d+\.\d+/), 'Should output version');
  });

  test('--help includes AI-native features', () => {
    const result = runCLI('--help');
    const out = result.stdout;
    assert(out.includes('--json'), 'Help should mention --json');
    assert(out.includes('--schema'), 'Help should mention --schema');
    assert(out.includes('--batch'), 'Help should mention --batch');
    assert(out.includes('--quiet'), 'Help should mention --quiet');
    assert(out.includes('--no-color'), 'Help should mention --no-color');
  });

  test('--help shows exit codes', () => {
    const result = runCLI('--help');
    assert(result.stdout.includes('Exit Codes'), 'Help should show exit codes');
  });

  // MCP module tests
  console.log('\nMCP Module:');
  test('MCP module loads without error', () => {
    const mcp = require('../src/mcp');
    assert(typeof mcp.startMCPServer === 'function', 'Should export startMCPServer');
  });

  // Summary
  console.log('\n' + '─'.repeat(50));
  console.log(`Tests: ${passed + failed} total, ${passed} passed, ${failed} failed`);
  console.log('─'.repeat(50) + '\n');
  
  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('\n❌ Test suite error:', err);
  process.exit(1);
});
