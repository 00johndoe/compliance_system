// Usage: node tests/e2e/run.mjs [name-filter]
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import { startStaticServer, launchBrowser, runAll } from './harness.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.test.mjs')).sort()) await import(pathToFileURL(path.join(dir, f)).href);

const server = await startStaticServer();
const { page, close } = await launchBrowser();
console.log(`\nEnd-to-end tests against ${server.url}\n`);
const started = Date.now();
let result;
try { result = await runAll({ page, base: server.url }, process.argv[2]); }
finally { close(); server.close(); }
console.log(`\n${result.passed} passed, ${result.failed} failed (${((Date.now() - started) / 1000).toFixed(1)}s)\n`);
process.exit(result.failed ? 1 : 0);
