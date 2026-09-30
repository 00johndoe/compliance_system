// Dependency-free end-to-end harness: a static file server + headless Chrome driven over the DevTools Protocol.
// Requires Node 22+ (global WebSocket/fetch) and a Chrome/Chromium binary (set CHROME_PATH to override).
import { spawn, execSync } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.json': 'application/json' };
// Same public surface as the backend: top-level pages/assets and /vendor only.
const PUBLIC = /^\/(?:[A-Za-z0-9_-]+(?:\.(?:html|css|js|ico))?|vendor\/[A-Za-z0-9_./-]+)$/;

export function startStaticServer() {
  const server = http.createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (p === '/') p = '/index.html';
    if (!PUBLIC.test(p) || p.includes('..')) { res.writeHead(404); return res.end('not found'); }
    let file = path.join(ROOT, p);
    if (!path.extname(file)) file += '.html';
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      res.end(data);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() })));
}

function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium-browser', '/usr/bin/chromium',
  ].filter(Boolean);
  const hit = candidates.find((c) => fs.existsSync(c));
  if (!hit) throw new Error('No Chrome/Chromium found. Set CHROME_PATH.');
  return hit;
}

// Headless Chrome's launcher can exit while the real browser keeps running outside its process tree,
// so kill every process that was started with this run's unique profile directory.
function killBrowser(proc, profile) {
  const needle = path.basename(profile);
  try {
    if (process.platform === 'win32') {
      execSync(`powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*${needle}*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"`, { stdio: 'ignore' });
    } else {
      try { process.kill(-proc.pid, 'SIGKILL'); } catch {}
      execSync(`pkill -9 -f ${needle} || true`, { stdio: 'ignore', shell: '/bin/sh' });
    }
  } catch {}
  try { proc.kill(); } catch {}
  for (let i = 0; i < 5; i++) { try { fs.rmSync(profile, { recursive: true, force: true }); break; } catch { /* still locked, retry */ } }
}

export async function launchBrowser() {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'gh-e2e-'));
  const proc = spawn(findChrome(), ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--hide-scrollbars',
    '--no-first-run', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-extensions', 'about:blank'], { stdio: 'ignore', detached: process.platform !== 'win32' });
  let version;
  for (let i = 0; i < 200 && !version; i++) { try { version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json(); } catch { await sleep(150); } }
  if (!version) { killBrowser(proc, profile); throw new Error('Chrome did not start'); }
  const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));
  const page = new Page(ws);
  await page.init();
  const close = () => { try { ws.close(); } catch {} killBrowser(proc, profile); };
  return { page, close };
}

export class Page {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map();
    this.hosts = new Set(); this.problems = [];
    ws.addEventListener('message', (m) => {
      const d = JSON.parse(m.data);
      if (d.id && this.pending.has(d.id)) { this.pending.get(d.id)(d); this.pending.delete(d.id); return; }
      if (d.method === 'Network.requestWillBeSent') { try { this.hosts.add(new URL(d.params.request.url).host); } catch {} }
      if (d.method === 'Runtime.exceptionThrown') this.problems.push('exception: ' + (d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text).slice(0, 200));
      if (d.method === 'Log.entryAdded' && (d.params.entry.level === 'error')) this.problems.push('log: ' + d.params.entry.text.slice(0, 200));
    });
  }
  send(method, params = {}) { return new Promise((res) => { const i = ++this.id; this.pending.set(i, res); this.ws.send(JSON.stringify({ id: i, method, params })); }); }
  async init() { for (const d of ['Page', 'Runtime', 'Network', 'Log']) await this.send(d + '.enable'); await this.send('Network.setCacheDisabled', { cacheDisabled: true }); }
  async eval(expression) {
    const r = await this.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (r.result?.exceptionDetails) throw new Error('eval failed: ' + (r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text) + '\n  in: ' + expression.slice(0, 160));
    return r.result?.result?.value;
  }
  async viewport(width, height = 900, reduceMotion = true) {
    await this.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: width < 768 });
    await this.send('Emulation.setEmulatedMedia', { media: 'screen', features: [{ name: 'prefers-reduced-motion', value: reduceMotion ? 'reduce' : 'no-preference' }] });
  }
  async goto(base, pathname, { width = 1280, height = 900, reduceMotion = true } = {}) {
    await this.viewport(width, height, reduceMotion);
    await this.send('Page.navigate', { url: base + pathname });
    await this.waitFor("document.readyState === 'complete'", 15000);
    await this.eval('document.fonts.ready.then(() => true)');
    await sleep(500);
    await this.eval("document.documentElement.style.scrollBehavior = 'auto'; true");
  }
  async waitFor(expression, timeout = 6000, interval = 100) {
    const end = Date.now() + timeout;
    let last;
    while (Date.now() < end) { try { last = await this.eval(expression); } catch { last = false; } if (last) return last; await sleep(interval); }
    throw new Error(`timed out waiting for: ${expression.slice(0, 140)} (last=${JSON.stringify(last)})`);
  }
  async key(key, code = key, vk = 0) {
    await this.send('Input.dispatchKeyEvent', { type: 'keyDown', key, code, windowsVirtualKeyCode: vk, text: key.length === 1 ? key : undefined });
    await this.send('Input.dispatchKeyEvent', { type: 'keyUp', key, code, windowsVirtualKeyCode: vk });
    await sleep(120);
  }
  async mouseClick(x, y) {
    await this.send('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1 });
    await this.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1 });
    await sleep(200);
  }
  // Store a completed assessment the way assessment.html does (deterministic data for the report/dashboard tests).
  async seedAssessment(base, data) {
    await this.goto(base, '/index.html');
    await this.eval(`localStorage.clear(); localStorage.setItem('assessmentData', JSON.stringify(${JSON.stringify(data)})); true`);
  }
}

// ---- tiny test runner ----
const tests = [];
export const test = (name, fn) => tests.push({ name, fn });
export function expect(cond, msg) { if (!cond) throw new Error(msg || 'expectation failed'); }
export function eq(actual, expected, msg) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a !== e) throw new Error(`${msg || 'not equal'}\n    expected: ${e}\n    actual:   ${a}`);
}
export async function runAll(ctx, filter) {
  let passed = 0, failed = 0;
  for (const t of tests) {
    if (filter && !t.name.toLowerCase().includes(filter.toLowerCase())) continue;
    const started = Date.now();
    try { await t.fn(ctx); passed++; console.log(`  \u2713 ${t.name} (${Date.now() - started}ms)`); }
    catch (e) { failed++; console.log(`  \u2717 ${t.name}\n    ${String(e.message).replace(/\n/g, '\n    ')}`); }
  }
  return { passed, failed };
}
