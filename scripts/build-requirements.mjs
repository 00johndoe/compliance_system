// Generates gh-requirements.js (browser copy) from data/ghana-requirements.json (the single source of truth).
//   node scripts/build-requirements.mjs          write the file
//   node scripts/build-requirements.mjs --check  exit 1 if the file is out of date (used by CI)
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const data = JSON.parse(readFileSync(join(root, 'data', 'ghana-requirements.json'), 'utf8'));

// ISO/IEC 27002 control list for the browser, taken from the backend reference data so both agree.
const { ISO27002 } = createRequire(import.meta.url)(join(root, 'backend', 'src', 'data', 'frameworks.js'));
data.iso = ISO27002.themes.flatMap((t) =>
  t.controls.map((c) => ({ id: c.id, title: c.title, theme: t.name.replace(/ Controls$/, '') }))
);
const isoIds = new Set(data.iso.map((c) => c.id));

const ids = new Set();
const groupIds = new Set(data.groups.map((g) => g.id));
const tierIds = new Set(data.tiers.map((t) => t.id));
for (const r of data.requirements) {
  if (ids.has(r.id)) throw new Error('duplicate id ' + r.id);
  ids.add(r.id);
  if (!groupIds.has(r.group)) throw new Error(r.id + ': unknown group ' + r.group);
  if (!tierIds.has(r.tier)) throw new Error(r.id + ': unknown tier ' + r.tier);
  for (const l of r.iso27002Links) if (!isoIds.has(l)) throw new Error(r.id + ': unknown ISO control ' + l);
  for (const f of ['title', 'requirement', 'source', 'assessmentQuestion']) {
    if (!r[f]) throw new Error(r.id + ': missing ' + f);
  }
}

const out =
  '/* GENERATED from data/ghana-requirements.json by scripts/build-requirements.mjs - do not edit by hand. */\n' +
  'window.GHRequirements = ' + JSON.stringify(data) + ';\n';

const target = join(root, 'gh-requirements.js');
if (process.argv.includes('--check')) {
  if (!existsSync(target) || readFileSync(target, 'utf8') !== out) {
    console.error('gh-requirements.js is out of date. Run: node scripts/build-requirements.mjs');
    process.exit(1);
  }
  console.log('gh-requirements.js is up to date (' + data.requirements.length + ' requirements)');
} else {
  writeFileSync(target, out);
  console.log('wrote gh-requirements.js (' + data.requirements.length + ' requirements)');
}
