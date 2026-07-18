'use strict';

/**
 * Seeds / upserts the reference data (frameworks, control mappings, gap
 * analysis) into MongoDB. Idempotent — safe to run repeatedly. Existing
 * assessments are never touched.
 *
 * Usage:
 *   node src/seed.js          (standalone; connects + disconnects)
 *   require('./seed').seed()  (programmatic; assumes an open connection)
 */

const Framework = require('./models/Framework');
const Mapping = require('./models/Mapping');
const GapAnalysis = require('./models/GapAnalysis');
const { GHANA_NCF, ISO27002 } = require('./data/frameworks');
const { CONTROL_MAPPING } = require('./data/mapping');
const { GAP_ANALYSIS } = require('./data/gaps');

function toFrameworkDoc(fw) {
  return {
    key: fw.key,
    name: fw.name,
    version: fw.version,
    groupLabel: fw.groupLabel,
    groups: fw.domains || fw.themes || [],
  };
}

async function seedFrameworks() {
  const docs = [toFrameworkDoc(GHANA_NCF), toFrameworkDoc(ISO27002)];
  for (const doc of docs) {
    await Framework.findOneAndUpdate({ key: doc.key }, doc, { upsert: true, new: true });
  }
  return docs.length;
}

async function seedMappings() {
  const ops = CONTROL_MAPPING.map((m) => ({
    updateOne: {
      filter: { ncf: m.ncf, iso: m.iso },
      update: { $set: m },
      upsert: true,
    },
  }));
  if (ops.length) await Mapping.bulkWrite(ops, { ordered: false });
  return ops.length;
}

async function seedGaps() {
  await GapAnalysis.findOneAndUpdate(
    { key: 'default' },
    { key: 'default', ...GAP_ANALYSIS },
    { upsert: true, new: true }
  );
  return 1;
}

/** Upserts all reference data. Assumes an active mongoose connection. */
async function seed({ quiet = false } = {}) {
  const [frameworks, mappings, gaps] = [await seedFrameworks(), await seedMappings(), await seedGaps()];
  if (!quiet) {
    console.log(`  [seed] frameworks: ${frameworks}, mappings: ${mappings}, gap-analysis: ${gaps}`);
  }
  return { frameworks, mappings, gaps };
}

// Standalone execution
if (require.main === module) {
  (async () => {
    const { connectDB, disconnectDB } = require('./config/db');
    try {
      const uri = await connectDB();
      console.log(`  [seed] connected: ${uri.replace(/\/\/[^@]*@/, '//***@')}`);
      await seed();
      console.log('  [seed] done.');
      await disconnectDB();
      process.exit(0);
    } catch (err) {
      console.error('  [seed] failed:', err);
      process.exit(1);
    }
  })();
}

module.exports = { seed };
