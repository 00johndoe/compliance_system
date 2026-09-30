'use strict';

/**
 * Seeds / upserts the reference data (frameworks) into MongoDB. Idempotent — safe to run repeatedly. Existing
 * assessments are never touched.
 *
 * Usage:
 *   node src/seed.js          (standalone; connects + disconnects)
 *   require('./seed').seed()  (programmatic; assumes an open connection)
 */

const Framework = require('./models/Framework');
const mongoose = require('mongoose');
const { GHANA_REQUIREMENTS, ISO27002 } = require('./data/frameworks');

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
  const docs = [toFrameworkDoc(GHANA_REQUIREMENTS), toFrameworkDoc(ISO27002)];
  for (const doc of docs) {
    await Framework.findOneAndUpdate({ key: doc.key }, doc, { upsert: true, new: true });
  }
  return docs.length;
}

/**
 * Mappings and gap analysis are now derived from the requirements dataset at
 * request time, so the old stored copies (built for the retired NCF control
 * set (the earlier, unofficial Ghana control list)) are removed. They are reference data only; assessments are untouched.
 */
async function dropLegacyCollections() {
  const existing = (await mongoose.connection.db.listCollections().toArray()).map((c) => c.name);
  let dropped = 0;
  for (const name of ['mappings', 'gap_analysis']) {
    if (existing.includes(name)) {
      await mongoose.connection.db.dropCollection(name);
      dropped += 1;
    }
  }
  return dropped;
}

/** Upserts all reference data. Assumes an active mongoose connection. */
async function seed({ quiet = false } = {}) {
  const frameworks = await seedFrameworks();
  const legacyDropped = await dropLegacyCollections();
  if (!quiet) {
    console.log(`  [seed] frameworks: ${frameworks}, legacy collections removed: ${legacyDropped}`);
  }
  return { frameworks, legacyDropped };
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
