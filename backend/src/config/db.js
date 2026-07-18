'use strict';

const mongoose = require('mongoose');
const env = require('./env');

let memoryServer = null;

/**
 * Connects to MongoDB.
 *
 * - If USE_MEMORY_DB is true, boots an ephemeral in-memory MongoDB using
 *   mongodb-memory-server (zero external setup, data is NOT persisted).
 * - Otherwise connects to MONGODB_URI.
 *
 * Returns the resolved connection URI so callers can log it.
 */
async function connectDB() {
  mongoose.set('strictQuery', true);

  let uri = env.MONGODB_URI;

  if (env.USE_MEMORY_DB) {
    // Lazily required so it is only needed when explicitly enabled.
    const { MongoMemoryServer } = require('mongodb-memory-server');
    memoryServer = await MongoMemoryServer.create();
    uri = memoryServer.getUri('compliance_system');
    console.log('  [db] Using in-memory MongoDB (mongodb-memory-server)');
  }

  mongoose.connection.on('error', (err) => {
    console.error('  [db] connection error:', err.message);
  });
  mongoose.connection.on('disconnected', () => {
    console.warn('  [db] disconnected');
  });

  await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 8000,
  });

  return uri;
}

async function disconnectDB() {
  await mongoose.disconnect();
  if (memoryServer) {
    await memoryServer.stop();
    memoryServer = null;
  }
}

module.exports = { connectDB, disconnectDB };
