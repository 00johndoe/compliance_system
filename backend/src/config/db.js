'use strict';

const dns = require('dns');
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

  // On some Windows setups, Node's built-in resolver (c-ares) fails to pick
  // up the OS DNS servers and silently falls back to 127.0.0.1, where
  // nothing is listening. That breaks the SRV/TXT lookups a mongodb+srv://
  // URI needs (ECONNREFUSED on querySrv/queryTxt), even though normal
  // hostname lookups still work via the OS resolver. Force known-good
  // public resolvers before connecting so this doesn't depend on the
  // machine's DNS configuration.
  if (uri.startsWith('mongodb+srv://')) {
    dns.setServers(['8.8.8.8', '1.1.1.1']);
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
