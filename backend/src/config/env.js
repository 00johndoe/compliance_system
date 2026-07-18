'use strict';

const path = require('path');
const dotenv = require('dotenv');

// backend/ root (this file lives at backend/src/config/env.js)
const ROOT = path.resolve(__dirname, '..', '..');

// Load `.env.local` first so it takes precedence, then `.env` as a fallback.
// dotenv does not override already-set variables, so earlier files win.
dotenv.config({ path: path.join(ROOT, '.env.local') });
dotenv.config({ path: path.join(ROOT, '.env') });

function bool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

const env = {
  PORT: parseInt(process.env.PORT, 10) || 8000,
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/compliance_system',
  USE_MEMORY_DB: bool(process.env.USE_MEMORY_DB, false),
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
  SEED_ON_START: bool(process.env.SEED_ON_START, true),
  NODE_ENV: process.env.NODE_ENV || 'development',
};

module.exports = env;
