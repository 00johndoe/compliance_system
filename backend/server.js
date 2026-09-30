'use strict';

const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const env = require('./src/config/env');
const { connectDB, disconnectDB } = require('./src/config/db');
const { seed } = require('./src/seed');
const apiRoutes = require('./src/routes');
const { notFound, errorHandler } = require('./src/middleware/errorHandler');

// The existing (unchanged) HTML/CSS/JS frontend lives one level above /backend.
const FRONTEND_DIR = path.resolve(__dirname, '..');

// ─── Express application ───
const app = express();
app.disable('x-powered-by');

// Security headers. Every front-end asset is self-hosted (see /vendor), so the
// Content-Security-Policy only allows same-origin resources: no third-party
// scripts, styles, fonts or connections. 'unsafe-inline' remains for scripts and
// styles because the pages use inline <script>, onclick="" handlers and
// style="" attributes; moving those out is a separate refactor, after which
// nonces/hashes can replace it. No 'unsafe-eval'.
const isProd = env.NODE_ENV === 'production';
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'"],
        'connect-src': ["'self'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        ...(isProd ? { 'upgrade-insecure-requests': [] } : {}),
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false,
  })
);

// CORS
app.use(
  cors(
    env.CORS_ORIGIN === '*'
      ? { origin: '*' }
      : { origin: env.CORS_ORIGIN.split(',').map((s) => s.trim()) }
  )
);

// Body parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
if (env.NODE_ENV !== 'test') {
  app.use(morgan(env.NODE_ENV === 'production' ? 'combined' : 'dev'));
}

// ─── API routes ───
app.use('/api', apiRoutes);
app.use('/api', notFound); // JSON 404 for unmatched /api routes

// ─── Static frontend ───
// FRONTEND_DIR is the repository root, so serving it wholesale would also publish
// /backend/*, server.py, docs/ and anything else next to the pages. Serve only the
// public front-end files: top-level .html/.css/.js/.ico (and extensionless page
// names such as /mapping) plus the /vendor assets.
const PUBLIC_PATH = /^\/(?:[A-Za-z0-9_-]+(?:\.(?:html|css|js|ico|png|svg|webmanifest|txt))?|vendor\/[A-Za-z0-9_./-]+)$/;
const frontend = express.static(FRONTEND_DIR, { extensions: ['html'], index: 'index.html', dotfiles: 'ignore' });
app.use((req, res, next) => (PUBLIC_PATH.test(req.path) && !req.path.includes('..') ? frontend(req, res, next) : next()));
app.get('/', (req, res) => res.sendFile(path.join(FRONTEND_DIR, 'index.html')));

// ─── Error handling ───
app.use(errorHandler);

// ─── Bootstrap: DB → seed → listen → graceful shutdown ───
async function start() {
  const banner = '='.repeat(60);
  console.log(`\n${banner}`);
  console.log('  Ghana NCF vs ISO/IEC 27002 Compliance System');
  console.log(banner);

  const uri = await connectDB();
  console.log(`  [db] connected!`);

  if (env.SEED_ON_START) {
    await seed();
  }

  const server = app.listen(env.PORT, () => {
    console.log(`  [http] server running at http://localhost:${env.PORT}`);
    console.log(`  [http] API base:          http://localhost:${env.PORT}/api`);
    console.log(`${banner}\n`);
  });

  async function shutdown(signal) {
    console.log(`\n  [sys] ${signal} received, shutting down...`);
    server.close(async () => {
      await disconnectDB();
      console.log('  [sys] closed cleanly.');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  }

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

start().catch((err) => {
  console.error('\n  [fatal] failed to start:', err.message);
  console.error(err);
  process.exit(1);
});

// Exported for testing / programmatic use.
module.exports = app;
