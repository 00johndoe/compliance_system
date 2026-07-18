'use strict';

const env = require('../config/env');

/** 404 handler for unmatched /api routes. */
function notFound(req, res) {
  res.status(404).json({ error: 'Not found', path: req.originalUrl });
}

/** Centralized error handler. */
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  const status = err.status || err.statusCode || 500;

  // Mongoose validation / cast errors -> 400
  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: 'Validation failed', details: err.message });
  }
  if (err.name === 'CastError') {
    return res.status(400).json({ error: 'Invalid identifier', details: err.message });
  }

  if (status >= 500) {
    console.error('  [error]', err);
  }

  res.status(status).json({
    error: err.message || 'Internal server error',
    ...(env.NODE_ENV !== 'production' && status >= 500 ? { stack: err.stack } : {}),
  });
}

module.exports = { notFound, errorHandler };
