'use strict';

const { validationResult } = require('express-validator');

/**
 * Runs after a set of express-validator chains. If any failed, responds with a
 * 400 and a structured list of field errors; otherwise passes control on.
 */
module.exports = function validate(req, res, next) {
  const result = validationResult(req);
  if (result.isEmpty()) return next();

  const details = result.array().map((e) => ({
    field: e.path || e.param,
    message: e.msg,
  }));

  return res.status(400).json({ error: 'Validation failed', details });
};
