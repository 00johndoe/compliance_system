'use strict';

/**
 * Allowed organization field values. These mirror the <select> options in the
 * frontend assessment form so client and server validation agree.
 */
const SECTORS = [
  'Financial Services',
  'Telecommunications',
  'Healthcare',
  'Government',
  'Education',
  'Energy',
  'Other',
];

const SIZES = [
  'Small (1-50)',
  'Medium (51-250)',
  'Large (251-1000)',
  'Enterprise (1000+)',
];

module.exports = { SECTORS, SIZES };
