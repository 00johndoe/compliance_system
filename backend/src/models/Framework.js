'use strict';

const mongoose = require('mongoose');

const controlSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    title: { type: String, required: true },
    description: { type: String, default: '' },
    weight: { type: Number, required: true, min: 1, max: 5 },
  },
  { _id: false }
);

const groupSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    name: { type: String, required: true },
    controls: { type: [controlSchema], default: [] },
  },
  { _id: false }
);

const frameworkSchema = new mongoose.Schema(
  {
    // 'ghana' | 'iso27002'
    key: { type: String, required: true, unique: true, index: true },
    name: { type: String, required: true },
    version: { type: String, required: true },
    // Whether the top-level grouping is called 'domains' or 'themes'.
    groupLabel: { type: String, enum: ['domains', 'themes'], required: true },
    groups: { type: [groupSchema], default: [] },
  },
  { timestamps: true, collection: 'frameworks' }
);

/**
 * Serialize back to the exact shape the original API returned, i.e. with the
 * grouping key named "domains" (Ghana) or "themes" (ISO).
 */
frameworkSchema.methods.toApi = function toApi() {
  return {
    name: this.name,
    version: this.version,
    [this.groupLabel]: this.groups.map((g) => ({
      id: g.id,
      name: g.name,
      controls: g.controls.map((c) => ({
        id: c.id,
        title: c.title,
        ...(c.description ? { description: c.description } : {}),
        weight: c.weight,
      })),
    })),
  };
};

module.exports = mongoose.model('Framework', frameworkSchema);
