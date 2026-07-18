'use strict';

const mongoose = require('mongoose');

const mappingSchema = new mongoose.Schema(
  {
    ncf: { type: String, required: true, index: true },
    iso: { type: String, required: true, index: true },
    alignment: {
      type: String,
      enum: ['Strong', 'Moderate', 'Partial'],
      required: true,
    },
    notes: { type: String, default: '' },
  },
  { timestamps: true, collection: 'mappings' }
);

mappingSchema.index({ ncf: 1, iso: 1 }, { unique: true });

module.exports = mongoose.model('Mapping', mappingSchema);
