'use strict';

const mongoose = require('mongoose');

const uniqueItemSchema = new mongoose.Schema(
  {
    control: { type: String, required: true },
    title: { type: String, required: true },
    reason: { type: String, required: true },
  },
  { _id: false }
);

const structuralSchema = new mongoose.Schema(
  {
    aspect: { type: String, required: true },
    ghana: { type: String, required: true },
    iso: { type: String, required: true },
  },
  { _id: false }
);

const gapAnalysisSchema = new mongoose.Schema(
  {
    // Singleton document keyed by a stable slug.
    key: { type: String, required: true, unique: true, default: 'default' },
    ghana_unique: { type: [uniqueItemSchema], default: [] },
    iso_unique: { type: [uniqueItemSchema], default: [] },
    structural_comparison: { type: [structuralSchema], default: [] },
  },
  { timestamps: true, collection: 'gap_analysis' }
);

gapAnalysisSchema.methods.toApi = function toApi() {
  return {
    ghana_unique: this.ghana_unique.map((x) => ({ control: x.control, title: x.title, reason: x.reason })),
    iso_unique: this.iso_unique.map((x) => ({ control: x.control, title: x.title, reason: x.reason })),
    structural_comparison: this.structural_comparison.map((x) => ({ aspect: x.aspect, ghana: x.ghana, iso: x.iso })),
  };
};

module.exports = mongoose.model('GapAnalysis', gapAnalysisSchema);
