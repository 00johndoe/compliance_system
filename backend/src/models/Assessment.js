'use strict';

const mongoose = require('mongoose');
const crypto = require('crypto');

const organizationSchema = new mongoose.Schema(
  {
    name: { type: String, default: '' },
    sector: { type: String, default: '' },
    size: { type: String, default: '' },
    email: { type: String, default: '' },
  },
  { _id: false }
);

const controlResultSchema = new mongoose.Schema(
  {
    id: String,
    title: String,
    maturity: Number,
    score: Number,
    weight: Number,
  },
  { _id: false }
);

const domainScoreSchema = new mongoose.Schema(
  {
    id: String,
    name: String,
    score: Number,
    controls: { type: [controlResultSchema], default: [] },
  },
  { _id: false }
);

const frameworkScoreSchema = new mongoose.Schema(
  {
    overall: Number,
    domains: { type: [domainScoreSchema], default: [] },
  },
  { _id: false }
);

const responseItemSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    maturity: { type: Number, default: 0 },
  },
  { _id: false }
);

const recommendationSchema = new mongoose.Schema(
  {
    priority: { type: String, enum: ['Critical', 'High', 'Medium', 'Low'] },
    control: String,
    title: String,
    current_score: Number,
    target_score: Number,
    recommendation: String,
  },
  { _id: false }
);

const assessmentSchema = new mongoose.Schema(
  {
    // Short public id (matches the original 8-char uuid style).
    assessmentId: {
      type: String,
      required: true,
      unique: true,
      index: true,
      default: () => crypto.randomUUID().slice(0, 8),
    },
    organization: { type: organizationSchema, default: () => ({}) },
    date: { type: Date, default: Date.now },
    ghana_scores: { type: frameworkScoreSchema, required: true },
    iso_scores: { type: frameworkScoreSchema, required: true },
    recommendations: { type: [recommendationSchema], default: [] },
    alignment_score: Number,
    ghana_maturity: String,
    iso_maturity: String,
    // Raw responses retained (as [{id, maturity}]) so a report can be
    // regenerated / audited. Stored as an array rather than a Map because ISO
    // control ids contain dots, which are invalid Mongoose Map keys.
    ghana_responses: { type: [responseItemSchema], default: [] },
    iso_responses: { type: [responseItemSchema], default: [] },
  },
  { timestamps: true, collection: 'assessments' }
);

/**
 * Full detail payload — matches the original /api/assess response shape,
 * with `id` as the short assessment id.
 */
assessmentSchema.methods.toApi = function toApi() {
  return {
    id: this.assessmentId,
    organization: this.organization,
    date: this.date instanceof Date ? this.date.toISOString() : this.date,
    ghana_scores: this.ghana_scores,
    iso_scores: this.iso_scores,
    recommendations: this.recommendations,
    alignment_score: this.alignment_score,
    ghana_maturity: this.ghana_maturity,
    iso_maturity: this.iso_maturity,
  };
};

/** Compact summary used by the list endpoint. */
assessmentSchema.methods.toSummary = function toSummary() {
  return {
    id: this.assessmentId,
    organization: this.organization,
    date: this.date instanceof Date ? this.date.toISOString() : this.date,
    ghana_score: this.ghana_scores ? this.ghana_scores.overall : 0,
    iso_score: this.iso_scores ? this.iso_scores.overall : 0,
    alignment_score: this.alignment_score,
  };
};

module.exports = mongoose.model('Assessment', assessmentSchema);
