'use strict';

const express = require('express');
const mongoose = require('mongoose');
const ref = require('../controllers/referenceController');
const assess = require('../controllers/assessmentController');
const validate = require('../middleware/validate');
const {
  createAssessmentRules,
  reportRules,
  idParamRules,
} = require('../validators/assessmentValidators');

const router = express.Router();

// ─── Health ───
router.get('/health', (req, res) => {
  const states = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  res.json({
    status: 'ok',
    service: 'gh-cybercomply-backend',
    db: states[mongoose.connection.readyState] || 'unknown',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// ─── Reference data ───
router.get('/frameworks', ref.listFrameworks);
router.get('/frameworks/ghana', ref.getGhana);
router.get('/frameworks/iso27002', ref.getIso);
router.get('/mapping', ref.getMapping);
router.get('/gaps', ref.getGaps);

// ─── Assessments ───
router.post('/assess', createAssessmentRules, validate, assess.createAssessment);
router.get('/assessments', assess.listAssessments);
router.get('/assessments/:id', idParamRules, validate, assess.getAssessment);
router.delete('/assessments/:id', idParamRules, validate, assess.deleteAssessment);
router.post('/report', reportRules, validate, assess.getReport);

module.exports = router;
