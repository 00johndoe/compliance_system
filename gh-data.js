/* GH-CYBERCOMPLY — shared, browser-only assessment data helpers.
   Everything lives in this browser's localStorage; nothing is sent anywhere.

   Scoring mirrors results.html exactly (same formulas and labels) so the
   dashboard and the report can never disagree:
     domain % = round(mean(answers) / 5 * 100)
     NCF % / ISO % = round(mean of all answers in that framework / 5 * 100)
     overall % = round((NCF % + ISO %) / 2)

   Keys:
     assessmentData     latest completed assessment (written by assessment.html, read by results.html)
     assessmentHistory  compact summaries of completed assessments (newest last, max 20)
     assessmentDraft    in-progress answers, so an unfinished assessment can be resumed
*/
(function (w) {
  'use strict';

  var K_DATA = 'assessmentData', K_HIST = 'assessmentHistory', K_DRAFT = 'assessmentDraft';
  var MAX_HISTORY = 20;
  var MATURITY = ['Non-existent', 'Initial', 'Repeatable', 'Defined', 'Managed', 'Optimized'];

  function read(k) { try { return JSON.parse(localStorage.getItem(k) || 'null'); } catch (e) { return null; } }
  function write(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } }
  function remove(k) { try { localStorage.removeItem(k); } catch (e) { /* storage unavailable */ } }

  function level(p) { return p >= 100 ? 5 : Math.min(5, Math.max(0, Math.floor(p / 20))); }
  function risk(p) { return p >= 75 ? 'Compliant' : p >= 50 ? 'Moderate' : p >= 25 ? 'Needs Improvement' : 'Critical'; }
  function color(p) { return p >= 80 ? '#22c55e' : p >= 60 ? '#38bdf8' : p >= 40 ? '#f59e0b' : p >= 20 ? '#f97316' : '#ef4444'; }

  function mean(obj) {
    var v = Object.keys(obj || {}).map(function (k) { return Number(obj[k]) || 0; });
    return v.length ? v.reduce(function (s, x) { return s + x; }, 0) / v.length : 0;
  }

  // Keys look like "ncf_Governance_&_Leadership_0" -> domain "Governance & Leadership"
  function domainScores(obj, framework) {
    var groups = {};
    Object.keys(obj || {}).forEach(function (key) {
      var name = key.split('_').slice(1, -1).join(' ').trim();
      var n = Number(obj[key]);
      if (!name || !(n >= 0)) return;
      (groups[name] = groups[name] || []).push(n);
    });
    return Object.keys(groups).map(function (name) {
      var avg = groups[name].reduce(function (s, x) { return s + x; }, 0) / groups[name].length;
      return { domain: name, framework: framework, pct: Math.round((avg / 5) * 100) };
    });
  }

  function summarize(data) {
    if (!data || typeof data !== 'object') return null;
    var ncfPct = Math.round((mean(data.ncf) / 5) * 100);
    var isoPct = Math.round((mean(data.iso) / 5) * 100);
    var overall = Math.round((ncfPct + isoPct) / 2);
    return {
      org: (data.organization && data.organization.name) ? String(data.organization.name) : '',
      timestamp: data.timestamp || '',
      ncfPct: ncfPct, isoPct: isoPct, overallPct: overall,
      maturity: MATURITY[level(overall)], risk: risk(overall),
      domains: domainScores(data.ncf, 'Ghana NCF').concat(domainScores(data.iso, 'ISO 27002'))
    };
  }

  function loadLatest() {
    var d = read(K_DATA);
    if (!d || !d.ncf || !d.iso) return null;
    return summarize(d);
  }

  function loadHistory() {
    var h = read(K_HIST);
    if (!Array.isArray(h)) return [];
    return h.filter(function (x) { return x && typeof x.overall === 'number' && x.t; })
      .sort(function (a, b) { return new Date(a.t) - new Date(b.t); });
  }

  function addHistory(data) {
    var s = summarize(data);
    if (!s || !s.timestamp) return false;
    var hist = loadHistory();
    if (hist.some(function (x) { return x.t === s.timestamp; })) return false;
    hist.push({ t: s.timestamp, org: s.org, overall: s.overallPct, ncf: s.ncfPct, iso: s.isoPct });
    return write(K_HIST, hist.slice(-MAX_HISTORY));
  }

  // Assessments completed before history existed still count as the first data point.
  function seedHistory() {
    if (loadHistory().length) return;
    var d = read(K_DATA);
    if (d && d.ncf && d.iso) addHistory(d);
  }

  function saveDraft(d) {
    if (!d || !(d.answered > 0 || (d.org && d.org.name))) return false;
    return write(K_DRAFT, d);
  }
  function loadDraft() {
    var d = read(K_DRAFT);
    return d && typeof d === 'object' ? d : null;
  }
  function clearDraft() { remove(K_DRAFT); }
  function clearAll() { remove(K_DATA); remove(K_HIST); remove(K_DRAFT); }

  function formatDate(iso) {
    var d = new Date(iso);
    if (isNaN(d)) return '';
    return new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }).format(d);
  }

  w.GHData = {
    MATURITY: MATURITY, level: level, risk: risk, color: color, summarize: summarize,
    loadLatest: loadLatest, loadHistory: loadHistory, addHistory: addHistory, seedHistory: seedHistory,
    saveDraft: saveDraft, loadDraft: loadDraft, clearDraft: clearDraft, clearAll: clearAll, formatDate: formatDate
  };
})(window);
