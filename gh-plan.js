/* GH-CYBERCOMPLY — action plan data layer (browser-only, localStorage key "actionPlan").
   Turns assessment gaps into tracked actions: owner, due date, status, priority.

   Item:  { id, title, notes, status: todo|doing|done, priority: immediate|high|medium|low,
            owner, due: "YYYY-MM-DD" | "", source: { kind: "gap"|"manual", key, framework, ref, pct },
            createdAt, updatedAt, completedAt }

   Everything read from storage or from an imported file is validated and clamped by clean(), so a
   corrupted or hostile file can never put unexpected shapes, huge strings or bad enums into the plan.
   Nothing here builds HTML; pages must escape values when rendering. */
(function (w) {
  'use strict';

  var KEY = 'actionPlan', VERSION = 1, MAX_ITEMS = 500, MAX_IMPORT_CHARS = 1000000;
  var STATUSES = ['todo', 'doing', 'done'];
  var PRIORITIES = ['immediate', 'high', 'medium', 'low'];
  var LIMIT = { title: 140, notes: 1000, owner: 80, ref: 120, framework: 40 };
  var STATUS_LABEL = { todo: 'To do', doing: 'In progress', done: 'Done' };
  var PRIORITY_LABEL = { immediate: 'Immediate', high: 'High', medium: 'Medium', low: 'Low' };

  function now() { return new Date().toISOString(); }
  function uid() { return 'a' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
  function str(v, max) { return typeof v === 'string' ? v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, max) : ''; }
  function line(v, max) { return str(v, max).replace(/[\r\n\u2028\u2029]+/g, ' ').trim(); }   // single-line fields never carry line breaks
  function isoOrNow(v) { var d = new Date(v); return typeof v === 'string' && !isNaN(d) ? d.toISOString() : now(); }

  // Local calendar date as YYYY-MM-DD (deadlines are calendar dates, not instants)
  function todayStr(d) {
    d = d || new Date();
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  }
  function validDate(s) {
    if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
    var p = s.split('-').map(Number), d = new Date(p[0], p[1] - 1, p[2]);
    return d.getFullYear() === p[0] && d.getMonth() === p[1] - 1 && d.getDate() === p[2];
  }
  function daysBetween(a, b) {   // whole days from date string a to b
    var pa = a.split('-').map(Number), pb = b.split('-').map(Number);
    return Math.round((new Date(pb[0], pb[1] - 1, pb[2]) - new Date(pa[0], pa[1] - 1, pa[2])) / 86400000);
  }

  function priorityForScore(pct) { return pct < 25 ? 'immediate' : pct < 50 ? 'high' : pct < 75 ? 'medium' : 'low'; }
  function sourceKey(framework, domain) { return 'gap|' + framework + '|' + domain; }

  // Same wording the report uses for its recommendations
  function recommendationText(domain, framework) {
    return framework + ' should prioritize formal policies, operating procedures, and periodic testing for ' + domain.toLowerCase() +
      ', with measurable ownership and evidence of implementation.';
  }

  // Validate + normalise one item. Returns null when it is unusable (no title).
  function clean(raw) {
    if (!raw || typeof raw !== 'object') return null;
    var title = line(raw.title, LIMIT.title);
    if (!title) return null;
    var src = raw.source && typeof raw.source === 'object' ? raw.source : {};
    var kind = src.kind === 'gap' ? 'gap' : 'manual';
    var pct = Number(src.pct);
    var status = STATUSES.indexOf(raw.status) >= 0 ? raw.status : 'todo';
    return {
      id: typeof raw.id === 'string' && /^[A-Za-z0-9_-]{4,40}$/.test(raw.id) ? raw.id : uid(),
      title: title,
      notes: str(raw.notes, LIMIT.notes),
      status: status,
      priority: PRIORITIES.indexOf(raw.priority) >= 0 ? raw.priority : 'medium',
      owner: line(raw.owner, LIMIT.owner),
      due: validDate(raw.due) ? raw.due : '',
      source: {
        kind: kind,
        key: kind === 'gap' ? line(src.key, LIMIT.ref + LIMIT.framework + 8) : '',
        framework: kind === 'gap' ? line(src.framework, LIMIT.framework) : '',
        ref: kind === 'gap' ? line(src.ref, LIMIT.ref) : '',
        pct: kind === 'gap' && src.pct !== null && src.pct !== '' && isFinite(pct) ? Math.max(0, Math.min(100, Math.round(pct))) : null
      },
      createdAt: isoOrNow(raw.createdAt),
      updatedAt: isoOrNow(raw.updatedAt),
      completedAt: status === 'done' ? isoOrNow(raw.completedAt) : ''
    };
  }

  function read() {
    try {
      var d = JSON.parse(localStorage.getItem(KEY) || 'null');
      var arr = d && Array.isArray(d.items) ? d.items : [];
      var seen = {}, out = [];
      arr.forEach(function (r) { var it = clean(r); if (it && !seen[it.id] && out.length < MAX_ITEMS) { seen[it.id] = 1; out.push(it); } });
      return out;
    } catch (e) { return []; }
  }
  function write(items) {
    try { localStorage.setItem(KEY, JSON.stringify({ version: VERSION, items: items })); return true; } catch (e) { return false; }
  }

  function list() { return read(); }
  function get(id) { return read().filter(function (i) { return i.id === id; })[0] || null; }
  function plannedForKey(key) { return read().filter(function (i) { return i.source.key === key; })[0] || null; }

  // Add an action. Gap actions are de-duplicated by source key (returns the existing one).
  function add(fields) {
    var items = read();
    var cand = clean(Object.assign({}, fields, { id: undefined, createdAt: now(), updatedAt: now() }));
    if (!cand) return { ok: false, error: 'A title is required.' };
    if (cand.source.kind === 'gap' && cand.source.key) {
      var dup = items.filter(function (i) { return i.source.key === cand.source.key; })[0];
      if (dup) return { ok: true, item: dup, existing: true };
    }
    if (items.length >= MAX_ITEMS) return { ok: false, error: 'The plan is full (' + MAX_ITEMS + ' actions).' };
    items.push(cand);
    return write(items) ? { ok: true, item: cand } : { ok: false, error: 'Could not save (browser storage unavailable).' };
  }

  function update(id, patch) {
    var items = read(), idx = -1;
    items.forEach(function (i, n) { if (i.id === id) idx = n; });
    if (idx < 0) return { ok: false, error: 'Action not found.' };
    var prev = items[idx];
    var merged = Object.assign({}, prev, patch, { id: prev.id, source: prev.source, createdAt: prev.createdAt, updatedAt: now() });
    if (merged.status === 'done' && prev.status !== 'done') merged.completedAt = now();
    else if (merged.status === 'done') merged.completedAt = prev.completedAt;
    else merged.completedAt = '';
    var next = clean(merged);
    if (!next) return { ok: false, error: 'A title is required.' };
    items[idx] = next;
    return write(items) ? { ok: true, item: next } : { ok: false, error: 'Could not save.' };
  }

  function remove(id) {
    var items = read(), idx = -1;
    items.forEach(function (i, n) { if (i.id === id) idx = n; });
    if (idx < 0) return null;
    var removed = items.splice(idx, 1)[0];
    write(items);
    return { item: removed, index: idx };
  }
  function restore(item, index) {   // undo of remove()
    var items = read();
    if (items.some(function (i) { return i.id === item.id; })) return false;
    items.splice(Math.min(index, items.length), 0, item);
    return write(items);
  }
  function clearCompleted() {
    var items = read(), keep = items.filter(function (i) { return i.status !== 'done'; });
    write(keep);
    return items.length - keep.length;
  }
  function clearAll() { try { localStorage.removeItem(KEY); } catch (e) { /* unavailable */ } }

  function dueInfo(item, today) {   // { days, overdue, soon }; days until due (negative = overdue)
    today = today || todayStr();
    if (!item.due) return null;
    var days = daysBetween(today, item.due);
    return { days: days, overdue: item.status !== 'done' && days < 0, soon: item.status !== 'done' && days >= 0 && days <= 3 };
  }
  function isOverdue(item, today) { var d = dueInfo(item, today); return !!(d && d.overdue); }

  function stats() {
    var items = read(), today = todayStr();
    var s = { total: items.length, todo: 0, doing: 0, done: 0, overdue: 0, dueSoon: 0, open: 0, openDated: 0, percentDone: 0, nextDue: null };
    items.forEach(function (i) {
      s[i.status]++;
      if (i.status !== 'done') {
        s.open++;
        if (i.due) s.openDated++;
        var d = dueInfo(i, today);
        if (d && d.overdue) s.overdue++;
        if (d && d.soon) s.dueSoon++;
      }
    });
    s.percentDone = s.total ? Math.round((s.done / s.total) * 100) : 0;
    var upcoming = items.filter(function (i) { return i.status !== 'done' && i.due; }).sort(function (a, b) { return a.due < b.due ? -1 : a.due > b.due ? 1 : 0; });
    s.nextDue = upcoming[0] || null;
    return s;
  }

  // One suggested action for a domain score (used by the report's "Add to action plan" and by suggestions())
  function suggestionFor(domain, framework, pct) {
    return {
      title: 'Strengthen ' + domain + ' (' + framework + ')',
      notes: recommendationText(domain, framework),
      priority: priorityForScore(pct),
      status: 'todo',
      source: { kind: 'gap', key: sourceKey(framework, domain), framework: framework, ref: domain, pct: pct }
    };
  }
  // Domains below 75% in the latest assessment that are not yet in the plan, weakest first
  function suggestions() {
    if (!w.GHData) return [];
    var latest = w.GHData.loadLatest();
    if (!latest) return [];
    var planned = {};
    read().forEach(function (i) { if (i.source.key) planned[i.source.key] = 1; });
    return latest.domains.filter(function (d) { return d.pct < 75; })
      .sort(function (a, b) { return a.pct - b.pct; })
      .map(function (d) { return suggestionFor(d.domain, d.framework, d.pct); })
      .filter(function (s) { return !planned[s.source.key]; });
  }

  // ---- export / import ----
  function exportJSON() {
    return JSON.stringify({ app: 'GH-CYBERCOMPLY', type: 'action-plan', version: VERSION, exportedAt: now(), items: read() }, null, 2);
  }
  function csvCell(v) {
    var s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;   // neutralise spreadsheet formulas
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function exportCSV() {
    var rows = [['Title', 'Status', 'Priority', 'Owner', 'Due', 'Source', 'Notes', 'Created', 'Completed']];
    read().forEach(function (i) {
      rows.push([i.title, STATUS_LABEL[i.status], PRIORITY_LABEL[i.priority], i.owner, i.due,
        i.source.kind === 'gap' ? i.source.framework + ': ' + i.source.ref + (i.source.pct !== null ? ' (' + i.source.pct + '%)' : '') : 'Manual',
        i.notes, i.createdAt.slice(0, 10), i.completedAt ? i.completedAt.slice(0, 10) : '']);
    });
    return '﻿' + rows.map(function (r) { return r.map(csvCell).join(','); }).join('\r\n');
  }

  // ---- calendar export (iCalendar / RFC 5545) ----
  // Open actions that have a due date become all-day events with reminders at 09:00 the day before and on the day.
  // UIDs are stable (one per action), so importing again updates the same events in most calendar apps.
  var ICS_PRIORITY = { immediate: 1, high: 3, medium: 5, low: 7 };
  function icsEscape(v) {   // TEXT values: escape \ ; , and turn every line break into \n (also blocks property injection)
    return String(v == null ? '' : v).replace(/\\/g, '\\\\').replace(/\r\n|\r|\n/g, '\\n').replace(/;/g, '\\;').replace(/,/g, '\\,');
  }
  function icsFold(line) {   // lines must not exceed 75 octets; continuation lines start with a space; never split a character
    var enc = new TextEncoder(), out = [], cur = '', bytes = 0;
    for (var ch of line) {
      var b = enc.encode(ch).length;
      if (bytes + b > 75) { out.push(cur); cur = ' ' + ch; bytes = 1 + b; } else { cur += ch; bytes += b; }
    }
    out.push(cur);
    return out.join('\r\n');
  }
  function ymd(dateStr) { return dateStr.replace(/-/g, ''); }
  function nextDay(dateStr) {
    var p = dateStr.split('-').map(Number), d = new Date(p[0], p[1] - 1, p[2] + 1);
    return d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
  }
  function exportICS() {
    var items = read(), events = [], noDue = 0;
    var stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
    var link = (w.location && /^https?:$/.test(w.location.protocol)) ? w.location.origin + '/actions.html' : '';
    items.forEach(function (i) {
      if (i.status === 'done') return;
      if (!i.due) { noDue++; return; }
      var desc = [];
      if (i.notes) desc.push(i.notes);
      desc.push('Priority: ' + PRIORITY_LABEL[i.priority] + '  |  Status: ' + STATUS_LABEL[i.status]);
      if (i.owner) desc.push('Owner: ' + i.owner);
      if (i.source.kind === 'gap') desc.push('From your assessment: ' + i.source.framework + ' - ' + i.source.ref + (i.source.pct !== null ? ' (' + i.source.pct + '%)' : ''));
      if (link) desc.push('Action plan: ' + link);
      var lines = [
        'BEGIN:VEVENT',
        'UID:' + i.id + '@gh-cybercomply',
        'DTSTAMP:' + stamp,
        'DTSTART;VALUE=DATE:' + ymd(i.due),
        'DTEND;VALUE=DATE:' + nextDay(i.due),
        'SUMMARY:' + icsEscape('Due: ' + i.title),
        'DESCRIPTION:' + icsEscape(desc.join('\n')),
        'CATEGORIES:GH-CYBERCOMPLY,Action plan',
        'PRIORITY:' + ICS_PRIORITY[i.priority],
        'STATUS:CONFIRMED',
        'TRANSP:TRANSPARENT'
      ];
      if (link) lines.push('URL:' + link);
      lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:' + icsEscape('Due tomorrow: ' + i.title), 'TRIGGER:-PT15H', 'END:VALARM');
      lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:' + icsEscape('Due today: ' + i.title), 'TRIGGER:PT9H', 'END:VALARM');
      lines.push('END:VEVENT');
      events.push(lines);
    });
    var all = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//GH-CYBERCOMPLY//Action Plan//EN', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
      'X-WR-CALNAME:GH-CYBERCOMPLY Action Plan'];
    events.forEach(function (e) { all = all.concat(e); });
    all.push('END:VCALENDAR');
    return { ics: all.map(icsFold).join('\r\n') + '\r\n', count: events.length, noDue: noDue };
  }

  // Merge (default) or replace. Returns { ok, added, updated, skipped, total } or { ok:false, error }.
  function importJSON(text, mode) {
    if (typeof text !== 'string' || !text.trim()) return { ok: false, error: 'The file is empty.' };
    if (text.length > MAX_IMPORT_CHARS) return { ok: false, error: 'The file is too large (limit 1 MB).' };
    var data;
    try { data = JSON.parse(text); } catch (e) { return { ok: false, error: 'This is not a valid JSON file.' }; }
    if (!data || typeof data !== 'object' || data.type !== 'action-plan' || !Array.isArray(data.items)) {
      return { ok: false, error: 'This file is not a GH-CYBERCOMPLY action plan export.' };
    }
    var items = mode === 'replace' ? [] : read();
    var byId = {}; items.forEach(function (i, n) { byId[i.id] = n; });
    var added = 0, updated = 0, skipped = 0;
    data.items.forEach(function (raw) {
      var it = clean(raw);
      if (!it) { skipped++; return; }
      if (Object.prototype.hasOwnProperty.call(byId, it.id)) {
        var cur = items[byId[it.id]];
        if (it.updatedAt > cur.updatedAt) { items[byId[it.id]] = it; updated++; } else { skipped++; }
      } else if (items.length < MAX_ITEMS) { byId[it.id] = items.length; items.push(it); added++; }
      else { skipped++; }
    });
    if (!write(items)) return { ok: false, error: 'Could not save (browser storage unavailable).' };
    return { ok: true, added: added, updated: updated, skipped: skipped, total: items.length };
  }

  w.GHPlan = {
    STATUSES: STATUSES, PRIORITIES: PRIORITIES, STATUS_LABEL: STATUS_LABEL, PRIORITY_LABEL: PRIORITY_LABEL, LIMIT: LIMIT, MAX_ITEMS: MAX_ITEMS,
    list: list, get: get, add: add, update: update, remove: remove, restore: restore, clearCompleted: clearCompleted, clearAll: clearAll,
    plannedForKey: plannedForKey, stats: stats, suggestions: suggestions, suggestionFor: suggestionFor, sourceKey: sourceKey,
    todayStr: todayStr, validDate: validDate, dueInfo: dueInfo, isOverdue: isOverdue, priorityForScore: priorityForScore,
    exportJSON: exportJSON, exportCSV: exportCSV, exportICS: exportICS, importJSON: importJSON
  };
})(window);
