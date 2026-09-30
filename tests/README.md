# Tests

Automated checks that run on every push (see `.github/workflows/ci.yml`).

## Browser tests (`tests/e2e`)

Drive the real pages in headless Chrome. No dependencies to install: they use Node 22+'s built-in
`fetch`/`WebSocket` and a Chrome or Chromium that is already on the machine.

```bash
node tests/e2e/run.mjs                 # everything (about 100 seconds)
node tests/e2e/run.mjs dropdown        # only tests whose name contains "dropdown"
CHROME_PATH="/path/to/chrome" node tests/e2e/run.mjs   # if Chrome is not found automatically
```

What they cover:

| File | Covers |
| --- | --- |
| `layout.test.mjs` | No sideways scrolling at 320/390/768/1280px; scroll-reveal never leaves content invisible (including a 13,000px element); mapping table as cards on a phone; mobile menu focus handling |
| `consistency.test.mjs` | No third-party requests; no console errors; pinned assets load; dashboard, gap and mapping figures agree; no "official"/"version 2024"/"ISO 27001" wording; disclaimers present |
| `assessment.test.mjs` | "Partially implemented" scores 2.5 (50%); autosave and restore; validation and the custom dropdowns; dashboard trend, history and clear-data |
| `mapping.test.mjs` | Filters, search, sorting, URL state, grouped and coverage views, detail panel, CSV export |
| `dropdown.test.mjs` | Combobox roles, mouse and full keyboard use, outside click, viewport containment and flipping, long lists |
| `actions.test.mjs` | Action plan: suggestions from gaps and de-duplication, add/edit/status/delete with undo, validation and size limits, overdue and due-soon logic, filters and sorting, export/import round-trip, calendar (.ics) export (escaping, 75-byte folding, stable IDs, injection), hostile and corrupted data never rendered as HTML, dashboard card, report "Add to action plan", dialog focus handling, navigation |
| `results.test.mjs` | Report score matches the dashboard; controls table filter; phone layout; report menu; printing |

Each test starts from a clean browser state. A failing test prints what it expected and what it got.

## API and security smoke test (`backend/scripts/smoke-test.js`)

Needs a running server and MongoDB:

```bash
cd backend && npm run start:memory &       # in-memory MongoDB, no setup
BASE=http://localhost:8000 node scripts/smoke-test.js
```

Besides the API checks it verifies the Content-Security-Policy header, that no CDN assets are referenced,
and that backend source files (`/backend/...`, `/server.py`, `/docs/...`, `/.env`) are **not** publicly served.

## Are the tests actually catching bugs?

The tests were checked by deliberately reintroducing four bugs (the scroll-reveal threshold, truncating partial
answers, adding a CDN script, and a wrong dashboard count). Each one made the matching test fail.
Re-run that kind of check when adding a test for a bug: revert the fix and confirm the test fails.
