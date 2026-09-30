# GH-CYBERCOMPLY — Node.js + MongoDB Backend

Backend for the **Ghana requirements vs ISO/IEC 27002 Compliance Measurement System**.
Built with **Express** and **Mongoose (MongoDB)**. It serves the static frontend and exposes a
REST API for the Ghana requirements, the proposed requirement-to-ISO links, the gap analysis, and
organizational compliance assessments (scoring plus prioritized recommendations).

The Ghana side comes from `../data/ghana-requirements.json`, the single source of truth shared with
the browser (see the project README). This service replaces the original prototype `../server.py`,
which is retired and still holds an earlier, unofficial control list.

## Requirements

- Node.js 18+ (tested on Node 24)
- MongoDB 5+ running locally, **or** MongoDB Atlas, **or** the built-in
  in-memory mode (zero setup, non-persistent).

## Setup

```bash
cd backend
npm install
cp .env.example .env        # then edit if needed
```

### Run with a real MongoDB (recommended, persistent)

macOS (Homebrew):

```bash
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb-community    # listens on 127.0.0.1:27017
```

Then:

```bash
npm start
```

### Run with zero setup (in-memory MongoDB, non-persistent)

```bash
npm run start:memory
```

Open <http://localhost:8000> — the dashboard and all frontend pages are served
by this backend. The API base is <http://localhost:8000/api>.

## Scripts

| Command                | Description                                                     |
| ---------------------- | --------------------------------------------------------------- |
| `npm start`            | Start the server (connects to `MONGODB_URI`).                   |
| `npm run dev`          | Start with **nodemon** hot-reload (watches `server.js`, `src/`).|
| `npm run dev:memory`   | nodemon hot-reload + ephemeral in-memory MongoDB.               |
| `npm run start:memory` | Start with an ephemeral in-memory MongoDB.                      |
| `npm run seed`         | Upsert the framework reference data.                            |
| `npm run test:api`     | Run the end-to-end smoke test against a running server.         |

Development uses **nodemon** (config in `nodemon.json`) to auto-restart on
changes to `server.js` and anything under `src/`.

Reference data is also auto-seeded on boot when `SEED_ON_START=true` (default).
Seeding is idempotent (upserts) and never touches saved assessments. It also removes the
`mappings` and `gap_analysis` collections left by older versions: the mapping and gap analysis are
now calculated from the requirements data on every request.

## Configuration (`.env`)

| Variable        | Default                                          | Description                                    |
| --------------- | ------------------------------------------------ | ---------------------------------------------- |
| `PORT`          | `8000`                                           | HTTP port for API + static frontend.           |
| `MONGODB_URI`   | `mongodb://127.0.0.1:27017/compliance_system`    | MongoDB connection string.                     |
| `USE_MEMORY_DB` | `false`                                          | Boot an in-memory MongoDB instead of `URI`.    |
| `CORS_ORIGIN`   | `*`                                              | Allowed CORS origins (comma-separated or `*`). |
| `SEED_ON_START` | `true`                                           | Upsert reference data on startup.              |
| `NODE_ENV`      | `development`                                     | Environment.                                   |

## API

Base path: `/api`

### Health

- `GET /api/health` → `{ status, db, uptime, timestamp }`

### Reference data

- `GET /api/frameworks` - summary of both frameworks
- `GET /api/frameworks/ghana` - Ghana requirements (7 groups, 53 requirements; each has `tier` and `source`)
- `GET /api/frameworks/iso27002` - ISO/IEC 27002:2022 (4 themes, 93 controls)
- `GET /api/mapping` - proposed requirement to ISO control links (`{ requirement, iso, status: "proposed" }`, 153 rows). No strength ratings, because the links have not been validated.
- `GET /api/gaps` - calculated: requirements with no ISO link, ISO controls no requirement refers to, coverage by theme, structural comparison

### Assessments

- `POST /api/assess` — create an assessment and compute scores
- `GET /api/assessments` — list assessment summaries (`?limit=`)
- `GET /api/assessments/:id` — full assessment detail
- `DELETE /api/assessments/:id` — delete an assessment
- `POST /api/report` — `{ assessment_id }` → full assessment detail

#### `POST /api/assess` request body

```json
{
  "organization": { "name": "Acme Ltd", "sector": "Financial Services", "size": "Medium (51-250)", "email": "ops@acme.com" },
  "applicability": { "personalData": true, "ciiOwner": false },
  "ghana_responses": { "T1A-01": 5, "T1B-11": 2.5 },
  "iso_responses":   { "5.1": 5, "8.5": 4, "8.7": 2 }
}
```

- Keys are **requirement IDs** (`T1A-01`, `T1B-11`, `T2-04` ...) and **ISO control IDs** (`5.1` ...). Values are **maturity 0-5**.
- `applicability` decides which Ghana requirements are scored: Tier 1A always (2 requirements); Tier 1B when `personalData` is `true` (+18); Tier 2 when `ciiOwner` is `true` (+33). Omitted means both `false`. Answers for requirements that do not apply are ignored and not stored. The applicability is saved with the assessment.
- Aliases accepted: `ghana` / `ncf` (legacy) for `ghana_responses`, `iso` for `iso_responses`.
- Missing controls default to maturity `0`.
- The retired ids from the old "Ghana NCF" list (`GOV-01` ...) are rejected with `400`.

#### Validation

Requests are validated with **express-validator**; invalid input returns `400`
with `{ error: "Validation failed", details: [{ field, message }] }`:

- `organization.name` — required text, 2–200 chars, safe characters only
- `organization.email` — required, valid email
- `organization.sector` / `organization.size` — required, must match the allowed lists
- response values — must be numbers in `0–5`, keyed only by **known requirement / control IDs**
- `applicability` — optional object; `personalData` and `ciiOwner` must be booleans
- `assessment_id` / `:id` — required, alphanumeric/hyphen, ≤ 64 chars

The frontend form mirrors these rules for immediate feedback before submitting.

#### Scoring

```
control_score  = (maturity / 5) × 100
domain_score   = average(control_score) over the domain's controls
overall_score  = average(control_score) over all controls
```

Simple unweighted average — every control contributes equally. Control `weight`
is retained as criticality metadata and only affects how recommendations are
prioritised, not the compliance score.

Maturity labels: `Non-Existent (<10) · Initial (10) · Developing (30) · Defined (50) · Managed (70) · Optimized (90)`.

## Project structure

```
backend/
  server.js                  bootstrap: DB, seed, HTTP, graceful shutdown
  scripts/smoke-test.js      end-to-end API and security-header test
  src/
    config/                  env + db (real / in-memory)
    data/
      frameworks.js          Ghana requirements (from ../../data/ghana-requirements.json) + ISO/IEC 27002
      derived.js             requirement-to-ISO links and gap analysis, calculated from the dataset
    models/                  Mongoose schemas (Framework, Assessment)
    services/                scoring engine + framework repository
    controllers/             reference + assessment handlers
    routes/                  /api router
    middleware/              async wrapper + error handling
    validators/              express-validator rules
    seed.js                  idempotent reference-data seeder
```

## Notes on the frontend

The frontend pages in the repository root are served through an allow-list (top-level pages, scripts,
styles and `/vendor/` only), so backend source, `data/`, `docs/` and `server.py` are never exposed.
As shipped, the pages compute and store assessments in the browser (`localStorage`); this API is
available for flows that need server-side storage.
