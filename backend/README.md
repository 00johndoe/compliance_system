# GH-CYBERCOMPLY — Node.js + MongoDB Backend

Backend for the **Ghana NCF vs ISO/IEC 27002 Compliance Measurement System**.
Built with **Express** and **Mongoose (MongoDB)**. It serves the existing static
frontend **unchanged** and exposes a complete REST API for frameworks, control
mappings, gap analysis, and organizational compliance assessments (with weighted
maturity scoring and prioritized recommendations).

This replaces the original in-memory `server.py` with a persistent, production-
shaped Node.js service. The API surface is a superset of the Python server's.

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
| `npm run seed`         | Upsert reference data (frameworks, mappings, gaps).             |
| `npm run test:api`     | Run the end-to-end smoke test against a running server.         |

Development uses **nodemon** (config in `nodemon.json`) to auto-restart on
changes to `server.js` and anything under `src/`.

Reference data is also auto-seeded on boot when `SEED_ON_START=true` (default).
Seeding is idempotent (upserts) and never touches saved assessments.

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

- `GET /api/frameworks` — summary of both frameworks
- `GET /api/frameworks/ghana` — Ghana NCF (6 domains, 37 controls)
- `GET /api/frameworks/iso27002` — ISO/IEC 27002:2022 (4 themes, 93 controls)
- `GET /api/mapping` — NCF → ISO control mappings (47 rows)
- `GET /api/gaps` — gap analysis (Ghana-unique, ISO-unique, structural comparison)

### Assessments

- `POST /api/assess` — create an assessment and compute scores
- `GET /api/assessments` — list assessment summaries (`?limit=`)
- `GET /api/assessments/:id` — full assessment detail
- `DELETE /api/assessments/:id` — delete an assessment
- `POST /api/report` — `{ assessment_id }` → full assessment detail

#### `POST /api/assess` request body

```json
{
  "organization": { "name": "Acme Ltd", "sector": "Finance", "size": "201-500", "email": "ops@acme.com" },
  "ghana_responses": { "GOV-01": 5, "GOV-02": 4, "RISK-01": 3 },
  "iso_responses":   { "5.1": 5, "8.5": 4, "8.7": 2 }
}
```

- Keys are **control IDs** (`GOV-01…`, `5.1…`). Values are **maturity 0–5**.
- Aliases accepted: `ghana` / `ncf` for `ghana_responses`, `iso` for `iso_responses`.
- Missing controls default to maturity `0`.

#### Validation

Requests are validated with **express-validator**; invalid input returns `400`
with `{ error: "Validation failed", details: [{ field, message }] }`:

- `organization.name` — required text, 2–200 chars, safe characters only
- `organization.email` — required, valid email
- `organization.sector` / `organization.size` — required, must match the allowed lists
- response values — must be numbers in `0–5`, keyed only by **known control IDs**
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
├── server.js                  # bootstrap: DB → seed → HTTP → graceful shutdown
├── scripts/smoke-test.js      # end-to-end API test
└── src/
    ├── app.js                 # Express app (security, static frontend, routes)
    ├── config/                # env + db (real / in-memory)
    ├── data/                  # canonical reference data (frameworks, mapping, gaps)
    ├── models/                # Mongoose schemas (Framework, Mapping, GapAnalysis, Assessment)
    ├── services/              # scoring engine + framework repository
    ├── controllers/           # reference + assessment handlers
    ├── routes/                # /api router
    ├── middleware/            # async wrapper + error handling
    └── seed.js                # idempotent reference-data seeder
```

## Notes on the frontend

The frontend (`../index.html`, `../assessment.html`, `../results.html`,
`../mapping.html`, `../gaps.html`) is served **unchanged**. As shipped, it
computes and stores assessments client-side via `localStorage`. This backend
provides the persistent API those flows can be pointed at (POST `/api/assess`,
GET `/api/assessments/:id`, etc.) without any change to the visual UI.
