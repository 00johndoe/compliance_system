# GH-CYBERCOMPLY

A self-assessment tool that measures how an organization meets **Ghana's cybersecurity and data-protection
requirements** and how that compares with **ISO/IEC 27002:2022**. It shows a score and maturity level, the
areas that need attention, proposed links between the two, the gaps between them, and an action plan.

> **Status: draft.** The Ghana requirements are this project's plain-language summary of official texts.
> They are **not** an official publication of the Cyber Security Authority (CSA), have not yet been reviewed
> by a lawyer or supervisor, and are not legal advice. The links to ISO/IEC 27002 are **proposals** awaiting
> validation. Results are indicative only and are not a compliance certificate.

## Where the Ghana requirements come from

There is no official, numbered "Ghana NCF" control catalogue. (An earlier version of this project used a
control list that was not an official document; it has been retired.) The requirements are drawn from:

| Source | Used for |
| --- | --- |
| Cybersecurity Act, 2020 (Act 1038) | Incident reporting and institutional duties |
| Data Protection Act, 2012 (Act 843) | Data protection principles and security safeguards |
| CSA Directive for the Protection of Critical Information Infrastructure (effective 1 Oct 2021) | Duties of designated CII owners |

Each of the 53 requirements has an ID, a short title, its source citation, an assessment question, the proposed
ISO/IEC 27002 controls, and flags for anything not yet confirmed. Which ones an organization is asked about
depends on two questions at the start of the assessment:

| Tier | Requirements | Applies to |
| --- | --- | --- |
| 1A | 2 | Every organization (incident reporting) |
| 1B | 18 | Organizations that process personal data |
| 2 | 33 | Owners of CII formally designated by the CSA |

### Open questions (recorded in `data/ghana-requirements.json` under `openQuestions`)

- **Q2**: whether the CSA has issued general organizational standards under Act 1038 s.59. None found; ask the CSA.
- **Q3**: what "institution" means in s.47(5). It is not defined anywhere and needs legal counsel. The assessment and mapping pages carry a caveat on T1A-01 and T1A-02.
- **Q6**: who validates the ISO links. The supervisor first, and an ISO 27001 Lead Auditor in Ghana for production use.

### Planned

A later phase adds sector modules. The Bank of Ghana's Cyber and Information Security Directive (CISD, 2026) is the
first candidate. Its contents must be checked against the published document before any requirement is added.

## Single source of truth

Everything about the Ghana side lives in **`data/ghana-requirements.json`**. The assessment, results, dashboard,
mapping, gap analysis, API, scoring and tests all read from it.

```
data/ghana-requirements.json --> scripts/build-requirements.mjs --> gh-requirements.js   (browser copy, generated)
                             \-> backend/src/data/frameworks.js  (API, validation, scoring)
```

To change a requirement:

1. Edit `data/ghana-requirements.json` (keep `id`, `tier`, `group`, `title`, `requirement`, `source`, `assessmentQuestion` and `iso27002Links`).
2. Run `node scripts/build-requirements.mjs` to regenerate `gh-requirements.js`. It also embeds the ISO control list and validates ids, groups, tiers and ISO ids.
3. Run the tests (below). CI fails if `gh-requirements.js` is out of date (`node scripts/build-requirements.mjs --check`).

Do not edit `gh-requirements.js` by hand.

## Running it

```bash
cd backend
npm install
npm run start:memory      # zero-setup, in-memory MongoDB; open http://localhost:8000
```

See `backend/README.md` for MongoDB, configuration and the API.

## Pages

| Page | Purpose |
| --- | --- |
| `index.html` | Dashboard: your latest status, history, action-plan progress, requirement groups and ISO themes |
| `assessment.html` | Questionnaire: organization, the two applicability questions, Ghana requirements, then ISO controls |
| `results.html` / `results-print.html` | Report (with a per-requirement table) and its print version |
| `mapping.html` | Proposed requirement-to-ISO links (filters, views, CSV export) |
| `gaps.html` | Requirements with no ISO link and ISO controls no requirement refers to |
| `actions.html` | Action plan with owners, due dates and calendar (.ics) export |

Assessments, history, drafts and the action plan are stored **only in the browser** (`localStorage`); nothing is
sent anywhere. The stored `ncf` key (the per-group answers) keeps its old name for compatibility with saved data;
newer assessments also store `requirements` (an answer per requirement ID) and `applicability`. Assessments saved
before the rebuild are labelled "Ghana NCF (retired control set)".

### Scoring

```
answer:   Fully implemented = 5, Partially implemented = 2.5, Not implemented = 0
group %   = round(mean of answers / 5 x 100)
Ghana %   = round(mean of all Ghana answers / 5 x 100)      ISO % = same for ISO answers
overall   = round((Ghana % + ISO %) / 2)
maturity level = floor(% / 20)
risk: Compliant >= 75, Moderate >= 50, Needs Improvement >= 25, Critical
```

## Tests and CI

See `tests/README.md`. In short: `node tests/e2e/run.mjs` (browser tests, Node 22+ and Chrome) and the API smoke test
in `backend/` run on every push through `.github/workflows/ci.yml`.

## Repository notes

- `server.py` is the retired prototype server (earlier unofficial control list). It is kept for history only.
- `update_theme.py` is a one-off script from an earlier restyle.
- `docs/` (untracked) holds working drafts of the requirements with the source notes.
