# AuthLens — Architecture Guide

## What Is AuthLens?

AuthLens is a developer-facing tool that automatically tests authentication flows and tells you what's wrong, why it matters, and how to fix it.

### Core Workflow

```
TEST → DETECT → EXPLAIN → FIX → RE-TEST
```

---

## Folder Map

```
AuthLens/
│
├── frontend/               ← React + Vite UI (Round 1 focus)
│   └── src/
│       ├── components/     ← Reusable UI pieces (buttons, cards, badges)
│       ├── pages/          ← Full screens (Dashboard, Results, Demo Site)
│       ├── data/           ← Static mock data / test fixture JSON
│       ├── services/       ← API call wrappers (fetches backend endpoints)
│       ├── hooks/          ← Custom React hooks (e.g. useTestResults)
│       └── utils/          ← Pure helper functions (formatters, classifiers)
│
├── backend/                ← Express.js API (Round 2)
│   ├── routes/             ← URL → controller mapping
│   ├── controllers/        ← Request handling logic
│   └── services/           ← Business logic (calls testing-engine)
│
├── testing-engine/         ← Playwright test runners (Round 2)
│   ├── security/           ← Brute force, rate limiting, CSRF, session checks
│   ├── usability/          ← Error messages, password visibility, labels
│   ├── accessibility/      ← WCAG 2.1, keyboard nav, ARIA roles, contrast
│   └── recovery/           ← Forgot password, account lockout, token expiry
│
├── ai-service/             ← AI explanation layer (Round 3)
│   └── index.js            ← Provider-agnostic adapter interface
│
└── docs/                   ← Project documentation
    ├── ARCHITECTURE.md     ← This file
    └── TEST_CATEGORIES.md  ← What each test checks and why it matters
```

---

## Data Flow (Future State)

```
User clicks "Run Tests"
        │
        ▼
  frontend/services/  ──── HTTP POST ────▶  backend/routes/
                                                   │
                                                   ▼
                                          backend/controllers/
                                                   │
                                                   ▼
                                          testing-engine/index.js
                                          (runs all 4 test categories)
                                                   │
                                                   ▼
                                          ai-service/index.js
                                          (explains findings via LLM)
                                                   │
                                                   ▼
                                    JSON results returned to frontend
                                                   │
                                                   ▼
                                         frontend/pages/Results.jsx
```

---

## Module Status

| Module            | Status               | Round |
|-------------------|----------------------|-------|
| `frontend/`       | ✅ Scaffold created   | 1     |
| `backend/`        | 🔲 Stub only          | 2     |
| `testing-engine/` | 🔲 Stub only          | 2     |
| `ai-service/`     | 🔲 Stub only          | 3     |

---

## Key Design Decisions

- **No database** — test results are returned in-memory and displayed immediately.
- **No real auth** — AuthLens tests *other* apps' auth, it has no login of its own.
- **Provider-agnostic AI** — the AI provider is swappable without changing anything else.
- **Playwright** — chosen for testing because it runs real browser sessions, which is required to test real authentication flows.
