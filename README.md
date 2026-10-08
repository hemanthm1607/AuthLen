# AuthLens

> **AuthLens** is a developer-facing authentication testing and improvement tool.  
> It evaluates authentication flows across Security, Usability, Accessibility, and Account Recovery — then explains what's wrong and how to fix it.

---

## Core Workflow

```
TEST → DETECT → EXPLAIN → FIX → RE-TEST
```

---

## Project Structure

```
AuthLens/
├── frontend/          ← React + Vite UI              [✅ Active — Round 1]
├── backend/           ← Express.js REST API           [🔲 Stub — Round 2]
├── testing-engine/    ← Playwright test runners       [🔲 Stub — Round 2]
├── ai-service/        ← AI explanation layer          [🔲 Stub — Round 3]
└── docs/              ← Architecture & test reference [✅ Active]
```

---

## Getting Started

### Run the Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev
```

The app will be available at **http://localhost:5173**

### Backend (not yet implemented)

```bash
cd backend
# When ready: npm install express
# Then: node server.js
```

---

## Documentation

- [Architecture Guide](docs/ARCHITECTURE.md) — folder map, data flow, design decisions
- [Test Categories](docs/TEST_CATEGORIES.md) — what each test checks and why it matters

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19 + Vite |
| Styling | Tailwind CSS (Round 1) |
| Backend | Node.js + Express.js |
| Testing | Playwright |
| AI | TBD (provider-agnostic) |

---

## Hackathon Context

Built solo in ~20 hours. Each round focuses on one area:

- **Round 1** — Frontend UI
- **Round 2** — Backend API + Testing Engine
- **Round 3** — AI Explanation Layer
