# Deploying AuthLens on Vercel

This guide outlines how to deploy AuthLens as a fullstack application on Vercel.

---

## 1. Architecture Overview on Vercel

```
                         [ Vercel Edge Router ]
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
   Static Assets & SPA                              Serverless Function
   `frontend/dist`                                   `api/index.js`
   - React 19 + Vite 6 bundle                        - Express 5 application (`backend/app.js`)
   - Served via CDN                                  - Session Auth (HttpOnly cookie)
   - SPA fallback to `index.html`                    - Security Testing Engine
                                                     - AI Remediation Service (Gemini / OpenAI)
                                                             │
                                                             ▼
                                                    [ Cloud PostgreSQL ]
                                                    Neon / Supabase / Vercel Postgres
```

- **Same-Domain API**: The frontend calls `/api/...` directly on the same Vercel domain (`https://your-app.vercel.app/api/...`), avoiding cross-domain cookies and third-party cookie restrictions.
- **Serverless Backend**: The Express application runs via `api/index.js`, using connection pooling optimized for serverless instances and `trust proxy` enabled for secure cookies.
- **Persistent Sessions**: User sessions are stored in PostgreSQL using `connect-pg-simple`.

---

## 2. Prerequisites

1. A **Vercel Account** ([vercel.com](https://vercel.com)).
2. A cloud **PostgreSQL Database** with public connection string support:
   - [Neon](https://neon.tech) (Recommended — free serverless Postgres)
   - [Supabase](https://supabase.com)
   - [Vercel Postgres](https://vercel.com/docs/storage/vercel-postgres)
   - AWS RDS / Render PostgreSQL
3. A **Gemini API Key** from [Google AI Studio](https://aistudio.google.com/) for AI remediation recommendations.

---

## 3. Step-by-Step Deployment Instructions

### Step 1: Push Code to GitHub
Ensure all recent changes are committed and pushed to your GitHub repository:
```bash
git add .
git commit -m "Configure AuthLens for Vercel deployment"
git push origin main
```

### Step 2: Import Project into Vercel
1. Log in to [vercel.com](https://vercel.com) and click **"Add New..." > "Project"**.
2. Select your repository: `hemanthm1607/AuthLen`.
3. In the project configuration screen:
   - **Framework Preset**: Leave as **Other** (or Vite).
   - **Root Directory**: Leave as `./` (repository root).
   - **Build Command**: `npm run vercel-build` (automatically populated from `vercel.json`).
   - **Output Directory**: `frontend/dist` (automatically populated from `vercel.json`).

### Step 3: Configure Environment Variables in Vercel
Expand the **Environment Variables** section and add the following variables:

| Variable Name | Required | Example / Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | **Yes** | `postgres://user:pass@ep-xyz.us-east-1.aws.neon.tech/neondb?sslmode=require` |
| `SESSION_SECRET` | **Yes** | 64-character random string (e.g. `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`) |
| `NODE_ENV` | **Yes** | `production` |
| `AI_PROVIDER` | **Yes** | `gemini` |
| `GEMINI_API_KEY` | **Yes** | Your Google Gemini API Key |
| `GEMINI_MODEL` | **Yes** | `gemini-3.5-flash` |
| `FRONTEND_URL` | Optional | `https://your-project.vercel.app` (auto-detected if blank) |
| `DB_SSL` | Optional | `true` (automatically enabled for non-localhost connection strings) |

> [!IMPORTANT]
> Never set `DATABASE_URL` to `localhost` in Vercel. Cloud functions cannot connect to your local computer's PostgreSQL. Use a cloud PostgreSQL provider like Neon or Supabase.

### Step 4: Deploy
Click **"Deploy"**. Vercel will:
1. Install root dependencies (`express`, `pg`, `bcryptjs`, etc.).
2. Build the Vite frontend to `frontend/dist`.
3. Package `api/index.js` as a serverless function.
4. Assign a production URL (e.g. `https://authlens-xxx.vercel.app`).

---

## 4. Database Migrations on Cloud PostgreSQL

When connecting a new database for the first time:

### Automatic Migration
AuthLens automatically checks and executes pending migrations when the `/api/health` endpoint or authentication routes are accessed.

### Manual Migration (Optional)
You can apply migrations to your cloud database before deployment:
```bash
# In your local terminal, temporarily set DATABASE_URL and run:
DATABASE_URL="postgres://user:pass@ep-xyz.us-east-1.aws.neon.tech/neondb?sslmode=require" npm run migrate
```

---

## 5. Post-Deployment Verification Checklist

Once deployed, verify your live deployment:

1. **Health & Database Status**:
   Visit: `https://your-project.vercel.app/api/health`
   Expected response:
   ```json
   {
     "status": "ok",
     "serverless": true,
     "database": {
       "connected": true,
       "name": "neondb",
       "user": "neondb_owner"
     }
   }
   ```

2. **AI Provider Status**:
   Visit: `https://your-project.vercel.app/api/ai/status`
   Expected response:
   ```json
   {
     "configured": true,
     "provider": "gemini",
     "model": "gemini-3.5-flash"
   }
   ```

3. **Frontend Application**:
   Navigate to `https://your-project.vercel.app`:
   - Register a user account.
   - Verify active session persistence upon page reload.
   - Navigate to **Security Testing** and run an audit against your domain.
   - Navigate to **AI Recommendations** and generate remediations for the audit.
