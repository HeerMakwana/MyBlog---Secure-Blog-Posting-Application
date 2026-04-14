# MyBlog Secure Blog Application

MyBlog is a full-stack blog platform with local CAPTCHA authentication hardening, RBAC, and Firebase deployment support.

## What You Can Deploy

- frontend/ React app (Firebase Hosting)
- functions/ API (Firebase Functions, route prefix /api)
- backend/ standalone local API (optional for local dev)

Important: Firebase deployment uses functions/ as the API. The backend/ service is for local/standalone use.

## Prerequisites

- Node.js 18.x
- npm 9+
- Firebase CLI installed globally
- A Firebase project
- MongoDB connection string

Install Firebase CLI:

npm i -g firebase-tools

## 1. Clone And Install

From a fresh pull:

git clone https://github.com/HeerMakwana/MyBlog.git
cd MyBlog
npm install
npm run install:all
cd functions && npm install && cd ..

## 2. Configure Environment Files

Create these local files before running or deploying.

### backend/.env (local backend only)

Copy backend/.env.example to backend/.env and fill required values.

Minimum values to run local backend:

- NODE_ENV=development
- PORT=5000
- MONGODB_URI=your MongoDB URI
- JWT_SECRET=64+ char random string
- SESSION_SECRET=64+ char random string
- CSRF_SECRET=32+ char random string
- ENCRYPTION_KEY=64 hex chars
- ALLOWED_ORIGINS=http://localhost:3000
- ADMIN_EMAIL=valid email (if ADMIN_USERNAME is set)
- ADMIN_PASSWORD=12+ chars (if ADMIN_USERNAME is set)

Generate secure values quickly:

node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

### frontend/.env

Copy frontend/.env.example to frontend/.env.

For local backend development:

- REACT_APP_API_URL=http://localhost:5000/api

For Firebase Hosting + Functions deployment:

- REACT_APP_API_URL=/api

### functions/.env (Firebase Functions runtime)

Create functions/.env (template provided in functions/.env.example) with:

- NODE_ENV=production
- MONGODB_URI=your MongoDB URI
- JWT_SECRET=64+ char random string
- ALLOWED_ORIGINS=https://your-frontend-domain

If you use multiple Firebase projects, create per-project files:

- functions/.env.dev
- functions/.env.prod

and select the project with firebase use before deploy.

## 3. Run Locally

### Option A: Local backend + React (recommended for development)

At repository root:

npm run dev

App: http://localhost:3000
API: http://localhost:5000/api

### Option B: Firebase Functions emulator

In functions/:

npm run serve

## 4. Validate Before Deploy

From root:

- npm run build

In functions/:

- npm run lint
- npm run test:security
- npm run test:password-security

In backend/ (optional but recommended):

- npm run test:security
- npm run audit

## 5. Deploy To Firebase

1. Authenticate and select project:

firebase login
firebase use YOUR_PROJECT_ID

2. Build frontend:

npm run build

3. Deploy Hosting + Functions:

firebase deploy

The firebase.json rewrite routes /api/** to the api function and all other routes to frontend/index.html.

## 6. Post-Deploy Verification

After deployment, verify:

- GET /api/health (backend local) or /health (functions direct)
- Registration requires CAPTCHA
- Login requires CAPTCHA
- Protected routes reject missing/invalid token
- Admin routes deny non-admin users

## Common Deployment Issues

- Functions fail to connect to DB:
  Check functions/.env has MONGODB_URI and deploy again.

- CORS blocked:
  Ensure ALLOWED_ORIGINS exactly matches frontend domain, including protocol.

- Frontend cannot call API:
  Ensure REACT_APP_API_URL=/api for Firebase Hosting deployment.

- Security validator fails local backend startup:
  Ensure backend/.env includes valid ADMIN_EMAIL and strong secrets.

## Security Notes

- MFA endpoints are deprecated and return 410 Gone.
- Local CAPTCHA endpoint: GET /api/auth/captcha.
- Never commit secrets (.env files are gitignored).

## License

MIT
