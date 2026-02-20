# MyBlog - MERN Stack with Firebase Deployment

A secure blogging platform converted from PHP to MERN stack (MongoDB, Express, React, Node.js) with Firebase deployment.

## Features

- 🔐 **User Authentication** - Register, Login with JWT tokens
- 🔑 **Multi-Factor Authentication (MFA)** - TOTP-based 2FA using authenticator apps
- 📝 **Blog Posts** - Create, Read, Update, Delete posts
- 👤 **User Profiles** - Update profile and change password
- 👑 **Admin Panel** - Manage users and posts (admin only)
- 🚀 **Firebase Deployment** - Hosted on Firebase with Cloud Functions

## Project Structure

```
mern/
├── backend/              # Express.js API (for local development)
│   ├── src/
│   │   ├── index.js      # Server entry point
│   │   ├── models/       # Mongoose models
│   │   ├── routes/       # API routes
│   │   ├── middleware/   # Auth middleware
│   │   └── utils/        # TOTP utilities
│   └── package.json
│
├── frontend/             # React application
│   ├── public/
│   ├── src/
│   │   ├── components/   # Reusable components
│   │   ├── pages/        # Page components
│   │   ├── context/      # React context (Auth)
│   │   └── services/     # API service
│   └── package.json
│
├── functions/            # Firebase Cloud Functions
│   ├── models/
│   ├── routes/
│   ├── middleware/
│   ├── utils/
│   └── index.js
│
├── firebase.json         # Firebase configuration
└── .firebaserc           # Firebase project settings
```

## Prerequisites

- Node.js 18 or later
- MongoDB Atlas account (or local MongoDB)
- Firebase account with a project created
- Firebase CLI (`npm install -g firebase-tools`)

## Local Development Setup

### 1. Backend Setup

```bash
cd mern\backend

# Copy environment variables
copy .env.example .env

# Edit .env with your MongoDB URI and JWT secret
# MONGODB_URI=mongodb+srv://...
# JWT_SECRET=your-secret-key

# Install dependencies
npm install

# Start development server
npm run dev
```

### 2. Frontend Setup

```bash
cd mern/frontend

# Install dependencies
npm install

# Start React development server
npm start
```

The frontend will run on `http://localhost:3000` and proxy API requests to `http://localhost:5000`.

## Firebase Deployment

### 1. Install Firebase CLI

```bash
npm install -g firebase-tools
```

### 2. Login to Firebase

```bash
firebase login
```

### 3. Initialize Firebase Project

Edit `.firebaserc` and replace `your-firebase-project-id` with your actual Firebase project ID.

### 4. Configure Environment Variables

Set MongoDB URI and JWT secret for Firebase Functions:

```bash
firebase functions:config:set mongodb.uri="your-mongodb-uri" jwt.secret="your-jwt-secret"
```

### 5. Build Frontend

```bash
cd mern/frontend
npm run build
```

### 6. Deploy to Firebase

```bash
cd mern

# Deploy functions only
firebase deploy --only functions

# Deploy hosting only
firebase deploy --only hosting

# Deploy everything
firebase deploy
```

## Environment Variables

### Backend (.env)

| Variable | Description |
|----------|-------------|
| `MONGODB_URI` | MongoDB connection string |
| `JWT_SECRET` | Secret key for JWT tokens |
| `JWT_EXPIRES_IN` | Token expiration (default: 7d) |
| `PORT` | Server port (default: 5000) |
| `FRONTEND_URL` | Frontend URL for CORS |
| `NODE_ENV` | Environment (development/production) |

### Frontend

Create `.env` in frontend directory if needed:

| Variable | Description |
|----------|-------------|
| `REACT_APP_API_URL` | API URL (empty for same-origin) |

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login user |
| POST | `/api/auth/verify-mfa` | Verify MFA code |
| GET | `/api/auth/me` | Get current user |
| POST | `/api/auth/enable-mfa` | Generate MFA secret |
| POST | `/api/auth/confirm-mfa` | Confirm MFA setup |
| POST | `/api/auth/disable-mfa` | Disable MFA |

### Posts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/posts` | Get all posts |
| GET | `/api/posts/my` | Get user's posts |
| GET | `/api/posts/:slug` | Get post by slug |
| POST | `/api/posts` | Create post |
| PUT | `/api/posts/:id` | Update post |
| DELETE | `/api/posts/:id` | Delete post |

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users/profile` | Get profile |
| PUT | `/api/users/profile` | Update profile |

### Admin (requires admin role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/users` | Get all users |
| DELETE | `/api/admin/users/:id` | Delete user |
| GET | `/api/admin/posts` | Get all posts |
| DELETE | `/api/admin/posts/:id` | Delete any post |
| GET | `/api/admin/stats` | Get dashboard stats |

## Creating an Admin User

To create an admin user, you can either:

1. **Using MongoDB Compass/Atlas:**
   - Find the user document
   - Set `isAdmin: true`

2. **Using a script:**
   ```javascript
   const User = require('./models/User');
   await User.findOneAndUpdate(
     { username: 'admin' },
     { isAdmin: true }
   );
   ```

## Security Features

- **Password Hashing** - bcrypt with 12 rounds
- **JWT Authentication** - Secure token-based auth
- **MFA/TOTP** - Time-based one-time passwords
- **Input Validation** - Server-side validation
- **CORS Protection** - Configured for specific origins
- **XSS Protection** - React's built-in escaping

## Tech Stack

### Backend
- Express.js - Web framework
- MongoDB/Mongoose - Database
- JWT - Authentication
- otplib - TOTP generation/verification
- bcryptjs - Password hashing

### Frontend
- React 18 - UI library
- React Router 6 - Client-side routing
- Axios - HTTP client
- Context API - State management

### Deployment
- Firebase Hosting - Static file hosting
- Firebase Functions - Serverless backend
- MongoDB Atlas - Cloud database

## License

MIT License
