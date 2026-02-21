# College Billing Website (From Your Excel Logic)

This project converts your Excel fee workflow into a web app.

Stack:
- Frontend: React + Vite
- Backend: Node.js + Express
- DB: MongoDB Atlas (M0 free tier)
- Deploy: Netlify (frontend) + Render (backend)

## Features implemented

Based on workbook `College_Fee_System_fixed_v2.xlsm`:
- Student master: `PIN, Name, Course, College Total Fee`
- College daily payment entry
- Hostel fee master (month-wise fee)
- Hostel attendance entry with calculated fee:
  - `calculatedFee = round((monthlyFee / totalDays) * min(daysStayed, totalDays))`
- Hostel payment entry
- Dashboard per student:
  - College Paid, College Balance
  - Hostel Charged, Hostel Paid, Hostel Balance
- Receipt data lookup by PIN
- Login system (JWT)
- Roles:
  - `admin`: can create/import users
  - `staff`: can enter students/payments/attendance
  - `principal`: can enter students/payments/attendance
  - `accountant`: can enter students/payments/attendance

## API endpoints

- `GET /api/health`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/students`
- `GET /api/students`
- `POST /api/college-payments`
- `POST /api/hostel-fees`
- `GET /api/hostel-fees`
- `POST /api/hostel-attendance`
- `POST /api/hostel-payments`
- `GET /api/dashboard/students`
- `GET /api/receipt/:pin`
- `GET /api/admin/users` (admin)
- `POST /api/admin/users` (admin)
- `POST /api/admin/users/import` (admin, upload `.xlsx` or `.csv`)
- `GET /api/admin/users/template` (admin)

## Local run

Requirements:
- Node.js 20+
- npm

### Backend

```bash
cd backend
npm install
copy .env.example .env
npm run dev
```

Set `backend/.env`:

```env
PORT=5000
MONGODB_URI=mongodb+srv://username:password@cluster-url/website_db?retryWrites=true&w=majority
USE_IN_MEMORY_DB=false
IN_MEMORY_DB_PATH=.data/mongo
FRONTEND_URL=http://localhost:5173,https://your-site.netlify.app
JWT_SECRET=change_this_to_a_long_random_secret
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=ChangeMe123!
ADMIN_NAME=Admin
```

The first time you run the backend, it seeds an admin user if there is no admin in the database.

### Frontend

```bash
cd frontend
npm install
copy .env.example .env
npm run dev
```

Set `frontend/.env`:

```env
VITE_API_URL=http://localhost:5000
```

Open `http://localhost:5173`.

## Admin user import (Excel)

Admin can upload an Excel file (`.xlsx`) or CSV (`.csv`) to create users.

Template columns:
- `collegeKey` (required; use college code like `008`)
- `email` (required)
- `name` (required)
- `role` (required: `admin`, `principal`, `accountant`, or `staff`)
- `password` (required)
- `active` (optional: `true/false`, default `true`)

Template file in repo:
- `backend/templates/users_template.csv`

## Deploy

### Render (backend)
1. Push repo to GitHub.
2. Render -> New Web Service.
3. Root Directory: `website/backend`
4. Build command: `npm install`
5. Start command: `npm start`
6. Add env vars:
   - `MONGODB_URI`
   - `FRONTEND_URL` (your Netlify URL)

### Netlify (frontend)
1. Netlify -> Add new site -> Import from Git.
2. Base directory: `website/frontend`
3. Build command: `npm run build`
4. Publish directory: `dist`
5. Env var:
   - `VITE_API_URL=https://your-api.onrender.com`

### GoDaddy DNS
Use values shown in Netlify/Render custom domain screens.

Typical:
- `www` -> CNAME -> `your-site.netlify.app`
- `@` -> A/ALIAS value from Netlify
- optional API subdomain: `api` -> CNAME -> Render target

SSL is auto-issued after DNS propagation.
