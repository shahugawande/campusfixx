# CampusFix (all-in-one)

One server = website + API. Run `npm install`, create `.env` from `.env.example`, then `npm start` and open **http://localhost:3000**.

The website files are in `public/`. Everything below is the API reference.


Node.js + Express + built-in SQLite (node:sqlite) + JWT + bcrypt. API only. The UI is the separate `campusfix-frontend` project.

## Run in VS Code
1. Install **Node.js 22.13 or newer** (24 LTS is perfect) (nodejs.org, LTS).
2. VS Code → *File → Open Folder* → this folder → terminal (`Ctrl + ~`).
3. `npm install`
4. Copy `.env.example` → `.env`; set `JWT_SECRET`, `ADMIN_INVITE_CODE`, and optionally `ADMIN_USER` / `ADMIN_PASS` (creates the first admin automatically).
5. `npm start` (or `npm run dev` for auto-restart) → **http://localhost:3000**, health check at `/api/health`.

`campusfix.db` and `uploads/` are created automatically.

## Quick test (no frontend needed)
```bash
curl -X POST localhost:3000/api/auth/register-student -H "Content-Type: application/json" \
  -d '{"prn":"PRN123456","name":"Test Student","password":"Pass@1234","year":"Second Year","branch":"Computer Engineering","division":"A","incharge":"Prof. Sharma"}'
curl -X POST localhost:3000/api/auth/login -H "Content-Type: application/json" -d '{"login":"PRN123456","password":"Pass@1234","role":"student"}'
curl localhost:3000/api/issues -H "Authorization: Bearer <TOKEN>"
```
Or use Postman / the Thunder Client extension in VS Code.

## Auth model
* Student and admin accounts are separate. Login takes `role`: `student` (PRN) or `admin` (user ID).
* Admin sign-up needs `ADMIN_INVITE_CODE`, so students cannot make admin accounts.
* bcrypt passwords, JWT (7 days) as `Authorization: Bearer <token>`, auth endpoints rate limited (40 per 15 min).
* A student token gets **403** on every admin endpoint.

## Endpoints
| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | /api/meta | public | categories, years, branches, buildings, departments |
| POST | /api/auth/register-student | public | prn, name, password, year, branch, division, incharge |
| POST | /api/auth/register-admin | invite code | userId, name, password, dept, inviteCode |
| POST | /api/auth/login | public | login, password, role |
| GET | /api/me | any | current user |
| POST | /api/issues | student | create (duplicates become a "me too") |
| GET | /api/issues | any | list; query status, category, q, mine, dept |
| GET | /api/issues/:id | any | detail, timeline, comments |
| POST | /api/issues/:id/vote | student | me too |
| POST | /api/issues/:id/comments | any | {body} |
| POST | /api/issues/:id/rate | student owner | {rating 1-5} after fixed |
| PATCH | /api/issues/:id | admin | status, assigned, eta, note, after (photo) |
| GET | /api/stats | any | resolution %, SLA %, satisfaction %, chart data |
| GET | /api/leaderboard | any | top students by XP |
| GET | /api/admin/export.csv | admin | CSV export |

## Server-side rules
* Teaching Staff and Bullying/Ragging complaints are confidential (reporter + admins only).
* Bullying is always anonymous and urgent. Anonymous reports never reveal the reporter, even to admins.
* Photos: jpeg/png/webp only, stored in `uploads/`.

## Customise / deploy
Edit `config.js` (categories, problems, SLA hours, buildings, years, branches) and restart. For production use HTTPS (Render, Railway, VPS + Nginx), a strong `JWT_SECRET`, `CORS_ORIGIN` = your frontend URL, and a persistent disk for `campusfix.db` + `uploads/`.
