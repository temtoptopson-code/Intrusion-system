# Cloud-Based Network Intrusion Detection System (NIDS)
**Final-year project:** Design and Implementation of Network Intrusion Detection Using Cloud Computing  
**Stack:** React + TypeScript, FastAPI, PostgreSQL, SQLAlchemy, Docker  
**Regional time:** `Africa/Lagos` (West Africa Time, UTC+1)

## Deploy to GitHub + Render
This repository includes `render.yaml` for Render Blueprint deployment.

1. Create a GitHub repository and upload/push the contents of this folder to its root.
2. In Render, choose **New → Blueprint**, connect the GitHub repository, and select `render.yaml`.
3. When prompted, provide `ADMIN_EMAIL` and a unique `ADMIN_PASSWORD` of at least 12 characters.
4. Review the resources and deploy. The blueprint creates a FastAPI API, React static site and PostgreSQL database.
5. Wait for the API and frontend deploys to finish. Open `https://nids-frontend.onrender.com`.
6. If you change either Render service name, update `VITE_API_URL` on the frontend and `CORS_ORIGINS` on the API to the actual URLs, then redeploy both.

**Database cost note:** the Blueprint specifies Render Postgres `basic-256mb` (a paid database plan). Render's free web/static services have limitations and may spin down; check current pricing before creating resources. Do not assume the database is free.

Detailed steps and troubleshooting: [`docs/DEPLOY_TO_GITHUB_RENDER.md`](docs/DEPLOY_TO_GITHUB_RENDER.md).

## Run locally with Docker
Install Docker Desktop, then:
```bash
docker compose up --build
```
Open:
- Dashboard: http://localhost:5173
- API documentation: http://localhost:8000/docs

Local demo login: `admin@nids.local` / `ChangeMe123!`. Change this before any deployment. For a persistent local setup, use the environment variables documented in `.env.example`.

## Features
- Hybrid dark/light security operations dashboard
- JWT authentication and protected API endpoints
- Rule-based event analysis: port scans, repeated authentication failures, SYN-rate indicators, suspicious DNS and high-volume events
- Synthetic Simulation Lab (does not send attack traffic)
- Alert investigation, status workflow and notes
- Traffic records, analytics, CSV export and WebSocket alert notifications
- PostgreSQL deployment and SQLite local-development fallback
- Optional Scapy sensor that forwards packet metadata only
- Nigeria-localized time display (`en-NG`, `Africa/Lagos`)

## Important academic and operational limitations
This is a functional academic prototype, not a certified commercial IDS. Detection rules are heuristics. Brute-force identification requires authentication failure events from application/server logs; packet capture alone does not establish failed logins. SYN-rate signals are not proof of DDoS. The optional sensor does not decrypt traffic or inspect payloads.

This initial version does **not** contain a trained machine-learning model. Do not claim machine-learning performance or accuracy until a model has been trained and independently evaluated. The project guide describes a reproducible ML extension.

Only monitor networks for which you have explicit authorization. Before public/production use, add TLS-only sensor ingestion, per-sensor credential management and rotation, rate limiting, role-based access control, migrations, backups, monitoring and a security review.


## Extended administration and reporting features

The application now includes:
- Incident investigation with status updates and analyst notes.
- IP watchlist, blacklist and whitelist records. Blacklist matches create alerts; these records do not directly configure a firewall or block packets.
- Configurable heuristic detection thresholds for port scans, brute-force patterns and SYN flood indicators.
- Super Administrator, Security Analyst and Viewer account roles.
- Audit history for key administrative actions.
- Extended analytics for top alert sources, attack categories and destination ports.
- Downloadable PDF and CSV security reports.
- Database-aware API health checks.
- Resend-powered email test messages and High/Critical alert notifications.
- Super Administrator email-recipient management (add, edit, enable/disable and delete).

### Email notifications and recipient management

Configure `RESEND_API_KEY` and `RESEND_FROM` as private environment variables on the Render backend service. Do not commit credentials to GitHub or expose the API key in frontend code.

Open **Notifications** in the dashboard while signed in as a Super Administrator to manage recipient addresses. Recipients are stored in the application database; only active recipients receive automatic High and Critical alert notifications. The existing `ALERT_RECIPIENTS` comma-separated environment variable is imported into the database once on first use so existing destinations remain manageable. The test button sends a test message to the signed-in user's email address.

### Feature access

User creation, role management, audit-log access and detection-rule changes require a Super Administrator account. The Viewer role is read-only for alert updates. IP blacklist/whitelist changes are also restricted to Super Administrators.

Detection remains heuristic/rule-based. The application does not claim machine-learning accuracy, and the IP lists are application-level records rather than an active firewall integration.
