# Deployment Guide: GitHub + Render

## Architecture
- `nids-frontend`: React/Vite static site served by Render's CDN.
- `nids-api`: FastAPI service running in Docker.
- `nids-postgres`: managed PostgreSQL database.
- Frontend requests the API over HTTPS; API stores events/alerts in PostgreSQL.
- Browser clock and backend event formatting explicitly use `Africa/Lagos`; database timestamps are UTC.

## A. Prepare GitHub
1. Extract the project ZIP.
2. Create a new repository on GitHub, e.g. `cloud-network-intrusion-detection`.
3. Upload the **contents** of the extracted folder (not an extra nested folder). The root must contain `render.yaml`, `backend/`, `frontend/`, `sensor/`, and `docs/`.
4. Commit to the `main` branch. Do not upload `.env` files, database files, virtual environments, or `node_modules`.

Git command alternative:
```bash
git init
git add .
git commit -m "Initial cloud NIDS implementation"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

## B. Deploy the Blueprint
1. Sign in to Render and connect your GitHub account.
2. Choose **New + → Blueprint** (not a single Web Service).
3. Select your repository and the branch containing `render.yaml`.
4. Review the Blueprint resources: `nids-api`, `nids-frontend`, and `nids-postgres`.
5. Enter `ADMIN_EMAIL` and `ADMIN_PASSWORD` when Render prompts for values. Use a unique password of at least 12 characters. Never reuse the sample local password.
6. Confirm resource creation. The database plan in the supplied Blueprint is `basic-256mb` and is paid; verify the current Render price before proceeding. The API and static frontend are configured on the free plan, subject to Render's current free-service limits.
7. Wait for the database, API and frontend to finish deploying.

## C. Confirm the public URLs
The default service names produce:
- Frontend: `https://nids-frontend.onrender.com`
- API: `https://nids-api.onrender.com`
- API health: `https://nids-api.onrender.com/api/health`
- Interactive API docs: `https://nids-api.onrender.com/docs`

If Render assigns different URLs or you rename services:
- In `nids-frontend` → Environment, set `VITE_API_URL` to the actual API URL (no trailing slash), then redeploy.
- In `nids-api` → Environment, set `CORS_ORIGINS` to the exact frontend origin (scheme + host, no path), then redeploy.
The `render.yaml` values assume the default service names shown above.

## D. Sign in and verify
1. Open the frontend URL.
2. Sign in with the `ADMIN_EMAIL` and `ADMIN_PASSWORD` supplied during Blueprint creation.
3. Open Simulation Lab and run each scenario.
4. Open Security Alerts and verify that the generated alerts appear.
5. Open Live Monitoring and review traffic metadata.
6. Export a CSV report.
7. Check API health and confirm `timezone` is `Africa/Lagos`.

## E. Local development
Requirements: Docker Desktop. From the project root:
```bash
docker compose up --build
```
Open `http://localhost:5173` and `http://localhost:8000/docs`.
Stop services with `Ctrl+C`, then `docker compose down`. To delete the local Docker database volume as well, use `docker compose down -v` (this permanently deletes that local database data).

## Troubleshooting
- **Frontend cannot connect:** verify `VITE_API_URL`, then redeploy the static site. Check `CORS_ORIGINS` on the API and make sure it exactly matches the frontend URL.
- **401 login:** confirm the admin credentials entered at Blueprint creation. The first administrator is seeded only when the configured email does not already exist. Changing `ADMIN_PASSWORD` later does not automatically reset an existing user's password.
- **Database connection failure:** confirm the Render Postgres resource is available and `DATABASE_URL` is linked using the internal connection string.
- **Build failure:** inspect Render deploy logs. Frontend uses `npm install && npm run build`; backend is installed with `pip install -r requirements.txt` and started with Uvicorn.
- **Free API sleeps:** free web services may spin down when idle; the first request after inactivity can take longer. This is a hosting-plan behavior, not necessarily an application fault.
- **Missing records after restart:** use managed PostgreSQL in the deployed environment; do not rely on the container filesystem for persistence.

## Security checklist before public demonstration
- Set unique strong admin credentials.
- Keep JWT and sensor tokens in Render environment variables only.
- Restrict CORS to the deployed frontend domain.
- Use HTTPS for the sensor endpoint and never expose the sensor token in frontend code.
- Rotate sensor tokens if exposed.
- Monitor only authorized networks.
- Back up the database and verify retention requirements.
- Review access controls and add account management before multi-user production use.

## What this project does and does not claim
The shipped detection engine uses explainable heuristic rules. The simulation lab creates synthetic records. The optional Scapy agent forwards packet metadata. This release does not ship a trained ML model or claim validated real-world detection accuracy. For a defensible academic evaluation, train and test a model on a documented dataset and report measured precision, recall, F1 and confusion matrix.
