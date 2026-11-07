# Project guide and step-by-step explanation

## 1. Problem statement
Organizations need visibility into network activity and timely identification of suspicious behaviour. This prototype centralizes traffic metadata, applies detection rules, records alerts and presents the results in a cloud-ready dashboard.

## 2. System modules
- **Frontend:** React/TypeScript SOC dashboard, theme switch, alert investigation drawer, simulation lab and analytics tables.
- **Backend:** FastAPI REST API and WebSocket event channel.
- **Database:** SQLAlchemy relational models; PostgreSQL in Docker, SQLite for local development.
- **Detection engine:** rolling-window rules over event metadata.
- **Sensor:** optional Scapy capture agent for authorized networks.
- **Cloud:** Dockerized services and sensor-to-cloud ingestion endpoint.

## 3. Request flow
1. User signs in; backend verifies a bcrypt password hash and issues a JWT.
2. Dashboard requests metrics, alerts and traffic records using the JWT.
3. Simulation Lab submits a scenario to `/api/simulation/{scenario}`.
4. Synthetic events are persisted and processed by `process_event`.
5. Matching rules create alerts in the same database.
6. WebSocket broadcasts a change so the dashboard refreshes.
7. An analyst updates status and notes; an audit record is stored.

## 4. Nigerian time
The backend stores event timestamps as UTC. API responses convert them using Python `zoneinfo` and `Africa/Lagos`. The frontend clock and formatting also explicitly specify `Africa/Lagos` and `en-NG`; browser timezone is not used for display.

## 5. Detection rules and limitations
Port scanning is inferred from many unique destination ports from one source in a rolling minute. Brute force requires repeated `auth_failure` metadata from a service-log integration or simulator. SYN-rate is a heuristic indicator. Suspicious DNS is a signal from DNS metadata. These rules are not a substitute for tuned IDS signatures, endpoint logs, or expert investigation.

## 6. Machine-learning research extension
This starter intentionally does not claim a trained model. For the research component:
1. Obtain CICIDS2017 or UNSW-NB15 from an official research source.
2. Record dataset provenance, selected features, cleaning, encoding and label mapping.
3. Split data into training, validation and held-out test sets without leakage.
4. Train a baseline Random Forest or other explainable classifier.
5. Report precision, recall, F1, confusion matrix and class imbalance.
6. Save the model and implement versioned inference with drift monitoring.
Never invent model results.

## 7. Test plan for defence
- Login success/failure and protected endpoints.
- Detection rules with controlled sample event sequences.
- Alert lifecycle: New -> Acknowledged -> Investigating -> Resolved.
- CSV export correctness.
- WAT display for timestamps.
- Sensor token rejection and acceptance.
- WebSocket notification on generated alerts.
- PostgreSQL persistence after container restart.

## 8. Suggested report chapters
1. Introduction, background, problem statement, aim and objectives.
2. Literature review: NIDS, cloud computing, signature/rule/ML detection.
3. Methodology, requirements, architecture, use cases and database design.
4. Implementation, screenshots, API design and detection algorithms.
5. Testing, results, limitations, conclusion and future work.

## 9. Deployment caution
Replace all demo passwords and secrets, restrict CORS, terminate TLS, rotate sensor credentials, apply rate limiting, back up the database, and monitor service health before any public deployment.
