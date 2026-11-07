import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nids.db")
# Render provides postgresql:// URLs; explicitly select the installed psycopg v3 driver.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

JWT_SECRET = os.getenv("JWT_SECRET", "INSECURE-LOCAL-SECRET-CHANGE-ME")
SENSOR_TOKEN = os.getenv("SENSOR_TOKEN", "local-demo-sensor-token")
TIMEZONE = os.getenv("NIDS_TIMEZONE", "Africa/Lagos")
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()]
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@nids.local").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
ADMIN_NAME = os.getenv("ADMIN_NAME", "NIDS Administrator")
