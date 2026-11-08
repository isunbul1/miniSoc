"""Verification script for Phase 5 backend stats & end-to-end integration.

Uses an isolated test database (verification_phase5.db).
NEVER touches backend/minisoc.db.
"""

import os
import sys

# Ensure backend directory is in python path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, backend_dir)

# Set isolated database and development environment
test_db_path = os.path.join(backend_dir, "verification_phase5.db")
if os.path.exists(test_db_path):
    os.remove(test_db_path)

os.environ["DATABASE_URL"] = f"sqlite:///{test_db_path}"
os.environ["ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient
from app.main import app
from app.db.init_db import init_db

print(f"Initializing isolated verification DB at: {test_db_path}")
init_db()

client = TestClient(app)

# 1. Check health
health_res = client.get("/api/v1/health")
assert health_res.status_code == 200, f"Health check failed: {health_res.text}"
print(f"1. Health check passed: {health_res.json()}")

# 2. Check stats on empty DB
empty_stats = client.get("/api/v1/stats/summary")
assert empty_stats.status_code == 200, f"Stats failed: {empty_stats.text}"
stats_data = empty_stats.json()
assert stats_data["total_logs"] == 0
assert stats_data["total_alerts"] == 0
assert len(stats_data["log_counts_per_hour"]) == 24
print("2. Empty DB stats summary verified (0 logs, 0 alerts, 24 hourly buckets).")

# 3. Generate demo logs
gen_res = client.post("/api/v1/logs/generate", json={"seed": 42})
assert gen_res.status_code == 201, f"Generate logs failed: {gen_res.text}"
print(f"3. Generated logs successfully: {gen_res.json()}")

# 4. Run detection engine
det_res = client.post("/api/v1/detection/run")
assert det_res.status_code == 200, f"Detection run failed: {det_res.text}"
print(f"4. Threat detection run successfully: {det_res.json()}")

# 5. Check populated stats summary
populated_stats = client.get("/api/v1/stats/summary")
assert populated_stats.status_code == 200
pdata = populated_stats.json()
print(f"5. Populated stats: {pdata['total_logs']} logs, {pdata['total_alerts']} alerts")
print(f"   Severity breakdown: {pdata['alerts_by_severity']}")
print(f"   Status breakdown: {pdata['alerts_by_status']}")
print(f"   MITRE techniques: {pdata['alerts_by_mitre']}")
assert pdata["total_logs"] > 0
assert pdata["total_alerts"] > 0

# 6. Check alert triage PATCH workflow
alerts_res = client.get("/api/v1/alerts")
assert alerts_res.status_code == 200
alerts = alerts_res.json()["items"]
assert len(alerts) > 0
first_alert_id = alerts[0]["id"]

patch_res = client.patch(f"/api/v1/alerts/{first_alert_id}", json={"status": "investigating"})
assert patch_res.status_code == 200
assert patch_res.json()["status"] == "investigating"

patch_res2 = client.patch(f"/api/v1/alerts/{first_alert_id}", json={"status": "resolved"})
assert patch_res2.status_code == 200
assert patch_res2.json()["status"] == "resolved"
print(f"6. Alert #{first_alert_id} triage workflow (open -> investigating -> resolved) verified.")

# Cleanup isolated verification db
from app.db.database import engine
engine.dispose()

if os.path.exists(test_db_path):
    os.remove(test_db_path)
print("Verification complete. Isolated database cleanly removed.")
