"""CLI script to generate synthetic security logs into the MiniSOC database.

Usage:
    python scripts/generate_logs.py [--seed SEED]
"""

import argparse
import sys
from pathlib import Path

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.db.database import SessionLocal
from app.db.init_db import init_db
from app.models.security_log import SecurityLog
from app.services.log_generator import generate_synthetic_logs


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic security logs.")
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible log generation (default: 42)",
    )
    args = parser.parse_args()

    print(f"Initializing database and seeding reference data...")
    init_db()

    print(f"Generating synthetic security logs with seed={args.seed}...")
    log_dicts = generate_synthetic_logs(seed=args.seed)

    db = SessionLocal()
    try:
        inserted = 0
        for entry in log_dicts:
            log_model = SecurityLog(**entry)
            db.add(log_model)
            inserted += 1
        db.commit()
        print(f"Successfully generated and inserted {inserted} synthetic security logs into the database.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
