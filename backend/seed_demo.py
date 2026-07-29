"""
Demo seed script — populates the database with realistic transfer history
for a demo user so that anomaly detection has enough data to fire.

Usage:
    python seed_demo.py

Creates user `demo` / password `Demo1234!` if it doesn't exist, then inserts
14 normal-sized transfers and 1 clear outlier so the anomaly badge is visible.
"""

import base64
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app import create_app, db
from app.models import User, EncryptedFile, Metadata, AnomalyResult
from app.services.anomaly_service import analyse_metadata
import bcrypt


DEMO_USERNAME = "demo"
DEMO_PASSWORD = "Demo1234!"
DEMO_EMAIL    = "demo@securetransfer.local"

DEFAULT_LOCAL_DB = "sqlite:///securetransfer.db"


def _check_target_db():
    """Refuse to seed a non-local database unless explicitly forced and confirmed."""
    db_uri = os.getenv("DATABASE_URI", DEFAULT_LOCAL_DB)
    print(f"Target database: {db_uri}")

    if db_uri == DEFAULT_LOCAL_DB:
        return

    if "--force" not in sys.argv:
        print(
            "\nRefusing to run: DATABASE_URI does not point at the local dev database.\n"
            "This script creates a known demo account (demo / Demo1234!) and is not "
            "safe to run against a deployed instance.\n"
            "Pass --force to override."
        )
        sys.exit(1)

    answer = input(
        f"\nAbout to seed a NON-LOCAL database: {db_uri}\nType 'yes' to continue: "
    )
    if answer.strip().lower() != "yes":
        print("Aborted.")
        sys.exit(1)

# 14 normal transfers (~50–200 KB encrypted) + 1 giant outlier (~4 MB)
# These represent realistic user behaviour: mostly small docs, one huge file
TRANSFER_SIZES = [
    52_400,   # ~51 KB  — small text doc
    68_900,   # ~67 KB
    81_200,   # ~79 KB
    95_600,   # ~93 KB
    102_400,  # ~100 KB — typical PDF page
    115_000,  # ~112 KB
    128_800,  # ~126 KB
    143_200,  # ~140 KB
    158_700,  # ~155 KB
    172_100,  # ~168 KB
    189_400,  # ~185 KB
    201_300,  # ~197 KB
    214_900,  # ~210 KB
    223_600,  # ~218 KB — upper end of normal
    4_194_304, # ~4 MB  — OUTLIER: triggers anomaly flag
]

FAKE_IV       = base64.b64encode(b"x" * 12).decode()
FAKE_CIPHER   = base64.b64encode(b"c" * 32).decode()


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def seed():
    app = create_app("development")
    with app.app_context():
        # Get or create demo user
        user = User.query.filter_by(username=DEMO_USERNAME).first()
        if not user:
            user = User(
                username=DEMO_USERNAME,
                email=DEMO_EMAIL,
                password_hashed=_hash(DEMO_PASSWORD),
                key_salt=base64.b64encode(os.urandom(16)).decode(),
            )
            db.session.add(user)
            db.session.commit()
            print(f"Created user '{DEMO_USERNAME}'")
        else:
            print(f"User '{DEMO_USERNAME}' already exists — adding transfers")

        # Insert transfers
        inserted = 0
        for i, size in enumerate(TRANSFER_SIZES):
            fake_data = os.urandom(min(size, 256))  # store a small real blob
            enc_file = EncryptedFile(
                user_id=user.user_id,
                filename=None,
                filename_enc=base64.b64encode(b"encrypted_name_" + str(i).encode()).decode(),
                filename_iv=FAKE_IV[:24],
                encrypted_data=fake_data,
                iv=FAKE_IV,
                salt=None,
            )
            db.session.add(enc_file)
            db.session.flush()

            meta = Metadata(
                file_id=enc_file.file_id,
                user_id=user.user_id,
                enc_file_size=size,
                transfer_frequency=i + 1,
            )
            db.session.add(meta)
            db.session.flush()
            inserted += 1

        db.session.commit()
        print(f"Inserted {inserted} transfer records")

        # Run anomaly detection on all records
        all_meta = Metadata.query.filter_by(user_id=user.user_id).all()
        flagged = 0
        for m in all_meta:
            result = analyse_metadata(m.metadata_id)
            if result["is_flagged"]:
                flagged += 1
                print(f"  [FLAGGED] metadata_id={m.metadata_id} size={m.enc_file_size:,}B "
                      f"Z={result['zscore']} IQR={result['iqr_flagged']}")

        # Evaluation metrics — ground truth: any file >= 1 MB is a genuine outlier
        OUTLIER_THRESHOLD = 1_000_000
        all_meta_eval = Metadata.query.filter_by(user_id=user.user_id).all()
        tp = fp = fn = tn = 0
        for m in all_meta_eval:
            result = AnomalyResult.query.filter_by(metadata_id=m.metadata_id).first()
            is_flagged = result.anomaly_flag if result else False
            is_outlier = m.enc_file_size >= OUTLIER_THRESHOLD
            if is_flagged and is_outlier:     tp += 1
            elif is_flagged and not is_outlier: fp += 1
            elif not is_flagged and is_outlier: fn += 1
            else:                              tn += 1

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        fpr       = fp / (fp + tn) if (fp + tn) else 0.0

        print(f"\n--- Evaluation Metrics (ground truth: size >= 1 MB = outlier) ---")
        print(f"True Positives  (correctly flagged outliers) : {tp}")
        print(f"False Positives (normal files wrongly flagged): {fp}")
        print(f"False Negatives (outliers missed)            : {fn}")
        print(f"True Negatives  (normal files correctly OK)  : {tn}")
        print(f"Precision          : {precision:.2f}")
        print(f"Recall             : {recall:.2f}")
        print(f"False Positive Rate: {fpr:.2f}")
        print(f"------------------------------------------------------------------")

        print(f"\nDone. {inserted} transfers, {flagged} anomaly flag(s).")
        print(f"\nDemo login: username='{DEMO_USERNAME}'  password='{DEMO_PASSWORD}'")


if __name__ == "__main__":
    _check_target_db()
    seed()
