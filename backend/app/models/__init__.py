from datetime import datetime, timezone
from app import db


class User(db.Model):
    __tablename__ = "user"

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hashed = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))

    files = db.relationship("EncryptedFile", backref="owner", lazy=True)
    metadata_records = db.relationship("Metadata", backref="owner", lazy=True)


class EncryptedFile(db.Model):
    __tablename__ = "encrypted_file"

    file_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    upload_timestamp = db.Column(db.DateTime(timezone=True), nullable=False,
                                 default=lambda: datetime.now(timezone.utc))
    iv = db.Column(db.String(32), nullable=False)

    metadata_record = db.relationship("Metadata", backref="encrypted_file",
                                      uselist=False, lazy=True)


class Metadata(db.Model):
    __tablename__ = "metadata"

    metadata_id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("encrypted_file.file_id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    enc_file_size = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False,
                          default=lambda: datetime.now(timezone.utc))
    transfer_frequency = db.Column(db.Integer, nullable=False, default=1)

    anomaly_result = db.relationship("AnomalyResult", backref="metadata_record",
                                     uselist=False, lazy=True)


class AnomalyResult(db.Model):
    __tablename__ = "anomaly_result"

    result_id = db.Column(db.Integer, primary_key=True)
    metadata_id = db.Column(db.Integer, db.ForeignKey("metadata.metadata_id"), nullable=False)
    zscore_value = db.Column(db.Float, nullable=True)
    iqr_threshold = db.Column(db.String(64), nullable=True)
    anomaly_flag = db.Column(db.Boolean, nullable=False, default=False)
    detected_at = db.Column(db.DateTime(timezone=True), nullable=False,
                            default=lambda: datetime.now(timezone.utc))