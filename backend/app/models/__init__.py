import uuid
from datetime import datetime, timezone, timedelta
from app import db


class User(db.Model):
    __tablename__ = "user"

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hashed = db.Column(db.String(256), nullable=False)
    key_salt = db.Column(db.String(64), nullable=True)  # PBKDF2 salt for client-side vault key
    created_at = db.Column(db.DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))

    files = db.relationship("EncryptedFile", backref="owner", lazy=True)
    metadata_records = db.relationship("Metadata", backref="owner", lazy=True)


class EncryptedFile(db.Model):
    __tablename__ = "encrypted_file"

    file_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    filename = db.Column(db.String(255), nullable=True)          # plaintext fallback
    filename_enc = db.Column(db.Text, nullable=True)             # AES-GCM encrypted filename (base64)
    filename_iv = db.Column(db.String(32), nullable=True)        # IV for filename encryption
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    upload_timestamp = db.Column(db.DateTime(timezone=True), nullable=False,
                                 default=lambda: datetime.now(timezone.utc))
    iv = db.Column(db.String(32), nullable=False)
    salt = db.Column(db.String(64), nullable=True)

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


class ShareToken(db.Model):
    """Time-limited token allowing unauthenticated download of one file."""
    __tablename__ = "share_token"

    token_id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False,
                      default=lambda: uuid.uuid4().hex)
    file_id = db.Column(db.Integer, db.ForeignKey("encrypted_file.file_id"), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc) + timedelta(hours=24))
    # Per-share key wrapping: vault key encrypted with PBKDF2(share_passphrase)
    wrapped_key = db.Column(db.Text, nullable=True)      # base64 AES-GCM ciphertext of vault key
    share_salt  = db.Column(db.String(64), nullable=True) # base64 PBKDF2 salt
    share_iv    = db.Column(db.String(32), nullable=True) # hex IV for vault key encryption
    # Access tracking: count how many times this token has been used to download
    access_count = db.Column(db.Integer, nullable=False, default=0)
    last_accessed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    @property
    def is_expired(self):
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires


class AnomalyResult(db.Model):
    __tablename__ = "anomaly_result"

    result_id = db.Column(db.Integer, primary_key=True)
    metadata_id = db.Column(db.Integer, db.ForeignKey("metadata.metadata_id"), nullable=False)
    zscore_value = db.Column(db.Float, nullable=True)
    iqr_threshold = db.Column(db.String(64), nullable=True)
    anomaly_flag = db.Column(db.Boolean, nullable=False, default=False)
    detected_at = db.Column(db.DateTime(timezone=True), nullable=False,
                            default=lambda: datetime.now(timezone.utc))