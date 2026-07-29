# SecureTransfer — Privacy-Preserving File Transfer Platform

> COM668 Computing Project · BSc (Hons) Computing · Ulster University · Academic Year 2025/26 — Semester I  
> Student: Vishnu Vekaria

---

## Overview

SecureTransfer is a zero-knowledge file transfer platform. All encryption happens **in the browser** using the Web Crypto API — the server stores only ciphertext and never has access to file content, filenames, or encryption keys.

The platform uses a **vault architecture** (inspired by Bitwarden) where a single master key is derived from the user's login password via PBKDF2 (200,000 iterations, SHA-256). This key encrypts every file and every filename. It is stored only in `sessionStorage` and never transmitted to the server.

On top of the zero-knowledge storage layer, a **metadata-only anomaly detection engine** runs Z-score and IQR statistical analysis on non-semantic transfer attributes (encrypted file size, timestamp, transfer frequency) — detecting abnormal patterns without ever inspecting file content.

---

## Tech Stack

### Backend
- **Python / Flask** — REST API with Blueprint structure
- **SQLite + SQLAlchemy** — ORM with 5-table schema
- **pyjwt** — JWT authentication (24-hour tokens, HS256)
- **bcrypt** — password hashing (12 rounds)
- **Flask-Limiter** — rate limiting on auth endpoints
- **Flask-CORS** — cross-origin support for Angular frontend
- **pytest** — 50 tests across 5 test modules (auth, dashboard, detection, files, share)

### Frontend
- **Angular 20** — standalone components, lazy-loaded routes
- **Web Crypto API** — PBKDF2 + AES-256-GCM, all in-browser
- **Chart.js** — dashboard visualisations
- **RxJS** — reactive HTTP and async vault operations

---

## Features

### Authentication
- Registration with email, username, password (bcrypt, 12 rounds)
- Login with JWT (24-hour expiry)
- Rate limiting: 5 registrations/min, 10 logins/min, 3 logins/10s
- `key_salt` generated per user at registration, returned on login for client-side key derivation

### Vault Architecture (Zero-Knowledge)
- On login: `PBKDF2(password + key_salt, 200k iterations, SHA-256)` → AES-256 master key
- Master key stored in `sessionStorage` only — cleared when the tab closes
- Never transmitted to the server under any circumstances
- All files and filenames encrypted with this single vault key

### File Management
- **Upload** — AES-256-GCM encryption in browser before upload; filename encrypted separately
- **My Files** — filenames auto-decrypted client-side on load; shows `••••••••••` when vault is locked
- **Download** — one-click; ciphertext fetched from server, decrypted in browser
- **Delete** — cascades through share tokens, anomaly results, and metadata

### Secure Sharing
- Owner generates a 24-hour share link and sets a **per-share passphrase**
- Client wraps the vault key: `PBKDF2(share_passphrase)` → AES-GCM encrypt(vault key raw bytes) → `wrapped_key` stored on token
- Recipient opens link, enters share passphrase → unwraps vault key → decrypts file
- Owner's login password is never shared or exposed
- Tokens expire automatically after 24 hours; owner can revoke early
- No authentication required for recipients
- Every download via a share link increments `access_count` and updates `last_accessed_at` on the token
- Owner can check access stats (`GET /api/share/<token>/stats`) to see how many times a link was used

### Anomaly Detection
- Fires automatically on every upload
- Dual algorithm: Z-score + IQR on encrypted file size metadata
- Results stored and displayed per file (✓ Normal / ⚠ Anomaly badge)
- Batch re-analysis endpoint for recalibration
- Ownership enforced: users can only analyse their own records

### Dashboard
- Total files, total size, anomaly count stat cards
- Upload frequency chart (Chart.js)
- File size distribution
- Anomaly events table with Z-score and IQR values

---

## Architecture

```
Browser
├── PBKDF2(password + key_salt)  →  AES-256 vault key (sessionStorage only)
├── AES-256-GCM encrypt(file)    →  ciphertext
├── AES-256-GCM encrypt(filename)→  filename_enc + filename_iv
│
│   [Only ciphertext + IV sent over HTTPS — no plaintext ever]
│
Flask API
├── /api/health     →  health check
├── /api/auth       →  register, login (rate-limited, bcrypt, JWT)
├── /api/files      →  upload, list, get, delete, dismiss-anomaly (ownership enforced)
├── /api/share      →  create token, retrieve ciphertext, access stats, revoke
├── /api/detection  →  analyse (single), batch (Z-score + IQR)
└── /api/dashboard  →  aggregated stats, frequency chart, size distribution, anomaly events
│
SQLite (via SQLAlchemy)
├── user              →  user_id, username, email, password_hashed, key_salt
├── encrypted_file    →  file_id, user_id, encrypted_data, iv, filename_enc, filename_iv
├── metadata          →  metadata_id, file_id, enc_file_size, timestamp, transfer_frequency
├── anomaly_result    →  result_id, metadata_id, zscore_value, iqr_threshold, anomaly_flag
└── share_token       →  token, file_id, expires_at, wrapped_key, share_salt, share_iv,
                          access_count, last_accessed_at
```

---

## Database Schema

| Table | Key Fields |
|-------|-----------|
| `user` | user_id, username, email, password_hashed, key_salt, created_at |
| `encrypted_file` | file_id, user_id, encrypted_data, iv, filename_enc, filename_iv, upload_timestamp |
| `metadata` | metadata_id, file_id, user_id, enc_file_size, timestamp, transfer_frequency |
| `anomaly_result` | result_id, metadata_id, zscore_value, iqr_threshold, anomaly_flag, detected_at |
| `share_token` | token_id, token, file_id, owner_id, expires_at, wrapped_key, share_salt, share_iv, access_count, last_accessed_at |

---

## Threat Model

- **Server model:** honest-but-curious — server follows the protocol but may attempt inference from stored data. Mitigated by encrypting both file content and filenames before upload.
- **Database breach:** attacker obtains only ciphertext, encrypted filenames, bcrypt hashes, and PBKDF2 salts. No plaintext is recoverable without the user's password.
- **Share link interception:** a stolen link alone is insufficient — the per-share passphrase (delivered out-of-band) is required to unwrap the vault key.
- **Out of scope:** compromised client devices, nation-state adversaries, side-channel attacks.

---

## Running Locally

### Backend
```bash
cd backend
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

### Frontend
```bash
cd frontend
npm install
ng serve
```

Open `http://localhost:4200`

### Tests
```bash
cd backend
python -m pytest tests/ -v
# 50 tests — auth, files, detection, share, dashboard
```

---

## Functional Requirements

| ID | Requirement | Status |
|----|-------------|--------|
| FR1 | Secure user registration + authentication | ✅ |
| FR2 | Password hashing (bcrypt, 12 rounds) | ✅ |
| FR3 | Client-side AES-256-GCM encryption before upload | ✅ |
| FR4 | Vault master key derived from password, never transmitted | ✅ |
| FR5 | Server stores ciphertext only — no plaintext, no filenames | ✅ |
| FR6 | Metadata logging (enc size, timestamp, frequency) | ✅ |
| FR7 | Z-score anomaly computation | ✅ |
| FR8 | IQR threshold computation | ✅ |
| FR9 | Flag entries exceeding thresholds, auto-fire on upload | ✅ |
| FR10 | Persist anomaly results, display per file | ✅ |
| FR11 | Dashboard visualisation with Chart.js | ✅ |
| FR12 | Secure 24-hour share links with per-share key wrapping | ✅ |
| FR13 | Rate limiting on authentication endpoints | ✅ |
| FR14 | File delete with cascade | ✅ |

---

## Project Status

| Phase | Status |
|-------|--------|
| Backend API (auth, files, detection, share, dashboard) | ✅ Complete |
| Frontend (Angular 20, vault, upload, files, share, dashboard) | ✅ Complete |
| Test suite (50 tests, 0 warnings) | ✅ Complete |
| Demo video | ⏳ Pending |

**AT3 Deadline: 7 July 2026, 12:00 noon**

---

## Academic Context

- **Module:** COM668 Computing Project
- **Institution:** Ulster University
- **Academic Year:** 2025/26, Semester I
- **AT1 Concept Proposal:** submitted (12 February, formative)
- **AT2 Challenge Definition Report:** submitted, 45% of module mark
- **AT3 Software Demonstration Video:** due 7 July 2026, 12:00 noon, 25% of module mark (15 minutes max)
- **AT4 Project Review Report:** due 11 August 2026, 12:00 noon, 30% of module mark (2400 words max)

---

## Disclaimer

This repository is submitted as part of an assessed university module. All work is my own. Any referenced material is cited in the accompanying report. AI tool contributions are fully acknowledged per Ulster University academic integrity policy.
