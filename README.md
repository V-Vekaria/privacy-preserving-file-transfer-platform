# SecureTransfer — Privacy-Preserving File Transfer Platform

> COM668 Computing Project · BSc (Hons) Computing · Ulster University · 2024/2025  
> Student: Vishnu Vekaria · B00969091 · Mentor: Mr. Prathap Soma

---

## Overview

SecureTransfer is a web-based file transfer platform that enforces **client-side AES-GCM encryption** before any data reaches the server, ensuring plaintext file content is never accessible server-side (zero-knowledge boundary). On top of this privacy-preserving storage layer, the platform runs a **metadata-only anomaly detection engine** using Z-score and IQR statistical methods — detecting abnormal usage patterns without ever inspecting file content.

This project demonstrates that meaningful anomaly detection can operate entirely within a zero-knowledge architectural boundary using only non-semantic structured metadata (encrypted file size, timestamp, transfer frequency).

---

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| AT2 | Challenge Definition Report | ✅ Submitted |
| AT3 Week 1 | Flask scaffold + models | ✅ Complete |
| AT3 Week 2 | Auth routes + JWT | ✅ Complete |
| AT3 Week 3 | File upload + metadata logging | 🔄 In Progress |
| AT3 Week 4 | Z-score + IQR detection engine | 🔄 In Progress |
| AT3 Week 5 | Angular init + auth module | ⏳ Pending |
| AT3 Week 6 | Upload component + dashboard | ⏳ Pending |
| AT3 Week 7 | Testing + fixes | ⏳ Pending |
| AT3 Week 8 | Demo video + submission | ⏳ Pending |

**Deadline: 7 July 2025, 12:00 noon**

---

## Tech Stack

### Backend
- **Python / Flask** — REST API server
- **SQLite + SQLAlchemy** — database ORM
- **pyjwt** — JWT-based session tokens
- **bcrypt** — password hashing

### Frontend
- **Angular** — SPA framework
- **Web Crypto API** — in-browser AES-GCM encryption (key never leaves client)
- **Chart.js** — dashboard visualisations

### Dev Environment
- OS: Windows
- Editor: VS Code
- Node: v24.15.0 · npm: 11.12.1

---

## Core Features (Planned)

- **Client-Side Encryption** — AES-GCM via Web Crypto API; key generated and retained in browser only; IV transmitted with ciphertext
- **Zero-Knowledge Storage** — server stores ciphertext binary; no decryption pathway server-side
- **Secure Authentication** — bcrypt password hashing; JWT session management
- **Metadata Logging** — non-semantic attributes only: encrypted file size, timestamp, transfer frequency; no filenames stored
- **Anomaly Detection Engine** — Z-score and IQR thresholding; real-time trigger on upload + periodic batch recalibration
- **Analytics Dashboard** — colour-coded stat cards, upload frequency chart, file size distribution histogram, flagged anomaly events table with Z-score and IQR values per row

---

## Architecture

```
Client (Browser)
├── Web Crypto API  →  AES-GCM encrypt (key stays here)
├── Angular UI      →  file select, upload, dashboard
│
│   [HTTPS / TLS — only ciphertext + IV transmitted]
│
Flask Server
├── Auth Module     →  bcrypt hash, JWT issue/verify
├── API Layer       →  file endpoints, metadata logging, dashboard data
├── Detection Engine→  Z-score + IQR, anomaly flagging, batch recalibration
│
Storage
├── Encrypted File Storage  →  ciphertext binary
├── Metadata DB             →  enc_file_size, timestamp, transfer_frequency
└── Anomaly Results DB      →  zscore_value, iqr_threshold, anomaly_flag
```

---

## Database Schema (4 tables)

| Table | Key Fields |
|-------|-----------|
| `USER` | user_id, username, email, password_hashed, created_at |
| `ENCRYPTED_FILE` | file_id, user_id, encrypted_data, upload_timestamp, iv |
| `METADATA` | metadata_id, file_id, user_id, enc_file_size, timestamp, transfer_frequency |
| `ANOMALY_RESULT` | result_id, metadata_id, zscore_value, iqr_threshold, anomaly_flag, detected_at |

---

## Threat Model

- **Server model:** honest-but-curious (server follows protocol but may attempt inference from stored data)
- **Out of scope:** compromised client devices, nation-state adversaries, ML-based detection, blockchain integration, enterprise multi-tenancy

---

## Development Conventions

- **Branch strategy:** one feature branch per component
- **Commit format:** Conventional Commits — `feat/fix/chore/test` prefixes
- **Commit cadence:** ~3–4 commits/week · ~28 total commits target
- **Scope discipline:** Must requirements implemented before Should/Could items

---

## Functional Requirements Summary

| ID | Requirement | Priority |
|----|-------------|----------|
| FR1 | Secure user registration + authentication | Must |
| FR2 | Password hashing (bcrypt/Argon2) | Must |
| FR3 | Client-side AES-GCM encryption before upload | Must |
| FR4 | Keys generated + retained client-side only | Must |
| FR5 | Server stores encrypted content only | Must |
| FR6 | Metadata logging (size, timestamp, frequency) | Must |
| FR7 | Z-score anomaly computation | Must |
| FR8 | IQR threshold computation | Must |
| FR9 | Flag entries exceeding thresholds | Must |
| FR10 | Persist anomaly results for review | Must |
| FR11 | Dashboard visualisation | Should |

---

## Academic Context

- **Module:** COM668 Computing Project
- **Institution:** Ulster University
- **PSG:** PSG-Q1
- **AT2 Report:** Challenge Definition Report (submitted 23 April 2025)
- **AT3 Deliverable:** Working prototype + demo video (due 7 July 2025)
- **AT4 Deliverable:** Final evaluation report (due 11 August 2025)

---

## Disclaimer

This repository is submitted as part of an assessed university module. All work is my own. Any referenced material is cited in the accompanying report. AI tool contributions are fully acknowledged per Ulster University academic integrity policy.
