# Privacy-Preserving File Transfer Platform

## Problem Statement

Modern cloud-based file transfer systems require users to trust service providers with sensitive data. While end-to-end encryption enhances confidentiality, it often eliminates server-side visibility entirely, limiting the ability to detect abnormal or potentially harmful usage patterns. This project evaluates whether structured metadata analysis can provide operational insight without exposing file content.

---

## Research Question

To what extent can statistically explainable anomaly detection techniques applied to structured file-transfer metadata provide meaningful operational insight within a zero-knowledge, client-side encrypted architecture without compromising confidentiality?

---

## Objectives

- Design and justify a zero-knowledge client-side encryption architecture  
- Implement encrypted file transfer with structured metadata capture  
- Generate controlled synthetic datasets to model normal and anomalous behaviour  
- Apply Z-score and IQR anomaly detection techniques to metadata  
- Evaluate detection performance using precision, recall, and false positive rate  
- Analyse privacy–visibility trade-offs in the system architecture  
- Critically assess technical limitations and ethical implications  

---

## Threat Model

The system assumes an honest-but-curious server model:

- File content is encrypted client-side prior to upload  
- Encryption keys are generated and retained client-side  
- The server stores encrypted files and structured metadata only  
- Metadata is restricted to non-semantic attributes (e.g., file size, timestamp, frequency)

### Non-Goals

- Protection against compromised client devices  
- Advanced traffic analysis resistance  
- Malicious users operating with valid credentials  

---

## Methodology

A hybrid approach combines structured research planning with iterative Agile implementation. System boundaries, threat model, and requirements are defined during the planning phase. Implementation proceeds incrementally, followed by controlled experimental evaluation of anomaly detection techniques.

---

## Planned Technology Stack

- Python  
- Flask  
- AES-GCM client-side encryption (via Web Crypto API)  
- Structured metadata logging  
- Statistical anomaly detection (Z-score, IQR)  
- Synthetic dataset generation for controlled evaluation  

---

## Evaluation Strategy

- Requirement-based verification testing  
- Controlled anomaly detection performance evaluation  
- Risk-informed analysis of architectural decisions  
- Critical assessment of trade-offs and system limitations  

---

## Project Phases

**AT2 – Challenge Definition**  
Research framing, literature review, methodology justification, requirements engineering, risk management, and system design.

**AT3 – Software Demonstration**  
Implementation of encrypted file transfer, metadata logging, anomaly detection, and monitoring dashboard.

**AT4 – Project Review**  
Verification, validation, performance evaluation, architectural trade-off analysis, and critical reflection.

---

## Repository Structure

- `docs/` – Academic documentation and diagrams  
- `project_management/` – Risk register, traceability matrix, progress log  
- `src/` – Application source code  
- `tests/` – Testing scripts and validation logic  
