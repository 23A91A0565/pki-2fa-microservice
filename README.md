# Auth Microservice

## Overview

This project implements a **secure, containerized authentication microservice** with enterprise-grade security practices. It demonstrates:

- **RSA 4096-bit encryption** for secure seed transmission  
- **TOTP-based 2FA** (Two-Factor Authentication) for user verification  
- **Docker containerization** with persistent storage and cron job for automated logging  
- REST API endpoints for decryption, 2FA generation, and verification  


---

## Features

1. **RSA Seed Decryption** – Decrypt instructor-provided encrypted seed using student private key.  
2. **TOTP 2FA Generation** – Generate 6-digit time-based one-time passwords.  
3. **2FA Verification** – Validate user-provided TOTP codes with time window tolerance.  
4. **Cron Job Logging** – Automatically logs 2FA codes every minute to `/cron/cron.log`.  
5. **Persistent Storage** – Seed and logs survive container restarts using Docker volumes (`/data` and `/cron`).

---

## API Endpoints

| Method | Endpoint          | Description                                |
|--------|-----------------|--------------------------------------------|
| POST   | `/decrypt-seed`  | Decrypts the encrypted seed and stores it |
| GET    | `/generate-2fa`  | Generates current TOTP 2FA code           |
| POST   | `/verify-2fa`    | Verifies a given TOTP code                |

# Build Docker image
docker-compose build

# Start containers in detached mode
docker-compose up -d

# Check running containers
docker ps


**Example**:

```bash
# Decrypt seed
curl -X POST http://localhost:8080/decrypt-seed \
-H "Content-Type: application/json" \
-d '{"encrypted_seed": "<PASTE_ENCRYPTED_SEED>"}'

# Generate TOTP code
curl http://localhost:8080/generate-2fa

# Verify TOTP code
curl -X POST http://localhost:8080/verify-2fa \
-H "Content-Type: application/json" \
-d '{"code": "123456"}'
