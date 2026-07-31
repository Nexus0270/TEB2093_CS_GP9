# TEB2093 Computer Security — Coursework Demos

This repository contains two hands-on demos built for a Computer Security course. Each demo pairs a small Flask app with companion scripts that simulate an attacker, so you can show a control working *and* show what happens when it's attacked.

| Asset | Control demonstrated | Folder |
|---|---|---|
| **Asset 1** | Login security: MFA/OTP, rate limiting/lockout, bcrypt password hashing | [`login-control/`](./login-control) |
| **Asset 2** | Data protection: field-level encryption at rest (Fernet: AES‑128‑CBC + HMAC‑SHA256), key/data separation | [`database-encryption/`](./database-encryption) |

---

## Repository structure

```
.
├── login-control/
│   ├── app.py                     # Flask app: registration, login, MFA
│   ├── totp_display.py            # Simulated authenticator app (prints live OTP)
│   ├── attacker_bruteforce.py     # Simulates credential stuffing / brute force
│   ├── attacker_hash_crack.py     # Simulates offline dictionary attack on a stolen hash
│   ├── start_app.bat              # One-click launcher (Windows)
│   ├── requirements.txt
│   └── README.md                  # Full command & scenario walkthrough
│
└── database-encryption/
    ├── app_styled.py               # Flask app: add records, authorized view, attacker view
    ├── attacker_attempt.py         # Simulates an attacker with a stolen DB copy
    └── README.md                   # Full setup guide (encryption demo)
```

Each subfolder's README contains the detailed, step-by-step commands for that demo. This top-level README is just the map.

---

## Asset 1: Login Control

Demonstrates why multi-factor authentication and rate limiting matter, using four scenarios:

1. **Legitimate login** — correct password + current OTP → dashboard access.
2. **Brute-force / credential stuffing** — automated guessing against the login form, showing lockout after repeated failures.
3. **Offline dictionary attack on a stolen hash** — simulates a DB leak, then times how long bcrypt (cost factor 12) resists cracking attempts.
4. **Correct password, no MFA device** — shows that a leaked/guessed password alone isn't enough to log in.

**Stack:** Python, Flask, bcrypt, TOTP (RFC 6238), SQLite.
**Platform:** Windows Terminal, no venv required.

---

## Asset 2: Database Encryption at Rest

Demonstrates field-level encryption for sensitive customer data (email, credit card), and — critically — that encryption only protects data when the key is stored separately from the database.

- **Authorized View** — the app decrypts data because it holds the key.
- **Attacker View / `attacker_attempt.py`** — a copy of the database file alone yields only ciphertext (`InvalidToken` errors).
- **Optional contrast test** — if the attacker also obtains `secret.key`, decryption succeeds, illustrating that *key separation*, not encryption alone, is what makes the control effective.

**Stack:** Python, Flask, `cryptography` (Fernet), SQLite.
**Platform:** WSL2/Ubuntu recommended, uses a Python venv.

---

## Quick start

```bash
# Asset 1 (Windows Terminal)
cd login-control
pip install -r requirements.txt
python app.py

# Asset 2 (WSL2/Ubuntu)
cd database-encryption
python3 -m venv venv && source venv/bin/activate
pip install flask cryptography
python3 app_styled.py
```
