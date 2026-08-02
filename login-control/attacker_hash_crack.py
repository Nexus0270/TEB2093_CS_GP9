"""
Scenario 3: Attacker steals the password hash (simulated DB leak) and
attempts an offline dictionary attack. Demonstrates that bcrypt's cost
factor makes this impractical.

Get a stolen hash by opening users.db yourself, e.g.:
    sqlite3 users.db "SELECT password_hash FROM users WHERE username='victim';"

Usage:
    python attacker_hash_crack.py "<stolen_bcrypt_hash>"
"""
import sys
import time
import bcrypt

if len(sys.argv) < 2:
    print('Usage: python attacker_hash_crack.py "<stolen_bcrypt_hash>"')
    sys.exit(1)

stolen_hash = sys.argv[1].encode()

CANDIDATES = [
    "123456", "password", "qwerty", "letmein",
    "admin123", "welcome1", "iloveyou", "111111",
]

print(f"Attempting offline dictionary attack against stolen hash:\n{stolen_hash.decode()}\n")

start = time.time()
found = None
for pwd in CANDIDATES:
    t0 = time.time()
    match = bcrypt.checkpw(pwd.encode(), stolen_hash)
    elapsed = time.time() - t0
    print(f"Trying {pwd!r}... ({elapsed:.2f}s for this attempt)")
    if match:
        found = pwd
        break
total = time.time() - start

if found:
    print(f"\nCRACKED: {found}  (total time: {total:.2f}s)")
else:
    print(f"\nNo match in candidate list (total time: {total:.2f}s).")

print(
    "\nNote: bcrypt's cost factor (12) intentionally makes each attempt slow, "
    "making large-scale dictionary/brute-force attacks against a stolen hash "
    "impractical at scale."
)
