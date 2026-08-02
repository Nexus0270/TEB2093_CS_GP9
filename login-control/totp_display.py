"""
Simulated authenticator app.
Run this in a second terminal after registering, using the secret
shown on the "Account created" page.

Usage:
    python totp_display.py <TOTP_SECRET>
"""
import sys
import time
import pyotp

if len(sys.argv) < 2:
    print("Usage: python totp_display.py <TOTP_SECRET>")
    sys.exit(1)

secret = sys.argv[1]
totp = pyotp.TOTP(secret)

print(f"Simulated Authenticator App\nSecret: {secret}\n")
try:
    while True:
        code = totp.now()
        remaining = totp.interval - (int(time.time()) % totp.interval)
        print(f"Current OTP: {code}   (refreshes in {remaining}s)   ", end="\r")
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopped.")
