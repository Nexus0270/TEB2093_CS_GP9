"""
Dynamic attacker script.
Checks whether secret.key exists in the current folder:
  - If NOT present: attacker only has the stolen database -> decryption fails (InvalidToken)
  - If present: attacker has both the database AND the key -> decryption succeeds

This single script represents a realistic attacker: they don't know in advance
what they'll find, they just attempt decryption with whatever is available.

Usage: python3 attacker_dynamic.py
"""

import os
import sqlite3
from cryptography.fernet import Fernet, InvalidToken

DB_FILE = "customers_encrypted.db"
KEY_FILE = "secret.key"

key_found = os.path.exists(KEY_FILE)

if key_found:
    print("[*] secret.key FOUND in this folder. Using it for decryption attempts.\n")
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
else:
    print("[*] secret.key NOT found in this folder. Using a random guessed key instead.\n")
    key = Fernet.generate_key()
    fernet = Fernet(key)

conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()
cur.execute("SELECT id, username, email_enc, credit_card_enc FROM customers")
rows = cur.fetchall()
conn.close()

print("Attacker pulled {0} row(s) from the stolen database.\n".format(len(rows)))

any_success = False
for row in rows:
    row_id, username, email_enc, cc_enc = row
    print("--- Row id={0}, username={1} ---".format(row_id, username))
    print("  Raw stolen ciphertext (email): {0}".format(email_enc))
    try:
        email = fernet.decrypt(email_enc).decode()
        cc = fernet.decrypt(cc_enc).decode()
        print("  Decryption SUCCEEDED: email={0}, credit_card={1}".format(email, cc))
        any_success = True
    except InvalidToken:
        print("  Decryption FAILED: InvalidToken")
    print("")

print("=" * 60)
if key_found and any_success:
    print("RESULT: Attacker had BOTH the database and the key -> full data recovered.")
    print("This is why encryption alone is not enough - key separation is essential.")
else:
    print("RESULT: Attacker had the database but NOT the key -> no data recovered.")
    print("This demonstrates the control working as intended.")