"""
Customer Database Security Control Demo - Styled Edition
TEB2093 Project - Asset 2: Customer/Item Database
Control: Field-level Encryption at Rest (encrypt on write, decrypt on authorized read)

Same encryption logic as before (Fernet: AES-128-CBC + HMAC-SHA256, key stored
separately from the database) - this version has a redesigned visual interface
suitable for live demo / evaluation.
"""

import os
import sqlite3
from flask import Flask, request, render_template_string
from cryptography.fernet import Fernet, InvalidToken

APP_DB = "customers_encrypted.db"
KEY_FILE = "secret.key"

app = Flask(__name__)


def get_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    with open(KEY_FILE, "rb") as f:
        return f.read()


KEY = get_or_create_key()
fernet = Fernet(KEY)


def init_db():
    if os.path.exists(APP_DB):
        os.remove(APP_DB)
    conn = sqlite3.connect(APP_DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email_enc BLOB,
            credit_card_enc BLOB
        )
    """)
    conn.commit()
    conn.close()


def encrypt(plaintext):
    return fernet.encrypt(plaintext.encode())


def decrypt(ciphertext):
    return fernet.decrypt(ciphertext).decode()


BASE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{{ title }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0B1220;
    --panel: #121B2E;
    --panel-border: #223049;
    --text: #C9D6E3;
    --text-dim: #7E8FA8;
    --accent-key: #F5C744;
    --accent-safe: #3ED598;
    --accent-danger: #FF6B5B;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Space Grotesk', sans-serif;
    margin: 0;
    padding: 0;
    min-height: 100vh;
  }
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 32px;
    border-bottom: 1px solid var(--panel-border);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 700;
    font-size: 18px;
    letter-spacing: 0.02em;
  }
  .brand .dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--accent-safe);
    box-shadow: 0 0 8px var(--accent-safe);
  }
  nav a {
    color: var(--text-dim);
    text-decoration: none;
    font-size: 14px;
    margin-left: 24px;
    padding: 6px 12px;
    border-radius: 6px;
    transition: all 0.15s ease;
  }
  nav a:hover, nav a.active {
    color: var(--text);
    background: var(--panel);
  }
  main {
    max-width: 820px;
    margin: 0 auto;
    padding: 40px 24px 80px;
  }
  h1 {
    font-size: 28px;
    margin: 0 0 6px;
    letter-spacing: -0.01em;
  }
  .subtitle {
    color: var(--text-dim);
    font-size: 14px;
    margin-bottom: 28px;
  }
  .panel {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 4px 10px;
    border-radius: 20px;
    margin-bottom: 14px;
  }
  .badge.safe { background: rgba(62,213,152,0.12); color: var(--accent-safe); border: 1px solid rgba(62,213,152,0.35); }
  .badge.danger { background: rgba(255,107,91,0.12); color: var(--accent-danger); border: 1px solid rgba(255,107,91,0.35); }
  .badge.key { background: rgba(245,199,68,0.12); color: var(--accent-key); border: 1px solid rgba(245,199,68,0.35); }
  label {
    display: block;
    font-size: 13px;
    color: var(--text-dim);
    margin-bottom: 6px;
    margin-top: 16px;
  }
  input {
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--panel-border);
    color: var(--text);
    padding: 10px 12px;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
  }
  input:focus { outline: none; border-color: var(--accent-safe); }
  button {
    margin-top: 22px;
    background: var(--accent-safe);
    color: #06140F;
    border: none;
    padding: 12px 22px;
    border-radius: 8px;
    font-weight: 700;
    font-size: 14px;
    cursor: pointer;
    font-family: 'Space Grotesk', sans-serif;
  }
  button:hover { filter: brightness(1.08); }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th {
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-dim);
    padding: 8px 10px;
    border-bottom: 1px solid var(--panel-border);
  }
  td {
    padding: 10px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    border-bottom: 1px solid rgba(34,48,73,0.5);
    word-break: break-all;
    vertical-align: top;
  }
  .cipher { color: var(--text-dim); }
  .plain { color: var(--accent-safe); font-weight: 700; }
  .fail { color: var(--accent-danger); font-weight: 700; }
  .lockicon { font-size: 15px; }
  .footnote {
    font-size: 12px;
    color: var(--text-dim);
    margin-top: 16px;
    line-height: 1.6;
  }
</style>
</head>
<body>
  <div class="topbar">
    <div class="brand"><span class="dot"></span> VaultDemo — Customer DB Encryption Control</div>
    <nav>
      <a href="/" class="{{ 'active' if active=='add' else '' }}">Add Record</a>
      <a href="/view" class="{{ 'active' if active=='view' else '' }}">Authorized View</a>
      <a href="/attacker_dump" class="{{ 'active' if active=='attacker' else '' }}">Attacker View</a>
    </nav>
  </div>
  <main>
    {{ body|safe }}
  </main>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def add_customer():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        cc = request.form["credit_card"]

        email_enc = encrypt(email)
        cc_enc = encrypt(cc)

        conn = sqlite3.connect(APP_DB)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO customers (username, email_enc, credit_card_enc) VALUES (?, ?, ?)",
            (username, email_enc, cc_enc),
        )
        conn.commit()
        conn.close()

        body = """
        <h1>Record encrypted &amp; stored</h1>
        <div class="subtitle">Here is exactly what was written to the database column.</div>
        <div class="panel">
          <span class="badge safe">&#128274; Encrypted before storage</span>
          <table>
            <tr><th>Field</th><th>Stored value</th></tr>
            <tr><td>username</td><td>{0}</td></tr>
            <tr><td>email_enc</td><td class="cipher">{1}</td></tr>
            <tr><td>credit_card_enc</td><td class="cipher">{2}</td></tr>
          </table>
          <div class="footnote">Plaintext never touches the database &mdash; only this AES-128-CBC + HMAC-SHA256 ciphertext is stored.</div>
        </div>
        """.format(username, email_enc, cc_enc)
        return render_template_string(BASE, title="Record Stored", body=body, active="add")

    body = """
    <h1>Add a customer record</h1>
    <div class="subtitle">Sensitive fields are encrypted before this data ever reaches the database.</div>
    <div class="panel">
      <form method="post">
        <label>Username</label>
        <input name="username" value="testuser">
        <label>Email</label>
        <input name="email" value="test@example.com">
        <label>Credit card</label>
        <input name="credit_card" value="4111-1111-1111-1111">
        <button type="submit">Encrypt &amp; Save</button>
      </form>
    </div>
    """
    return render_template_string(BASE, title="Add Record", body=body, active="add")


@app.route("/view")
def view_authorized():
    conn = sqlite3.connect(APP_DB)
    cur = conn.cursor()
    cur.execute("SELECT id, username, email_enc, credit_card_enc FROM customers")
    rows = cur.fetchall()
    conn.close()

    rows_html = ""
    for r in rows:
        try:
            email = decrypt(r[2])
            cc = decrypt(r[3])
            rows_html += """<tr><td>{0}</td><td>{1}</td><td class="plain">{2}</td><td class="plain">{3}</td></tr>""".format(r[0], r[1], email, cc)
        except InvalidToken:
            rows_html += """<tr><td>{0}</td><td>{1}</td><td class="fail">DECRYPTION FAILED</td><td class="fail">DECRYPTION FAILED</td></tr>""".format(r[0], r[1])

    body = """
    <h1>Authorized view</h1>
    <div class="subtitle">This endpoint holds secret.key and can decrypt normally.</div>
    <div class="panel">
      <span class="badge key">&#128273; Key present &mdash; decrypting</span>
      <table>
        <tr><th>ID</th><th>Username</th><th>Email</th><th>Credit Card</th></tr>
        {0}
      </table>
    </div>
    """.format(rows_html)
    return render_template_string(BASE, title="Authorized View", body=body, active="view")


@app.route("/attacker_dump")
def attacker_dump():
    conn = sqlite3.connect(APP_DB)
    cur = conn.cursor()
    cur.execute("SELECT id, username, email_enc, credit_card_enc FROM customers")
    rows = cur.fetchall()
    conn.close()

    rows_html = ""
    for r in rows:
        rows_html += """<tr><td>{0}</td><td>{1}</td><td class="cipher">{2}</td><td class="cipher">{3}</td></tr>""".format(r[0], r[1], r[2], r[3])

    fake_key = Fernet.generate_key()
    fake_fernet = Fernet(fake_key)
    result_html = ""
    if rows:
        try:
            fake_fernet.decrypt(rows[0][2])
            result_html = '<span class="badge safe">Unexpected success</span>'
        except InvalidToken:
            result_html = '<span class="badge danger">&#9940; InvalidToken &mdash; decryption blocked</span>'

    body = """
    <h1>Attacker view</h1>
    <div class="subtitle">Simulated attacker who stole the database file only &mdash; no access to secret.key.</div>
    <div class="panel">
      <span class="badge danger">&#128274; No key &mdash; ciphertext only</span>
      <table>
        <tr><th>ID</th><th>Username</th><th>Email (stolen)</th><th>Credit Card (stolen)</th></tr>
        {0}
      </table>
      <div class="footnote">Attacker attempts decryption with a guessed key: {1}</div>
    </div>
    """.format(rows_html, result_html)
    return render_template_string(BASE, title="Attacker View", body=body, active="attacker")


if __name__ == "__main__":
    init_db()
    print("Demo DB seeded. Key stored separately in {0}. Visit http://localhost:5001".format(KEY_FILE))
    app.run(debug=True, host='0.0.0.0', port=5001)