# Secure File Sharing System — Web Edition

A Flask web app version of the "Secure File Sharing System using Python
Sockets" project. It implements every module from the report using
**AES encryption only** — no RSA/asymmetric cryptography — through a
browser interface instead of a command-line socket client, which makes it
far easier to demo live in a review.

## 1. Setup

```bash
# 1. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python app.py
```

Open **http://127.0.0.1:5000** in your browser. The database (`app.db`) is
created automatically on first run — nothing to configure.

## 2. How to demo it (2 minutes)

1. Register two accounts, e.g. `alice` and `bob`.
2. Log in as `alice`, upload a file, and type `bob` in the "Share with"
   box.
3. Log out, log in as `bob`. The file appears under **Shared With Me**.
4. Click **Download** — the app decrypts it live and hands you back the
   original file.
5. Open **Activity Log** to show the audit trail (login, upload, download
   events) — this is your evidence for the "Integrity and Audit Logging
   Module".
6. To show the integrity check catching tampering: open
   `encrypted_storage/` while the server is stopped, flip a byte in any
   `.enc` file, restart the server, and try to download it — it will
   refuse with an integrity error instead of returning corrupted data.

## 3. How this maps onto your report

| Report Module                        | Where it lives in this app |
|----------------------------------------|-----------------------------|
| User and Interface Module              | `/register`, `/login`, dashboard templates — passwords stored as salted hashes via Werkzeug (`generate_password_hash`), never in plain text; Bootstrap UI provides file selection and transfer status |
| Cryptography and Security Module       | `upload()` in `app.py` — each file gets its own one-time AES key (`Fernet.generate_key()`) and is encrypted before it's written to disk |
| Network Communication Module           | Flask's development server, which itself is built on Python's `socket` module — HTTP requests/responses carry the client-server data stream, replacing the raw socket protocol from the original design while keeping the same underlying transport |
| Integrity and Audit Logging Module     | SHA-256 checksum computed on upload (`hashlib.sha256`) and re-verified on every download before the file is released; `ActivityLog` table + `/logs` page record every login, upload, download, and failed attempt |

The **ER diagram** from your report also maps directly:
- `User` → `User` model
- `File` → `FileRecord` model
- `Transfer_Log` → `ActivityLog` model
- `Session` → handled implicitly by Flask's signed session cookie, so no
  separate table is needed for a project of this size

## 4. Why these design choices (useful for your viva)

- **A fresh AES key per file** — every uploaded file gets its own
  randomly-generated key (via `Fernet.generate_key()`), so even if one
  file's key were ever exposed, no other file is affected.
- **Checksum before encryption, verified after decryption** — this proves
  the *decrypted* file matches the *original* file, catching both storage
  corruption and tampering, not just transmission errors.
- **Symmetric-only encryption (AES)** — the project deliberately keeps to
  one cryptographic mechanism, which is simpler to build, test, and
  explain end-to-end than mixing in a second (asymmetric) scheme, while
  still meeting the "end-to-end encryption" requirement in the abstract.
- **HTTP instead of raw sockets** — a browser request over HTTP already
  rides on top of a TCP socket (the same transport layer the original
  design used directly); using Flask lets you demonstrate the same
  security modules with a much friendlier interface for a live review.

## 5. Known limitations (mention these proactively — examiners like it)

- Runs over plain HTTP in development. In a production deployment you'd
  put this behind HTTPS (TLS) so the network hop between browser and
  server is also encrypted, not just the file payload.
- Each file's AES key is stored directly in the database alongside its
  record. That's appropriate for a course-level demo; a production system
  would keep keys in a separate, access-controlled key store (or derive
  them from a user's password) rather than next to the data they protect.
- `debug=True` should be turned off before any real deployment.

## 6. Project structure

```
secure_file_share/
├── app.py                 # All routes + AES encryption logic
├── requirements.txt
├── app.db                 # SQLite database (auto-created)
├── encrypted_storage/      # AES-encrypted files live here (auto-created)
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    └── logs.html
```
