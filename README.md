# Secure Zero-Trust File Sharing System

A client-server web application prototype implementing the **Zero-Trust security model** for file upload, sharing, and integrity verification. Designed for local classroom demonstration on Windows laptops.

Built exclusively with Node.js standard library modules (`node:http`, `node:https`, `node:crypto`, `node:fs`, `node:path`, `node:stream`). Requires no external npm packages or installations.

---

## 1. Zero-Trust Security Architecture

In accordance with Zero-Trust principles (**"Never Trust, Always Verify"** and **"Default Deny"**):

1. **Authentication != File Authorization:** A successful login verifies user identity only. It grants **zero** implicit access to stored files.
2. **Per-Request Authorization:** Every single operation (`upload`, `list`, `share`, `revoke`, `download`, `integrity-demo`) is verified on the server against the file's ownership and explicit sharing ACLs before any file bytes are read or decrypted.
3. **Encryption at Rest:** Plaintext files are never written to disk. Files are encrypted with **AES-256-GCM** using a fresh, random 96-bit Initialization Vector (IV) for each file.
4. **Dual-Layer Integrity Verification:**
   - **Server-side:** Server checks the AES-GCM authentication tag upon decryption, recomputes the SHA-256 digest, and validates it against the pre-encryption digest recorded in metadata. Downloads are rejected with HTTP 409 if any mismatch occurs.
   - **Client-side:** The browser recomputes the SHA-256 digest using the Web Cryptography API (`crypto.subtle.digest`) upon receiving the downloaded bytes and independently verifies the match.
5. **Auditing & Monitoring:** The server terminal and web interface record concise structured events: `[ALLOW]`, `[DENY]`, and `[INTEGRITY-FAIL]`. Passwords, bearer tokens, and plaintext file contents are never logged.

---

## 2. Demo User Accounts

The prototype comes pre-seeded with four demonstration accounts:

| Username | Password | Role | Zero-Trust Access Rights |
| :--- | :--- | :--- | :--- |
| **`asha`** | `asha123` | **Student** | Can upload private files. Can download own files or files explicitly shared with her. Cannot access other students' or faculty's unshared files. |
| **`rao`** | `rao123` | **Faculty** | Can upload private files. Can download files explicitly shared with him by students, faculty, or Admin. Has no automatic access to unshared student files. |
| **`ravi`** | `ravi123` | **Student** | Can upload private files. Can download own files or files explicitly shared with him. Cannot access Asha's or Rao's unshared files. |
| **`admin`** | `admin123` | **Admin** | User management and audit oversight. Under strict Zero-Trust rules, Admin has NO blanket access to other users' files and requires ownership or explicit sharing. |

> **Role Provisioning & Privilege-Escalation Defense:** Under Zero-Trust principles, public self-registration is strictly restricted to the **Student** role. Client-supplied elevated roles (`Faculty`, `Admin`) are rejected by the server with HTTP 403. Faculty and Admin accounts can only be provisioned or promoted by an authenticated Admin through the dedicated `/api/admin/users` endpoints.

> **Zero-Trust File Isolation:** Administrative privileges apply strictly to user management and audit feed oversight. Administrators do NOT have automatic access to list, download, decrypt, share, or revoke files owned by other users. File access strictly requires ownership or explicit sharing.

> **Note on Credentials:** Clearly labeled as demo credentials. Passwords are stored in `storage/metadata.json` as per-user salted **scrypt** hashes (`N=16384, r=8, p=1`, 64-byte key length). Passwords are never stored or logged in plaintext.

---

## 3. How Authentication and Sessions Work

1. **Login Flow:**
   - The user submits `username` and `password` via `POST /api/login`.
   - The server retrieves the user's unique 16-byte random salt and expected scrypt hash.
   - The password hash is recomputed and compared using `crypto.timingSafeEqual` to prevent timing attacks.
   - Upon success, the server generates a cryptographically secure 256-bit random token (`crypto.randomBytes(32).toString('hex')`) and records the session in memory.
   - The client receives the bearer token, username, and role.
2. **Public Self-Registration Flow:**
   - Users submit `username` and `password` via `POST /api/register`.
   - Public self-registration always assigns the **Student** role. Any explicit request for `Admin` or `Faculty` is rejected with HTTP 403 and logged as `[DENY] register ... (privilege escalation blocked)`.
   - Set environment variable `ALLOW_PUBLIC_REGISTRATION=false` to disable public self-registration entirely.
3. **Admin User Management:**
   - Authenticated Admins have access to `/api/admin/users` to view the user roster without exposing password hashes or tokens.
   - Admins can provision new accounts with any role (`Student`, `Faculty`, `Admin`) via `POST /api/admin/users`.
   - Admins can modify existing user roles via `POST /api/admin/users/:username/role`. Users (including Admins) cannot modify their own roles.
   - All Admin actions are audited and logged with `[ALLOW]` or `[DENY]`.
4. **Audit Log & Activity Feed Security:**
   - `GET /api/activity` is restricted to authenticated Administrators (unauthenticated requests receive HTTP 401, while Student/Faculty requests receive HTTP 403).
   - Log injection defense: all log event parameters are sanitized to strip carriage returns (`\r`), newlines (`\n`), and control characters.
5. **Atomic Metadata Persistence:**
   - `persist()` writes database updates to an ephemeral `.tmp` file in the storage directory before atomically renaming it, preventing database truncation or corruption during server termination.
6. **Session Lifecycle:**
   - Each request sends the token in the HTTP `Authorization: Bearer <token>` header.
   - Sessions are memory-bound. Restarting the server instantly invalidates all active sessions.

---

## 4. Required File Flows

### A. Upload
1. Validates authenticated session. Enforces a 10 MB maximum file size limit.
2. Generates an opaque server-side file ID (`crypto.randomUUID()`) and sanitizes the displayed filename against path traversal and control characters.
3. Computes the original file's pre-encryption SHA-256 digest.
4. Generates a fresh, random 12-byte IV (`crypto.randomBytes(12)`).
5. Encrypts plaintext bytes using `aes-256-gcm`.
6. Writes only ciphertext to `storage/<file-id>.aes`. Stores IV, GCM authentication tag, owner, SHA-256, and metadata in `storage/metadata.json`.
7. Logs `[ALLOW] upload ...`.

### B. Share and Revoke
1. Only the file owner or Admin can modify file access. Unauthorized attempts log `[DENY] share` or `[DENY] revoke` and return HTTP 403.
2. **Share:** Adds the chosen user to the file's `sharedWith` list in metadata. Logs `[ALLOW] share`.
3. **Revoke:** Removes the chosen user from `sharedWith`. Logs `[ALLOW] revoke`. The revoked user immediately loses download access.

### C. Download and Integrity Verification
1. Server verifies authentication and checks permissions under default-deny. Unauthorized requests return HTTP 403 Forbidden.
2. Server reads ciphertext from disk and decrypts using AES-256-GCM. If the file bytes were corrupted on disk, the GCM auth tag check fails, logging `[INTEGRITY-FAIL]` and returning HTTP 409.
3. Server recomputes the SHA-256 digest of decrypted bytes and compares it with the saved digest using `crypto.timingSafeEqual`. If mismatched, server logs `[INTEGRITY-FAIL]` and returns HTTP 409.
4. If valid, server logs `[ALLOW] download ...` and returns base64 content along with expected SHA-256.
5. The browser decodes the bytes, recomputes SHA-256 using the browser's Web Crypto API, verifies that the client hash matches the server digest, and prompts the file download.

### D. Integrity Demo (Simulated Checksum Mismatch)
- The UI includes an **"Integrity Demo"** button for file owners/Admin.
- Clicking **"Simulate Hash Mismatch"** alters the recorded expected SHA-256 digest in metadata to simulate checksum mismatch, **without** modifying the encrypted file on disk.
- Attempting to download the file triggers a server-side rejection (HTTP 409 Conflict) and logs `[INTEGRITY-FAIL]`.
- Clicking **"Restore Valid Hash"** restores the recorded hash and re-enables normal downloads.

### E. Secure File Deletion
- **Owner-Only Authorization:** Only the original file owner (Student or Faculty) can delete a file via `DELETE /api/files/:id`.
- **Zero-Trust Privilege Boundary:** Neither other Students, Faculty, nor Administrators have permission to delete another user's private file. Shared recipients cannot delete the original file.
- **Two-Phase Atomic Cleanup:** The server unlinks the physical `.aes` ciphertext blob from disk and removes the file record and all sharing ACLs from metadata atomically. If a filesystem error occurs, changes are rolled back to prevent orphaned blobs or missing-file metadata.
- **Audit Logging:** Logs `[ALLOW] delete user=... file=...` or `[DENY] delete user=... (not owner)` without exposing sensitive credentials or payloads.

---

## 5. Quick Start Instructions (Windows)

### Prerequisites
- Windows 10/11
- Node.js v18 or later installed (`node --version`)

### Starting the Server
1. Double-click **`start-demo.bat`** (or open PowerShell in this directory and run `node server.js`).
2. A server console window will open, display the demo credentials, and automatically launch your browser to:
   ```
   http://127.0.0.1:4173
   ```
3. Keep the console window open to observe live `[ALLOW]`, `[DENY]`, and `[INTEGRITY-FAIL]` log messages.

### Stopping the Server
- Press `Ctrl + C` in the server console window.

### Running Automated Verification
To run the automated 9-point security test suite:
```powershell
node verify-zero-trust.js
```

### Resetting Demo Files
To wipe uploaded demo files and reset storage while keeping demo accounts:
- Double-click **`reset-demo.bat`**

---

## 6. Transport & Optional HTTPS/TLS Support

- **Default Transport:** By default, the server binds strictly to `127.0.0.1` (loopback) over HTTP. The UI displays **● LOCAL ONLY · HTTP 127.0.0.1:4173** to make it explicit that traffic is not encrypted in transit.
- **Optional HTTPS / TLS Support:** The server includes optional local HTTPS support using a self-signed certificate via Node.js `node:https`.
  - **Certificate Generation:** Use the provided `gen-cert.js` tool to generate an Elliptic Curve (EC P-256 / `prime256v1`) self-signed certificate with Subject Alternative Names (SAN) for `localhost` and `127.0.0.1`, valid for 365 days:
    ```powershell
    node gen-cert.js
    ```
    Existing certificates are never overwritten unless `--force` is supplied (`node gen-cert.js --force`).
  - **Running in HTTPS Mode:**
    - On Windows, double-click **`start-https.bat`** (or run `start-demo.bat --https`). It will automatically check for or generate certificates and launch your browser to `https://127.0.0.1:4173`.
    - Or from PowerShell:
      ```powershell
      $env:USE_HTTPS="true"; node server.js
      ```
  - **Fail-Loud Configuration:** If `USE_HTTPS=true` and `storage/cert.pem` or `storage/key.pem` is missing, unreadable, or invalid, the server fails loudly with a descriptive startup error (`[HTTPS-CONFIG-ERROR]`). It **never silently falls back to plaintext HTTP**.
  - **Enforced Minimum TLS Version:** The HTTPS server strictly requires **TLSv1.2** or higher (`minVersion: 'TLSv1.2'`). Legacy, insecure protocols (SSLv3, TLSv1.0, TLSv1.1) are rejected at the TLS handshake level.
  - **HTTP Strict Transport Security (HSTS):** When HTTPS is active, the server automatically emits the `Strict-Transport-Security: max-age=31536000; includeSubDomains` header. HSTS is **only** applied when HTTPS is active; it is omitted over plain HTTP to prevent accidental lockouts on unencrypted origins.
  - **Transport Indicators:** The frontend header badge automatically updates to **🔒 SECURE · HTTPS 127.0.0.1:4173** with hover tooltips indicating the active TLS mode and URL.
  - **Browser Warnings on Self-Signed Certs:** Because self-signed certificates are not signed by a commercial Public Certificate Authority, browsers will display a one-time security warning (`NET::ERR_CERT_AUTHORITY_INVALID`). In the browser, click **Advanced** -> **Proceed to 127.0.0.1 (unsafe)** to view the application over TLS.
- **Key Storage:** The master AES key is stored in `storage/.master-key`. In a production deployment, keys would be managed via a dedicated Hardware Security Module (HSM) or Key Management Service (KMS) rather than a local file.
- **Sessions & Database:** Sessions and audit logs are stored in memory; file metadata is stored in a JSON file for classroom portability. Production systems require persistent databases with token rotation and rate limiting.

---

## Key management & threat model

This project implements server-enforced Zero-Trust authorization and server-side encryption at rest:

1. **Server-Side Encryption:** All uploaded file payloads are encrypted server-side using **AES-256-GCM**.
2. **Per-File Random IV:** A fresh, cryptographically secure 96-bit Initialization Vector (`crypto.randomBytes(12)`) is generated for each file upload.
3. **Master Key Storage:** The 256-bit AES master encryption key is generated once and stored in `storage/.master-key`.
4. **Key Separation:** The master encryption key is stored separately from the encrypted `.aes` file blobs and metadata.
5. **Git-Ignored Storage:** All storage artifacts (`storage/*`, including `.master-key`, `.aes` blobs, `metadata.json`, and `audit.log`) are explicitly listed in `.gitignore` to prevent credential or data exposure in source control.
6. **Threat Model & Encryption at Rest:** The server host has direct read access to the master key and decrypts file bytes upon authorized requests. Therefore, this implementation provides **encryption at rest**, **NOT zero-knowledge encryption** (end-to-end encryption where only client devices hold decryption keys). If the server host or master key file is compromised, an attacker with filesystem access could decrypt the stored blobs.
7. **Future Architectural Improvements:**
   - **Client-Side Encryption:** Performing client-side encryption and key derivation using the browser Web Cryptography API (`crypto.subtle`) before upload, ensuring true zero-knowledge privacy where the server never sees plaintext or master keys.
   - **External Key Management:** Delegating key storage and cryptographic operations to an external Key Management Service (KMS, such as AWS KMS, Google Cloud KMS, or HashiCorp Vault) or a dedicated Hardware Security Module (HSM) with strict envelope encryption and key rotation policies.
8. **In-Memory Demonstration Sessions:** For portability and classroom demonstration simplicity, authenticated sessions are tracked in memory with a configurable time-to-live (`SESSION_TTL_MINUTES`, defaulting to 30 minutes).
9. **Persistent Audit Trail:** All security events (`[ALLOW]`, `[DENY]`, `[INTEGRITY-FAIL]`) are appended to `storage/audit.log` with ISO-8601 timestamps and sanitized fields, in addition to being held in an in-memory ring buffer for the administrative activity feed.

---

## 7. Automated Test Verification Results

All required checks have been implemented and verified via `verify-zero-trust.js`:

| # | Check Case | Result | Observation |
| :-: | :--- | :-: | :--- |
| **1** | Wrong password is rejected | **PASS** | HTTP 401 received. Error: "Incorrect username or password". No token issued. Logged `[DENY]`. |
| **1b** | User registration with salted scrypt hashing | **PASS** | Registered user with role Student (201). Duplicate registration rejected with HTTP 400. |
| **1c** | Privilege escalation prevention & Admin user management | **PASS** | Admin/Faculty self-reg blocked (403), Student default assigned (201), non-Admin access blocked (403), Admin provisioned Faculty (201), user list secrets-free (200), Admin self-demotion blocked (400), invalid input rejected (400), ALLOW_PUBLIC_REGISTRATION=false enforced (403). |
| **1d** | Activity audit feed access control | **PASS** | Unauthenticated requests blocked (401), Student blocked (403), Faculty blocked (403), Admin granted access (200) with zero secret leakage. |
| **1e** | Audit log CRLF sanitization & malformed JSON handling | **PASS** | CRLF injection stripped from log details (no forged events), malformed JSON returns HTTP 400 (not 500). |
| **1f** | Registration role own-property edge cases | **PASS** | All 9 role property edge cases verified: omitted role creates Student (201), whitespace-padded '  Student  ' creates Student (201), explicit Admin/Faculty/null/empty/whitespace/numeric/boolean roles blocked (403), zero rejected users or tokens created in database or sessions. |
| **1g** | Persistent audit logging & failure resilience | **PASS** | Events appended to `audit.log` with ISO-8601 timestamps and sanitized fields. No passwords, tokens, hashes, or salts leaked. Disk write failures handled without crashing the server. |
| **1h** | Session expiry lifecycle & configurable TTL | **PASS** | Valid sessions allowed, expired sessions rejected with HTTP 401 and removed from memory. Default 30-min TTL and custom TTL (`SESSION_TTL_MINUTES`) verified; polling does not refresh TTL. |
| **1i** | Login rate limiting & lockout threshold | **PASS** | 4 failed logins permitted (HTTP 401); 5th failed login establishes 60-second lock; subsequent attempts return HTTP 429 without executing scrypt. Independent tracking per IP and username; rate limits unknown usernames without enumeration; successful login resets counters. |
| **1j** | Demo accounts UI & credentials integrity | **PASS** | Classroom demo accounts box and credentials for `asha`, `rao`, `ravi`, and `admin` verified intact and functional. |
| **2** | Asha uploads and downloads own file | **PASS** | File encrypted with AES-256-GCM. HTTP 200 download. Decrypted bytes match original. SHA-256 verified. Logged `[ALLOW]`. |
| **3** | Ravi cannot download Asha's unshared file | **PASS** | Ravi (Student) denied access. HTTP 403 Forbidden. Logged `[DENY]`. |
| **3b** | Admin Zero-Trust file isolation | **PASS** | Unshared files hidden from Admin list (200), Admin download of unshared file blocked (403), unauthorized share/revoke blocked (403), Admin can access own files, explicit share to Admin verified (200), revoke verified (403). |
| **4** | Asha shares with Rao, Rao downloads | **PASS** | Share updated metadata. Rao (Faculty) downloaded file with HTTP 200. Logged `[ALLOW]`. |
| **5** | Revoked access stops working | **PASS** | Asha revoked access. Rao subsequent download returned HTTP 403 Forbidden. Logged `[DENY]`. |
| **6** | Tampered / mismatched file is rejected | **PASS** | Simulated SHA-256 mismatch rejected with HTTP 409. Bit-tampered ciphertext rejected with HTTP 409 (AES-GCM tag check). Restoring valid hash restores HTTP 200. Logged `[INTEGRITY-FAIL]`. |
| **7** | Stored file bytes are ciphertext | **PASS** | Inspected `storage/*.aes`. Plaintext string absent. Stored file is AES-256-GCM ciphertext. |
| **8** | Server & browser SHA-256 match | **PASS** | Client-computed SHA-256 matches server digest and original pre-encryption hash bit-for-bit. |
| **9** | HTTPS works, if implemented | **PASS** | Built-in HTTPS handler supported. Local demo default binds strictly to `127.0.0.1` with explicit transport banner. |
| **10** | Secure file deletion & transaction safety | **PASS** | Owner-only deletion (200), Students/Faculty/Admin/recipients denied (403), ciphertext and metadata purged, download rejected (404), filesystem failure rolled back safely. |
| **11** | Generic HTTP 500 & exception detail masking | **PASS** | Uncaught exceptions return generic "Internal server error." (raw message/paths masked). Expected client errors (400, 401, 403, 404, 413) preserved. |
| **12** | Security headers & Content-Security-Policy | **PASS** | Full security headers enforced on all responses: CSP, X-Frame-Options: DENY, Referrer-Policy: no-referrer, nosniff, no-store. |
| **13** | Registration & login rate limiting with sliding window | **PASS** | Max 5 registrations/60s per IP (HTTP 429 with Retry-After). Rate limit checked before scrypt/validation. 15-minute sliding window decay for logins. Unref periodic sweep. |
| **14** | Periodic session cleanup mechanism | **PASS** | `sweepExpiredSessions()` automatically purges expired tokens every 10 min without invalidating active sessions. |
| **15** | Role-based storage quotas & atomic enforcement | **PASS** | Quotas enforced: Student (30 MB), Faculty (150 MB), Admin (Unlimited). Over-quota uploads rejected with HTTP 413. Shared files isolated from recipient quota. |
| **16** | Code review corrections & transaction rollback | **PASS** | Failed login attempts persist across 60s lockout expiration until 15m window decays; immediate re-lock confirmed. Fail-closed quota calculation handles malformed sizes with HTTP 500. Persistence failure triggers automatic transactional rollback (0 orphaned files, clean metadata, released in-flight quota). |
| **17** | Optional HTTPS/TLS & EC P-256 Certificates | **PASS** | `gen-cert.js` generates self-signed EC P-256 cert with SAN (localhost, 127.0.0.1) valid 365 days; preserves existing unless `--force`. Fail-loud on missing/invalid certs when `USE_HTTPS=true` (never falls back). Enforces TLS 1.2+ minimum. Applies HSTS only on HTTPS. |
