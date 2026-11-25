# ZTFILE — Verified Project Facts Sheet

This document contains a verified technical facts sheet for the Secure Zero-Trust File Sharing System (**ZTFILE**).
Every claim is backed by concrete source code citations formatted as `file:line`.

---

## 1. Authentication & Password Hashing

- **Authentication Scheme**: Bearer token session authentication following username and password credential exchange (`server.js:337-339, 504-521`).
- **Password Hashing Algorithm**: `scrypt` via Node.js built-in `crypto.scryptSync(password, salt, 64)` (`server.js:265, 482`).
- **Scrypt Parameters**:
  - **$N$ (CPU/memory cost factor)**: $16384$ ($2^{14}$) — default in Node.js built-in `crypto.scryptSync` (`server.js:265, 482`; Node.js standard library documentation).
  - **$r$ (block size factor)**: $8$ — default in Node.js built-in `crypto.scryptSync` (`server.js:265, 482`; Node.js standard library documentation).
  - **$p$ (parallelization factor)**: $1$ — default in Node.js built-in `crypto.scryptSync` (`server.js:265, 482`; Node.js standard library documentation).
  - **Derived Key Length**: $64\text{ bytes}$ ($512\text{ bits}$), encoded as a 128-character hexadecimal string (`server.js:265, 482`).
  - **Salt Generation & Size**: $16\text{ bytes}$ ($128\text{ bits}$) of cryptographically secure random bytes generated via `crypto.randomBytes(16)`, stored as a 32-character hexadecimal string (`server.js:264`).
- **Password Verification**: Computed using constant-time comparison `crypto.timingSafeEqual(inputHash, expectedHash)` to prevent timing side-channel attacks (`server.js:485`).
- **Credential Storage**: Salt and hash are persisted in `storage/metadata.json` under `db.users[cleanUsername] = { salt, hash, role }` (`server.js:266, 267`). Raw plaintext passwords are never stored or logged (`server.js:139-162, 266`).
- **Account Validation Rules**:
  - Username: 2 to 30 characters long, matching regex `/^[a-z0-9_.-]+$/i` (alphanumeric, underscores, dots, hyphens) (`server.js:248-254`).
  - Password: Minimum 4 characters long (`server.js:255-257`).
- **Demo Seed Accounts**: Four demo accounts seeded into the database on startup if absent:
  - `asha` / `asha123` (Role: `Student`) (`server.js:279`).
  - `rao` / `rao123` (Role: `Faculty`) (`server.js:280`).
  - `ravi` / `ravi123` (Role: `Student`) (`server.js:281`).
  - `admin` / `admin123` (Role: `Admin`) (`server.js:282`).

---

## 2. Session Handling & Token Lifecycle

- **Token Generation**: Generated via `crypto.randomBytes(32).toString('hex')` producing a 64-character hexadecimal cryptographically secure random token (256 bits of entropy) (`server.js:504, 569`).
- **Token Format & Header**: Client passes token in the HTTP `Authorization` request header formatted as `Bearer <token>` (`server.js:337-338`; `app.js:70`).
- **Session Storage**: Stored exclusively in an in-memory JavaScript `Map` (`sessions`) mapping `token -> { username, role, loginTime }` (`server.js:23, 505, 570`). Sessions are volatile and reset upon server restart.
- **Client-Side Token Storage**: Stored only in an in-memory JavaScript variable `let token = '';` inside `app.js` (`app.js:4`). It is explicitly **not** stored in `localStorage`, `sessionStorage`, or browser cookies (`app.js:4, 67-74`).
- **Session Time-To-Live (TTL)**:
  - Default duration: $30\text{ minutes}$ (`server.js:104, 111`).
  - Configurable via the `SESSION_TTL_MINUTES` environment variable (`server.js:103-110`).
  - If `SESSION_TTL_MINUTES` is invalid, negative, or non-finite, safely defaults to 30 minutes (`server.js:105-110`).
- **Session Expiration Enforcement**:
  - **On-Access (Lazy)**: `userFor(req)` evaluates `Date.now() - session.loginTime > ttlMs`. If expired, the token is deleted from `sessions` and rejected with HTTP 401 (`server.js:344-348, 606-610`).
  - **Periodic Background Pruning (Eager)**: `sweepExpiredSessions()` runs every 10 minutes (`10 * 60 * 1000` ms) via an unreferenced timer `setInterval(sweepExpiredSessions, 600000)` (`server.js:114-127`).
- **Session Revocation (Logout)**: Explicit logout via `POST /api/logout` immediately invokes `sessions.delete(token)` (`server.js:708-713`).

---

## 3. Roles, Permissions & Zero-Trust Authorization Model

- **Supported Roles**:
  - `Student` (`server.js:34, 191`).
  - `Faculty` (`server.js:35, 192`).
  - `Admin` (`server.js:36, 193`).
- **Role Normalization**: `normalizeRole(role)` performs case-insensitive trim and maps to canonical `'Student'`, `'Faculty'`, or `'Admin'`. Any other value returns `null` (`server.js:188-195`).
- **Role-Based Storage Quotas**:
  - `Student`: $30\text{ MB}$ ($31,457,280\text{ bytes}$) (`server.js:34`).
  - `Faculty`: $150\text{ MB}$ ($157,286,400\text{ bytes}$) (`server.js:35`).
  - `Admin`: Unlimited (`Infinity`) (`server.js:36`).
- **Zero-Trust File Authorization Principle (Default-Deny)**:
  - Function `allowed(user, file, action)` governs file permissions (`server.js:357-366`).
  - **File Owner**: Has full privileges (`read`, `share`, `revoke`, `delete`, `tamper-demo`) (`server.js:360, 858, 907, 933, 954, 981`).
  - **Shared Recipient**: Granted **read-only** (`download`) access if and only if their username is explicitly listed in `file.sharedWith` (`server.js:362-364, 981`).
  - **Strict Admin File Isolation**: Administrators do **NOT** have automatic or ambient privileges to view, download, share, revoke, or delete private files owned by other users (`server.js:357-366, 858-861, 907-910, 933-936, 954-957, 981-984`).
  - **Recipient Limitation**: Shared recipients cannot re-share, revoke, or delete the original file (`server.js:858, 907, 933`).
- **Self-Registration Privilege Guard**:
  - Public registration (`POST /api/register`) only permits creation of `Student` accounts (`server.js:263, 567`).
  - Attempting to pass any `role` other than `'student'` (including `Admin`, `Faculty`, `null`, numbers, or empty strings) is rejected with HTTP 403 Forbidden (`server.js:547-555`).
  - Public registration can be globally disabled by setting `ALLOW_PUBLIC_REGISTRATION=false` (`server.js:537-540`).
- **Admin Management Capabilities**:
  - View live audit feed: `GET /api/activity` (Admin only) (`server.js:615-621`).
  - List all users and roles: `GET /api/admin/users` (Admin only) (`server.js:631-638`).
  - Provision users with arbitrary roles (`Student`, `Faculty`, `Admin`): `POST /api/admin/users` (Admin only) (`server.js:641-668`).
  - Update user roles: `POST /api/admin/users/:username/role` (Admin only; cannot modify own role) (`server.js:671-702`).

---

## 4. Complete API Route Catalog

| Method | Path | Required Auth | Allowed Roles / Callers | Authorization Logic & Code Location |
|---|---|---|---|---|
| `GET` | `/` | None | Public | Serves `index.html` (`server.js:417-419`) |
| `GET` | `/app.js` | None | Public | Serves `app.js` (`server.js:420-422`) |
| `GET` | `/style.css` | None | Public | Serves `style.css` (`server.js:423-425`) |
| `POST` | `/api/login` | None | Public (Rate-limited) | Checks IP/username rate limit & lockout; verifies scrypt hash; issues Bearer token (`server.js:428-521`) |
| `POST` | `/api/register` | None | Public (Rate-limited) | Checks IP rate limit; verifies `ALLOW_PUBLIC_REGISTRATION`; enforces `role === 'Student'`; creates user (`server.js:524-588`) |
| `GET` | `/api/transport` | None | Public | Returns protocol, TLS status, host, port, active URL, and transport mode description (`server.js:591-602`) |
| *Gate* | `/api/*` | Valid Token | Any Authenticated | `userFor(req)` verifies token presence and active TTL; returns HTTP 401 if missing/expired (`server.js:605-612`) |
| `GET` | `/api/activity` | Authenticated | `Admin` only | Checks `user.role === 'Admin'`; returns last 25 sanitized audit log entries (`server.js:615-621`) |
| `GET` | `/api/admin/users` | Authenticated | `Admin` only | Checks `user.role === 'Admin'`; returns user list with usernames and roles (`server.js:631-638`) |
| `POST` | `/api/admin/users` | Authenticated | `Admin` only | Checks `user.role === 'Admin'`; validates input; creates user with requested valid role (`server.js:641-668`) |
| `POST` | `/api/admin/users/:username/role` | Authenticated | `Admin` only | Checks `user.role === 'Admin'`; blocks self-role modification; updates role in DB (`server.js:671-702`) |
| `POST` | `/api/logout` | Authenticated | Any active user | Deletes caller's session token from `sessions` Map (`server.js:708-713`) |
| `GET` | `/api/me` | Authenticated | Any active user | Returns current username, role, quota, and storage usage (`server.js:716-730`) |
| `GET` | `/api/files` | Authenticated | Any active user | Calls `listFiles(user)`; returns files caller owns or has been shared with (`server.js:733-753`) |
| `POST` | `/api/files` | Authenticated | Any active user (Quota-checked) | Validates size $\le 10\text{ MB}$; checks storage quota + in-flight bytes; encrypts AES-256-GCM; writes disk & metadata (`server.js:756-842`) |
| `DELETE`| `/api/files/:id` | Authenticated | File Owner only | Strict owner check `file.owner === user.username`; unlinks ciphertext blob; deletes metadata atomically with rollback (`server.js:857-903`) |
| `POST` | `/api/files/:id/share` | Authenticated | File Owner only | Strict owner check `file.owner === user.username`; verifies target exists; adds target to `file.sharedWith` (`server.js:906-929`) |
| `POST` | `/api/files/:id/revoke` | Authenticated | File Owner only | Strict owner check `file.owner === user.username`; removes target from `file.sharedWith` (`server.js:932-950`) |
| `POST` | `/api/files/:id/tamper-demo` | Authenticated | File Owner only | Strict owner check `file.owner === user.username`; sets `file.sha256` to zeroed string or restores original digest (`server.js:953-976`) |
| `GET` | `/api/files/:id/download` | Authenticated | Owner or Shared Recipient | Checks `allowed(user, file, 'read')`; decrypts AES-256-GCM; verifies auth tag; verifies SHA-256; returns base64 content (`server.js:979-1009`) |

---

## 5. File Upload & Encryption Flow

1. **Payload Ingestion**:
   - `readBody(req)` streams payload chunks, enforcing a strict $15,000,000\text{ byte}$ maximum buffer limit (`server.js:315-320`).
   - Rejects payloads exceeding limit with HTTP 413 and invalid JSON with HTTP 400 (`server.js:317, 328`).
2. **Input Validation**:
   - Requires non-empty `name` and base64-encoded `content` string (`server.js:757-760`).
   - Decodes base64 buffer `Buffer.from(content, 'base64')` (`server.js:761`).
   - Rejects empty files ($0\text{ bytes}$) with HTTP 400 (`server.js:762-764`).
   - Enforces single file size limit: maximum $10\text{ MB}$ ($10 \times 1024 \times 1024\text{ bytes}$) (`server.js:765-767`).
3. **Storage Quota & Concurrency Reservation**:
   - Calculates user's cumulative storage usage via `getUserStorageUsage(user.username)` (`server.js:205-230, 773`).
   - **Fail-Closed Quota Evaluation**: If any file in `db.files` contains an invalid, negative, non-integer, or non-safe integer size, `getUserStorageUsage()` throws `INVALID_METADATA`, returning HTTP 500 and aborting the upload (`server.js:219-224, 774-777`).
   - Tracks concurrent in-flight uploads per user via `inflightUploads.get(user.username)` (`server.js:232-245, 778`).
   - If `currentUsage + inFlight + plain.length > quota`, rejects upload with HTTP 413 without writing to disk (`server.js:780-783`).
   - Atomically reserves in-flight bytes: `addInflightBytes(user.username, plain.length)` (`server.js:785`).
4. **Pre-Encryption Integrity Digest**:
   - Calculates authoritative SHA-256 digest on original plaintext buffer prior to encryption: `crypto.createHash('sha256').update(plain).digest('hex')` (`server.js:790`).
5. **Cryptographic Key & IV Management**:
   - **Master Key**: $32\text{ bytes}$ ($256\text{ bits}$) AES key loaded from `storage/.master-key` or generated with `crypto.randomBytes(32)` on initial startup (`server.js:10, 17-20`). Stored with filesystem permissions `0o600` (`server.js:19`).
   - **Cipher Algorithm**: `aes-256-gcm` (Galois/Counter Mode) (`server.js:376`).
   - **Initialization Vector (IV)**: Fresh, cryptographically random $12\text{ bytes}$ ($96\text{ bits}$) IV generated per file: `crypto.randomBytes(12)` (`server.js:375`).
6. **Encryption & Authentication Tag**:
   - `cipher.update(plainBuffer)` and `cipher.final()` compute ciphertext (`server.js:377`).
   - `cipher.getAuthTag()` extracts the $16\text{ byte}$ ($128\text{ bit}$) GCM authentication tag (`server.js:380`).
7. **Storage & Metadata Persistence**:
   - Generates unique file ID: `id = crypto.randomUUID()` (`server.js:791`).
   - Ciphertext written to disk at `storage/<id>.aes`: `fs.writeFileSync(createdDiskPath, sealed.data)` (`server.js:792, 798`).
   - File record created in `db.files[id]` storing `{ id, name, diskName, iv, tag, owner, ownerRole, sharedWith: [], size, sha256, originalSha256, createdAt, tampered: false }` (`server.js:800-815`).
   - Persists metadata atomically via `persist()`: writes temporary file `storage/metadata.<uuid>.tmp`, flushes, and invokes `fs.renameSync` (`server.js:175-186, 817`).
8. **Transactional Rollback on Failure**:
   - If disk write or metadata persistence fails:
     - Unlinks orphaned ciphertext file if present (`server.js:822-828`).
     - Removes `db.files[createdFileId]` and attempts rollback persist (`server.js:829-836`).
     - Logs `[DENY] upload ... (upload transaction failed and rolled back)` (`server.js:837`).
   - `finally` block guarantees release of reserved in-flight quota bytes: `releaseInflightBytes(user.username, plain.length)` (`server.js:839-841`).

---

## 6. File Download & Integrity Verification Flow

1. **Authorization Check (Zero-Trust Guard)**:
   - Evaluates `allowed(user, file, 'read')` before accessing ciphertext or disk (`server.js:981`).
   - If caller is neither the owner nor in `file.sharedWith`, emits `[DENY] download ... (access denied)` and returns HTTP 403 Forbidden (`server.js:982-984`).
2. **Authenticated Decryption (`decrypt`)**:
   - Initializes decipher: `crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(record.iv, 'hex'))` (`server.js:386`).
   - Sets authentication tag: `decipher.setAuthTag(Buffer.from(record.tag, 'hex'))` (`server.js:387`).
   - Reads ciphertext blob from disk: `fs.readFileSync(filePath)` (`server.js:389`).
   - Computes plaintext: `Buffer.concat([decipher.update(cipherData), decipher.final()])` (`server.js:390`).
3. **GCM Authentication Tag Verification**:
   - If ciphertext has been altered, truncated, or tampered on disk, or if the stored tag/IV does not match, `decipher.final()` throws an OpenSSL authentication error (`server.js:390, 989`).
   - Caught in `try...catch`: logs `[INTEGRITY-FAIL] download ... (AES-GCM authentication tag invalid)` and returns HTTP 409 Conflict with message `"Integrity check failed: encrypted file authentication tag invalid or data corrupted. File rejected."` (`server.js:989-992`).
4. **SHA-256 Plaintext Hash Verification**:
   - If AES-GCM tag verification succeeds, recomputes SHA-256 hash on decrypted plaintext: `actual = crypto.createHash('sha256').update(plain).digest('hex')` (`server.js:995`).
   - Compares with stored authoritative digest `file.sha256` using constant-time check: `crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))` (`server.js:996-998`).
   - If hash mismatch occurs (e.g. simulated via integrity demo): logs `[INTEGRITY-FAIL] download ... (SHA-256 mismatch)` and returns HTTP 409 Conflict (`server.js:999-1001`).
5. **Success Response**:
   - Emits `[ALLOW] download user=<username> file=<name> sha256=<hash>` (`server.js:1003`).
   - Returns HTTP 200 with `{ name, content: plain.toString('base64'), sha256: actual }` (`server.js:1004-1008`).

---

## 7. File Sharing, Revocation & Deletion Lifecycle

- **File Sharing (`POST /api/files/:id/share`)**:
  - Caller must be the original file owner (`file.owner === user.username`); non-owners rejected with HTTP 403 (`server.js:907-910`).
  - Target user must exist in `db.users`; non-existent user returns HTTP 400 (`server.js:914-917`).
  - Target user cannot be the owner themselves; returns HTTP 400 (`server.js:918-920`).
  - Adds target to `file.sharedWith` (avoiding duplicates) and invokes `persist()` (`server.js:921-925`).
  - Emits audit event `[ALLOW] share user=<owner> target=<target> file=<filename>` (`server.js:927`).
- **Access Revocation (`POST /api/files/:id/revoke`)**:
  - Caller must be the original file owner (`file.owner === user.username`); non-owners rejected with HTTP 403 (`server.js:933-936`).
  - Target user must currently exist in `file.sharedWith`; returns HTTP 400 if not present (`server.js:939-943`).
  - Removes target: `file.sharedWith = file.sharedWith.filter(u => u !== target)` and calls `persist()` (`server.js:945-946`).
  - Subsequent download attempts by revoked user immediately return HTTP 403 (`server.js:981-984`).
- **File Deletion (`DELETE /api/files/:id`)**:
  - Strict ownership enforcement: `file.owner === user.username`. Shared recipients and Admins are rejected with HTTP 403 (`server.js:858-861`).
  - **Two-Phase Transaction with Rollback**:
    - **Backup**: Reads disk blob into memory buffer `blobBackup` prior to unlinking (`server.js:864-873`).
    - **Phase 1**: Removes ciphertext file from disk via `fs.unlinkSync(filePath)` (`server.js:876-883`).
    - **Phase 2**: Removes file from database `delete db.files[id]` and invokes `persist()` (`server.js:886-890`).
    - **Rollback on Persistence Failure**: If `persist()` throws an error, restores `db.files[id] = fileBackup` and writes `blobBackup` back to `filePath` (`server.js:891-899`).
  - Successful deletion logs `[ALLOW] delete user=<owner> file=<filename>` and returns HTTP 200 (`server.js:901-902`).
  - Reclaims storage quota headroom for subsequent uploads (`server.js:205-230`).

---

## 8. Audit Logging & Security Sanitization

- **Log Locations**:
  - Standard output (`console.log`) (`server.js:140`).
  - In-memory circular buffer `auditLogs = []`, capped at 50 entries for admin UI feed (`server.js:24, 141-148`).
  - Persistent disk log file `storage/audit.log` (`server.js:154-159`).
- **Persistent Log Entry Format**:
  - Line syntax: `<ISO-8601-Timestamp> [<TYPE>] <action> <details>\n` (`server.js:139, 154-155`).
  - Example: `2026-11-25T13:01:30.123Z [ALLOW] login user=asha role=Student`.
- **Log Event Types**:
  - `ALLOW`: Permitted operations (login, registration, upload, download, share, revoke, delete, role changes) (`server.js:506, 572, 663, 695, 819, 901, 927, 948, 1003`).
  - `DENY`: Rejected requests (bad passwords, locked accounts, privilege escalation, unauthorized access, quota exceeded) (`server.js:457, 478, 497, 528, 538, 552, 563, 608, 617, 626, 647, 653, 658, 677, 682, 688, 775, 781, 837, 851, 859, 870, 880, 897, 908, 915, 934, 941, 955, 982`).
  - `INTEGRITY-FAIL`: Authentication tag corruption or SHA-256 digest mismatches (`server.js:990, 999`).
  - `DEMO`: Educational integrity demonstration events (`server.js:973`).
- **CRLF Injection Neutralization**:
  - `sanitizeLogField(val)` strips newline characters (`\r`, `\n`) and ASCII control characters `[\r\n\x00-\x1f\x7f]+`, replacing them with spaces (`server.js:129-133, 136-138`).
  - Prevents log forging, log injection, or splitting log entries.
- **Sensitive Data Omission**:
  - Passwords, session tokens, master encryption keys, scrypt salts, password hashes, and raw file contents are strictly omitted from log statements (`server.js:139-162`).
- **Filesystem Error Resilience**:
  - Persistent write uses `fs.appendFile` with an error-swallowing callback to ensure disk write issues or filesystem locks never crash or stall request processing (`server.js:157-162`).

---

## 9. Rate Limiting & Denial-of-Service Defense

### A. Login Rate Limiting (`loginRateLimits`)
- **Key Formulation**: Combined `${cleanUsername}|${clientIp}` (`server.js:432`).
- **IP Isolation**: Usernames evaluated separately per IP address; failed attempts on one account do not lock out other accounts on the same or different IPs (`server.js:432-435`).
- **Account Enumeration Defense**: Unknown usernames are rate-limited identically to valid usernames without revealing account existence (`server.js:467-477`).
- **Sliding Window**: $15\text{ minutes}$ (`LOGIN_WINDOW_MS = 15 * 60_000`) (`server.js:31, 442-452`).
- **Lockout Threshold**: Reaching $5\text{ failed attempts}$ within the 15-minute window activates a $60\text{ second}$ lockout (`lockUntil = now + 60_000`) (`server.js:476, 495`).
- **Lockout Enforcement**:
  - The lock check occurs **before** running the CPU-heavy `scryptSync` calculation to prevent CPU exhaustion DoS (`server.js:455-462`).
  - When locked, returns HTTP 429 Too Many Requests with header `Retry-After: 60` and body `"Too many failed login attempts. Account temporarily locked for 60 seconds."` (`server.js:458-462`).
- **Window Persistence**:
  - Lockout expiration resets `lockUntil = 0` without erasing unexpired attempt timestamps, maintaining sliding window effectiveness (`server.js:438-440`).
- **Reset on Success**:
  - A successful authentication immediately deletes the rate-limit record for that username and IP pair (`server.js:501-502`).
- **Periodic Cleanup**:
  - Swept every 60 seconds by `sweepRateLimits()` via `setInterval` (`server.js:65-95, 97-100`).

### B. Registration Rate Limiting (`registrationRateLimits`)
- **Key Formulation**: Client IP address (`server.js:46, 525-526`).
- **Sliding Window**: $60\text{ seconds}$ (`REGISTRATION_WINDOW_MS = 60_000`) (`server.js:29, 52`).
- **Threshold**: Maximum $5\text{ attempts}$ per IP per 60 seconds (`REGISTRATION_MAX_ATTEMPTS = 5`) (`server.js:30, 55`).
- **Enforcement**:
  - 6th attempt within the 60-second window returns HTTP 429 with dynamic `Retry-After` header indicating seconds until the oldest attempt decays (`server.js:55-58, 529-534`).
- **Pruning**: Pruned every 60 seconds in `sweepRateLimits()` (`server.js:65-74`).

### C. Client IP Resolution & Anti-Spoofing
- `getClientIp(req)` extracts `req.socket.remoteAddress` directly (`server.js:39-44`).
- Ignores untrusted `X-Forwarded-For` and `X-Real-IP` headers to prevent header spoofing bypasses (`server.js:39-44`).
- Normalizes IPv6 loopback `::1` and IPv4-mapped IPv6 `::ffff:127.0.0.1` to `127.0.0.1` (`server.js:41-42`).

---

## 10. HTTP / HTTPS Transport Behavior & Security Headers

- **Default Transport**: Plain HTTP bound strictly to loopback IP `127.0.0.1` on port `4173` (`server.js:11-12, 1024, 1105-1112`).
- **HTTPS Activation Condition**: Activated when `USE_HTTPS=true` or `HTTPS=true` environment variable is set (`server.js:1024, 1029-1031`).
- **Fail-Loud Certificate Validation**:
  - If HTTPS is requested and certificates are missing or invalid, the server **fails loudly** and halts immediately; it **never** falls back silently to HTTP (`server.js:1035-1103, 1115-1124`).
  - Error Codes Thrown:
    - `ERR_HTTPS_CERT_MISSING`: Certificate file not found (`server.js:1041`).
    - `ERR_HTTPS_KEY_MISSING`: Private key file not found (`server.js:1049`).
    - `ERR_HTTPS_FILE_READ`: Unreadable cert/key files (`server.js:1060`).
    - `ERR_HTTPS_KEY_INVALID`: Corrupt private key failed `crypto.createPrivateKey` (`server.js:1068`).
    - `ERR_HTTPS_CERT_INVALID`: Certificate missing PEM header (`server.js:1074`).
    - `ERR_HTTPS_KEY_CERT_MISMATCH`: Key and certificate do not match (`server.js:1091`).
- **TLS Version Constraints**:
  - Server enforces minimum TLS version 1.2: `minVersion: 'TLSv1.2'` (`server.js:1081`).
  - TLS 1.0 and TLS 1.1 handshakes are rejected at the TLS layer (`server.js:1081; verify-zero-trust.js:1835-1894`).
- **Certificate Generation (`gen-cert.js`)**:
  - Uses OpenSSL CLI to generate self-signed Elliptic Curve certificate (`gen-cert.js:16, 120-129`).
  - Curve: `prime256v1` (NIST P-256) (`gen-cert.js:122`).
  - Validity: 365 days (`gen-cert.js:114, 126`).
  - Subject: `CN=localhost` (`gen-cert.js:127`).
  - Subject Alternative Name (SAN): `DNS:localhost, IP:127.0.0.1` (`gen-cert.js:115-116, 128`).
  - Complete pairs are preserved unless `--force` is supplied (`gen-cert.js:76-91`).
  - Incomplete pairs (one file present, one missing) throw `ERR_TLS_PAIR_INCOMPLETE` unless `--force` is supplied (`gen-cert.js:93-102`).
- **HTTP Security Headers**:
  - `Content-Security-Policy`: `"default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"` (`server.js:297`).
  - `X-Frame-Options`: `"DENY"` (`server.js:298`).
  - `X-Content-Type-Options`: `"nosniff"` (`server.js:295`).
  - `Cache-Control`: `"no-store"` (`server.js:296`).
  - `Referrer-Policy`: `"no-referrer"` (`server.js:299`).
  - `Strict-Transport-Security`: `"max-age=31536000; includeSubDomains"` (applied **only** when request is over an encrypted TLS socket) (`server.js:287-290, 300`).

---

## 11. Storage Quotas & System Limits

- **Cumulative Storage Quotas by Role**:
  - `Student`: $30\text{ MB}$ ($31,457,280\text{ bytes}$) (`server.js:34`).
  - `Faculty`: $150\text{ MB}$ ($157,286,400\text{ bytes}$) (`server.js:35`).
  - `Admin`: Unlimited (`Infinity`) (`server.js:36`).
- **Recipient Isolation**: Shared files are attributed strictly to the file owner; recipient quota calculations ignore shared files (`server.js:205-230`).
- **Quota Recovery**: Deleting an owned file permanently reclaims storage usage (`server.js:857-903`).
- **Per-File Size Limit**: $10\text{ MB}$ ($10 \times 1024 \times 1024\text{ bytes}$) (`server.js:765-767`).
- **HTTP Request Body Limit**: $15,000,000\text{ bytes}$ raw buffer limit (`server.js:315-320`).
- **Filename Length Limit**: Truncated to 120 characters; illegal filesystem characters sanitized (`server.js:368-372`).

---

## 12. Not Implemented

The following features are **not implemented** in the current ZTFILE codebase:

1. **Client-Side / End-to-End Encryption (E2EE)**: Plaintext is transmitted to the server as base64; encryption and decryption occur exclusively server-side (`server.js:757-761, 797, 988`).
2. **Per-User or Per-File Encryption Keys**: A single global master key (`storage/.master-key`) encrypts all files across all users (`server.js:10, 17, 376, 386`).
3. **Key Derivation from User Passwords / Envelope Encryption**: Master key is generated via random bytes; it is not derived from user passphrases or wrapped by user-held keys (`server.js:17-20`).
4. **Multi-Factor Authentication (MFA / 2FA)**: Authentication relies strictly on single-factor username and password (`server.js:428-500`).
5. **Password Complexity & Expiration Enforcement**: Passwords only require a minimum length of 4 characters; no checks for uppercase, digits, symbols, or dictionary words (`server.js:255-257`).
6. **Password Reset / Account Recovery**: No email verification, security questions, or password reset endpoints exist.
7. **Distributed / Persistent Sessions**: Sessions are stored in an in-memory `Map` (`sessions`) and are lost upon process restart (`server.js:23`).
8. **Token Revocation List / Blacklist**: Revocation is handled only by in-memory deletion; no distributed blacklist or JWT token revocation scheme exists.
9. **Streaming File Uploads / Downloads**: Entire files are buffered into memory as base64 strings (`server.js:313-315, 761, 1006`).
10. **Folder / Directory Organization**: The file storage model is completely flat (`db.files[id]`) (`server.js:166, 800`).
11. **Cryptographic Signing / HMAC for Metadata**: `metadata.json` is plain JSON without digital signatures or HMAC authentication (`server.js:175-186`).
12. **Cryptographic Log Tamper Proofing**: `audit.log` is a plain append-only text file without cryptographic hash chaining, forward-secure signatures, or remote syslog shipping (`server.js:154-159`).
13. **User Deletion API**: Administrators can list, create, and update user roles, but cannot delete user accounts (`server.js:630-705`).
