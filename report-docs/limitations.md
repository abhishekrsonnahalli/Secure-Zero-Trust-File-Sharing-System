# ZTFILE — Architectural & Cryptographic Limitations

This document analyzes the real architectural, cryptographic, and operational limitations identified in the Secure Zero-Trust File Sharing System (**ZTFILE**) codebase.

---

## 1. Master Encryption Key in Plaintext Storage

- **Implementation**: The AES-256 master key is stored directly on disk at `storage/.master-key` (`server.js:10, 17-20`).
- **Limitation**:
  - The key is stored as raw binary bytes on the local filesystem.
  - While permissions are set to `0o600` on POSIX systems (`server.js:19`), on Windows filesystems, standard POSIX octal modes are not enforced identically without explicit Windows ACL configuration.
  - If an attacker obtains filesystem read access (via server backup leakage, directory traversal vulnerability, or host compromise), they acquire the master key and can decrypt every encrypted file (`storage/*.aes`) across all users.
- **Enterprise Standard**: Use a Hardware Security Module (HSM), a managed Key Management Service (AWS KMS, Google Cloud KMS, Azure Key Vault), or HashiCorp Vault. Alternatively, implement envelope encryption where each file has a unique data encryption key (DEK) wrapped by a key encryption key (KEK).

---

## 2. Server-Side Decryption (Not End-to-End Encrypted)

- **Implementation**:
  - The browser reads files locally and encodes them into base64 strings (`app.js:287-293`).
  - Base64 plaintext is transmitted to the server over HTTP/HTTPS (`server.js:757-761`).
  - The server encrypts the file on upload (`server.js:797`) and decrypts it on download (`server.js:988`), sending decrypted base64 back to the browser (`server.js:1006`).
- **Limitation**:
  - This system is **not End-to-End Encrypted (E2EE)**. It implements **Server-Side Encryption at Rest**.
  - The server runtime has full visibility into unencrypted file contents in process memory.
  - A rogue administrator, memory dumper, or compromised server process can intercept plaintext files during upload or download operations.
- **Enterprise Standard**: Client-side encryption using Web Cryptography API (`crypto.subtle`) in the browser, where only ciphertext and client-held public/private keys are processed by the server.

---

## 3. Single Global Master Key (No Key Isolation)

- **Implementation**: A single 256-bit symmetric key (`key`) is shared across all users and files (`server.js:17, 376, 386`).
- **Limitation**:
  - There is zero cryptographic segregation between tenants, roles, or users.
  - Access control is enforced strictly at the application layer (`allowed(user, file, action)`) (`server.js:357-366`).
  - If the master key is compromised, all files for all users (past, present, and future) are compromised simultaneously.
  - There is no mechanism for cryptographic key rotation or re-keying individual files.
- **Enterprise Standard**: Per-user or per-organization key derivation, or unique per-file Data Encryption Keys (DEKs) wrapped by user public keys.

---

## 4. In-Memory Session Management & Single-Node State

- **Implementation**: Sessions are stored in an in-memory `Map` (`const sessions = new Map()`) (`server.js:23`).
- **Limitation**:
  - **Process Volatility**: Restarting the Node.js server immediately wipes all active sessions, disconnecting all users.
  - **Horizontal Scaling Barrier**: The system cannot be scaled across multiple server instances behind a load balancer without sticky sessions or a shared session cache (such as Redis or Memcached).
  - **Token Tracking**: Tokens cannot be inspected or revoked by an administrator from persistent storage.
- **Enterprise Standard**: Distributed session cache (Redis / Valkey) or signed/encrypted stateless session tokens (JWT/PASETO) combined with a distributed revocation list.

---

## 5. In-Memory Rate Limiting

- **Implementation**: Both login rate limits (`loginRateLimits`) and registration rate limits (`registrationRateLimits`) are stored in volatile JavaScript `Map` objects (`server.js:25-26`).
- **Limitation**:
  - A server restart clears all rate-limit counters, lockouts, and attempt histories.
  - In a clustered or multi-instance deployment, rate limiting would be partitioned per node, allowing attackers to multiply their attack volume by distributing requests across nodes.
- **Enterprise Standard**: Centralized, atomic rate limiting using Redis token buckets or sliding-window sorted sets (`ZADD` / `ZREMRANGEBYSCORE`).

---

## 6. Monolithic Unindexed JSON Metadata (`metadata.json`)

- **Implementation**: Database metadata for all users and files is stored in a single flat JSON file (`storage/metadata.json`) loaded into memory as `db` (`server.js:9, 166-173`).
- **Limitation**:
  - **Performance Bottleneck**: Every single write operation (upload, delete, share, revoke, user registration, role change) serializes the entire database into a JSON string and writes it to disk (`persist()`) (`server.js:175-186`).
  - **Memory Footprint**: As the number of files and users grows into thousands, memory usage scales linearly with total metadata size.
  - **Concurrency / Race Conditions**: While `fs.renameSync` provides atomic file replacement, concurrent asynchronous requests operate on the shared in-memory `db` object without database-level row locking or ACID transaction isolation.
- **Enterprise Standard**: Relational database (PostgreSQL, SQLite) or transactional document store with indexed fields, foreign keys, and ACID transactions.

---

## 7. Unsigned & Unauthenticated Metadata

- **Implementation**:
  - File ciphertext blobs are authenticated using AES-256-GCM authentication tags (`server.js:380, 387`).
  - However, `metadata.json` is plain JSON with no digital signatures, HMACs, or hash chains (`server.js:178`).
- **Limitation**:
  - If an attacker gains unauthorized write access to the filesystem, they can manipulate metadata attributes directly:
    - Change `owner` of any file.
    - Add unauthorized usernames to `sharedWith`.
    - Change a user's `role` from `Student` to `Admin`.
    - Alter `originalSha256` or `size`.
  - The application cannot detect out-of-band tampering with `metadata.json` until file operations are executed.
- **Enterprise Standard**: Cryptographic message authentication codes (HMAC-SHA256) or digital signatures over metadata records, or database-level cryptographic audit trails.

---

## 8. Synchronous File I/O Blocking Event Loop

- **Implementation**: File operations utilize synchronous Node.js filesystem methods in critical HTTP request paths:
  - `fs.readFileSync` for ciphertext reading during download (`server.js:389`).
  - `fs.writeFileSync` for ciphertext writing during upload (`server.js:798`).
  - `fs.writeFileSync` and `fs.renameSync` during metadata persistence (`server.js:178-179`).
  - `fs.unlinkSync` during file deletion (`server.js:878`).
- **Limitation**:
  - Node.js operates on a single-threaded event loop.
  - When an upload or download of a 10MB file occurs, `fs.readFileSync` or `fs.writeFileSync` blocks the event loop for the duration of the disk I/O.
  - All concurrent HTTP requests, session sweeps, and timers stall during this time, creating severe latency spikes and vulnerability to Denial of Service (DoS) attacks.
- **Enterprise Standard**: Asynchronous, streaming file I/O using `fs.promises` or Node.js Streams (`fs.createReadStream`, `fs.createWriteStream`, `stream.pipeline`).

---

## 9. Lack of Streaming Cryptography (High Memory Buffering)

- **Implementation**:
  - Files are received as base64-encoded strings inside JSON payloads (`server.js:313, 757-761`).
  - Decoded into a full `Buffer` in memory before encryption (`server.js:761, 797`).
  - Download operations buffer the entire decrypted file in memory before base64 encoding (`server.js:390, 1006`).
- **Limitation**:
  - Base64 encoding imposes a 33% memory and network overhead.
  - A 10MB file requires ~13.3MB for the JSON body + 10MB for the plaintext buffer + 10MB for ciphertext buffer.
  - Multiple concurrent file operations can rapidly trigger Node.js Out-Of-Memory (OOM) crashes.
- **Enterprise Standard**: Direct multipart/form-data streaming with cipher/decipher Transform streams piping directly between the incoming HTTP socket and the filesystem.

---

## 10. Plaintext Local HTTP by Default

- **Implementation**: Default startup runs unencrypted HTTP on `127.0.0.1:4173` unless `USE_HTTPS=true` is explicitly provided (`server.js:1024, 1105`).
- **Limitation**:
  - While binding to `127.0.0.1` prevents remote LAN packet sniffing, unencrypted HTTP does not protect against local packet capture (e.g. Wireshark on loopback, hostile local services, or unprivileged local users on shared systems).
  - Session tokens and credentials travel in plaintext across the local network stack.
- **Enterprise Standard**: Require TLS/HTTPS by default in all environments, or provide automated TLS certificate provisioning via ACME (Let's Encrypt).

---

## 11. Self-Signed Certificates Without PKI Trust Chain

- **Implementation**: The optional HTTPS mode uses self-signed EC P-256 certificates generated locally via OpenSSL (`gen-cert.js:10-14, 120-129`).
- **Limitation**:
  - Browsers will inevitably flag the connection with `NET::ERR_CERT_AUTHORITY_INVALID` warnings (`start-demo.bat:54-56`).
  - Users become conditioned to clicking through TLS certificate warnings, defeating the purpose of transport security against Man-in-the-Middle (MitM) attacks.
- **Enterprise Standard**: Certificates issued by recognized public Certificate Authorities (CAs) or internal enterprise PKI root certificates installed in client trust stores.

---

## 12. Audit Log Vulnerability to Local Modification

- **Implementation**: `storage/audit.log` is a plain append-only text file (`server.js:154-159`).
- **Limitation**:
  - The log file has no cryptographic forward secrecy, hash chaining (Merkle tree / blockchain), or digital signatures.
  - An attacker with filesystem access can delete, edit, or truncate log entries to cover their tracks without leaving cryptographic evidence of log tampering.
- **Enterprise Standard**: Remote syslog forwarding (RFC 5424) over TLS, write-once-read-many (WORM) cloud storage buckets, or tamper-evident hash-chained audit ledgers.

---

## 13. Single-Factor Authentication & Weak Password Requirements

- **Implementation**:
  - Single-factor username and password authentication (`server.js:428-500`).
  - Password validation requires only a minimum length of 4 characters (`server.js:256`).
- **Limitation**:
  - No Multi-Factor Authentication (MFA / 2FA) using TOTP, FIDO2/WebAuthn, or hardware tokens.
  - No password complexity rules (uppercase, digits, special characters).
  - No check against breached password dictionaries (e.g. HaveIBeenPwned API).
  - No password expiration or rotation policy.
- **Enterprise Standard**: FIDO2 / WebAuthn passwordless authentication or mandatory TOTP 2FA, combined with NIST SP 800-63B password complexity and breach checking.

---

## 14. Missing Account Lifecycle Operations

- **Implementation**: User administration endpoints allow user listing (`GET /api/admin/users`), user creation (`POST /api/admin/users`), and role modification (`POST /api/admin/users/:username/role`) (`server.js:630-705`).
- **Limitation**:
  - **No User Deletion**: Administrators cannot delete or deactivate compromised accounts.
  - **No Self Password Change**: Users cannot update their own passwords.
  - **No Password Recovery**: No email verification or recovery tokens exist for forgotten credentials.
- **Enterprise Standard**: Comprehensive identity lifecycle management (CRUD on users, self-service profile management, automated deprovisioning, and secure password reset workflows).
