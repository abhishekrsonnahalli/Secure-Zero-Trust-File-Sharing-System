# ZTFILE — Verification Test Evidence & Analysis

This document contains the complete, unedited execution output of the official test suite (`node verify-zero-trust.js`) run on the local system, followed by an in-depth security analysis table detailing what each check validates and what it does not prove.

---

## 1. Raw Test Execution Console Output

```
======================================================================
       RUNNING COMPREHENSIVE ZERO-TRUST VERIFICATION TESTS
======================================================================

[DENY] login user=asha (invalid password)
[CHECK 1] ✅ PASS - Wrong password is rejected
  Details: HTTP 401 received. Server returned error: "Incorrect username or password.". No session token issued.

[ALLOW] register user=priya_test role=Student
[DENY] register user=priya_test (already exists)
[CHECK 1b] ✅ PASS - New user registration with salted scrypt hashing and duplicate rejection
  Details: Registered user "priya_test" returned HTTP 201 with token and role "Student". Duplicate registration correctly rejected with HTTP 400 (Username 'priya_test' is already taken.).

[DENY] register user=bad_admin role=Admin (privilege escalation blocked)
[DENY] register user=bad_faculty role=Faculty (privilege escalation blocked)
[ALLOW] register user=student_norole role=Student
[DENY] admin user=student_norole role=Student path=/api/admin/users (admin required)
[DENY] admin user=student_norole role=Student path=/api/admin/users/student_norole/role (admin required)
[ALLOW] login user=admin role=Admin
[ALLOW] admin-create-user admin=admin created_user=prof_kavita role=Faculty
[ALLOW] admin-list-users admin=admin count=7
[DENY] admin-change-role admin=admin target=admin (self role change prohibited)
[DENY] admin-create-user admin=admin role=Superuser (invalid role)
[DENY] admin-create-user admin=admin user=prof_kavita (already exists)
[DENY] admin-change-role admin=admin target=prof_kavita role=Superuser (invalid role)
[DENY] admin-change-role admin=admin target=nobody_here (user not found)
[DENY] register public registration disabled (ALLOW_PUBLIC_REGISTRATION=false)
[CHECK 1c] ✅ PASS - Privilege escalation prevention and Admin user management
  Details: All 10 RBAC authorization tests verified: Admin self-reg blocked (403), Faculty self-reg blocked (403), Student default role assigned (201), Student admin access blocked (403), Student self-promotion blocked (403), Admin provisioned Faculty account (201), Admin listed users with no secrets exposed (200), Admin self-demotion blocked (400), Invalid roles & duplicate rejection verified (400/404), ALLOW_PUBLIC_REGISTRATION=false enforcement confirmed (403).

[DENY] unauthenticated method=GET path=/api/activity
[DENY] activity user=student_norole role=Student (admin required)
[ALLOW] login user=rao role=Faculty
[DENY] activity user=rao role=Faculty (admin required)
[CHECK 1d] ✅ PASS - Activity audit feed access control (Admin-only restriction)
  Details: Unauthenticated access blocked (HTTP 401), Student access blocked (HTTP 403), Faculty access blocked (HTTP 403), Admin access granted (HTTP 200) with no credential leakage.

[DENY] register user=crlf_user role=Faculty [ALLOW] forged_action user=admin (privilege escalation blocked)
[DENY] bad-request error=Invalid JSON payload.
[CHECK 1e] ✅ PASS - Audit log CRLF injection sanitization and malformed JSON HTTP 400 handling
  Details: CRLF injection neutralized (newlines stripped from details, no forged events), malformed JSON payload correctly returned HTTP 400 (Invalid JSON payload.) instead of 500.

[ALLOW] register user=edge_omitted role=Student
[ALLOW] register user=edge_student role=Student
[DENY] register user=edge_admin role=Admin (privilege escalation blocked)
[DENY] register user=edge_faculty role=Faculty (privilege escalation blocked)
[DENY] register user=edge_null role=null (privilege escalation blocked)
[DENY] register user=edge_empty role= (privilege escalation blocked)
[DENY] register user=edge_ws role=     (privilege escalation blocked)
[DENY] register user=edge_num role=123 (privilege escalation blocked)
[DENY] register user=edge_bool role=true (privilege escalation blocked)
[CHECK 1f] ✅ PASS - Registration role own-property edge-case handling
  Details: All 9 role property edge cases verified: Omitted role created Student (HTTP 201), whitespace-padded '  Student  ' created Student (HTTP 201), explicit Admin blocked (HTTP 403), explicit Faculty blocked (HTTP 403), explicit null blocked (HTTP 403), explicit empty string blocked (HTTP 403), explicit whitespace blocked (HTTP 403), numeric/boolean roles blocked (HTTP 403), zero rejected users or tokens created in database or active sessions.

[DENY] login user=asha (invalid password)
[CHECK 1g] ✅ PASS - Persistent audit logging (audit.log) and disk error resilience
  Details: Audit events persisted to "C:\Users\abhis\AppData\Local\Temp\ztfile-test-f2mu4H\audit.log" with valid ISO timestamps and "[TYPE] action details" formatting. Secrets check passed (0 passwords, tokens, hashes, salts, or file payloads logged). Server handled simulated disk write error without crashing (HTTP 401).

[ALLOW] login user=asha role=Student
[DENY] unauthenticated method=GET path=/api/me
[ALLOW] login user=ravi role=Student
[DENY] unauthenticated method=GET path=/api/me
[ALLOW] login user=admin role=Admin
[ALLOW] login user=rao role=Faculty
[CHECK 1h] ✅ PASS - Session expiry lifecycle and configurable TTL enforcement
  Details: Active sessions valid before expiry, expired sessions rejected (HTTP 401) and purged from memory. Default 30-min TTL verified (29m valid, 31m expired), custom TTL (5m) verified (4m valid, 6m expired), activity feed polling does not refresh TTL, invalid/negative TTL safely falls back to 30-min default.

[DENY] login user=rl_testuser (user not found)
[DENY] login user=rl_testuser (user not found)
[DENY] login user=rl_testuser (user not found)
[DENY] login user=rl_testuser (user not found)
[DENY] login user=rl_testuser (user not found)
[DENY] login user=rl_testuser (locked out)
[DENY] login user=rl_locked_target (invalid password)
[DENY] login user=rl_locked_target (invalid password)
[DENY] login user=rl_locked_target (invalid password)
[DENY] login user=rl_locked_target (invalid password)
[DENY] login user=rl_locked_target (invalid password)
[DENY] login user=rl_locked_target (locked out)
[ALLOW] login user=rl_locked_target role=Student
[DENY] login user=rl_other_user (user not found)
[DENY] login user=ghost_unknown_account_xyz (user not found)
[DENY] login user=ghost_unknown_account_xyz (user not found)
[DENY] login user=ghost_unknown_account_xyz (user not found)
[DENY] login user=ghost_unknown_account_xyz (user not found)
[DENY] login user=ghost_unknown_account_xyz (user not found)
[DENY] login user=ghost_unknown_account_xyz (locked out)
[DENY] login user=rl_testuser (locked out)
[DENY] login user=rl_sliding_win_user (invalid password)
[DENY] login user=rl_sliding_win_user (invalid password)
[DENY] login user=rl_sliding_win_user (invalid password)
[DENY] login user=rl_sliding_win_user (invalid password)
[DENY] login user=rl_sliding_win_user (invalid password)
[DENY] login user=rl_sliding_win_user (invalid password)
[DENY] login user=rl_sliding_win_user (locked out)
[DENY] login user=rl_sliding_win_user (invalid password)
[ALLOW] login user=rl_sliding_win_user role=Student
[CHECK 1i] ✅ PASS - Login rate limiting, lockout threshold, and IP/user isolation
  Details: 4 failed attempts allowed (HTTP 401), 5th failed attempt established 60-second lock (HTTP 401), 6th attempt returned HTTP 429 with confirmed "Retry-After: 60" header. Lock checked before scrypt (correct password returned 429 with Retry-After: 60 while locked). Successful login cleared only matching counter. Independent counters for different users on same IP verified. Unknown usernames locked identically without account enumeration. X-Forwarded-For spoofing rejected (socket remote address enforced). Sliding window persistence verified: failed attempts survive lockout expiration until 15-minute decay.

[ALLOW] login user=asha role=Student
[ALLOW] login user=rao role=Faculty
[ALLOW] login user=ravi role=Student
[ALLOW] login user=admin role=Admin
[CHECK 1j] ✅ PASS - Classroom demo accounts box and credentials integrity
  Details: Demo Accounts box in index.html verified present with all 4 unaltered credentials (asha, rao, ravi, admin). All 4 demo accounts authenticate successfully with exact assigned roles (Student, Faculty, Student, Admin).

[ALLOW] login user=asha role=Student
[ALLOW] upload user=asha file=asha-cns-notes.txt size=69B sha256=9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de
[ALLOW] download user=asha file=asha-cns-notes.txt sha256=9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de
[CHECK 2] ✅ PASS - Asha uploads and downloads her own file
  Details: Uploaded file ID 201213e1-d211-4710-b414-dff486fcf79d. Download returned HTTP 200. Decrypted text matches original (69 bytes), SHA-256 verified (9891d4597941087e...).

[ALLOW] login user=ravi role=Student
[DENY] download user=ravi file=asha-cns-notes.txt (access denied)
[CHECK 3] ✅ PASS - Ravi cannot download Asha’s unshared file
  Details: Ravi (Student) requested Asha's private file 201213e1-d211-4710-b414-dff486fcf79d. Server returned HTTP 403 (Forbidden). Message: "Access denied: this file was not shared with you.". Access denied by Zero-Trust policy.

[ALLOW] list-files user=admin visible=0
[DENY] download user=admin file=asha-cns-notes.txt (access denied)
[DENY] share user=admin file=asha-cns-notes.txt (not owner)
[DENY] revoke user=admin file=asha-cns-notes.txt (not owner)
[ALLOW] upload user=admin file=admin-doc.txt size=50B sha256=f21cbab5c202edc3aeb6565ca4619a10387eb4cba59bde3b1b9fe2d5cc6d6791
[ALLOW] download user=admin file=admin-doc.txt sha256=f21cbab5c202edc3aeb6565ca4619a10387eb4cba59bde3b1b9fe2d5cc6d6791
[ALLOW] share user=asha target=admin file=asha-cns-notes.txt
[ALLOW] download user=admin file=asha-cns-notes.txt sha256=9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de
[ALLOW] revoke user=asha target=admin file=asha-cns-notes.txt
[DENY] download user=admin file=asha-cns-notes.txt (access denied)
[CHECK 3b] ✅ PASS - Admin Zero-Trust file isolation (No automatic file access)
  Details: Unshared file hidden from Admin list (200), Admin download of unshared file blocked (HTTP 403), Admin unauthorized share/revoke blocked (HTTP 403), Admin can access own files (f78a2f3b-3fe4-4284-8607-1f677d5a44bb), explicit sharing to Admin verified (200), revocation from Admin verified (403).

[ALLOW] share user=asha target=rao file=asha-cns-notes.txt
[ALLOW] login user=rao role=Faculty
[ALLOW] download user=rao file=asha-cns-notes.txt sha256=9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de
[CHECK 4] ✅ PASS - Asha shares that file with Rao, and Rao can download it
  Details: Share returned HTTP 200. Rao (Faculty) download returned HTTP 200. Decrypted content correctly received and verified.

[ALLOW] revoke user=asha target=rao file=asha-cns-notes.txt
[DENY] download user=rao file=asha-cns-notes.txt (access denied)
[CHECK 5] ✅ PASS - Revoked access stops working
  Details: Revoke returned HTTP 200. Rao subsequent download attempt immediately returned HTTP 403 (Forbidden). Access successfully revoked.

[DEMO] tamper-demo user=asha file=asha-cns-notes.txt (simulated checksum mismatch: expected SHA-256 set to 000...)
[INTEGRITY-FAIL] download user=asha file=asha-cns-notes.txt (SHA-256 mismatch: expected 0000000000... actual 9891d45979...)
[INTEGRITY-FAIL] download user=asha file=asha-cns-notes.txt (AES-GCM authentication tag invalid)
[ALLOW] restore-checksum user=asha file=asha-cns-notes.txt restored_sha256=9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de
[ALLOW] download user=asha file=asha-cns-notes.txt sha256=9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de
[CHECK 6] ✅ PASS - A tampered or mismatched file is rejected
  Details: Both integrity checks verified: 1) Simulated SHA-256 mismatch rejected with HTTP 409 (Integrity check failed: SHA-256 digest does not match. File has been modified or corrupted. File rejected.). 2) Direct ciphertext bit-tampering rejected with HTTP 409 (AES-GCM auth tag check). Restoring valid state restored HTTP 200 download.

[CHECK 7] ✅ PASS - Stored file bytes are ciphertext, not readable plaintext
  Details: Inspected disk blob "201213e1-d211-4710-b414-dff486fcf79d.aes" (69 bytes). Plaintext string was NOT found anywhere in file bytes. Stored data is pure AES-256-GCM ciphertext.

[ALLOW] download user=asha file=asha-cns-notes.txt sha256=9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de
[CHECK 8] ✅ PASS - Server and browser SHA-256 values match for a successful download
  Details: Client-computed SHA-256: 9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de. Server-reported SHA-256: 9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de. Original digest: 9891d4597941087e9293036cbc3fba9b1c6abbed336909a93b08f67554efe7de. Exact cryptographic match confirmed.

[CHECK 9] ✅ PASS - HTTPS works, if implemented
  Details: Documented prototype status: TLS not enabled by default in local demonstration. In accordance with project instructions, the prototype binds strictly to 127.0.0.1 and clearly labels the interface as "LOCAL ONLY · HTTP 127.0.0.1:4173", documenting that traffic is not protected in transit. Full instructions for optional TLS with self-signed certificate are provided in README.md.

[ALLOW] upload user=asha file=asha-del-test.txt size=62B sha256=1c1d812917a5a9fb44fb1b3c3b19657f221c78c05c7bc852050f31ef4050f386
[ALLOW] share user=asha target=rao file=asha-del-test.txt
[DENY] delete user=ravi file=asha-del-test.txt (not owner)
[DENY] delete user=rao file=asha-del-test.txt (not owner)
[DENY] delete user=admin file=asha-del-test.txt (not owner)
[DENY] delete user=asha file=asha-del-test.txt (filesystem unlink error)
[ALLOW] delete user=asha file=asha-del-test.txt
[ALLOW] upload user=rao file=faculty-doc.txt size=62B sha256=1c1d812917a5a9fb44fb1b3c3b19657f221c78c05c7bc852050f31ef4050f386
[ALLOW] delete user=rao file=faculty-doc.txt
[DENY] delete user=asha file_id=non-existent-uuid-999 (file not found)
[CHECK 10] ✅ PASS - Secure file deletion authorization, cleanup, and transaction safety
  Details: All 10 deletion security requirements verified: Owner can delete own file (HTTP 200), Student denied deleting another's file (HTTP 403), Faculty denied deleting another's file (HTTP 403), Admin denied deleting another's private file (HTTP 403), shared recipient denied deleting original file (HTTP 403), deleted files rejected on download (HTTP 404), encrypted .aes blob removed from disk, metadata and sharing ACLs purged, audit log recorded ALLOW/DENY events without data leakage, and failed disk operations rolled back safely leaving consistent storage.

[ALLOW] login user=asha role=Student
[DENY] bad-request error=Invalid JSON payload.
[CHECK 11] ✅ PASS - Generic HTTP 500 responses and internal exception detail masking
  Details: Uncaught server exceptions return HTTP 500 with generic message "Internal server error." (raw internal message and path "C:\Confidential\System\Path\leak-key.pem" were strictly masked). Server-side console.error recorded the fault. Expected client errors (HTTP 400 "Invalid JSON payload.") were appropriately preserved.

[CHECK 12] ✅ PASS - Comprehensive HTTP security headers and Content-Security-Policy enforcement
  Details: All frontend assets (HTML, JS, CSS) and API responses consistently received CSP ("default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"), X-Frame-Options ("DENY"), Referrer-Policy ("no-referrer"), nosniff, and no-store headers.

[ALLOW] register user=rate_user_1 role=Student
[ALLOW] register user=rate_user_2 role=Student
[ALLOW] register user=rate_user_3 role=Student
[ALLOW] register user=rate_user_4 role=Student
[ALLOW] register user=rate_user_5 role=Student
[DENY] register ip=198.51.100.42 (registration rate limit exceeded)
[DENY] register ip=198.51.100.42 (registration rate limit exceeded)
[ALLOW] register user=other_ip_user role=Student
[ALLOW] register user=rate_user_recovered role=Student
[CHECK 13] ✅ PASS - Registration rate limiting (5 req/60s), sliding window decay, and periodic sweep
  Details: 5 registration attempts accepted from 198.51.100.42, 6th attempt rejected with HTTP 429 (Retry-After: 60s). Rate limit enforced before validation/scrypt. Independent IP (198.51.100.99) unaffected. Expired entries pruned by sweepRateLimits(), and rate limit recovered automatically after window expiration.

[DENY] unauthenticated method=GET path=/api/me
[CHECK 14] ✅ PASS - Periodic session cleanup mechanism and expired token purging
  Details: sweepExpiredSessions() purged expired session (f1962834..., 35m old) while retaining active session (bf8ea910...). Expired session returned HTTP 401; active session verified HTTP 200.

[ALLOW] login user=asha role=Student
[ALLOW] login user=admin role=Admin
[ALLOW] login user=quota_test_student role=Student
[DENY] upload user=quota_test_student file=overflow.txt size=200B (storage quota exceeded: used=31457230B in_flight=0B limit=31457280B)
[ALLOW] upload user=quota_test_student file=legit.txt size=33B sha256=687c019c3a27d86c2beb968a709fa37c5a0a267edf8ae82faef1b8ce9f55abc9
[ALLOW] delete user=quota_test_student file=legit.txt
[CHECK 15] ✅ PASS - Role-based cumulative storage quotas (Student: 30MB, Faculty: 150MB, Admin: Unlimited)
  Details: Quotas verified: Student (30 MB), Faculty (150 MB), Admin (Unlimited). Over-quota upload rejected with HTTP 413 without leaving orphaned files. Shared files excluded from recipient quota calculations. File deletion successfully restored quota headroom.

[DENY] login user=cr_sliding_user (invalid password)
[DENY] login user=cr_sliding_user (invalid password)
[DENY] login user=cr_sliding_user (invalid password)
[DENY] login user=cr_sliding_user (invalid password)
[DENY] login user=cr_sliding_user (invalid password)
[DENY] login user=cr_sliding_user (invalid password)
[DENY] login user=cr_sliding_user (locked out)
[ALLOW] login user=cr_sliding_user role=Student
[ALLOW] login user=cr_fail_closed_user role=Student
[DENY] upload user=cr_fail_closed_user file=blocked-by-corruption.txt (metadata integrity error: failed to verify storage usage)
[DENY] upload user=cr_fail_closed_user file=blocked-by-corruption.txt (metadata integrity error: failed to verify storage usage)
[DENY] upload user=cr_fail_closed_user file=blocked-by-corruption.txt (metadata integrity error: failed to verify storage usage)
[DENY] upload user=cr_fail_closed_user file=blocked-by-corruption.txt (metadata integrity error: failed to verify storage usage)
[DENY] upload user=cr_fail_closed_user file=blocked-by-corruption.txt (metadata integrity error: failed to verify storage usage)
[DENY] upload user=cr_fail_closed_user file=blocked-by-corruption.txt (metadata integrity error: failed to verify storage usage)
[DENY] upload user=cr_fail_closed_user file=blocked-by-corruption.txt (metadata integrity error: failed to verify storage usage)
[ALLOW] upload user=cr_fail_closed_user file=valid-test.txt size=13B sha256=e88142811dadd87838428f481240cae7745255f1f6fe2d520e51dbc51933d170
[ALLOW] delete user=cr_fail_closed_user file=valid-test.txt
[ALLOW] login user=cr_rollback_user role=Student
[DENY] upload user=cr_rollback_user file=doomed-file.txt (upload transaction failed and rolled back)
[ALLOW] upload user=cr_rollback_user file=healthy-after-rollback.txt size=13B sha256=5079d78b1ae1154c4f202d641a9b53ee962b94a41011733903ffff1b50cd83f9
[ALLOW] delete user=cr_rollback_user file=healthy-after-rollback.txt
[CHECK 16] ✅ PASS - Code Review Corrections: Sliding Window Persistence, Fail-Closed Quotas & Upload Rollback
  Details: Finding 1: Failed login attempts survived lockout expiration until 15m window decayed; immediate re-lock confirmed; cleared on success. Finding 2: Malformed metadata (negative/float/null/string/NaN) failed closed with HTTP 500; valid quota enforcement intact. Finding 3: Persistence failure after ciphertext creation triggered automatic transactional rollback (0 orphaned files, restored metadata, freed in-flight quota bytes).

[ALLOW] login user=asha role=Student
[CHECK 17] ✅ PASS - Optional HTTPS/TLS: EC P-256 cert generator, fail-loud missing certs, TLS 1.2+, and HTTPS-only HSTS
  Details: gen-cert.js generated self-signed EC P-256 certificate with SAN (DNS:localhost, IP:127.0.0.1) valid 365 days; existing complete certs preserved, incomplete pairs fail clearly unless --force. Server failed loudly when certificates missing, corrupt, or mismatched (never fell back to HTTP). Minimum TLS version 1.2 handshake enforced (real TLS 1.2+ succeeded; TLS 1.1 server-side rejection genuinely verified (TCP connected; server triggered qualifying tlsClientError [ERR_SSL_UNSUPPORTED_PROTOCOL]); server closed in all outcomes). Real HTTPS login and /api/me verified over live TLS server with HSTS ("max-age=31536000; includeSubDomains"). Transport URL and mode reported correctly for HTTP and HTTPS.

======================================================================
SUMMARY: 27 / 27 checks PASSED.
======================================================================
```

---

## 2. Comprehensive Test Evidence Analysis Table

| Test ID | What it checks | Expected | Actual | HTTP Status | What it proves | What it does NOT prove |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CHECK 1** | Wrong password rejection | HTTP 401 and generic error message without session token | Rejected with generic message and no token | 401 | Invalid passwords cannot authenticate; prevents unauthorized session token issuance | Does not prove protection against online password guessing without rate limiting |
| **CHECK 1b** | Self-registration & duplicate check | HTTP 201 with token for unique username; HTTP 400 for duplicate username | 201 for valid registration; 400 for duplicate username | 201, 400 | New users can register with default Student role; duplicate accounts cannot overwrite existing credentials | Does not prove password strength against dictionary attacks |
| **CHECK 1c** | Privilege escalation & Admin management | HTTP 403 on self-assigning Admin/Faculty role; HTTP 201 for Admin provisioning; HTTP 403 for Student accessing `/api/admin/*` | Public escalation blocked; Admin user management functional | 200, 201, 400, 403, 404 | Role-Based Access Control (RBAC) cannot be bypassed at registration or via API | Does not prove multi-tenant administrative boundaries or granular role delegation |
| **CHECK 1d** | Audit feed access control | HTTP 401 for anonymous; HTTP 403 for Student/Faculty; HTTP 200 for Admin | Only Admin can view `/api/activity` audit feed | 401, 403, 200 | Audit logs cannot be spied on by ordinary users or shared recipients | Does not prove logs cannot be read directly from `storage/audit.log` via filesystem access |
| **CHECK 1e** | Audit log CRLF injection & JSON parsing | HTTP 400 on malformed JSON; newlines stripped from audit log entries | Injection sanitized; malformed JSON rejected cleanly | 400, 200 | Prevents log forging/tampering via CRLF injection in username or error payloads | Does not prove cryptographic audit log immutability or write-once retention |
| **CHECK 1f** | Registration role property edge cases | HTTP 403 on non-Student role values (null, numbers, booleans, whitespace); HTTP 201 for valid defaults | All escalation attempts blocked with 403 | 201, 403 | Object own-property prototype pollution and loose typing tricks cannot bypass role gating | Does not prove server resilience against arbitrary memory injection outside Node runtime |
| **CHECK 1g** | Persistent audit logging & disk error resilience | Audit events appended to `storage/audit.log`; filesystem write failure does not crash server | Events persisted; simulated disk error handled gracefully | 401 | Audit log survives process restarts; disk errors fail soft without crashing HTTP service | Does not prove audit logs cannot be deleted or truncated by someone with OS-level access |
| **CHECK 1h** | Session TTL enforcement | Sessions older than TTL return HTTP 401; active sessions return HTTP 200 | Expired tokens rejected with 401; valid tokens return 200 | 200, 401 | Idle session hijacking window is bounded by configurable TTL (default 30 min) | Does not prove session revocation propagation across multiple clustered server instances |
| **CHECK 1i** | Login rate limiting & lockout | 5 failed attempts per user+IP lock account for 60s (HTTP 429 Retry-After: 60) | 6th attempt returned HTTP 429 with Retry-After: 60; scrypt bypassed while locked | 401, 429 | Protects against fast online credential brute-forcing; mitigates scrypt CPU exhaustion DoS | Does not prove protection against distributed credential stuffing across large botnet IP pools |
| **CHECK 1j** | Demo accounts & credentials integrity | 4 demo users (asha, rao, ravi, admin) present in UI and authenticate successfully | UI markup verified; all 4 accounts authenticate with assigned roles | 200 | Demonstration credentials match instructional CNS course requirements | Does not prove default credentials should ever be left in production environments |
| **CHECK 2** | Owner file upload and download | HTTP 201 on upload; HTTP 200 on download; plaintext matches original | Upload and download succeed; 69-byte notes text matched exactly | 201, 200 | File owner can upload, store, and retrieve their own file intact | Does not prove data confidentiality if the host server itself is compromised |
| **CHECK 3** | Access denial for unshared users | HTTP 403 when unshared user attempts download | Ravi denied download of Asha's private file | 403 | Zero-Trust default-deny isolation prevents unauthorized user downloads | Does not prove security against side-channel memory inspection |
| **CHECK 3b** | Admin Zero-Trust file isolation | Admin cannot list, download, share, or revoke unshared files; can only access if explicitly shared | Unshared file hidden from Admin; download returns 403; access granted only when shared | 200, 403 | Zero-Trust principle: Administrators have no inherent file read privileges | Does not prove protection if Admin has root access to the host OS filesystem |
| **CHECK 4** | Explicit file sharing | Owner shares file (HTTP 200); recipient downloads file (HTTP 200) | Sharing ACL updated; Rao downloads Asha's file successfully | 200 | Explicit authorization grants read access to designated recipients | Does not prove recipient cannot re-distribute downloaded plaintext out-of-band |
| **CHECK 5** | Access revocation | Revocation returns HTTP 200; subsequent download returns HTTP 403 | Revocation succeeds; recipient immediately denied access | 200, 403 | Revocation is immediate and takes effect without waiting for token renewal | Does not revoke file copies that the recipient already downloaded to their client machine |
| **CHECK 6** | Tamper detection & integrity rejection | Modified ciphertext or SHA-256 digest returns HTTP 409 | AES-GCM tag mismatch returns 409; checksum mismatch returns 409 | 409 | Both transport/storage ciphertext tampering and checksum corruption are detected and blocked | Does not prove metadata integrity if `metadata.json` is modified out-of-band without touching the file |
| **CHECK 7** | Ciphertext storage verification | Stored `.aes` file on disk contains raw ciphertext, zero plaintext | Inspected disk blob; plaintext not found; high entropy binary | N/A (disk read) | Files are encrypted at rest using AES-256-GCM before being written to disk | Does not prove end-to-end encryption (the server saw plaintext in memory) |
| **CHECK 8** | Client vs server SHA-256 consistency | Browser-computed SHA-256 matches server-computed SHA-256 | Exact 64-character hex match confirmed | 200 | Independent client validation confirms end-to-end data integrity over transport | Does not prove client browser runtime environment is free from malicious extensions |
| **CHECK 9** | Transport mode disclosure | Documented prototype status and `/api/transport` reporting | Protocol and mode reported accurately | 200 | Application accurately informs users whether transport is local HTTP or HTTPS | Does not prove plaintext HTTP is secure across untrusted physical networks |
| **CHECK 10** | Secure file deletion & cleanup | Owner deletes file (HTTP 200); `.aes` unlinked; metadata removed; non-owners blocked (HTTP 403) | All 10 deletion security requirements passed; disk blob and ACLs purged | 200, 403, 404 | Deletion permanently purges ciphertext and access rights; prevents orphaned files | Does not perform cryptographic DoD 5220.22-M multi-pass disk overwriting (unlinks file) |
| **CHECK 11** | Generic 500 error masking | Server exceptions return HTTP 500 "Internal server error." without stack traces or path leaks | Internal file paths strictly masked in HTTP response; logged to console | 500, 400 | Prevents information disclosure via stack traces, environment variables, or disk paths | Does not guarantee underlying bug causing the 500 exception is resolved |
| **CHECK 12** | HTTP security headers & CSP | CSP, X-Frame-Options, Referrer-Policy, nosniff, no-store headers present | All headers verified on HTML, CSS, JS, and API responses | 200 | Protects against MIME sniffing, clickjacking, CSS injection, and client-side caching | Does not protect against zero-day browser rendering engine vulnerabilities |
| **CHECK 13** | Registration rate limiting | 5 registrations per 60s per IP allowed; 6th rejected with HTTP 429 | 6th attempt rejected with HTTP 429; recovered after window decay | 201, 429 | Prevents automated registration spam and scrypt CPU starvation attacks from single IP | Does not prevent distributed registration attacks across rotating proxy networks |
| **CHECK 14** | Periodic session cleanup | Background timer purges expired sessions from memory | Expired token removed; active token retained | 200, 401 | Prevents unbounded memory growth from abandoned sessions; enforces session lifetime | Does not persist active sessions across server restarts |
| **CHECK 15** | Role-based storage quotas | Student: 30MB, Faculty: 150MB, Admin: Unlimited; over-quota rejected (HTTP 413) | Over-quota upload rejected; deletion restored quota; shared files excluded from recipient | 201, 413, 200 | Enforces storage boundaries per role; prevents single user from filling server disk | Does not prevent multiple distinct user accounts from aggregating disk usage |
| **CHECK 16** | Sliding window, fail-closed quotas & rollback | Failed logins survive lockout in 15m window; invalid metadata returns 500; failed uploads rollback | Lockout decays properly; corrupt metadata blocks upload; zero orphaned files | 401, 429, 500, 201 | Fail-closed security architecture: corrupted state blocks operations rather than bypassing checks | Does not repair corrupted metadata automatically (requires administrative intervention) |
| **CHECK 17** | Optional HTTPS/TLS & handshake enforcement | EC P-256 cert generated; TLS 1.2+ handshake succeeds; TLS 1.1 rejected; HSTS sent | Live TLS server rejected TLS 1.1 (`ERR_SSL_UNSUPPORTED_PROTOCOL`); HTTPS auth verified | 200, TLS Alert | Enforces TLS 1.2 minimum version, EC cryptography, and HTTPS-only HSTS protection | Does not eliminate browser self-signed certificate warnings without installing CA into root store |
