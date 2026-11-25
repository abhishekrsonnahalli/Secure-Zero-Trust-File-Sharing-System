# ZTFILE — Architecture & Workflow Diagrams (Mermaid)

All diagrams below have been verified directly against the implementation in [server.js](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js) and [app.js](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/app.js). No hypothetical or unintegrated components are included.

---

## 1. System Architecture Diagram

```mermaid
flowchart TD
    subgraph Client ["Client Tier (Browser)"]
        UI["Web UI (index.html / style.css)"]
        JS["Client Controller (app.js)"]
        Subtle["Web Crypto API (crypto.subtle)"]
        MemToken["In-Memory Token (let token = '')"]
        UI --- JS
        JS --- Subtle
        JS --- MemToken
    end

    subgraph Transport ["Transport & Security Boundary"]
        HTTP["HTTP (127.0.0.1:4173) [Default]"]
        HTTPS["HTTPS (TLS v1.2+, EC P-256) [Optional]"]
        Headers["Security Headers (CSP, X-Frame-Options, HSTS, no-store, nosniff)"]
    end

    subgraph Server ["Node.js Application Server (server.js)"]
        Router["HTTP/HTTPS Request Handler"]
        RateLimiter["Rate Limiting Engine (Login & Registration)"]
        AuthMgr["Authentication & Session Manager (userFor)"]
        AccessCtrl["Zero-Trust Access Controller (allowed)"]
        QuotaMgr["Cumulative Storage Quota Manager"]
        CryptoEng["Cryptography Engine (AES-256-GCM / scrypt / SHA-256)"]
        AuditLogger["Sanitized Audit Logger (logEvent)"]

        subgraph InMemState ["In-Memory Volatile State"]
            SessionsMap["sessions (Map: token -> user, role, loginTime)"]
            LoginRLMap["loginRateLimits (Map: user|ip -> attempts, lockUntil)"]
            RegRLMap["registrationRateLimits (Map: ip -> attempts)"]
            InflightMap["inflightUploads (Map: user -> bytes)"]
            AuditRingBuf["auditLogs (Array: last 50 events)"]
        end
    end

    subgraph Storage ["Persistent Storage Tier (storage/)"]
        MasterKeyFile[".master-key (32-byte AES-256 Key, Mode 0600)"]
        MetaFile["metadata.json (Users, Files, IVs, Auth Tags, Hashes, ACLs)"]
        AesBlobs["*.aes (AES-256-GCM Ciphertext Blobs)"]
        AuditFile["audit.log (Append-only ISO-8601 Audit Trail)"]
        CertFiles["cert.pem & key.pem (Self-signed EC P-256 Pair)"]
    end

    Client <-->|REST API JSON / Base64 Payload| Transport
    Transport <--> Router
    Router --> RateLimiter
    Router --> AuthMgr
    Router --> AccessCtrl
    Router --> QuotaMgr
    Router --> CryptoEng
    Router --> AuditLogger

    AuthMgr <--> SessionsMap
    RateLimiter <--> LoginRLMap
    RateLimiter <--> RegRLMap
    QuotaMgr <--> InflightMap
    AuditLogger <--> AuditRingBuf

    CryptoEng <--> MasterKeyFile
    Router <--> MetaFile
    CryptoEng <--> AesBlobs
    AuditLogger -->|Append-only| AuditFile
    HTTPS -.->|Reads TLS Certs| CertFiles
```

---

## 2. File Upload & Encryption Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as Client (app.js)
    participant Srv as Server (server.js)
    participant Quota as Quota Manager
    participant Crypto as Crypto Engine
    participant Disk as Storage (storage/)

    User->>Srv: POST /api/files (Authorization: Bearer <token>, name, content: base64)
    Note over Srv: Authenticate via userFor(req)
    alt Token Missing or Expired (>30m)
        Srv-->>User: HTTP 401 Unauthorized
    end

    Note over Srv: Validate filename, non-empty, and file size <= 10 MB
    alt File Size > 10 MB or Empty
        Srv-->>User: HTTP 400 Bad Request
    end

    Srv->>Quota: getUserStorageUsage(user) + inflight + size > quota?
    alt Cumulative Storage Quota Exceeded
        Srv-->>User: HTTP 413 Quota Exceeded (Storage quota limit reached)
    end

    Note over Srv: Reserve in-flight bytes (addInflightBytes)
    Srv->>Crypto: Compute SHA-256 digest on plaintext bytes
    Srv->>Crypto: Generate fresh 12-byte IV via crypto.randomBytes(12)
    Srv->>Crypto: Encrypt plaintext using AES-256-GCM + Master Key
    Crypto-->>Srv: Return Ciphertext, 12-byte IV (hex), 16-byte Auth Tag (hex)

    critical Disk & Metadata Atomic Persistence
        Srv->>Disk: Write ciphertext to storage/{uuid}.aes
        Srv->>Disk: Write updated metadata to storage/metadata.{uuid}.tmp
        Srv->>Disk: Atomic renameSync(tmp, metadata.json)
    option Persistence or I/O Failure
        Note over Srv: Rollback Transaction
        Srv->>Disk: Unlink storage/{uuid}.aes
        Srv->>Disk: Delete db.files[uuid] & restore metadata.json
        Srv->>Quota: releaseInflightBytes()
        Srv-->>User: HTTP 500 Internal Server Error
    end

    Note over Srv: releaseInflightBytes()
    Srv->>Disk: Append [ALLOW] upload to storage/audit.log
    Srv-->>User: HTTP 201 Created { file: { id, name, size, sha256, ... } }
```

---

## 3. File Download & Cryptographic Integrity Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as Client (app.js)
    participant Srv as Server (server.js)
    participant Disk as Storage (storage/)
    participant Crypto as Crypto Engine (Node.js)
    participant Browser as Browser WebCrypto

    User->>Srv: GET /api/files/:id/download (Authorization: Bearer <token>)
    Note over Srv: Authenticate user via userFor(req)
    alt Invalid or Expired Token
        Srv-->>User: HTTP 401 Unauthorized
    end

    Note over Srv: Lookup db.files[id]
    alt File Not Found
        Srv-->>User: HTTP 404 Not Found
    end

    Note over Srv: Zero-Trust Authorization: allowed(user, file, 'read')
    alt User is NOT Owner AND NOT in file.sharedWith
        Srv->>Disk: Append [DENY] download to audit.log
        Srv-->>User: HTTP 403 Forbidden ("Access denied: this file was not shared with you.")
    end

    Srv->>Disk: Read ciphertext from storage/{diskName}
    Srv->>Crypto: createDecipheriv('aes-256-gcm', key, iv) + setAuthTag(tag)

    alt Ciphertext Bit Altered or Auth Tag Mismatched
        Crypto-->>Srv: OpenSSL Decryption Failure (Invalid Auth Tag)
        Srv->>Disk: Append [INTEGRITY-FAIL] download (AES-GCM tag invalid) to audit.log
        Srv-->>User: HTTP 409 Conflict ("Integrity check failed: authentication tag invalid.")
    end

    Crypto-->>Srv: Decrypted Plaintext Buffer
    Srv->>Crypto: Compute actual SHA-256 = crypto.createHash('sha256').update(plain)
    Srv->>Crypto: timingSafeEqual(actual, expected)

    alt SHA-256 Digest Mismatch
        Srv->>Disk: Append [INTEGRITY-FAIL] download (SHA-256 mismatch) to audit.log
        Srv-->>User: HTTP 409 Conflict ("Integrity check failed: SHA-256 digest does not match.")
    end

    Srv->>Disk: Append [ALLOW] download to audit.log
    Srv-->>User: HTTP 200 OK { name, content: base64, sha256: actual }

    Note over User: Decode base64 to Uint8Array
    User->>Browser: crypto.subtle.digest('SHA-256', bytes)
    alt Browser SHA-256 != Server SHA-256
        User-->>User: Abort Download & Display Toast ("Client Integrity Verification Failed")
    else Browser SHA-256 == Server SHA-256
        User-->>User: Trigger Browser File Save Dialog
    end
```

---

## 4. Authentication & Authorization Flow

```mermaid
flowchart TD
    StartAuth([Incoming HTTP Request]) --> CheckRoute{Route Category}

    subgraph LoginFlow ["Login (/api/login)"]
        CheckRoute -->|POST /api/login| ExtractCreds[Read username & password]
        ExtractCreds --> CheckLock{Is account locked out?<br/>lockUntil > now?}
        CheckLock -->|Yes| DenyLockout[Log DENY & Return HTTP 429<br/>Retry-After: 60]
        CheckLock -->|No| SlideWin[Slide 15-min window over failed attempts]
        SlideWin --> LookupUser{db.users has username?}
        LookupUser -->|No| RecordFailUser[Record failure in loginRateLimits<br/>Lock for 60s if >= 5 failures]
        RecordFailUser --> Ret401A[Log DENY & Return HTTP 401<br/>'Incorrect username or password.']
        LookupUser -->|Yes| ComputeScrypt[Compute inputHash = scryptSync password, salt, 64]
        ComputeScrypt --> TimingComp{timingSafeEqual<br/>inputHash == storedHash?}
        TimingComp -->|No| RecordFailPass[Record failure in loginRateLimits<br/>Lock for 60s if >= 5 failures]
        RecordFailPass --> Ret401B[Log DENY & Return HTTP 401<br/>'Incorrect username or password.']
        TimingComp -->|Yes| ClearRL[Clear rate limit record]
        ClearRL --> GenToken[Generate 32-byte hex token]
        GenToken --> SaveSession[Store in sessions Map: username, role, loginTime]
        SaveSession --> Ret200Login[Log ALLOW & Return HTTP 200 with Token, Role, Quota]
    end

    subgraph RegisterFlow ["Registration (/api/register)"]
        CheckRoute -->|POST /api/register| CheckIPLimit{IP attempts in 60s >= 5?}
        CheckIPLimit -->|Yes| DenyRegRL[Log DENY & Return HTTP 429<br/>Retry-After: seconds]
        CheckIPLimit -->|No| CheckPubReg{ALLOW_PUBLIC_REGISTRATION<br/>== 'false'?}
        CheckPubReg -->|Yes| DenyPubReg[Log DENY & Return HTTP 403<br/>Public registration disabled]
        CheckPubReg -->|No| CheckRoleProp{body has 'role' property<br/>AND role != 'Student'?}
        CheckRoleProp -->|Yes| DenyEscalation[Log DENY & Return HTTP 403<br/>Privilege escalation blocked]
        CheckRoleProp -->|No| ValidateAcct{Username 2-30 chars<br/>Password >= 4 chars?}
        ValidateAcct -->|No| Ret400Reg[Return HTTP 400 Bad Request]
        ValidateAcct -->|Yes| CheckDupe{db.users has username?}
        CheckDupe -->|Yes| Ret400Dupe[Log DENY & Return HTTP 400<br/>Username already taken]
        CheckDupe -->|No| GenSaltScrypt[Generate 16-byte random salt<br/>Compute scrypt 64-byte hash]
        GenSaltScrypt --> SaveUser[Save in db.users as Student & persist]
        SaveUser --> CreateRegSession[Generate 32-byte hex token & store session]
        CreateRegSession --> Ret201Reg[Log ALLOW & Return HTTP 201 with Token]
    end

    subgraph ProtectedFlow ["Authenticated Endpoints (/api/*)"]
        CheckRoute -->|Other /api/*| CheckAuthHeader{Authorization header<br/>Bearer token?}
        CheckAuthHeader -->|Missing / Invalid| Ret401Unauth[Log DENY & Return HTTP 401<br/>Please log in first.]
        CheckAuthHeader -->|Present| LookupSession{Token in sessions Map?}
        LookupSession -->|No| Ret401NoSess[Log DENY & Return HTTP 401]
        LookupSession -->|Yes| CheckTTL{Date.now - loginTime > TTL?<br/>default: 30 min}
        CheckTTL -->|Yes| PurgeSess[Delete from sessions Map]
        PurgeSess --> Ret401Exp[Log DENY & Return HTTP 401]
        CheckTTL -->|No| RouteAuth{Route Type}

        RouteAuth -->|/api/admin/* or /api/activity| CheckAdminRole{user.role == 'Admin'?}
        CheckAdminRole -->|No| Ret403Admin[Log DENY & Return HTTP 403 Forbidden]
        CheckAdminRole -->|Yes| ExecAdmin[Execute Admin Handler]

        RouteAuth -->|/api/files/:id action| CheckFilePerm{allowed user, file, action?}
        CheckFilePerm -->|No| Ret403File[Log DENY & Return HTTP 403 Access Denied]
        CheckFilePerm -->|Yes| ExecFileOp[Execute File Operation]
    end
```

---

## 5. File Sharing & Revocation Flow

```mermaid
sequenceDiagram
    autonumber
    actor Owner as File Owner (Asha)
    actor Recipient as Shared Recipient (Rao)
    participant Srv as Server (server.js)
    participant Disk as Storage (metadata.json & audit.log)

    Note over Owner,Recipient: Phase 1: File Sharing
    Owner->>Srv: POST /api/files/:id/share { username: "rao" }
    Note over Srv: Authenticate Asha; verify file.owner === "asha"
    alt Requester is not File Owner
        Srv-->>Owner: HTTP 403 Forbidden ("Only the file owner can share this file.")
    end

    Note over Srv: Validate recipient exists and is not owner
    alt Recipient does not exist
        Srv-->>Owner: HTTP 400 Bad Request ("Selected user does not exist.")
    end

    Note over Srv: Append "rao" to file.sharedWith
    Srv->>Disk: Atomic persist() metadata.json
    Srv->>Disk: Append [ALLOW] share target=rao file=... to audit.log
    Srv-->>Owner: HTTP 200 OK { ok: true, files: [...] }

    Note over Owner,Recipient: Phase 2: Recipient Access Verification
    Recipient->>Srv: GET /api/files/:id/download
    Note over Srv: allowed(rao, file, 'read') -> file.sharedWith.includes("rao") === true
    Srv-->>Recipient: HTTP 200 OK { name, content: base64, sha256 }

    Note over Owner,Recipient: Phase 3: Access Revocation
    Owner->>Srv: POST /api/files/:id/revoke { username: "rao" }
    Note over Srv: Authenticate Asha; verify file.owner === "asha"
    alt Requester is not File Owner
        Srv-->>Owner: HTTP 403 Forbidden ("Only the file owner can revoke access.")
    end

    Note over Srv: Filter out "rao" from file.sharedWith
    Srv->>Disk: Atomic persist() metadata.json
    Srv->>Disk: Append [ALLOW] revoke target=rao file=... to audit.log
    Srv-->>Owner: HTTP 200 OK { ok: true, files: [...] }

    Note over Owner,Recipient: Phase 4: Revocation Verification
    Recipient->>Srv: GET /api/files/:id/download
    Note over Srv: allowed(rao, file, 'read') -> file.sharedWith.includes("rao") === false
    Srv->>Disk: Append [DENY] download user=rao (access denied) to audit.log
    Srv-->>Recipient: HTTP 403 Forbidden ("Access denied: this file was not shared with you.")
```

---

## 6. Metadata Storage & Memory Schema Structure

```mermaid
classDiagram
    class MetadataFile {
        +Object users
        +Object files
    }

    class UserRecord {
        +String salt "16-byte random hex (32 chars)"
        +String hash "64-byte scrypt hex (128 chars)"
        +String role "Student | Faculty | Admin"
    }

    class FileRecord {
        +String id "UUIDv4 string"
        +String name "Sanitized filename (max 120 chars)"
        +String diskName "{id}.aes"
        +String iv "12-byte random IV hex (24 chars)"
        +String tag "16-byte GCM auth tag hex (32 chars)"
        +String owner "Username of creator"
        +String ownerRole "Student | Faculty | Admin"
        +Array~String~ sharedWith "List of authorized recipient usernames"
        +Number size "Plaintext byte size (integer)"
        +String sha256 "Plaintext SHA-256 digest (64 chars hex)"
        +String originalSha256 "Backup digest for tamper demonstration"
        +String createdAt "ISO-8601 UTC timestamp"
        +Boolean tampered "Flag toggled by tamper demo"
    }

    class SessionRecord {
        +String token "32-byte random hex (64 chars) [Key]"
        +String username "Authenticated username"
        +String role "Student | Faculty | Admin"
        +Number loginTime "Timestamp in milliseconds"
    }

    class LoginRateLimitRecord {
        +String key "{username}|{clientIp} [Key]"
        +Array~Number~ attempts "Timestamps within 15-minute window"
        +Number failures "Number of failed attempts"
        +Number lockUntil "Lockout expiry timestamp (0 if unlocked)"
    }

    class DiskBlob {
        +Binary data "Raw AES-256-GCM ciphertext"
    }

    class MasterKeyFile {
        +Binary key "32-byte (256-bit) cryptographically random key"
    }

    MetadataFile "1" *-- "many" UserRecord : db.users
    MetadataFile "1" *-- "many" FileRecord : db.files
    FileRecord "1" --> "1" DiskBlob : references storage/{id}.aes
    DiskBlob ..> MasterKeyFile : encrypted under master key
    SessionRecord ..> UserRecord : references user & role
    FileRecord ..> UserRecord : owner & sharedWith reference users
```
