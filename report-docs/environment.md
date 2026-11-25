# ZTFILE — Runtime Environment & Dependency Audit

This document certifies the execution environment, runtime compatibility, built-in module inventory, and complete absence of external third-party dependencies for the **Secure Zero-Trust File Sharing System (ZTFILE)**.

---

## 1. Node.js Version Requirements

- **Minimum Version Required:** **Node.js 18.0.0+**
  - *Technical Justification:*
    - Native `crypto.randomUUID()` API used for file IDs and event IDs [server.js:142, server.js:791](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L142).
    - ECMAScript 2022 language features (logical assignment operators, numeric separators `60_000`, `Array.prototype.at`) [server.js:29-31](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L29-L31).
    - Built-in `node:` URI scheme imports (`node:http`, `node:https`, `node:fs`, `node:path`, `node:crypto`, `node:child_process`) [server.js:1-5, gen-cert.js:16-18](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L1-L5).
    - Native global `fetch` API used in test verification harness [verify-zero-trust.js](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/verify-zero-trust.js).
- **Verified Local Runtime Version:** **Node.js v24.11.0**
- **Bundled OpenSSL Version in Node Runtime:** **OpenSSL 3.5.4**

---

## 2. Operating System Compatibility

- **Host Environment Tested:** **Windows 11 / Windows 10** (`win32`, architecture `x64`).
- **Cross-Platform Portability:**
  - The core application server (`server.js`) and test suite (`verify-zero-trust.js`) are written to standard Node.js POSIX-compatible interfaces.
  - Path resolution consistently utilizes `path.join()`, ensuring correct path separators (`\` on Windows, `/` on Linux/macOS) [server.js:8-10](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L8-L10).
  - Storage directory configurable via `ZT_STORAGE_DIR` environment variable [server.js:8](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L8).
- **Platform-Specific Scripts:**
  - Windows Command Scripts provided for developer convenience:
    - `start-demo.bat` — Launches local HTTP or HTTPS server and opens default browser [start-demo.bat](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/start-demo.bat).
    - `start-https.bat` — Configures HTTPS mode and launches `start-demo.bat --https` [start-https.bat](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/start-https.bat).
    - `reset-demo.bat` — Restores demo storage files and database to clean classroom baseline [reset-demo.bat](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/reset-demo.bat).
  - On Linux / macOS, the application runs natively via standard shell: `node server.js` or `USE_HTTPS=true node server.js`.

---

## 3. Inventory of Built-in Node.js Modules

Every module imported across the codebase belongs strictly to the Node.js standard library. No packages from the npm registry are installed or imported.

### 3.1 Backend Server (`server.js`)
| Module Specifier | Purpose in Codebase | Source Reference |
| :--- | :--- | :--- |
| `node:http` | Core HTTP/1.1 server instantiation and request handling | [server.js:1, server.js:1105](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L1) |
| `node:https` | Optional TLS HTTPS server instantiation (`minVersion: 'TLSv1.2'`) | [server.js:2, server.js:1086](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L2) |
| `node:fs` | Filesystem I/O (metadata JSON read/write, master key management, audit logging, ciphertext blob persistence) | [server.js:3, server.js:14-20, server.js:157, server.js:178](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L3) |
| `node:path` | Normalized filesystem path resolution across storage and static directories | [server.js:4, server.js:8-10](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L4) |
| `node:crypto` | Cryptographic primitives: `scryptSync`, `timingSafeEqual`, `randomBytes`, `randomUUID`, `createCipheriv`, `createDecipheriv`, `createHash`, `createPrivateKey` | [server.js:5, server.js:17, server.js:264-265, server.js:375-380, server.js:386-390, server.js:482-485, server.js:790, server.js:1065](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/server.js#L5) |

### 3.2 Certificate Generator (`gen-cert.js`)
| Module Specifier | Purpose in Codebase | Source Reference |
| :--- | :--- | :--- |
| `node:child_process` | Spawns system OpenSSL binary via `spawnSync` to generate EC P-256 X.509 certificates | [gen-cert.js:16, gen-cert.js:26, gen-cert.js:131](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/gen-cert.js#L16) |
| `node:fs` | Checks certificate existence, creates directories, writes temporary OpenSSL config files | [gen-cert.js:17, gen-cert.js:62-74, gen-cert.js:152](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/gen-cert.js#L17) |
| `node:path` | Resolves target certificate and private key paths in `storage/` directory | [gen-cert.js:18, gen-cert.js:60-71](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/gen-cert.js#L18) |

### 3.3 Test Suite Harness (`verify-zero-trust.js`)
| Module Specifier | Purpose in Codebase | Source Reference |
| :--- | :--- | :--- |
| `node:http` & `node:https` | Issues test requests and runs live ephemeral test servers | [verify-zero-trust.js:1-2](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/verify-zero-trust.js#L1-L2) |
| `node:tls` | Tests raw TLS handshake rejection for legacy protocol versions (TLS 1.1) | [verify-zero-trust.js:3, verify-zero-trust.js:1841](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/verify-zero-trust.js#L3) |
| `node:fs` & `node:path` | Inspects test storage directories, tampers with ciphertext bytes for testing | [verify-zero-trust.js:4-5](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/verify-zero-trust.js#L4-L5) |
| `node:crypto` | Client-side digest validation, key pair checks, and simulation test fixtures | [verify-zero-trust.js:6](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/verify-zero-trust.js#L6) |
| `node:os` | Obtains temporary directories for isolated sandbox test runs | [verify-zero-trust.js:7](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/verify-zero-trust.js#L7) |
| `node:child_process` | Tests standalone script execution and certificate generator behavior | [verify-zero-trust.js:8](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/verify-zero-trust.js#L8) |
| `node:assert` | Strict assertion evaluations across all 27 verification checkpoints | [verify-zero-trust.js:9](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/verify-zero-trust.js#L9) |

---

## 4. Confirmation of Zero External Dependencies

An exhaustive audit of the workspace confirms the following:
1. **Absence of Package Manifest:** There is **NO `package.json`** file in the project directory.
2. **Absence of Dependency Tree:** There is **NO `node_modules/`** folder anywhere in the repository.
3. **Absence of Package Lockfiles:** There are **NO `package-lock.json`**, `yarn.lock`, or `pnpm-lock.yaml` files.
4. **Pure Vanilla Frontend:** The web client consists of:
   - Plain HTML5: [index.html](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/index.html)
   - Plain CSS3: [style.css](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/style.css)
   - Plain ECMAScript with standard Web APIs (`fetch`, `FileReader`, `crypto.subtle`): [app.js](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/app.js)
   - **Zero external CDN scripts, remote fonts, or frontend CSS/JS frameworks.**
5. **External Binary Prerequisite:**
   - The only external tool required is the system **OpenSSL CLI binary** (`openssl`), which is strictly used when running `node gen-cert.js` to create the self-signed certificate pair.
   - `gen-cert.js` automatically detects OpenSSL in system `PATH` or standard installation directories (including Git for Windows OpenSSL at `C:\Program Files\Git\usr\bin\openssl.exe`) [gen-cert.js:20-54](file:///c:/Users/abhis/Desktop/CNS_LAB/course_project/Secure-Zero-Trust-File-Sharing-main/Secure-Zero-Trust-File-Sharing-main/gen-cert.js#L20-L54).
