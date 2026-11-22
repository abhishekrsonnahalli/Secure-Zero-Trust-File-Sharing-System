const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = __dirname;
const STORE = process.env.ZT_STORAGE_DIR || path.join(ROOT, 'storage');
const META = path.join(STORE, 'metadata.json');
const KEY_FILE = path.join(STORE, '.master-key');
const PORT = Number(process.env.PORT || 4173);
const HOST = '127.0.0.1';

fs.mkdirSync(STORE, { recursive: true });

// AES-256 key management (stored separately from encrypted file blobs)
const key = fs.existsSync(KEY_FILE) ? fs.readFileSync(KEY_FILE) : crypto.randomBytes(32);
if (!fs.existsSync(KEY_FILE)) {
  fs.writeFileSync(KEY_FILE, key, { mode: 0o600 });
}

// In-memory sessions, audit log buffer, rate limiting, and quota tracking
const sessions = new Map();
const auditLogs = [];
const loginRateLimits = new Map();
const registrationRateLimits = new Map();
const inflightUploads = new Map();

const REGISTRATION_WINDOW_MS = 60_000;
const REGISTRATION_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60_000;

const STORAGE_QUOTAS = {
  Student: 30 * 1024 * 1024,
  Faculty: 150 * 1024 * 1024,
  Admin: Infinity
};

function getClientIp(req) {
  const raw = (req.socket && req.socket.remoteAddress) ? String(req.socket.remoteAddress).trim() : '127.0.0.1';
  if (raw === '::1' || raw === '::ffff:127.0.0.1') return '127.0.0.1';
  if (raw.startsWith('::ffff:')) return raw.slice(7);
  return raw || '127.0.0.1';
}

function checkRegistrationRateLimit(ip) {
  const now = Date.now();
  let attempts = registrationRateLimits.get(ip);
  if (!Array.isArray(attempts)) {
    attempts = [];
  }
  attempts = attempts.filter(ts => (now - ts) < REGISTRATION_WINDOW_MS);
  registrationRateLimits.set(ip, attempts);

  if (attempts.length >= REGISTRATION_MAX_ATTEMPTS) {
    const oldest = attempts[0];
    const retryAfter = Math.max(1, Math.ceil((oldest + REGISTRATION_WINDOW_MS - now) / 1000));
    return { allowed: false, retryAfter };
  }

  attempts.push(now);
  return { allowed: true };
}

function sweepRateLimits() {
  const now = Date.now();
  for (const [ip, attempts] of registrationRateLimits.entries()) {
    const valid = Array.isArray(attempts) ? attempts.filter(ts => (now - ts) < REGISTRATION_WINDOW_MS) : [];
    if (valid.length === 0) {
      registrationRateLimits.delete(ip);
    } else {
      registrationRateLimits.set(ip, valid);
    }
  }

  for (const [key, record] of loginRateLimits.entries()) {
    if (!record) {
      loginRateLimits.delete(key);
      continue;
    }
    if (record.lockUntil > 0 && now >= record.lockUntil) {
      record.lockUntil = 0;
    }
    const isLocked = record.lockUntil > 0 && now < record.lockUntil;
    const validAttempts = Array.isArray(record.attempts)
      ? record.attempts.filter(ts => (now - ts) < LOGIN_WINDOW_MS)
      : [];
    if (!isLocked && validAttempts.length === 0) {
      loginRateLimits.delete(key);
    } else {
      record.attempts = validAttempts;
      record.failures = validAttempts.length;
    }
  }
}

const rateLimitSweepTimer = setInterval(sweepRateLimits, 60_000);
if (typeof rateLimitSweepTimer.unref === 'function') {
  rateLimitSweepTimer.unref();
}

function getSessionTtlMs() {
  const envTtl = process.env.SESSION_TTL_MINUTES;
  let ttlMinutes = 30;
  if (envTtl !== undefined && envTtl !== null && String(envTtl).trim() !== '') {
    const parsed = Number(String(envTtl).trim());
    if (Number.isFinite(parsed) && parsed > 0) {
      ttlMinutes = parsed;
    }
  }
  return ttlMinutes * 60 * 1000;
}

function sweepExpiredSessions() {
  const now = Date.now();
  const ttlMs = getSessionTtlMs();
  for (const [token, session] of sessions.entries()) {
    if (!session || !session.loginTime || (now - session.loginTime > ttlMs)) {
      sessions.delete(token);
    }
  }
}

const sessionCleanupTimer = setInterval(sweepExpiredSessions, 10 * 60 * 1000);
if (typeof sessionCleanupTimer.unref === 'function') {
  sessionCleanupTimer.unref();
}

function sanitizeLogField(val) {
  return String(val === undefined || val === null ? '' : val)
    .replace(/[\r\n\x00-\x1f\x7f]+/g, ' ')
    .trim();
}

function logEvent(type, action, details) {
  const safeType = sanitizeLogField(type);
  const safeAction = sanitizeLogField(action);
  const safeDetails = sanitizeLogField(details);
  const line = `[${safeType}] ${safeAction} ${safeDetails}`.trim();
  console.log(line);
  auditLogs.push({
    id: crypto.randomUUID(),
    time: new Date().toLocaleTimeString(),
    type: safeType,
    action: safeAction,
    details: safeDetails
  });
  if (auditLogs.length > 50) auditLogs.shift();

  try {
    if (!fs.existsSync(STORE)) {
      try { fs.mkdirSync(STORE, { recursive: true }); } catch {}
    }
    const timestamp = new Date().toISOString();
    const persistentLine = `${timestamp} ${line}\n`;
    const auditFile = path.join(STORE, 'audit.log');
    fs.appendFile(auditFile, persistentLine, () => {
      // Ignore write errors to ensure disk errors never crash the server
    });
  } catch {
    // Ignore synchronous filesystem errors
  }
}

// Database initialization
let db = { users: {}, files: {} };
if (fs.existsSync(META)) {
  try {
    db = JSON.parse(fs.readFileSync(META, 'utf8'));
  } catch {
    db = { users: {}, files: {} };
  }
}

function persist() {
  const tmpMeta = path.join(STORE, `metadata.${crypto.randomUUID()}.tmp`);
  try {
    fs.writeFileSync(tmpMeta, JSON.stringify(db, null, 2), 'utf8');
    fs.renameSync(tmpMeta, META);
  } catch (err) {
    if (fs.existsSync(tmpMeta)) {
      try { fs.unlinkSync(tmpMeta); } catch {}
    }
    throw err;
  }
}

function normalizeRole(role) {
  if (!role || typeof role !== 'string') return null;
  const r = role.trim().toLowerCase();
  if (r === 'student') return 'Student';
  if (r === 'faculty') return 'Faculty';
  if (r === 'admin') return 'Admin';
  return null;
}

function getUserQuota(role) {
  const normalized = normalizeRole(role);
  if (normalized && Object.prototype.hasOwnProperty.call(STORAGE_QUOTAS, normalized)) {
    return STORAGE_QUOTAS[normalized];
  }
  return STORAGE_QUOTAS.Student;
}

function getUserStorageUsage(username) {
  const clean = String(username || '').trim().toLowerCase();
  let total = 0;
  if (db && db.files && typeof db.files === 'object') {
    for (const [fileId, file] of Object.entries(db.files)) {
      if (file && typeof file === 'object' && String(file.owner || '').trim().toLowerCase() === clean) {
        const rawSize = file.size;
        if (
          rawSize === undefined ||
          rawSize === null ||
          typeof rawSize !== 'number' ||
          !Number.isInteger(rawSize) ||
          rawSize < 0 ||
          !Number.isSafeInteger(rawSize)
        ) {
          const err = new Error(`Authoritative metadata contains invalid file size for file ${fileId}.`);
          err.code = 'INVALID_METADATA';
          err.statusCode = 500;
          throw err;
        }
        total += rawSize;
      }
    }
  }
  return total;
}

function getInflightBytes(username) {
  return inflightUploads.get(username) || 0;
}

function addInflightBytes(username, bytes) {
  inflightUploads.set(username, getInflightBytes(username) + bytes);
}

function releaseInflightBytes(username, bytes) {
  const cur = getInflightBytes(username);
  const rem = Math.max(0, cur - bytes);
  if (rem === 0) inflightUploads.delete(username);
  else inflightUploads.set(username, rem);
}

function validateNewAccount(username, password) {
  const cleanUsername = String(username || '').trim().toLowerCase();
  if (!cleanUsername || cleanUsername.length < 2 || cleanUsername.length > 30) {
    return { valid: false, error: 'Username must be between 2 and 30 characters.' };
  }
  if (!/^[a-z0-9_.-]+$/i.test(cleanUsername)) {
    return { valid: false, error: 'Username may only contain letters, numbers, dots, and hyphens.' };
  }
  if (!password || String(password).length < 4) {
    return { valid: false, error: 'Password must be at least 4 characters long.' };
  }
  return { valid: true, cleanUsername };
}

function createUser(username, password, role) {
  const cleanUsername = String(username || '').trim().toLowerCase();
  const assignedRole = normalizeRole(role) || 'Student';
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  db.users[cleanUsername] = { salt, hash, role: assignedRole };
  persist();
  return { username: cleanUsername, role: assignedRole };
}

function seedUser(username, password, role) {
  const userKey = username.toLowerCase();
  if (!db.users[userKey]) {
    createUser(userKey, password, role);
  }
}

// Seed the 4 required demo accounts with salted scrypt hashes
seedUser('asha', 'asha123', 'Student');
seedUser('rao', 'rao123', 'Faculty');
seedUser('ravi', 'ravi123', 'Student');
seedUser('admin', 'admin123', 'Admin');
persist();

function send(res, status, data, type = 'application/json; charset=utf-8', extraHeaders = {}) {
  const body = type.startsWith('application/json') ? JSON.stringify(data) : data;
  const isEncrypted = Boolean(
    (res.socket && res.socket.encrypted) ||
    (res.req && res.req.socket && res.req.socket.encrypted)
  );

  res.writeHead(status, {
    'content-type': type,
    'content-length': Buffer.byteLength(body),
    'x-content-type-options': 'nosniff',
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    ...(isEncrypted ? { 'strict-transport-security': 'max-age=31536000; includeSubDomains' } : {}),
    ...extraHeaders
  });
  res.end(body);
}

function fail(res, status, message, extraHeaders = {}) {
  send(res, status, { error: message }, 'application/json; charset=utf-8', extraHeaders);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 15_000_000) {
        const err = new Error('Request exceeds maximum allowed size (10 MB file limit).');
        err.statusCode = 413;
        reject(err);
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        const err = new Error('Invalid JSON payload.');
        err.statusCode = 400;
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function userFor(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;

  // Session TTL check (default 30 minutes, configurable via SESSION_TTL_MINUTES)
  const ttlMs = getSessionTtlMs();
  if (Date.now() - session.loginTime > ttlMs) {
    sessions.delete(token);
    return null;
  }

  const username = session.username;
  const userRecord = db.users[username];
  if (!userRecord) return null;
  return { username, role: userRecord.role };
}

// ZERO-TRUST AUTHORIZATION: Default Deny (Strict: No Role Bypasses File Isolation)
function allowed(user, file, action) {
  if (!user || !file) return false;
  // Owner can perform all operations on their file
  if (file.owner === user.username) return true;
  // Explicitly shared users have read (download) access only
  if (action === 'read' && Array.isArray(file.sharedWith) && file.sharedWith.includes(user.username)) {
    return true;
  }
  return false;
}

function cleanName(name) {
  return path.basename(String(name || 'file'))
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, '_')
    .slice(0, 120) || 'file';
}

function encrypt(plainBuffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  return {
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    data: encrypted
  };
}

function decrypt(record) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(record.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(record.tag, 'hex'));
  const filePath = path.join(STORE, record.diskName);
  const cipherData = fs.readFileSync(filePath);
  return Buffer.concat([decipher.update(cipherData), decipher.final()]);
}

function listFiles(user) {
  return Object.values(db.files)
    .filter(f => allowed(user, f, 'read'))
    .map(f => ({
      id: f.id,
      name: f.name,
      owner: f.owner,
      ownerRole: f.ownerRole,
      sharedWith: Array.isArray(f.sharedWith) ? f.sharedWith : [],
      size: f.size,
      sha256: f.sha256,
      createdAt: f.createdAt,
      canShare: f.owner === user.username,
      isOwner: f.owner === user.username,
      tampered: Boolean(f.tampered)
    }));
}

const requestHandler = async (req, res) => {
  const protocol = req.socket.encrypted ? 'https' : 'http';
  const url = new URL(req.url, `${protocol}://${req.headers.host || '127.0.0.1'}`);

  try {
    // Static assets
    if (req.method === 'GET' && url.pathname === '/') {
      return send(res, 200, fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8'), 'text/html; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/app.js') {
      return send(res, 200, fs.readFileSync(path.join(ROOT, 'app.js'), 'utf8'), 'text/javascript; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/style.css') {
      return send(res, 200, fs.readFileSync(path.join(ROOT, 'style.css'), 'utf8'), 'text/css; charset=utf-8');
    }

    // Authentication: Login (with rate limiting and lockout defense)
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { username, password } = await readBody(req);
      const cleanUsername = String(username || '').trim().toLowerCase();
      const clientIp = getClientIp(req);
      const rateLimitKey = `${cleanUsername}|${clientIp}`;

      const now = Date.now();
      let limitRecord = loginRateLimits.get(rateLimitKey);

      // Reset expired lockout without erasing unexpired attempt timestamps
      if (limitRecord && limitRecord.lockUntil > 0 && now >= limitRecord.lockUntil) {
        limitRecord.lockUntil = 0;
      }

      // Slide the 15-minute window over failed attempts
      if (limitRecord) {
        const validAttempts = Array.isArray(limitRecord.attempts)
          ? limitRecord.attempts.filter(ts => (now - ts) < LOGIN_WINDOW_MS)
          : [];
        limitRecord.attempts = validAttempts;
        limitRecord.failures = validAttempts.length;
        if (limitRecord.lockUntil === 0 && validAttempts.length === 0) {
          loginRateLimits.delete(rateLimitKey);
          limitRecord = undefined;
        }
      }

      // Check the lock BEFORE running the scrypt password comparison
      if (limitRecord && limitRecord.lockUntil > 0 && now < limitRecord.lockUntil) {
        logEvent('DENY', 'login', `user=${cleanUsername || 'anonymous'} (locked out)`);
        if (typeof res.setHeader === 'function') {
          res.setHeader('retry-after', '60');
        }
        return fail(res, 429, 'Too many failed login attempts. Account temporarily locked for 60 seconds.', { 'retry-after': '60' });
      }

      const record = db.users[cleanUsername];

      if (!record) {
        // Track failed attempt (rate-limits unknown usernames identically without enumeration)
        if (!limitRecord) {
          limitRecord = { attempts: [], failures: 0, lockUntil: 0 };
          loginRateLimits.set(rateLimitKey, limitRecord);
        }
        if (!Array.isArray(limitRecord.attempts)) limitRecord.attempts = [];
        limitRecord.attempts = limitRecord.attempts.filter(ts => (now - ts) < LOGIN_WINDOW_MS);
        limitRecord.attempts.push(now);
        limitRecord.failures = limitRecord.attempts.length;
        limitRecord.lockUntil = limitRecord.failures >= 5 ? now + 60_000 : 0;

        logEvent('DENY', 'login', `user=${cleanUsername || 'anonymous'} (user not found)`);
        return fail(res, 401, 'Incorrect username or password.');
      }

      const inputHash = crypto.scryptSync(String(password || ''), record.salt, 64);
      const expectedHash = Buffer.from(record.hash, 'hex');

      if (!crypto.timingSafeEqual(inputHash, expectedHash)) {
        // Track failed attempt for invalid password
        if (!limitRecord) {
          limitRecord = { attempts: [], failures: 0, lockUntil: 0 };
          loginRateLimits.set(rateLimitKey, limitRecord);
        }
        if (!Array.isArray(limitRecord.attempts)) limitRecord.attempts = [];
        limitRecord.attempts = limitRecord.attempts.filter(ts => (now - ts) < LOGIN_WINDOW_MS);
        limitRecord.attempts.push(now);
        limitRecord.failures = limitRecord.attempts.length;
        limitRecord.lockUntil = limitRecord.failures >= 5 ? now + 60_000 : 0;

        logEvent('DENY', 'login', `user=${cleanUsername} (invalid password)`);
        return fail(res, 401, 'Incorrect username or password.');
      }

      // Successful login resets failure counter and lock
      loginRateLimits.delete(rateLimitKey);

      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { username: cleanUsername, role: record.role, loginTime: Date.now() });
      logEvent('ALLOW', 'login', `user=${cleanUsername} role=${record.role}`);
      const quota = getUserQuota(record.role);
      let usage = null;
      try {
        usage = getUserStorageUsage(cleanUsername);
      } catch {
        usage = null;
      }
      return send(res, 200, {
        token,
        username: cleanUsername,
        role: record.role,
        quota: quota === Infinity ? 'unlimited' : quota,
        usage
      });
    }

    // Authentication: Register new user (Student-only self-registration)
    if (req.method === 'POST' && url.pathname === '/api/register') {
      const clientIp = getClientIp(req);
      const regLimit = checkRegistrationRateLimit(clientIp);
      if (!regLimit.allowed) {
        logEvent('DENY', 'register', `ip=${clientIp} (registration rate limit exceeded)`);
        if (typeof res.setHeader === 'function') {
          res.setHeader('retry-after', String(regLimit.retryAfter));
        }
        return fail(res, 429, 'Too many registration attempts. Please try again later.', {
          'retry-after': String(regLimit.retryAfter)
        });
      }

      if (String(process.env.ALLOW_PUBLIC_REGISTRATION || '').trim().toLowerCase() === 'false') {
        logEvent('DENY', 'register', 'public registration disabled (ALLOW_PUBLIC_REGISTRATION=false)');
        return fail(res, 403, 'Public registration is currently disabled.');
      }

      const body = await readBody(req);
      const safeBody = (body && typeof body === 'object' && !Array.isArray(body)) ? body : {};
      const { username, password } = safeBody;
      const cleanUsername = String(username || '').trim().toLowerCase();

      // Check whether request contains a role property using an own-property check
      if (body && typeof body === 'object' && Object.prototype.hasOwnProperty.call(body, 'role')) {
        const rawRole = body.role;
        const isExplicitStudent = typeof rawRole === 'string' && rawRole.trim().toLowerCase() === 'student';
        if (!isExplicitStudent) {
          logEvent('DENY', 'register', `user=${cleanUsername || 'anonymous'} role=${rawRole} (privilege escalation blocked)`);
          return fail(res, 403, 'Privilege escalation blocked: public registration only allows the Student role.');
        }
      }

      const validation = validateNewAccount(username, password);
      if (!validation.valid) {
        return fail(res, 400, validation.error);
      }

      if (db.users[cleanUsername]) {
        logEvent('DENY', 'register', `user=${cleanUsername} (already exists)`);
        return fail(res, 400, `Username '${cleanUsername}' is already taken.`);
      }

      createUser(cleanUsername, password, 'Student');

      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { username: cleanUsername, role: 'Student', loginTime: Date.now() });

      logEvent('ALLOW', 'register', `user=${cleanUsername} role=Student`);
      const quota = getUserQuota('Student');
      let usage = 0;
      try {
        usage = getUserStorageUsage(cleanUsername);
      } catch {
        usage = null;
      }
      return send(res, 201, {
        token,
        username: cleanUsername,
        role: 'Student',
        quota: quota === Infinity ? 'unlimited' : quota,
        usage,
        message: `Account created successfully for ${cleanUsername}.`
      });
    }

    // Transport info
    if (req.method === 'GET' && url.pathname === '/api/transport') {
      const isEncrypted = Boolean(req.socket.encrypted);
      const activeProto = isEncrypted ? 'https' : 'http';
      return send(res, 200, {
        protocol: activeProto,
        isTls: isEncrypted,
        host: HOST,
        port: PORT,
        url: `${activeProto}://${HOST}:${PORT}`,
        mode: isEncrypted ? 'HTTPS (TLS v1.2+)' : 'HTTP (Plaintext Local)'
      });
    }

    // Require authentication for all subsequent /api routes
    const user = userFor(req);
    if (!user) {
      if (url.pathname.startsWith('/api/')) {
        logEvent('DENY', 'unauthenticated', `method=${req.method} path=${url.pathname}`);
        return fail(res, 401, 'Please log in first.');
      }
      return fail(res, 404, 'Not found.');
    }

    // Live activity log (for UI audit feed - Admin only)
    if (req.method === 'GET' && url.pathname === '/api/activity') {
      if (user.role !== 'Admin') {
        logEvent('DENY', 'activity', `user=${user.username} role=${user.role} (admin required)`);
        return fail(res, 403, 'Forbidden: Admin access required to view audit feed.');
      }
      return send(res, 200, { logs: auditLogs.slice(-25) });
    }

    // Admin-only user management endpoints (/api/admin/...)
    if (url.pathname.startsWith('/api/admin/')) {
      if (user.role !== 'Admin') {
        logEvent('DENY', 'admin', `user=${user.username} role=${user.role} path=${url.pathname} (admin required)`);
        return fail(res, 403, 'Forbidden: Admin access required.');
      }

      // List all users
      if (req.method === 'GET' && url.pathname === '/api/admin/users') {
        const userList = Object.entries(db.users).map(([uname, u]) => ({
          username: uname,
          role: u.role
        }));
        logEvent('ALLOW', 'admin-list-users', `admin=${user.username} count=${userList.length}`);
        return send(res, 200, { users: userList });
      }

      // Create new user with arbitrary valid role
      if (req.method === 'POST' && url.pathname === '/api/admin/users') {
        const { username, password, role } = await readBody(req);
        const cleanUsername = String(username || '').trim().toLowerCase();

        const assignedRole = normalizeRole(role);
        if (!assignedRole) {
          logEvent('DENY', 'admin-create-user', `admin=${user.username} role=${role} (invalid role)`);
          return fail(res, 400, 'Invalid role. Role must be Student, Faculty, or Admin.');
        }

        const validation = validateNewAccount(username, password);
        if (!validation.valid) {
          logEvent('DENY', 'admin-create-user', `admin=${user.username} user=${cleanUsername} (${validation.error})`);
          return fail(res, 400, validation.error);
        }

        if (db.users[cleanUsername]) {
          logEvent('DENY', 'admin-create-user', `admin=${user.username} user=${cleanUsername} (already exists)`);
          return fail(res, 400, `Username '${cleanUsername}' is already taken.`);
        }

        createUser(cleanUsername, password, assignedRole);
        logEvent('ALLOW', 'admin-create-user', `admin=${user.username} created_user=${cleanUsername} role=${assignedRole}`);
        return send(res, 201, {
          message: `User ${cleanUsername} created successfully with role ${assignedRole}.`,
          user: { username: cleanUsername, role: assignedRole }
        });
      }

      // Update user role
      const adminRoleMatch = url.pathname.match(/^\/api\/admin\/users\/([a-z0-9_.-]+)\/role$/i);
      if (req.method === 'POST' && adminRoleMatch) {
        const target = adminRoleMatch[1].toLowerCase();
        const { role } = await readBody(req);

        if (!db.users[target]) {
          logEvent('DENY', 'admin-change-role', `admin=${user.username} target=${target} (user not found)`);
          return fail(res, 404, 'User not found.');
        }

        if (target === user.username.toLowerCase()) {
          logEvent('DENY', 'admin-change-role', `admin=${user.username} target=${target} (self role change prohibited)`);
          return fail(res, 400, 'Admin cannot change their own role.');
        }

        const newRole = normalizeRole(role);
        if (!newRole) {
          logEvent('DENY', 'admin-change-role', `admin=${user.username} target=${target} role=${role} (invalid role)`);
          return fail(res, 400, 'Invalid role specified. Must be Student, Faculty, or Admin.');
        }

        db.users[target].role = newRole;
        persist();

        logEvent('ALLOW', 'admin-change-role', `admin=${user.username} target=${target} new_role=${newRole}`);
        return send(res, 200, {
          ok: true,
          username: target,
          role: newRole,
          message: `Role for ${target} updated to ${newRole}.`
        });
      }

      return fail(res, 404, 'Admin endpoint not found.');
    }

    // Logout
    if (req.method === 'POST' && url.pathname === '/api/logout') {
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
      sessions.delete(token);
      logEvent('ALLOW', 'logout', `user=${user.username}`);
      return send(res, 200, { ok: true });
    }

    // Current user info
    if (req.method === 'GET' && url.pathname === '/api/me') {
      const quota = getUserQuota(user.role);
      let usage = null;
      try {
        usage = getUserStorageUsage(user.username);
      } catch {
        usage = null;
      }
      return send(res, 200, {
        username: user.username,
        role: user.role,
        quota: quota === Infinity ? 'unlimited' : quota,
        usage
      });
    }

    // List available files and directory of users
    if (req.method === 'GET' && url.pathname === '/api/files') {
      const visibleFiles = listFiles(user);
      const allUsers = Object.entries(db.users).map(([uname, u]) => ({
        username: uname,
        role: u.role
      }));
      const quota = getUserQuota(user.role);
      let usage = null;
      try {
        usage = getUserStorageUsage(user.username);
      } catch {
        usage = null;
      }
      logEvent('ALLOW', 'list-files', `user=${user.username} visible=${visibleFiles.length}`);
      return send(res, 200, {
        files: visibleFiles,
        users: allUsers,
        quota: quota === Infinity ? 'unlimited' : quota,
        usage
      });
    }

    // Upload file
    if (req.method === 'POST' && url.pathname === '/api/files') {
      const { name, content } = await readBody(req);
      if (!name || typeof content !== 'string') {
        return fail(res, 400, 'Filename and base64 file content are required.');
      }
      const plain = Buffer.from(content, 'base64');
      if (plain.length === 0) {
        return fail(res, 400, 'Cannot upload an empty file.');
      }
      if (plain.length > 10 * 1024 * 1024) {
        return fail(res, 400, 'File exceeds maximum size limit of 10 MB.');
      }

      // Role-based storage quota check
      const quota = getUserQuota(user.role);
      let currentUsage;
      try {
        currentUsage = getUserStorageUsage(user.username);
      } catch (metaErr) {
        logEvent('DENY', 'upload', `user=${user.username} file=${cleanName(name)} (metadata integrity error: failed to verify storage usage)`);
        return fail(res, 500, 'Storage quota verification failed due to invalid file metadata.');
      }
      const inFlight = getInflightBytes(user.username);

      if (quota !== Infinity && (currentUsage + inFlight + plain.length > quota)) {
        logEvent('DENY', 'upload', `user=${user.username} file=${cleanName(name)} size=${plain.length}B (storage quota exceeded: used=${currentUsage}B in_flight=${inFlight}B limit=${quota}B)`);
        return fail(res, 413, `Upload exceeds storage quota. Current usage: ${currentUsage} bytes, Quota: ${quota} bytes.`);
      }

      addInflightBytes(user.username, plain.length);
      let createdDiskPath = null;
      let createdFileId = null;
      try {
        // Compute original file digest before encryption
        const sha256 = crypto.createHash('sha256').update(plain).digest('hex');
        const id = crypto.randomUUID();
        const diskName = `${id}.aes`;
        createdDiskPath = path.join(STORE, diskName);
        createdFileId = id;

        // Encrypt bytes using AES-256-GCM with fresh random IV
        const sealed = encrypt(plain);
        fs.writeFileSync(createdDiskPath, sealed.data);

        const record = {
          id,
          name: cleanName(name),
          diskName,
          iv: sealed.iv,
          tag: sealed.tag,
          owner: user.username,
          ownerRole: user.role,
          sharedWith: [],
          size: plain.length,
          sha256,
          originalSha256: sha256,
          createdAt: new Date().toISOString(),
          tampered: false
        };

        db.files[id] = record;
        persist();

        logEvent('ALLOW', 'upload', `user=${user.username} file=${record.name} size=${plain.length}B sha256=${sha256}`);
        return send(res, 201, { file: listFiles(user).find(f => f.id === id) });
      } catch (uploadErr) {
        if (createdDiskPath && fs.existsSync(createdDiskPath)) {
          try {
            fs.unlinkSync(createdDiskPath);
          } catch (unlinkErr) {
            console.error('[ROLLBACK-ERROR] Failed to unlink orphaned ciphertext file:', unlinkErr);
          }
        }
        if (createdFileId && db.files && db.files[createdFileId]) {
          delete db.files[createdFileId];
          try {
            persist();
          } catch (persistRollbackErr) {
            console.error('[ROLLBACK-ERROR] Failed to persist metadata after rollback:', persistRollbackErr);
          }
        }
        logEvent('DENY', 'upload', `user=${user.username} file=${cleanName(name)} (upload transaction failed and rolled back)`);
        throw uploadErr;
      } finally {
        releaseInflightBytes(user.username, plain.length);
      }
    }

    // File-specific operations: share, revoke, download, tamper-demo, delete
    const fileRoute = url.pathname.match(/^\/api\/files\/([\w-]+)(?:\/(share|revoke|download|tamper-demo))?$/);
    if (fileRoute) {
      const [, id, action] = fileRoute;
      const file = db.files[id];
      if (!file) {
        if (req.method === 'DELETE') {
          logEvent('DENY', 'delete', `user=${user.username} file_id=${id} (file not found)`);
        }
        return fail(res, 404, 'File not found.');
      }

      // Delete file (Owner only - strict Zero-Trust ownership check)
      if (req.method === 'DELETE' && !action) {
        if (file.owner !== user.username) {
          logEvent('DENY', 'delete', `user=${user.username} file=${file.name} (not owner)`);
          return fail(res, 403, 'Access denied: only the file owner can delete this file.');
        }

        const filePath = path.join(STORE, file.diskName);
        let blobBackup = null;

        if (fs.existsSync(filePath)) {
          try {
            blobBackup = fs.readFileSync(filePath);
          } catch (readErr) {
            logEvent('DENY', 'delete', `user=${user.username} file=${file.name} (filesystem read error)`);
            return fail(res, 500, 'Filesystem error reading file for deletion.');
          }
        }

        // Phase 1: Unlink encrypted blob from disk
        if (fs.existsSync(filePath)) {
          try {
            fs.unlinkSync(filePath);
          } catch (unlinkErr) {
            logEvent('DENY', 'delete', `user=${user.username} file=${file.name} (filesystem unlink error)`);
            return fail(res, 500, 'Filesystem error removing encrypted file blob.');
          }
        }

        // Phase 2: Remove metadata and persist atomically
        const fileBackup = file;
        delete db.files[id];

        try {
          persist();
        } catch (persistErr) {
          // Transaction Rollback: restore metadata and restore disk blob
          db.files[id] = fileBackup;
          if (blobBackup) {
            try { fs.writeFileSync(filePath, blobBackup); } catch {}
          }
          logEvent('DENY', 'delete', `user=${user.username} file=${file.name} (metadata persistence error)`);
          return fail(res, 500, 'Failed to update metadata during file deletion.');
        }

        logEvent('ALLOW', 'delete', `user=${user.username} file=${file.name}`);
        return send(res, 200, { ok: true, id, message: 'File deleted successfully.' });
      }

      // Share file
      if (action === 'share' && req.method === 'POST') {
        if (file.owner !== user.username) {
          logEvent('DENY', 'share', `user=${user.username} file=${file.name} (not owner)`);
          return fail(res, 403, 'Only the file owner can share this file.');
        }

        const { username } = await readBody(req);
        const target = String(username || '').trim().toLowerCase();
        if (!db.users[target]) {
          logEvent('DENY', 'share', `user=${user.username} target=${target} (target user not found)`);
          return fail(res, 400, 'Selected user does not exist.');
        }
        if (target === file.owner) {
          return fail(res, 400, 'User is already the owner of this file.');
        }
        if (!Array.isArray(file.sharedWith)) file.sharedWith = [];
        if (!file.sharedWith.includes(target)) {
          file.sharedWith.push(target);
          persist();
        }

        logEvent('ALLOW', 'share', `user=${user.username} target=${target} file=${file.name}`);
        return send(res, 200, { ok: true, files: listFiles(user) });
      }

      // Revoke file access
      if (action === 'revoke' && req.method === 'POST') {
        if (file.owner !== user.username) {
          logEvent('DENY', 'revoke', `user=${user.username} file=${file.name} (not owner)`);
          return fail(res, 403, 'Only the file owner can revoke access to this file.');
        }

        const { username } = await readBody(req);
        const target = String(username || '').trim().toLowerCase();
        if (!Array.isArray(file.sharedWith) || !file.sharedWith.includes(target)) {
          logEvent('DENY', 'revoke', `user=${user.username} target=${target} (user not in shared list)`);
          return fail(res, 400, 'User is not currently granted access to this file.');
        }

        file.sharedWith = file.sharedWith.filter(u => u !== target);
        persist();

        logEvent('ALLOW', 'revoke', `user=${user.username} target=${target} file=${file.name}`);
        return send(res, 200, { ok: true, files: listFiles(user) });
      }

      // Integrity Demo: Simulate or restore checksum mismatch
      if (action === 'tamper-demo' && req.method === 'POST') {
        if (file.owner !== user.username) {
          logEvent('DENY', 'tamper-demo', `user=${user.username} file=${file.name} (not owner)`);
          return fail(res, 403, 'Only the file owner can run the integrity demo.');
        }

        const body = await readBody(req);
        const shouldRestore = body.action === 'restore' || (file.tampered && body.action !== 'tamper');

        if (shouldRestore) {
          file.sha256 = file.originalSha256 || file.sha256;
          file.tampered = false;
          persist();
          logEvent('ALLOW', 'restore-checksum', `user=${user.username} file=${file.name} restored_sha256=${file.sha256}`);
          return send(res, 200, { ok: true, tampered: false, sha256: file.sha256, files: listFiles(user) });
        } else {
          file.originalSha256 = file.originalSha256 || file.sha256;
          file.sha256 = '0'.repeat(64);
          file.tampered = true;
          persist();
          logEvent('DEMO', 'tamper-demo', `user=${user.username} file=${file.name} (simulated checksum mismatch: expected SHA-256 set to 000...)`);
          return send(res, 200, { ok: true, tampered: true, sha256: file.sha256, files: listFiles(user) });
        }
      }

      // Download file and verify integrity
      if (action === 'download' && req.method === 'GET') {
        // Zero-Trust check: verify permission before decrypting or touching bytes
        if (!allowed(user, file, 'read')) {
          logEvent('DENY', 'download', `user=${user.username} file=${file.name} (access denied)`);
          return fail(res, 403, 'Access denied: this file was not shared with you.');
        }

        let plain;
        try {
          plain = decrypt(file);
        } catch {
          logEvent('INTEGRITY-FAIL', 'download', `user=${user.username} file=${file.name} (AES-GCM authentication tag invalid)`);
          return fail(res, 409, 'Integrity check failed: encrypted file authentication tag invalid or data corrupted. File rejected.');
        }

        // Recompute SHA-256 and compare with saved digest
        const actual = crypto.createHash('sha256').update(plain).digest('hex');
        const expected = file.sha256;

        if (actual.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))) {
          logEvent('INTEGRITY-FAIL', 'download', `user=${user.username} file=${file.name} (SHA-256 mismatch: expected ${expected.slice(0, 10)}... actual ${actual.slice(0, 10)}...)`);
          return fail(res, 409, 'Integrity check failed: SHA-256 digest does not match. File has been modified or corrupted. File rejected.');
        }

        logEvent('ALLOW', 'download', `user=${user.username} file=${file.name} sha256=${actual}`);
        return send(res, 200, {
          name: file.name,
          content: plain.toString('base64'),
          sha256: actual
        });
      }
    }

    return fail(res, 404, 'Endpoint not found.');
  } catch (error) {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      logEvent('DENY', 'bad-request', `error=${error.message}`);
      return fail(res, error.statusCode, error.message);
    }
    console.error('[SERVER-ERROR]', error);
    return fail(res, 500, 'Internal server error.');
  }
};

// Transport configuration: default HTTP on 127.0.0.1; optional HTTPS if certs provided
const USE_HTTPS = process.env.USE_HTTPS === 'true' || process.env.HTTPS === 'true';
const CERT_FILE = process.env.SSL_CERT || path.join(STORE, 'cert.pem');
const SSL_KEY_FILE = process.env.SSL_KEY || path.join(STORE, 'key.pem');

function createAppServer(options = {}) {
  const useHttps = options.useHttps !== undefined
    ? Boolean(options.useHttps)
    : (process.env.USE_HTTPS === 'true' || process.env.HTTPS === 'true');
  const certFile = options.certFile || process.env.SSL_CERT || path.join(STORE, 'cert.pem');
  const keyFile = options.keyFile || process.env.SSL_KEY || path.join(STORE, 'key.pem');

  if (useHttps) {
    if (!fs.existsSync(certFile)) {
      const err = new Error(
        `[HTTPS-CONFIG-ERROR] HTTPS requested (USE_HTTPS=true), but SSL certificate file not found: ${certFile}. ` +
        `Run "node gen-cert.js" to generate a self-signed EC P-256 certificate, or set the SSL_CERT environment variable.`
      );
      err.code = 'ERR_HTTPS_CERT_MISSING';
      throw err;
    }
    if (!fs.existsSync(keyFile)) {
      const err = new Error(
        `[HTTPS-CONFIG-ERROR] HTTPS requested (USE_HTTPS=true), but SSL private key file not found: ${keyFile}. ` +
        `Run "node gen-cert.js" to generate a self-signed EC P-256 certificate, or set the SSL_KEY environment variable.`
      );
      err.code = 'ERR_HTTPS_KEY_MISSING';
      throw err;
    }

    let certData;
    let keyData;
    try {
      certData = fs.readFileSync(certFile);
      keyData = fs.readFileSync(keyFile);
    } catch (readErr) {
      const err = new Error(`[HTTPS-CONFIG-ERROR] Failed to read certificate or key file: ${readErr.message}`);
      err.code = 'ERR_HTTPS_FILE_READ';
      throw err;
    }

    try {
      crypto.createPrivateKey(keyData);
    } catch (keyErr) {
      const err = new Error(`[HTTPS-CONFIG-ERROR] SSL private key file is invalid or corrupt: ${keyErr.message}`);
      err.code = 'ERR_HTTPS_KEY_INVALID';
      throw err;
    }

    if (!certData.toString('utf8').includes('-----BEGIN CERTIFICATE-----')) {
      const err = new Error(`[HTTPS-CONFIG-ERROR] SSL certificate file is invalid: missing PEM certificate header.`);
      err.code = 'ERR_HTTPS_CERT_INVALID';
      throw err;
    }

    const httpsOptions = {
      key: keyData,
      cert: certData,
      minVersion: 'TLSv1.2'
    };

    let srv;
    try {
      srv = https.createServer(httpsOptions, requestHandler);
    } catch (tlsErr) {
      const err = new Error(
        `[HTTPS-CONFIG-ERROR] SSL certificate and private key are invalid or mismatched: ${tlsErr.message}`
      );
      err.code = 'ERR_HTTPS_KEY_CERT_MISMATCH';
      err.cause = tlsErr;
      throw err;
    }

    return {
      server: srv,
      protocol: 'https',
      minVersion: 'TLSv1.2',
      certFile,
      keyFile
    };
  }

  const srv = http.createServer(requestHandler);
  return {
    server: srv,
    protocol: 'http',
    minVersion: null,
    certFile: null,
    keyFile: null
  };
}

let serverConfig;
try {
  serverConfig = createAppServer();
} catch (startupErr) {
  if (require.main === module) {
    console.error(startupErr.message);
    process.exit(1);
  }
  throw startupErr;
}

const server = serverConfig.server;
const protocol = serverConfig.protocol;

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`=======================================================`);
    console.log(`Secure Zero-Trust File Sharing running at ${protocol}://${HOST}:${PORT}`);
    console.log(`Transport Mode: ${protocol.toUpperCase()} (${protocol === 'https' ? 'TLS v1.2+ encrypted' : 'Local plain HTTP'})`);
    console.log(`Access Rules: DEFAULT DENY (Checked on every operation)`);
    console.log(`Demo Users: asha (Student), rao (Faculty), ravi (Student), admin (Admin)`);
    console.log(`Log format: [ALLOW] [DENY] [INTEGRITY-FAIL]`);
    console.log(`=======================================================`);
  });
}

module.exports = {
  server,
  protocol,
  createAppServer,
  USE_HTTPS,
  CERT_FILE,
  SSL_KEY_FILE,
  requestHandler,
  db,
  sessions,
  loginRateLimits,
  registrationRateLimits,
  inflightUploads,
  getInflightBytes,
  sweepRateLimits,
  sweepExpiredSessions,
  getUserQuota,
  getUserStorageUsage,
  STORAGE_QUOTAS,
  getClientIp,
  checkRegistrationRateLimit,
  logEvent,
  persist,
  seedUser,
  createUser,
  validateNewAccount,
  normalizeRole,
  encrypt,
  decrypt,
  cleanName,
  allowed,
  listFiles,
  HOST,
  PORT,
  STORE,
  META,
  KEY_FILE
};
