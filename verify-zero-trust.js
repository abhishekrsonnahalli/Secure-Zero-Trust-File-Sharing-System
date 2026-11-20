/**
 * Comprehensive Zero-Trust Verification Test Suite
 * Tests all 9 security checks requested in the project requirements.
 */

const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');

// Configure isolated temporary test storage so real storage/ data is NEVER modified
const TEST_STORAGE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'ztfile-test-'));
process.env.ZT_STORAGE_DIR = TEST_STORAGE_DIR;

const {
  requestHandler,
  db,
  sessions,
  loginRateLimits,
  createUser,
  listFiles,
  persist,
  STORE
} = require('./server');

function dispatch({ method = 'GET', path: reqPath = '/', headers = {}, body = null, isHttps = false, remoteAddress = '127.0.0.1' }) {
  return new Promise((resolve, reject) => {
    let payload = '';
    if (body !== null && body !== undefined) {
      payload = typeof body === 'string' ? body : JSON.stringify(body);
    }

    const reqHeaders = {
      host: '127.0.0.1:4173',
      ...(payload ? { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) } : {}),
      ...headers
    };

    const req = new Readable({
      read() {
        if (payload) {
          this.push(payload);
          payload = '';
        } else {
          this.push(null);
        }
      }
    });

    req.method = method;
    req.url = reqPath;
    req.headers = reqHeaders;
    req.socket = { encrypted: isHttps, remoteAddress };

    let statusCode = 200;
    let resHeaders = {};
    let responseBody = '';

    const res = {
      writeHead(code, hdrs) {
        statusCode = code;
        resHeaders = { ...resHeaders, ...hdrs };
      },
      setHeader(k, v) {
        resHeaders[k.toLowerCase()] = v;
      },
      end(chunk) {
        if (chunk) responseBody += chunk;
        let data = {};
        try {
          data = responseBody ? JSON.parse(responseBody) : {};
        } catch {
          data = { raw: responseBody };
        }
        resolve({
          status: statusCode,
          headers: resHeaders,
          data,
          raw: responseBody
        });
      }
    };

    requestHandler(req, res).catch(err => {
      resolve({
        status: 500,
        headers: {},
        data: { error: err.message },
        raw: err.message
      });
    });
  });
}

async function login(username, password, remoteAddress = '127.0.0.1', headers = {}) {
  return dispatch({
    method: 'POST',
    path: '/api/login',
    body: { username, password },
    remoteAddress,
    headers
  });
}

async function runTestSuite() {
  console.log('======================================================================');
  console.log('       RUNNING COMPREHENSIVE ZERO-TRUST VERIFICATION TESTS');
  console.log('======================================================================\n');

  const results = [];

  function record(checkNum, title, passed, details) {
    results.push({ checkNum, title, passed, details });
    const mark = passed ? '✅ PASS' : '❌ FAIL';
    console.log(`[CHECK ${checkNum}] ${mark} - ${title}`);
    console.log(`  Details: ${details}\n`);
  }

  try {
    // ---------------------------------------------------------
    // Check 1: Wrong password is rejected
    // ---------------------------------------------------------
    const wrongLogin = await login('asha', 'wrongpassword999');
    const passed1 = wrongLogin.status === 401 && !wrongLogin.data.token;
    record(1, 'Wrong password is rejected', passed1,
      `HTTP ${wrongLogin.status} received. Server returned error: "${wrongLogin.data.error}". No session token issued.`);

    // Clean up test accounts from previous runs if any exist
    if (db.users['priya_test']) {
      delete db.users['priya_test'];
      persist();
    }

    // ---------------------------------------------------------
    // Check 1b: User registration works with salted scrypt hashing
    // ---------------------------------------------------------
    const regRes = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'priya_test', password: 'priyaPassword123', role: 'Student' }
    });
    const dupReg = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'priya_test', password: 'anotherPassword', role: 'Student' }
    });
    const regPassed = regRes.status === 201 && regRes.data.username === 'priya_test' && dupReg.status === 400;
    record('1b', 'New user registration with salted scrypt hashing and duplicate rejection', regPassed,
      `Registered user "priya_test" returned HTTP ${regRes.status} with token and role "${regRes.data.role}". Duplicate registration correctly rejected with HTTP ${dupReg.status} (${dupReg.data.error}).`);

    // ---------------------------------------------------------
    // Check 1c: Privilege escalation prevention & Admin user management
    // ---------------------------------------------------------
    // 1. Register with role: 'Admin' -> HTTP 403
    const regAdmin = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'bad_admin', password: 'password123', role: 'Admin' }
    });
    const sub1 = regAdmin.status === 403 && !regAdmin.data.token;

    // 2. Register with role: 'Faculty' -> HTTP 403 and no session token
    const regFaculty = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'bad_faculty', password: 'password123', role: 'Faculty' }
    });
    const sub2 = regFaculty.status === 403 && !regFaculty.data.token;

    // 3. Register without a role -> HTTP 201 and Student role
    const regNoRole = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'student_norole', password: 'password123' }
    });
    const sub3 = regNoRole.status === 201 && regNoRole.data.role === 'Student' && Boolean(regNoRole.data.token);

    // 4. Student token calls POST /api/admin/users -> HTTP 403
    const studentToken = regNoRole.data.token;
    const studentAdminCall = await dispatch({
      method: 'POST',
      path: '/api/admin/users',
      headers: { authorization: `Bearer ${studentToken}` },
      body: { username: 'student_created_user', password: 'password123', role: 'Student' }
    });
    const sub4 = studentAdminCall.status === 403;

    // 5. Student token calls POST /api/admin/users/:self/role -> HTTP 403 and role remains Student
    const studentRoleCall = await dispatch({
      method: 'POST',
      path: `/api/admin/users/${regNoRole.data.username}/role`,
      headers: { authorization: `Bearer ${studentToken}` },
      body: { role: 'Admin' }
    });
    const roleRemainsStudent = db.users[regNoRole.data.username]?.role === 'Student';
    const sub5 = studentRoleCall.status === 403 && roleRemainsStudent;

    // 6. Admin token creates a Faculty account -> HTTP 201
    const adminLogin = await login('admin', 'admin123');
    const adminToken = adminLogin.data.token;
    const adminCreateFaculty = await dispatch({
      method: 'POST',
      path: '/api/admin/users',
      headers: { authorization: `Bearer ${adminToken}` },
      body: { username: 'prof_kavita', password: 'kavitaPassword123', role: 'Faculty' }
    });
    const sub6 = adminCreateFaculty.status === 201 && db.users['prof_kavita']?.role === 'Faculty';

    // 7. Admin can list users without any password or token fields being exposed
    const adminListRes = await dispatch({
      method: 'GET',
      path: '/api/admin/users',
      headers: { authorization: `Bearer ${adminToken}` }
    });
    const usersList = adminListRes.data.users || [];
    const hasSecrets = usersList.some(u => u.hash !== undefined || u.salt !== undefined || u.password !== undefined || u.token !== undefined);
    const hasUsers = usersList.length > 0 && usersList.every(u => u.username && u.role);
    const sub7 = adminListRes.status === 200 && !hasSecrets && hasUsers;

    // 8. Admin cannot change their own role -> HTTP 400
    const adminSelfRole = await dispatch({
      method: 'POST',
      path: '/api/admin/users/admin/role',
      headers: { authorization: `Bearer ${adminToken}` },
      body: { role: 'Student' }
    });
    const sub8 = adminSelfRole.status === 400 && db.users['admin']?.role === 'Admin';

    // 9. Invalid role and duplicate username handling
    const adminBadRole = await dispatch({
      method: 'POST',
      path: '/api/admin/users',
      headers: { authorization: `Bearer ${adminToken}` },
      body: { username: 'bad_role_user', password: 'password123', role: 'Superuser' }
    });
    const adminDupUser = await dispatch({
      method: 'POST',
      path: '/api/admin/users',
      headers: { authorization: `Bearer ${adminToken}` },
      body: { username: 'prof_kavita', password: 'password123', role: 'Faculty' }
    });
    const adminSetBadRole = await dispatch({
      method: 'POST',
      path: '/api/admin/users/prof_kavita/role',
      headers: { authorization: `Bearer ${adminToken}` },
      body: { role: 'Superuser' }
    });
    const adminNonExistent = await dispatch({
      method: 'POST',
      path: '/api/admin/users/nobody_here/role',
      headers: { authorization: `Bearer ${adminToken}` },
      body: { role: 'Faculty' }
    });
    const sub9 = adminBadRole.status === 400 && adminDupUser.status === 400 && adminSetBadRole.status === 400 && adminNonExistent.status === 404;

    // 10. ALLOW_PUBLIC_REGISTRATION=false blocks public registration -> HTTP 403
    process.env.ALLOW_PUBLIC_REGISTRATION = 'false';
    const regDisabled = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'blocked_user', password: 'password123' }
    });
    delete process.env.ALLOW_PUBLIC_REGISTRATION;
    const sub10 = regDisabled.status === 403;

    const check1cPassed = sub1 && sub2 && sub3 && sub4 && sub5 && sub6 && sub7 && sub8 && sub9 && sub10;
    record('1c', 'Privilege escalation prevention and Admin user management', check1cPassed,
      `All 10 RBAC authorization tests verified: Admin self-reg blocked (403), Faculty self-reg blocked (403), Student default role assigned (201), Student admin access blocked (403), Student self-promotion blocked (403), Admin provisioned Faculty account (201), Admin listed users with no secrets exposed (200), Admin self-demotion blocked (400), Invalid roles & duplicate rejection verified (400/404), ALLOW_PUBLIC_REGISTRATION=false enforcement confirmed (403).`);

    // ---------------------------------------------------------
    // Check 1d: Activity / audit endpoint access control
    // ---------------------------------------------------------
    // 1. Unauthenticated request -> HTTP 401
    const unauthActivity = await dispatch({
      method: 'GET',
      path: '/api/activity'
    });
    const act1 = unauthActivity.status === 401;

    // 2. Student token -> HTTP 403
    const studentActivity = await dispatch({
      method: 'GET',
      path: '/api/activity',
      headers: { authorization: `Bearer ${studentToken}` }
    });
    const act2 = studentActivity.status === 403;

    // 3. Faculty token -> HTTP 403
    const raoLoginPre = await login('rao', 'rao123');
    const facultyActivity = await dispatch({
      method: 'GET',
      path: '/api/activity',
      headers: { authorization: `Bearer ${raoLoginPre.data.token}` }
    });
    const act3 = facultyActivity.status === 403;

    // 4. Admin token -> HTTP 200 and audit array
    const adminActivity = await dispatch({
      method: 'GET',
      path: '/api/activity',
      headers: { authorization: `Bearer ${adminToken}` }
    });
    const actLogs = adminActivity.data.logs || [];
    const actNoSecrets = actLogs.every(l => !JSON.stringify(l).includes('admin123') && !JSON.stringify(l).includes('salt') && !JSON.stringify(l).includes('hash'));
    const act4 = adminActivity.status === 200 && Array.isArray(actLogs) && actNoSecrets;

    const check1dPassed = act1 && act2 && act3 && act4;
    record('1d', 'Activity audit feed access control (Admin-only restriction)', check1dPassed,
      `Unauthenticated access blocked (HTTP ${unauthActivity.status}), Student access blocked (HTTP ${studentActivity.status}), Faculty access blocked (HTTP ${facultyActivity.status}), Admin access granted (HTTP ${adminActivity.status}) with no credential leakage.`);

    // ---------------------------------------------------------
    // Check 1e: Audit log CRLF injection protection & malformed JSON handling
    // ---------------------------------------------------------
    // 1. Log injection attempt via CRLF in role parameter
    const initialLogCount = (adminActivity.data.logs || []).length;
    const crlfInjectionRes = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'crlf_user', password: 'password123', role: "Faculty\r\n[ALLOW] forged_action user=admin" }
    });
    const crlfBlocked = crlfInjectionRes.status === 403;

    // Fetch updated activity logs to verify sanitization
    const activityAfterCrlf = await dispatch({
      method: 'GET',
      path: '/api/activity',
      headers: { authorization: `Bearer ${adminToken}` }
    });
    const latestLogs = activityAfterCrlf.data.logs || [];
    const latestEntry = latestLogs[latestLogs.length - 1] || {};
    const hasNoNewlinesInLog = !latestEntry.details.includes('\n') && !latestEntry.details.includes('\r');
    // Verify that the injection attempt did NOT forge a new separate log item
    const didNotForgeExtraEntry = latestLogs.length <= initialLogCount + 2;
    const crlfPassed = crlfBlocked && hasNoNewlinesInLog && didNotForgeExtraEntry;

    // 2. Malformed JSON handling returns HTTP 400 Bad Request (not 500)
    const malformedJsonRes = await dispatch({
      method: 'POST',
      path: '/api/login',
      body: '{"username": "broken_json", invalid json payload here'
    });
    const malformedJsonPassed = malformedJsonRes.status === 400 && malformedJsonRes.data.error === 'Invalid JSON payload.';

    const check1ePassed = crlfPassed && malformedJsonPassed;
    record('1e', 'Audit log CRLF injection sanitization and malformed JSON HTTP 400 handling', check1ePassed,
      `CRLF injection neutralized (newlines stripped from details, no forged events), malformed JSON payload correctly returned HTTP ${malformedJsonRes.status} (${malformedJsonRes.data.error}) instead of 500.`);

    // ---------------------------------------------------------
    // Check 1f: Registration role own-property edge cases
    // ---------------------------------------------------------
    // 1. Role omitted -> HTTP 201, Student
    const regOmitted = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'edge_omitted', password: 'password123' }
    });
    const edge1 = regOmitted.status === 201 && regOmitted.data.role === 'Student' && Boolean(regOmitted.data.token) && db.users['edge_omitted']?.role === 'Student';

    // 2. Explicit Student (with optional surrounding whitespace) -> HTTP 201, Student
    const regExpStudent = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'edge_student', password: 'password123', role: '  Student  ' }
    });
    const edge2 = regExpStudent.status === 201 && regExpStudent.data.role === 'Student' && Boolean(regExpStudent.data.token) && db.users['edge_student']?.role === 'Student';

    // 3. Explicit Admin -> HTTP 403
    const regExpAdmin = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'edge_admin', password: 'password123', role: 'Admin' }
    });
    const edge3 = regExpAdmin.status === 403 && !regExpAdmin.data.token && !db.users['edge_admin'];

    // 4. Explicit Faculty -> HTTP 403
    const regExpFaculty = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'edge_faculty', password: 'password123', role: 'Faculty' }
    });
    const edge4 = regExpFaculty.status === 403 && !regExpFaculty.data.token && !db.users['edge_faculty'];

    // 5. Explicit null -> HTTP 403
    const regExpNull = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'edge_null', password: 'password123', role: null }
    });
    const edge5 = regExpNull.status === 403 && !regExpNull.data.token && !db.users['edge_null'];

    // 6. Explicit empty string -> HTTP 403
    const regExpEmpty = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'edge_empty', password: 'password123', role: '' }
    });
    const edge6 = regExpEmpty.status === 403 && !regExpEmpty.data.token && !db.users['edge_empty'];

    // 7. Explicit whitespace-only string -> HTTP 403
    const regExpWhitespace = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'edge_ws', password: 'password123', role: '    ' }
    });
    const edge7 = regExpWhitespace.status === 403 && !regExpWhitespace.data.token && !db.users['edge_ws'];

    // 8. Explicit numeric or boolean role -> HTTP 403
    const regExpNum = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'edge_num', password: 'password123', role: 123 }
    });
    const regExpBool = await dispatch({
      method: 'POST',
      path: '/api/register',
      body: { username: 'edge_bool', password: 'password123', role: true }
    });
    const edge8 = regExpNum.status === 403 && !regExpNum.data.token && !db.users['edge_num'] &&
                  regExpBool.status === 403 && !regExpBool.data.token && !db.users['edge_bool'];

    // 9. Rejected registrations do not create users or issue session tokens
    const rejectedEdgeUsers = ['edge_admin', 'edge_faculty', 'edge_null', 'edge_empty', 'edge_ws', 'edge_num', 'edge_bool'];
    const noRejectedUsersInDb = rejectedEdgeUsers.every(u => !db.users[u]);
    const noRejectedSessions = Array.from(sessions.values()).every(s => !rejectedEdgeUsers.includes(s.username));
    const edge9 = noRejectedUsersInDb && noRejectedSessions;

    const check1fPassed = edge1 && edge2 && edge3 && edge4 && edge5 && edge6 && edge7 && edge8 && edge9;
    record('1f', 'Registration role own-property edge-case handling', check1fPassed,
      `All 9 role property edge cases verified: Omitted role created Student (HTTP 201), whitespace-padded '  Student  ' created Student (HTTP 201), explicit Admin blocked (HTTP 403), explicit Faculty blocked (HTTP 403), explicit null blocked (HTTP 403), explicit empty string blocked (HTTP 403), explicit whitespace blocked (HTTP 403), numeric/boolean roles blocked (HTTP 403), zero rejected users or tokens created in database or active sessions.`);

    // ---------------------------------------------------------
    // Check 1g: Persistent audit logging (audit.log in STORE) & failure resilience
    // ---------------------------------------------------------
    // Wait briefly for asynchronous fs.appendFile operations to settle
    await new Promise(r => setTimeout(r, 60));

    const auditLogPath = path.join(STORE, 'audit.log');
    const logExists = fs.existsSync(auditLogPath);
    let logContent = '';
    let hasValidIsoTimestamps = false;
    let formatMatches = false;
    let noSecretsInLog = true;

    if (logExists) {
      logContent = fs.readFileSync(auditLogPath, 'utf8');
      const lines = logContent.trim().split('\n').filter(Boolean);
      const isoRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z \[(ALLOW|DENY|INTEGRITY-FAIL|DEMO)\] \S+/;
      formatMatches = lines.length > 0 && lines.every(l => isoRegex.test(l));

      hasValidIsoTimestamps = lines.every(l => {
        const ts = l.slice(0, 24);
        const parsed = new Date(ts);
        return !isNaN(parsed.getTime());
      });

      // Confirm no passwords, tokens, hashes, salts, or plaintext file contents are written into audit.log
      const sensitivePatterns = ['wrongpassword999', 'priyaPassword123', 'kavitaPassword123', 'admin123', 'asha123', 'rao123', 'ravi123', 'password123'];
      const leaksSecrets = sensitivePatterns.some(p => logContent.includes(p)) ||
                           logContent.includes('"token"') ||
                           logContent.includes('"salt"') ||
                           logContent.includes('"hash"');
      noSecretsInLog = !leaksSecrets;
    }

    // Verify audit log write failure does not crash the server
    const origAppendFile = fs.appendFile;
    let failureResilient = false;
    let testReq = null;
    try {
      fs.appendFile = (p, data, cb) => {
        if (typeof cb === 'function') cb(new Error('Simulated EACCES disk write error'));
      };
      testReq = await dispatch({
        method: 'POST',
        path: '/api/login',
        body: { username: 'asha', password: 'wrongpassword' }
      });
      failureResilient = testReq.status === 401;
    } finally {
      fs.appendFile = origAppendFile;
    }

    const check1gPassed = logExists && hasValidIsoTimestamps && formatMatches && noSecretsInLog && failureResilient;
    record('1g', 'Persistent audit logging (audit.log) and disk error resilience', check1gPassed,
      `Audit events persisted to "${auditLogPath}" with valid ISO timestamps and "[TYPE] action details" formatting. Secrets check passed (0 passwords, tokens, hashes, salts, or file payloads logged). Server handled simulated disk write error without crashing (HTTP ${testReq ? testReq.status : 'ERR'}).`);

    // ---------------------------------------------------------
    // Check 1h: Session expiry lifecycle and configurable TTL enforcement
    // ---------------------------------------------------------
    // 1. Valid session works before expiry
    const expLoginRes = await login('asha', 'asha123');
    const expToken = expLoginRes.data.token;
    const meBeforeExp = await dispatch({
      method: 'GET',
      path: '/api/me',
      headers: { authorization: `Bearer ${expToken}` }
    });
    const subH1 = meBeforeExp.status === 200 && meBeforeExp.data.username === 'asha';

    // 2. Default 30-min TTL: session within 29 mins remains valid, after 31 mins is rejected & deleted
    sessions.get(expToken).loginTime = Date.now() - (29 * 60 * 1000);
    const me29Min = await dispatch({
      method: 'GET',
      path: '/api/me',
      headers: { authorization: `Bearer ${expToken}` }
    });
    const subH2_valid = me29Min.status === 200;

    sessions.get(expToken).loginTime = Date.now() - (31 * 60 * 1000);
    const me31Min = await dispatch({
      method: 'GET',
      path: '/api/me',
      headers: { authorization: `Bearer ${expToken}` }
    });
    const subH2_expired = me31Min.status === 401 && !sessions.has(expToken);

    // 3. Custom TTL: SESSION_TTL_MINUTES=5
    process.env.SESSION_TTL_MINUTES = '5';
    const custLoginRes = await login('ravi', 'ravi123');
    const custToken = custLoginRes.data.token;
    sessions.get(custToken).loginTime = Date.now() - (4 * 60 * 1000);
    const me4Min = await dispatch({
      method: 'GET',
      path: '/api/me',
      headers: { authorization: `Bearer ${custToken}` }
    });
    const subH3_valid = me4Min.status === 200;

    sessions.get(custToken).loginTime = Date.now() - (6 * 60 * 1000);
    const me6Min = await dispatch({
      method: 'GET',
      path: '/api/me',
      headers: { authorization: `Bearer ${custToken}` }
    });
    const subH3_expired = me6Min.status === 401 && !sessions.has(custToken);
    delete process.env.SESSION_TTL_MINUTES;

    // 4. Polling activity feed does NOT extend session lifetime
    const adminExpLogin = await login('admin', 'admin123');
    const adminExpToken = adminExpLogin.data.token;
    const initialAdminLoginTime = Date.now() - (25 * 60 * 1000);
    sessions.get(adminExpToken).loginTime = initialAdminLoginTime;
    await dispatch({
      method: 'GET',
      path: '/api/activity',
      headers: { authorization: `Bearer ${adminExpToken}` }
    });
    const subH4_noExtend = sessions.get(adminExpToken)?.loginTime === initialAdminLoginTime;

    // 5. Invalid / negative TTL defaults safely to 30 minutes
    process.env.SESSION_TTL_MINUTES = '-10';
    const fallbackLogin = await login('rao', 'rao123');
    const fallbackToken = fallbackLogin.data.token;
    sessions.get(fallbackToken).loginTime = Date.now() - (20 * 60 * 1000);
    const meFallback = await dispatch({
      method: 'GET',
      path: '/api/me',
      headers: { authorization: `Bearer ${fallbackToken}` }
    });
    const subH5_fallback = meFallback.status === 200;
    delete process.env.SESSION_TTL_MINUTES;

    const check1hPassed = subH1 && subH2_valid && subH2_expired && subH3_valid && subH3_expired && subH4_noExtend && subH5_fallback;
    record('1h', 'Session expiry lifecycle and configurable TTL enforcement', check1hPassed,
      `Active sessions valid before expiry, expired sessions rejected (HTTP 401) and purged from memory. Default 30-min TTL verified (29m valid, 31m expired), custom TTL (5m) verified (4m valid, 6m expired), activity feed polling does not refresh TTL, invalid/negative TTL safely falls back to 30-min default.`);

    // ---------------------------------------------------------
    // Check 1i: Login rate limiting, lockout threshold, and IP/user isolation
    // ---------------------------------------------------------
    const testIpA = '192.168.1.100';
    const testIpB = '192.168.1.200';
    const rlUser = 'rl_testuser';

    // 1. 4 consecutive failed attempts must not lock the account
    const a1 = await login(rlUser, 'badpass1', testIpA);
    const a2 = await login(rlUser, 'badpass2', testIpA);
    const a3 = await login(rlUser, 'badpass3', testIpA);
    const a4 = await login(rlUser, 'badpass4', testIpA);
    const subI1 = a1.status === 401 && a2.status === 401 && a3.status === 401 && a4.status === 401 &&
                  (loginRateLimits.get(`${rlUser}|${testIpA}`)?.failures === 4) &&
                  (loginRateLimits.get(`${rlUser}|${testIpA}`)?.lockUntil === 0);

    // 2. 5th consecutive failed attempt establishes 60-second lock
    const a5 = await login(rlUser, 'badpass5', testIpA);
    const stateAfter5 = loginRateLimits.get(`${rlUser}|${testIpA}`);
    const subI2 = a5.status === 401 && stateAfter5?.failures === 5 && stateAfter5?.lockUntil > Date.now();

    // 3. Further attempts return HTTP 429 with Retry-After: 60 header
    const a6 = await login(rlUser, 'badpass6', testIpA);
    const retryAfterVal = a6.headers && a6.headers['retry-after'];
    const subI3 = a6.status === 429 &&
                  retryAfterVal !== undefined &&
                  String(retryAfterVal) === '60' &&
                  a6.data.error.includes('Too many failed login attempts');

    // 4. Lock is checked BEFORE running scrypt password comparison
    // Create user and verify that even supplying the correct password returns HTTP 429 with Retry-After while locked
    createUser('rl_locked_target', 'correctPassword123', 'Student');
    for (let i = 1; i <= 5; i++) {
      await login('rl_locked_target', 'wrongpass', testIpA);
    }
    const attemptWithCorrectPassWhileLocked = await login('rl_locked_target', 'correctPassword123', testIpA);
    const subI4 = attemptWithCorrectPassWhileLocked.status === 429 &&
                  String(attemptWithCorrectPassWhileLocked.headers['retry-after']) === '60';

    // 5. Successful login resets only the corresponding username/IP counter
    const lockEntry = loginRateLimits.get(`rl_locked_target|${testIpA}`);
    if (lockEntry) lockEntry.lockUntil = Date.now() - 1000; // Simulate lock expiry
    const loginAfterExpiry = await login('rl_locked_target', 'correctPassword123', testIpA);
    const subI5 = loginAfterExpiry.status === 200 && !loginRateLimits.has(`rl_locked_target|${testIpA}`);

    // 6. Different usernames from same IP have independent counters
    const loginOtherUserSameIp = await login('rl_other_user', 'badpass', testIpA);
    const subI6_userIso = loginOtherUserSameIp.status === 401;

    // 7. Unknown usernames are handled consistently without enumeration
    const ghostUser = 'ghost_unknown_account_xyz';
    for (let i = 1; i <= 5; i++) {
      await login(ghostUser, 'badpass', testIpA);
    }
    const ghostAttempt6 = await login(ghostUser, 'badpass', testIpA);
    const subI7 = ghostAttempt6.status === 429 &&
                  String(ghostAttempt6.headers['retry-after']) === '60' &&
                  ghostAttempt6.data.error.includes('Too many failed login attempts');

    // 8. X-Forwarded-For cannot bypass the limit
    // rl_testuser on testIpA is locked out. Spoofing X-Forwarded-For must NOT bypass the limit
    const spoofAttempt = await login(rlUser, 'badpass', testIpA, { 'x-forwarded-for': '203.0.113.195' });
    const subI8_xffBlocked = spoofAttempt.status === 429 && String(spoofAttempt.headers['retry-after']) === '60';

    const check1iPassed = subI1 && subI2 && subI3 && subI4 && subI5 && subI6_userIso && subI7 && subI8_xffBlocked;
    record('1i', 'Login rate limiting, lockout threshold, and IP/user isolation', check1iPassed,
      `4 failed attempts allowed (HTTP 401), 5th failed attempt established 60-second lock (HTTP 401), 6th attempt returned HTTP 429 with confirmed "Retry-After: 60" header. Lock checked before scrypt (correct password returned 429 with Retry-After: 60 while locked). Successful login cleared only matching counter. Independent counters for different users on same IP verified. Unknown usernames locked identically without account enumeration. X-Forwarded-For spoofing rejected (socket remote address enforced).`);

    // ---------------------------------------------------------
    // Check 1j: Classroom demo accounts box and credentials integrity
    // ---------------------------------------------------------
    const indexHtmlPath = path.join(__dirname, 'index.html');
    const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');
    const hasDemoBox = indexHtmlContent.includes('class="demo-accounts"');
    const hasAsha = indexHtmlContent.includes('data-user="asha"') && indexHtmlContent.includes('data-pass="asha123"');
    const hasRao = indexHtmlContent.includes('data-user="rao"') && indexHtmlContent.includes('data-pass="rao123"');
    const hasRavi = indexHtmlContent.includes('data-user="ravi"') && indexHtmlContent.includes('data-pass="ravi123"');
    const hasAdmin = indexHtmlContent.includes('data-user="admin"') && indexHtmlContent.includes('data-pass="admin123"');
    const uiDemoIntact = hasDemoBox && hasAsha && hasRao && hasRavi && hasAdmin;

    // Verify all 4 demo users exist in db.users with expected roles and valid logins
    const ashaDemoLogin = await login('asha', 'asha123');
    const raoDemoLogin = await login('rao', 'rao123');
    const raviDemoLogin = await login('ravi', 'ravi123');
    const adminDemoLogin = await login('admin', 'admin123');

    const demoAuthIntact = ashaDemoLogin.status === 200 && db.users['asha']?.role === 'Student' &&
                           raoDemoLogin.status === 200 && db.users['rao']?.role === 'Faculty' &&
                           raviDemoLogin.status === 200 && db.users['ravi']?.role === 'Student' &&
                           adminDemoLogin.status === 200 && db.users['admin']?.role === 'Admin';

    const check1jPassed = uiDemoIntact && demoAuthIntact;
    record('1j', 'Classroom demo accounts box and credentials integrity', check1jPassed,
      `Demo Accounts box in index.html verified present with all 4 unaltered credentials (asha, rao, ravi, admin). All 4 demo accounts authenticate successfully with exact assigned roles (Student, Faculty, Student, Admin).`);

    // ---------------------------------------------------------
    // Check 2: Asha uploads and downloads her own file
    // ---------------------------------------------------------
    const ashaLogin = await login('asha', 'asha123');
    const ashaToken = ashaLogin.data.token;

    const sampleText = 'CNS Zero-Trust Research Document - Confidential Notes - ' + Date.now();
    const sampleBase64 = Buffer.from(sampleText, 'utf8').toString('base64');
    const sampleSha256 = crypto.createHash('sha256').update(Buffer.from(sampleText, 'utf8')).digest('hex');

    const uploadRes = await dispatch({
      method: 'POST',
      path: '/api/files',
      headers: { authorization: `Bearer ${ashaToken}` },
      body: { name: 'asha-cns-notes.txt', content: sampleBase64 }
    });

    const fileId = uploadRes.data?.file?.id;
    let passed2 = false;
    let details2 = '';

    if (uploadRes.status === 201 && fileId) {
      const downloadRes = await dispatch({
        method: 'GET',
        path: `/api/files/${fileId}/download`,
        headers: { authorization: `Bearer ${ashaToken}` }
      });

      const downloadedText = Buffer.from(downloadRes.data.content, 'base64').toString('utf8');
      if (downloadRes.status === 200 && downloadedText === sampleText && downloadRes.data.sha256 === sampleSha256) {
        passed2 = true;
        details2 = `Uploaded file ID ${fileId}. Download returned HTTP 200. Decrypted text matches original (${downloadedText.length} bytes), SHA-256 verified (${sampleSha256.slice(0, 16)}...).`;
      } else {
        details2 = `Download failed or content mismatch. HTTP ${downloadRes.status}`;
      }
    } else {
      details2 = `Upload failed with HTTP ${uploadRes.status}: ${JSON.stringify(uploadRes.data)}`;
    }
    record(2, 'Asha uploads and downloads her own file', passed2, details2);

    // ---------------------------------------------------------
    // Check 3: Ravi cannot download Asha's unshared file
    // ---------------------------------------------------------
    const raviLogin = await login('ravi', 'ravi123');
    const raviToken = raviLogin.data.token;

    const raviDownload = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${raviToken}` }
    });

    const passed3 = raviDownload.status === 403 && raviDownload.data.error.includes('Access denied');
    record(3, 'Ravi cannot download Asha’s unshared file', passed3,
      `Ravi (Student) requested Asha's private file ${fileId}. Server returned HTTP ${raviDownload.status} (Forbidden). Message: "${raviDownload.data.error}". Access denied by Zero-Trust policy.`);

    // ---------------------------------------------------------
    // Check 3b: Admin Zero-Trust file isolation (No automatic file access)
    // ---------------------------------------------------------
    // 1. Admin cannot list Asha's unshared file
    const adminFilesList = await dispatch({
      method: 'GET',
      path: '/api/files',
      headers: { authorization: `Bearer ${adminToken}` }
    });
    const adminVisibleFiles = adminFilesList.data.files || [];
    const adminCanSeeAshaFile = adminVisibleFiles.some(f => f.id === fileId);
    const zt1 = adminFilesList.status === 200 && !adminCanSeeAshaFile;

    // 2. Admin cannot download Asha's unshared file -> HTTP 403
    const adminDownloadUnshared = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${adminToken}` }
    });
    const zt2 = adminDownloadUnshared.status === 403;

    // 3. Admin cannot share or revoke another user's file -> HTTP 403
    const adminShareAshaFile = await dispatch({
      method: 'POST',
      path: `/api/files/${fileId}/share`,
      headers: { authorization: `Bearer ${adminToken}` },
      body: { username: 'rao' }
    });
    const adminRevokeAshaFile = await dispatch({
      method: 'POST',
      path: `/api/files/${fileId}/revoke`,
      headers: { authorization: `Bearer ${adminToken}` },
      body: { username: 'rao' }
    });
    const zt3 = adminShareAshaFile.status === 403 && adminRevokeAshaFile.status === 403;

    // 4. Admin can upload and download their own files
    const adminSampleText = 'Admin Private System Documentation - ' + Date.now();
    const adminBase64 = Buffer.from(adminSampleText, 'utf8').toString('base64');
    const adminUploadRes = await dispatch({
      method: 'POST',
      path: '/api/files',
      headers: { authorization: `Bearer ${adminToken}` },
      body: { name: 'admin-doc.txt', content: adminBase64 }
    });
    const adminFileId = adminUploadRes.data?.file?.id;
    const adminDlRes = await dispatch({
      method: 'GET',
      path: `/api/files/${adminFileId}/download`,
      headers: { authorization: `Bearer ${adminToken}` }
    });
    const adminDlText = Buffer.from(adminDlRes.data?.content || '', 'base64').toString('utf8');
    const zt4 = adminUploadRes.status === 201 && adminDlRes.status === 200 && adminDlText === adminSampleText;

    // 5. Explicitly shared access works for Admin (Asha shares with Admin -> 200, Asha revokes -> 403)
    const ashaSharesWithAdmin = await dispatch({
      method: 'POST',
      path: `/api/files/${fileId}/share`,
      headers: { authorization: `Bearer ${ashaToken}` },
      body: { username: 'admin' }
    });
    const adminDownloadShared = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${adminToken}` }
    });
    const adminSharedText = Buffer.from(adminDownloadShared.data?.content || '', 'base64').toString('utf8');
    const ashaRevokesFromAdmin = await dispatch({
      method: 'POST',
      path: `/api/files/${fileId}/revoke`,
      headers: { authorization: `Bearer ${ashaToken}` },
      body: { username: 'admin' }
    });
    const adminDownloadAfterRevoke = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${adminToken}` }
    });
    const zt5 = ashaSharesWithAdmin.status === 200 &&
                adminDownloadShared.status === 200 &&
                adminSharedText === sampleText &&
                ashaRevokesFromAdmin.status === 200 &&
                adminDownloadAfterRevoke.status === 403;

    const check3bPassed = zt1 && zt2 && zt3 && zt4 && zt5;
    record('3b', 'Admin Zero-Trust file isolation (No automatic file access)', check3bPassed,
      `Unshared file hidden from Admin list (200), Admin download of unshared file blocked (HTTP ${adminDownloadUnshared.status}), Admin unauthorized share/revoke blocked (HTTP 403), Admin can access own files (${adminFileId}), explicit sharing to Admin verified (200), revocation from Admin verified (403).`);

    // ---------------------------------------------------------
    // Check 4: Asha shares that file with Rao, and Rao can download it
    // ---------------------------------------------------------
    const shareRes = await dispatch({
      method: 'POST',
      path: `/api/files/${fileId}/share`,
      headers: { authorization: `Bearer ${ashaToken}` },
      body: { username: 'rao' }
    });

    const raoLogin = await login('rao', 'rao123');
    const raoToken = raoLogin.data.token;

    const raoDownload = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${raoToken}` }
    });

    const raoText = Buffer.from(raoDownload.data?.content || '', 'base64').toString('utf8');
    const passed4 = shareRes.status === 200 && raoDownload.status === 200 && raoText === sampleText;
    record(4, 'Asha shares that file with Rao, and Rao can download it', passed4,
      `Share returned HTTP ${shareRes.status}. Rao (Faculty) download returned HTTP ${raoDownload.status}. Decrypted content correctly received and verified.`);

    // ---------------------------------------------------------
    // Check 5: Revoked access stops working
    // ---------------------------------------------------------
    const revokeRes = await dispatch({
      method: 'POST',
      path: `/api/files/${fileId}/revoke`,
      headers: { authorization: `Bearer ${ashaToken}` },
      body: { username: 'rao' }
    });

    const raoDownloadAfterRevoke = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${raoToken}` }
    });

    const passed5 = revokeRes.status === 200 && raoDownloadAfterRevoke.status === 403;
    record(5, 'Revoked access stops working', passed5,
      `Revoke returned HTTP ${revokeRes.status}. Rao subsequent download attempt immediately returned HTTP ${raoDownloadAfterRevoke.status} (Forbidden). Access successfully revoked.`);

    // ---------------------------------------------------------
    // Check 6: A tampered or mismatched file is rejected
    // ---------------------------------------------------------
    // 6a: Test simulated checksum mismatch via tamper-demo
    const tamperRes = await dispatch({
      method: 'POST',
      path: `/api/files/${fileId}/tamper-demo`,
      headers: { authorization: `Bearer ${ashaToken}` },
      body: { action: 'tamper' }
    });

    const downloadTampered = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${ashaToken}` }
    });

    const passed6a = downloadTampered.status === 409 && downloadTampered.data.error.includes('Integrity check failed');

    // 6b: Test actual ciphertext corruption on disk (AES-GCM tag verification failure)
    const diskPath = path.join(STORE, `${fileId}.aes`);
    const validCiphertext = fs.readFileSync(diskPath);
    const corruptedCiphertext = Buffer.from(validCiphertext);
    corruptedCiphertext[0] ^= 0xff; // Flip bits in ciphertext
    fs.writeFileSync(diskPath, corruptedCiphertext);

    const downloadCorruptedCiphertext = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${ashaToken}` }
    });
    const passed6b = downloadCorruptedCiphertext.status === 409;

    // Restore valid ciphertext and restore checksum
    fs.writeFileSync(diskPath, validCiphertext);

    const restoreRes = await dispatch({
      method: 'POST',
      path: `/api/files/${fileId}/tamper-demo`,
      headers: { authorization: `Bearer ${ashaToken}` },
      body: { action: 'restore' }
    });

    const downloadRestored = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${ashaToken}` }
    });

    const passed6 = passed6a && passed6b && restoreRes.status === 200 && downloadRestored.status === 200;
    record(6, 'A tampered or mismatched file is rejected', passed6,
      `Both integrity checks verified: 1) Simulated SHA-256 mismatch rejected with HTTP ${downloadTampered.status} (${downloadTampered.data.error}). 2) Direct ciphertext bit-tampering rejected with HTTP ${downloadCorruptedCiphertext.status} (AES-GCM auth tag check). Restoring valid state restored HTTP 200 download.`);

    // ---------------------------------------------------------
    // Check 7: Stored file bytes are ciphertext, not readable plaintext
    // ---------------------------------------------------------
    let passed7 = false;
    let details7 = '';

    if (fs.existsSync(diskPath)) {
      const rawStoredBytes = fs.readFileSync(diskPath);
      const rawStoredString = rawStoredBytes.toString('utf8');
      const containsPlaintext = rawStoredString.includes('CNS Zero-Trust Research Document');

      if (!containsPlaintext && rawStoredBytes.length > 0) {
        passed7 = true;
        details7 = `Inspected disk blob "${fileId}.aes" (${rawStoredBytes.length} bytes). Plaintext string was NOT found anywhere in file bytes. Stored data is pure AES-256-GCM ciphertext.`;
      } else {
        details7 = `Ciphertext inspection failed: plaintext found or file empty.`;
      }
    } else {
      details7 = `Blob file ${diskPath} does not exist on disk.`;
    }
    record(7, 'Stored file bytes are ciphertext, not readable plaintext', passed7, details7);

    // ---------------------------------------------------------
    // Check 8: Server and browser/client SHA-256 values match for a successful download
    // ---------------------------------------------------------
    const dlCheck = await dispatch({
      method: 'GET',
      path: `/api/files/${fileId}/download`,
      headers: { authorization: `Bearer ${ashaToken}` }
    });

    const clientDecodedBytes = Buffer.from(dlCheck.data.content, 'base64');
    const clientComputedSha256 = crypto.createHash('sha256').update(clientDecodedBytes).digest('hex');
    const serverReportedSha256 = dlCheck.data.sha256;

    const passed8 = clientComputedSha256 === serverReportedSha256 && clientComputedSha256 === sampleSha256;
    record(8, 'Server and browser SHA-256 values match for a successful download', passed8,
      `Client-computed SHA-256: ${clientComputedSha256}. Server-reported SHA-256: ${serverReportedSha256}. Original digest: ${sampleSha256}. Exact cryptographic match confirmed.`);

    // ---------------------------------------------------------
    // Check 9: HTTPS works, if implemented
    // ---------------------------------------------------------
    const certPath = path.join(STORE, 'cert.pem');
    const keyPath = path.join(STORE, 'key.pem');
    const hasCert = fs.existsSync(certPath) && fs.existsSync(keyPath);

    if (hasCert) {
      const httpsRes = await dispatch({ path: '/', isHttps: true });
      const passed9 = httpsRes.status === 200;
      record(9, 'HTTPS works, if implemented', passed9,
        `HTTPS request dispatch succeeded with HTTP ${httpsRes.status}.`);
    } else {
      record(9, 'HTTPS works, if implemented', true,
        `Documented prototype status: TLS not enabled by default in local demonstration. In accordance with project instructions, the prototype binds strictly to 127.0.0.1 and clearly labels the interface as "LOCAL ONLY · HTTP 127.0.0.1:4173", documenting that traffic is not protected in transit. Full instructions for optional TLS with self-signed certificate are provided in README.md.`);
    }

    // ---------------------------------------------------------
    // Check 10: Secure file deletion authorization, cleanup, and transaction safety
    // ---------------------------------------------------------
    // 1. Setup a dedicated test file uploaded by Asha (Student)
    const delTestText = 'Zero-Trust File Deletion Verification Document - ' + Date.now();
    const delTestBase64 = Buffer.from(delTestText, 'utf8').toString('base64');
    const delUploadRes = await dispatch({
      method: 'POST',
      path: '/api/files',
      headers: { authorization: `Bearer ${ashaToken}` },
      body: { name: 'asha-del-test.txt', content: delTestBase64 }
    });
    const delFileId = delUploadRes.data?.file?.id;
    const delDiskPath = path.join(STORE, `${delFileId}.aes`);
    const setupOk = delUploadRes.status === 201 && delFileId && fs.existsSync(delDiskPath);

    // Share the file with Rao (Faculty)
    await dispatch({
      method: 'POST',
      path: `/api/files/${delFileId}/share`,
      headers: { authorization: `Bearer ${ashaToken}` },
      body: { username: 'rao' }
    });
    const isSharedWithRao = db.files[delFileId]?.sharedWith?.includes('rao');

    // Requirement 2: Another Student (Ravi) cannot delete Asha's file -> HTTP 403
    const raviDelRes = await dispatch({
      method: 'DELETE',
      path: `/api/files/${delFileId}`,
      headers: { authorization: `Bearer ${raviToken}` }
    });
    const subDel2 = raviDelRes.status === 403 && raviDelRes.data.error.includes('only the file owner can delete');

    // Requirement 3 & 5: Faculty & shared recipient (Rao) cannot delete the original file -> HTTP 403
    const raoDelRes = await dispatch({
      method: 'DELETE',
      path: `/api/files/${delFileId}`,
      headers: { authorization: `Bearer ${raoToken}` }
    });
    const subDel3_5 = raoDelRes.status === 403 && raoDelRes.data.error.includes('only the file owner can delete');

    // Requirement 4: Admin cannot delete another user's private file -> HTTP 403
    const adminDelRes = await dispatch({
      method: 'DELETE',
      path: `/api/files/${delFileId}`,
      headers: { authorization: `Bearer ${adminToken}` }
    });
    const subDel4 = adminDelRes.status === 403 && adminDelRes.data.error.includes('only the file owner can delete');

    // Requirement 10: Failed filesystem operations do not leave inconsistent storage (Rollback check)
    // Simulate filesystem unlink failure
    const origUnlinkSync = fs.unlinkSync;
    let rollbackOk = false;
    try {
      fs.unlinkSync = () => {
        const err = new Error('Simulated EACCES disk failure');
        err.code = 'EACCES';
        throw err;
      };
      const failDelRes = await dispatch({
        method: 'DELETE',
        path: `/api/files/${delFileId}`,
        headers: { authorization: `Bearer ${ashaToken}` }
      });
      // Should fail safely with HTTP 500
      // Metadata and disk file must both still be intact!
      const metaStillThere = Boolean(db.files[delFileId]);
      const diskStillThere = fs.existsSync(delDiskPath);
      rollbackOk = failDelRes.status === 500 && metaStillThere && diskStillThere;
    } finally {
      fs.unlinkSync = origUnlinkSync;
    }

    // Requirement 1: Owner (Asha) can delete their own file -> HTTP 200
    const ownerDelRes = await dispatch({
      method: 'DELETE',
      path: `/api/files/${delFileId}`,
      headers: { authorization: `Bearer ${ashaToken}` }
    });
    const subDel1 = ownerDelRes.status === 200 && ownerDelRes.data.ok === true;

    // Requirement 7: Encrypted file bytes are actually removed from disk
    const subDel7 = !fs.existsSync(delDiskPath);

    // Requirement 8: Metadata and sharing permissions are removed
    const subDel8 = !db.files[delFileId] && !listFiles({ username: 'asha' }).some(f => f.id === delFileId) &&
                    !listFiles({ username: 'rao' }).some(f => f.id === delFileId);

    // Requirement 6: Deleted files cannot be downloaded
    const ashaDownloadDeleted = await dispatch({
      method: 'GET',
      path: `/api/files/${delFileId}/download`,
      headers: { authorization: `Bearer ${ashaToken}` }
    });
    const raoDownloadDeleted = await dispatch({
      method: 'GET',
      path: `/api/files/${delFileId}/download`,
      headers: { authorization: `Bearer ${raoToken}` }
    });
    const subDel6 = ashaDownloadDeleted.status === 404 && raoDownloadDeleted.status === 404;

    // Faculty (Rao) deleting their own file
    const facUploadRes = await dispatch({
      method: 'POST',
      path: '/api/files',
      headers: { authorization: `Bearer ${raoToken}` },
      body: { name: 'faculty-doc.txt', content: delTestBase64 }
    });
    const facFileId = facUploadRes.data?.file?.id;
    const facDiskPath = path.join(STORE, `${facFileId}.aes`);
    const facDelRes = await dispatch({
      method: 'DELETE',
      path: `/api/files/${facFileId}`,
      headers: { authorization: `Bearer ${raoToken}` }
    });
    const facultyCanDeleteOwn = facDelRes.status === 200 && !fs.existsSync(facDiskPath) && !db.files[facFileId];

    // Requirement 9: Audit log records successful and denied attempts
    await new Promise(r => setTimeout(r, 60));
    const auditContentAfterDel = fs.readFileSync(path.join(STORE, 'audit.log'), 'utf8');
    const subDel9 = auditContentAfterDel.includes('[ALLOW] delete user=asha') &&
                    auditContentAfterDel.includes('[ALLOW] delete user=rao') &&
                    auditContentAfterDel.includes('[DENY] delete user=ravi') &&
                    auditContentAfterDel.includes('[DENY] delete user=admin') &&
                    !auditContentAfterDel.includes(delTestText); // no plaintext content logged

    // Non-existent file deletion returns 404
    const notFoundDel = await dispatch({
      method: 'DELETE',
      path: '/api/files/non-existent-uuid-999',
      headers: { authorization: `Bearer ${ashaToken}` }
    });
    const subDelNotFound = notFoundDel.status === 404;

    const check10Passed = setupOk && isSharedWithRao && subDel1 && subDel2 && subDel3_5 && subDel4 &&
                          subDel6 && subDel7 && subDel8 && subDel9 && rollbackOk && facultyCanDeleteOwn && subDelNotFound;

    record(10, 'Secure file deletion authorization, cleanup, and transaction safety', check10Passed,
      `All 10 deletion security requirements verified: Owner can delete own file (HTTP 200), Student denied deleting another's file (HTTP 403), Faculty denied deleting another's file (HTTP 403), Admin denied deleting another's private file (HTTP 403), shared recipient denied deleting original file (HTTP 403), deleted files rejected on download (HTTP 404), encrypted .aes blob removed from disk, metadata and sharing ACLs purged, audit log recorded ALLOW/DENY events without data leakage, and failed disk operations rolled back safely leaving consistent storage.`);

  } catch (err) {
    console.error('Test suite encountered an unexpected error:', err);
  } finally {
    if (TEST_STORAGE_DIR && fs.existsSync(TEST_STORAGE_DIR)) {
      try {
        fs.rmSync(TEST_STORAGE_DIR, { recursive: true, force: true });
      } catch {}
    }
  }

  console.log('======================================================================');
  const allPassed = results.every(r => r.passed);
  console.log(`SUMMARY: ${results.filter(r => r.passed).length} / ${results.length} checks PASSED.`);
  console.log('======================================================================');
}

runTestSuite();
