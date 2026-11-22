/**
 * gen-cert.js — Self-Signed EC P-256 TLS Certificate Generator for ZTFILE
 *
 * Generates an Elliptic Curve (P-256 / prime256v1) self-signed X.509 certificate
 * with Subject Alternative Name (SAN) entries for localhost and 127.0.0.1,
 * valid for 365 days, using the OpenSSL CLI.
 *
 * Requirements:
 * - Pure Node.js built-ins (zero npm dependencies).
 * - Self-signed EC P-256 (prime256v1) certificate.
 * - SAN entries: DNS:localhost, IP:127.0.0.1.
 * - Valid for 365 days.
 * - Never overwrite existing certificates unless --force is supplied.
 */

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

function findOpenSSL() {
  if (process.env.OPENSSL_BIN && fs.existsSync(process.env.OPENSSL_BIN)) {
    return process.env.OPENSSL_BIN;
  }

  try {
    const res = spawnSync('openssl', ['version'], { stdio: 'pipe', encoding: 'utf8' });
    if (res.status === 0) {
      return 'openssl';
    }
  } catch {}

  if (process.platform === 'win32') {
    const candidatePaths = [
      'C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe',
      'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
      'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
      'C:\\OpenSSL-Win64\\bin\\openssl.exe',
      'C:\\Program Files (x86)\\OpenSSL-Win32\\bin\\openssl.exe',
      'C:\\OpenSSL-Win32\\bin\\openssl.exe'
    ];
    for (const cand of candidatePaths) {
      if (fs.existsSync(cand)) {
        try {
          const res = spawnSync(cand, ['version'], { stdio: 'pipe', encoding: 'utf8' });
          if (res.status === 0) {
            return cand;
          }
        } catch {}
      }
    }
  }

  return null;
}

function generateCert(options = {}) {
  const force = Boolean(options.force || process.argv.includes('--force'));
  const storageDir = options.outDir ||
                     process.env.ZT_STORAGE_DIR ||
                     path.join(__dirname, 'storage');

  if (!fs.existsSync(storageDir)) {
    fs.mkdirSync(storageDir, { recursive: true });
  }

  const certPath = options.certPath ||
                   process.env.SSL_CERT ||
                   path.join(storageDir, 'cert.pem');
  const keyPath = options.keyPath ||
                  process.env.SSL_KEY ||
                  path.join(storageDir, 'key.pem');

  const certExists = fs.existsSync(certPath);
  const keyExists = fs.existsSync(keyPath);

  if (certExists && keyExists && !force) {
    const msg = `[CERT] Existing certificate and private key found:\n` +
                `       - Cert: ${certPath}\n` +
                `       - Key:  ${keyPath}\n` +
                `       Preserving existing certificates. Run with --force to regenerate.`;
    if (!options.silent) {
      console.log(msg);
    }
    return {
      generated: false,
      preserved: true,
      certPath,
      keyPath,
      message: msg
    };
  }

  if ((certExists || keyExists) && !force) {
    const missingFile = !certExists ? `certificate file (${certPath})` : `private key file (${keyPath})`;
    const presentFile = certExists ? `certificate file (${certPath})` : `private key file (${keyPath})`;
    const err = new Error(
      `Incomplete TLS certificate pair found: ${presentFile} exists, but ${missingFile} is missing. ` +
      `An incomplete certificate pair cannot be preserved. Run "node gen-cert.js --force" to generate a fresh matching key and certificate pair.`
    );
    err.code = 'ERR_TLS_PAIR_INCOMPLETE';
    throw err;
  }

  const opensslBin = options.opensslBin || findOpenSSL();
  if (!opensslBin) {
    const err = new Error(
      `OpenSSL CLI not found. Please install OpenSSL or ensure openssl is in your PATH, ` +
      `or set the OPENSSL_BIN environment variable to the path of openssl.exe.`
    );
    err.code = 'ERR_OPENSSL_NOT_FOUND';
    throw err;
  }

  const days = options.days || 365;
  const sanList = options.san || ['DNS:localhost', 'IP:127.0.0.1'];
  const sanExt = 'subjectAltName=' + sanList.join(',');

  // Attempt direct invocation with -addext (OpenSSL 1.1.1+)
  const primaryArgs = [
    'req', '-x509',
    '-newkey', 'ec',
    '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-nodes',
    '-keyout', keyPath,
    '-out', certPath,
    '-days', String(days),
    '-subj', '/CN=localhost',
    '-addext', sanExt
  ];

  let execResult = spawnSync(opensslBin, primaryArgs, { stdio: 'pipe', encoding: 'utf8' });

  // If -addext failed, fallback to a temporary config file
  if (execResult.status !== 0 || !fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    const tmpCnf = path.join(storageDir, `openssl-san-${Date.now()}.cnf`);
    const cnfContent = `
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
subjectAltName = ${sanList.join(',')}
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
`;
    try {
      fs.writeFileSync(tmpCnf, cnfContent.trim(), 'utf8');
      const fallbackArgs = [
        'req', '-x509',
        '-newkey', 'ec',
        '-pkeyopt', 'ec_paramgen_curve:prime256v1',
        '-nodes',
        '-keyout', keyPath,
        '-out', certPath,
        '-days', String(days),
        '-config', tmpCnf
      ];
      execResult = spawnSync(opensslBin, fallbackArgs, { stdio: 'pipe', encoding: 'utf8' });
    } finally {
      if (fs.existsSync(tmpCnf)) {
        try { fs.unlinkSync(tmpCnf); } catch {}
      }
    }
  }

  if (execResult.status !== 0 || !fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    const errText = (execResult.stderr || execResult.stdout || 'Unknown error').trim();
    const err = new Error(`OpenSSL certificate generation failed: ${errText}`);
    err.code = 'ERR_OPENSSL_EXEC';
    throw err;
  }

  try {
    fs.chmodSync(keyPath, 0o600);
  } catch {}

  if (!options.silent) {
    console.log(`======================================================================`);
    console.log(`         ZTFILE TLS CERTIFICATE GENERATOR (EC P-256)`);
    console.log(`======================================================================`);
    console.log(`OpenSSL binary:   ${opensslBin}`);
    console.log(`Curve:            prime256v1 (NIST P-256)`);
    console.log(`Validity:         ${days} days`);
    console.log(`Subject:          CN=localhost`);
    console.log(`SAN entries:      ${sanList.join(', ')}`);
    console.log(`Certificate file: ${certPath}`);
    console.log(`Private key file: ${keyPath}`);
    console.log(`======================================================================`);
    console.log(`[SUCCESS] Self-signed EC P-256 TLS certificate and key generated successfully.`);
  }

  return {
    generated: true,
    preserved: false,
    certPath,
    keyPath,
    opensslBin,
    curve: 'prime256v1',
    days,
    san: sanList
  };
}

if (require.main === module) {
  try {
    generateCert();
  } catch (err) {
    console.error(`[ERROR] ${err.message}`);
    process.exit(1);
  }
}

module.exports = {
  findOpenSSL,
  generateCert
};
