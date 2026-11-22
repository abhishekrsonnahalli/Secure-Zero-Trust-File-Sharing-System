const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

let token = '';
let me = null;
let picked = null;
let pollTimer = null;
let toastTimer = null;

const toast = $('#toast');

function clearLoginForm() {
  const form = $('#loginForm');
  if (form && typeof form.reset === 'function') {
    form.reset();
  }
  const u = $('#username');
  const p = $('#password');
  if (u) u.value = '';
  if (p) p.value = '';
}

// Clear login credentials on page load, refresh, and bfcache navigation
clearLoginForm();
document.addEventListener('DOMContentLoaded', clearLoginForm);
window.addEventListener('load', clearLoginForm);
window.addEventListener('pageshow', clearLoginForm);
setTimeout(clearLoginForm, 50);
setTimeout(clearLoginForm, 200);

function notice(message, type = 'info') {
  toast.textContent = message;
  toast.className = `show toast-${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.className = '';
  }, 4200);
}

function esc(s) {
  return String(s || '').replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

function formatSize(n) {
  if (typeof n !== 'number' || isNaN(n)) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDate(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return iso;
  }
}

async function api(url, options = {}) {
  const headers = {
    'content-type': 'application/json',
    ...(token ? { authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {})
  };

  const res = await fetch(url, { ...options, headers });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { error: text || `HTTP error ${res.status}` };
  }

  if (!res.ok) {
    const err = new Error(data.error || `Request failed with HTTP ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

// Auth tab switching (Sign In vs Register)
const tabSignIn = $('#tabSignIn');
const tabRegister = $('#tabRegister');
const signInPane = $('#signInPane');
const registerPane = $('#registerPane');

if (tabSignIn && tabRegister) {
  tabSignIn.addEventListener('click', () => {
    tabSignIn.classList.add('active');
    tabRegister.classList.remove('active');
    signInPane.hidden = false;
    registerPane.hidden = true;
  });

  tabRegister.addEventListener('click', () => {
    tabRegister.classList.add('active');
    tabSignIn.classList.remove('active');
    registerPane.hidden = false;
    signInPane.hidden = true;
    $('#regUsername').focus();
  });
}

// Click to auto-fill demo accounts
$$('.demo-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    if (tabSignIn && tabRegister) {
      tabSignIn.classList.add('active');
      tabRegister.classList.remove('active');
      signInPane.hidden = false;
      registerPane.hidden = true;
    }
    $('#username').value = chip.dataset.user;
    $('#password').value = chip.dataset.pass;
    $('#username').focus();
  });
});

function updateStorageQuotaDisplay(quota, usage) {
  const usageEl = $('#storageUsageVal');
  const quotaEl = $('#storageQuotaVal');
  const percentEl = $('#storagePercentVal');
  const barEl = $('#storageProgressBar');
  if (!usageEl || !quotaEl) return;

  const usedBytes = Number(usage) || 0;
  usageEl.textContent = formatSize(usedBytes);

  if (quota === 'unlimited' || quota === Infinity) {
    quotaEl.textContent = 'Unlimited (Admin)';
    if (percentEl) percentEl.textContent = 'Unlimited';
    if (barEl) {
      barEl.style.width = '100%';
      barEl.style.background = 'var(--success)';
    }
  } else {
    const quotaBytes = Number(quota) || (30 * 1024 * 1024);
    quotaEl.textContent = formatSize(quotaBytes);
    const pct = Math.min(100, Math.round((usedBytes / quotaBytes) * 100));
    if (percentEl) percentEl.textContent = `${pct}%`;
    if (barEl) {
      barEl.style.width = `${pct}%`;
      barEl.style.background = pct >= 90 ? 'var(--danger)' : (pct >= 75 ? '#e67e22' : 'var(--accent)');
    }
  }
}

function enterWorkspace(r) {
  token = r.token;
  me = r;
  clearLoginForm();
  if (r.quota !== undefined && r.usage !== undefined) {
    updateStorageQuotaDisplay(r.quota, r.usage);
  }

  $('#login').hidden = true;
  $('#workspace').hidden = false;
  $('#who').textContent = r.username;
  
  const roleBadge = $('#roleBadge');
  roleBadge.textContent = r.role;
  roleBadge.className = `role-badge ${r.role.toLowerCase()}`;

  const desc = $('#roleDescription');
  if (r.role === 'Admin') {
    desc.textContent = 'Admin role: User management and audit oversight. Under Zero-Trust policy, file access requires explicit ownership or sharing.';
  } else if (r.role === 'Faculty') {
    desc.textContent = 'Faculty role: Can upload private files. Can access files explicitly shared by owners.';
  } else {
    desc.textContent = 'Student role: Can upload private files. Can download own files or files explicitly shared with you.';
  }

  const adminPanel = $('#adminPanel');
  if (adminPanel) {
    if (r.role === 'Admin') {
      adminPanel.hidden = false;
      loadAdminUsers();
    } else {
      adminPanel.hidden = true;
    }
  }

  refresh();
  updateActivity();
  startPolling();
}

// Sign In Form Submission
$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const username = $('#username').value.trim();
  const password = $('#password').value;

  try {
    const r = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
    enterWorkspace(r);
    notice(`Authenticated as ${r.username} (${r.role})`, 'success');
  } catch (err) {
    notice(err.message, 'error');
    await updateActivity();
  }
});

// Register Form Submission
const regForm = $('#registerForm');
if (regForm) {
  regForm.addEventListener('submit', async e => {
    e.preventDefault();
    const username = $('#regUsername').value.trim();
    const password = $('#regPassword').value;

    try {
      const r = await api('/api/register', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      enterWorkspace(r);
      notice(`✅ Account created for ${r.username} (${r.role})! Enrolled into Zero-Trust workspace.`, 'success');
      $('#regUsername').value = '';
      $('#regPassword').value = '';
    } catch (err) {
      notice(err.message, 'error');
      await updateActivity();
    }
  });
}

// Sign Out
$('#logout').addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST' });
  } catch {}
  token = '';
  me = null;
  picked = null;
  stopPolling();
  $('#workspace').hidden = true;
  const adminPanel = $('#adminPanel');
  if (adminPanel) adminPanel.hidden = true;
  $('#login').hidden = false;
  clearLoginForm();
  notice('Signed out. In-memory session destroyed.', 'info');
  await updateActivity();
});

// File picker handling
$('#fileInput').addEventListener('change', e => {
  picked = e.target.files[0] || null;
  const pickedLabel = $('#picked');
  const uploadBtn = $('#upload');

  if (!picked) {
    pickedLabel.textContent = 'No file selected (Max size: 10 MB)';
    uploadBtn.disabled = true;
    return;
  }

  if (picked.size > 10 * 1024 * 1024) {
    pickedLabel.textContent = `❌ ${picked.name} (${formatSize(picked.size)}) exceeds 10 MB limit`;
    uploadBtn.disabled = true;
    notice('File exceeds 10 MB maximum limit.', 'error');
    return;
  }

  pickedLabel.textContent = `Selected: ${picked.name} (${formatSize(picked.size)})`;
  uploadBtn.disabled = false;
});

// Upload and Encrypt
$('#upload').addEventListener('click', async () => {
  if (!picked) return;
  const uploadBtn = $('#upload');
  uploadBtn.disabled = true;
  uploadBtn.textContent = 'Encrypting & Uploading...';

  try {
    const content = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const base64 = reader.result.split(',')[1] || '';
        resolve(base64);
      };
      reader.onerror = reject;
      reader.readAsDataURL(picked);
    });

    await api('/api/files', {
      method: 'POST',
      body: JSON.stringify({ name: picked.name, content })
    });

    notice(`Encrypted with AES-256-GCM and saved to storage.`, 'success');
    picked = null;
    $('#fileInput').value = '';
    $('#picked').textContent = 'No file selected (Max size: 10 MB)';
    await refresh();
    await updateActivity();
  } catch (err) {
    notice(err.message, 'error');
  } finally {
    uploadBtn.textContent = 'Encrypt and Upload';
    uploadBtn.disabled = !picked;
  }
});

// Refresh button
$('#refreshBtn').addEventListener('click', async () => {
  await refresh();
  await updateActivity();
  notice('File list refreshed.', 'info');
});

// Download with Client-side SHA-256 verification
async function downloadFile(id, expectedName) {
  try {
    notice(`Requesting ${expectedName}... Verifying permissions & server integrity...`, 'info');
    const r = await api(`/api/files/${id}/download`);

    // Decode base64 to binary bytes
    const binaryStr = atob(r.content);
    const len = binaryStr.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }

    // Client-side SHA-256 recomputation using Web Cryptography API
    const digestBuffer = await crypto.subtle.digest('SHA-256', bytes);
    const clientHash = Array.from(new Uint8Array(digestBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (clientHash !== r.sha256) {
      throw new Error(`Client integrity mismatch! Server reported ${r.sha256.slice(0, 12)}..., but client computed ${clientHash.slice(0, 12)}... File rejected.`);
    }

    // Trigger download in browser
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const downloadUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = r.name || expectedName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(downloadUrl);

    notice(`✅ Download verified! Server & client SHA-256 match (${clientHash.slice(0, 12)}...)`, 'success');
    await updateActivity();
  } catch (err) {
    if (err.status === 403) {
      notice(`❌ 403 Forbidden: Access denied by Zero-Trust policy.`, 'error');
    } else if (err.status === 409) {
      notice(`❌ 409 Integrity Failure: Server rejected download. SHA-256 or AES-GCM tag mismatch!`, 'error');
    } else {
      notice(`❌ ${err.message}`, 'error');
    }
    await updateActivity();
  }
}

// Share file with another user
async function shareFile(id, targetUser) {
  if (!targetUser) return;
  try {
    await api(`/api/files/${id}/share`, {
      method: 'POST',
      body: JSON.stringify({ username: targetUser })
    });
    notice(`Granted read access on file to ${targetUser}.`, 'success');
    await refresh();
    await updateActivity();
  } catch (err) {
    notice(err.message, 'error');
  }
}

// Revoke file access from a user
async function revokeFile(id, targetUser) {
  if (!confirm(`Revoke file access from ${targetUser}?`)) return;
  try {
    await api(`/api/files/${id}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ username: targetUser })
    });
    notice(`Revoked access from ${targetUser}.`, 'info');
    await refresh();
    await updateActivity();
  } catch (err) {
    notice(err.message, 'error');
  }
}

// Delete file permanently (Owner only)
async function deleteFile(id, name) {
  if (!confirm(`Are you sure you want to permanently delete "${name}"?\n\nUnder Zero-Trust policy, the encrypted file blob, metadata, and all sharing permissions will be permanently removed.`)) {
    return;
  }
  try {
    await api(`/api/files/${id}`, {
      method: 'DELETE'
    });
    notice(`✅ File "${name}" was permanently deleted.`, 'success');
    await refresh();
    await updateActivity();
  } catch (err) {
    notice(`❌ Delete failed: ${err.message}`, 'error');
    await updateActivity();
  }
}

// Integrity Demo: Simulate or restore checksum mismatch
async function toggleTamper(id, action) {
  try {
    const res = await api(`/api/files/${id}/tamper-demo`, {
      method: 'POST',
      body: JSON.stringify({ action })
    });
    if (res.tampered) {
      notice('Simulated checksum mismatch active. Download will now trigger 409 Integrity Failure!', 'warning');
    } else {
      notice('Checksum restored to original valid value. Downloads will now succeed.', 'success');
    }
    await refresh();
    await updateActivity();
  } catch (err) {
    notice(err.message, 'error');
  }
}

// Render files list
async function refresh() {
  if (!token) return;
  try {
    const data = await api('/api/files');
    const files = data.files || [];
    const users = data.users || [];
    if (data.quota !== undefined && data.usage !== undefined) {
      updateStorageQuotaDisplay(data.quota, data.usage);
    }
    const container = $('#files');
    const emptyState = $('#empty');

    emptyState.hidden = files.length > 0;

    // Filter available recipients (excluding owner)
    container.innerHTML = files.map(f => {
      const isOwner = f.owner === me.username;
      const canManage = f.canShare;
      const potentialRecipients = users.filter(u => u.username !== f.owner && !f.sharedWith.includes(u.username));

      return `
        <div class="file-row ${f.tampered ? 'tampered-row' : ''}">
          <div class="file-top">
            <div>
              <span class="file-name">${esc(f.name)}</span>
              ${f.tampered ? '<span class="tamper-tag">⚠️ SIMULATED MISMATCH</span>' : ''}
            </div>
            <div style="display: flex; gap: 8px; align-items: center;">
              <button class="primary-btn btn-dl" data-id="${f.id}" data-name="${esc(f.name)}">
                Download &amp; Verify
              </button>
              ${
                isOwner
                  ? `<button class="btn-delete" data-id="${f.id}" data-name="${esc(f.name)}" title="Permanently delete this file">Delete</button>`
                  : ''
              }
            </div>
          </div>

          <div class="meta">
            <span>Owner: <b>${esc(f.owner)}</b> (${esc(f.ownerRole)})</span> ·
            <span>Size: <b>${formatSize(f.size)}</b></span> ·
            <span>Uploaded: ${formatDate(f.createdAt)}</span>
          </div>

          <div class="hash-box">
            <span class="hash-label">EXPECTED SHA-256</span>
            <code class="hash-code">${esc(f.sha256)}</code>
          </div>

          <div class="sharing-section">
            <span class="sharing-label">Shared With:</span>
            ${
              f.sharedWith.length === 0
                ? '<span class="muted-tag">Private (Owner only)</span>'
                : f.sharedWith.map(u => `
                    <span class="shared-chip">
                      ${esc(u)}
                      ${canManage ? `<button class="chip-revoke" data-id="${f.id}" data-user="${esc(u)}" title="Revoke access">×</button>` : ''}
                    </span>
                  `).join(' ')
            }
          </div>

          ${
            canManage
              ? `
                <div class="file-actions">
                  ${
                    potentialRecipients.length > 0
                      ? `
                        <div class="share-inline-form">
                          <select id="share-select-${f.id}" class="user-select">
                            <option value="">Select user to share...</option>
                            ${potentialRecipients.map(u => `<option value="${esc(u.username)}">${esc(u.username)} (${esc(u.role)})</option>`).join('')}
                          </select>
                          <button class="btn-share" data-id="${f.id}">Grant Access</button>
                        </div>
                      `
                      : '<span class="muted-tag">Shared with all eligible users</span>'
                  }

                  <div class="integrity-actions">
                    ${
                      f.tampered
                        ? `<button class="btn-restore" data-id="${f.id}" data-action="restore" title="Restore original recorded SHA-256">Restore Valid Hash</button>`
                        : `<button class="btn-tamper" data-id="${f.id}" data-action="tamper" title="Simulate hash mismatch to test server rejection">Simulate Hash Mismatch</button>`
                    }
                  </div>
                </div>
              `
              : ''
          }
        </div>
      `;
    }).join('');

    // Attach event listeners for downloads
    container.querySelectorAll('.btn-dl').forEach(btn => {
      btn.onclick = () => downloadFile(btn.dataset.id, btn.dataset.name);
    });

    // Attach event listeners for sharing
    container.querySelectorAll('.btn-share').forEach(btn => {
      btn.onclick = () => {
        const id = btn.dataset.id;
        const select = $(`#share-select-${id}`);
        if (select && select.value) {
          shareFile(id, select.value);
        } else {
          notice('Please select a user to share with.', 'warning');
        }
      };
    });

    // Attach event listeners for revoking
    container.querySelectorAll('.chip-revoke').forEach(btn => {
      btn.onclick = () => revokeFile(btn.dataset.id, btn.dataset.user);
    });

    // Attach event listeners for deletion (owner only)
    container.querySelectorAll('.btn-delete').forEach(btn => {
      btn.onclick = () => deleteFile(btn.dataset.id, btn.dataset.name);
    });

    // Attach event listeners for integrity demo (tamper / restore)
    container.querySelectorAll('.btn-tamper, .btn-restore').forEach(btn => {
      btn.onclick = () => toggleTamper(btn.dataset.id, btn.dataset.action);
    });

  } catch (err) {
    notice(err.message, 'error');
  }
}

// Live Activity Log polling (Admin only)
async function updateActivity() {
  const logBox = $('#activityLog');
  if (!logBox) return;

  if (!token || !me || me.role !== 'Admin') {
    logBox.innerHTML = '<div class="log-placeholder">Audit feed restricted to Administrators under Zero-Trust policy.</div>';
    return;
  }

  try {
    const { logs } = await api('/api/activity');
    if (!logs || logs.length === 0) {
      logBox.innerHTML = '<div class="log-placeholder">Waiting for server access events...</div>';
      return;
    }

    logBox.innerHTML = logs.slice().reverse().map(l => {
      let typeClass = 'log-allow';
      if (l.type === 'DENY') typeClass = 'log-deny';
      if (l.type === 'INTEGRITY-FAIL') typeClass = 'log-fail';
      if (l.type === 'DEMO') typeClass = 'log-demo';

      return `
        <div class="log-item ${typeClass}">
          <span class="log-time">${esc(l.time)}</span>
          <span class="log-badge ${typeClass}">${esc(l.type)}</span>
          <span class="log-action">${esc(l.action)}</span>
          <span class="log-details">${esc(l.details)}</span>
        </div>
      `;
    }).join('');
  } catch {}
}

function startPolling() {
  stopPolling();
  if (me && me.role === 'Admin') {
    pollTimer = setInterval(() => {
      updateActivity();
    }, 2500);
  }
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

// Admin User Management
async function loadAdminUsers() {
  if (!token || !me || me.role !== 'Admin') return;
  const container = $('#adminUsersList');
  if (!container) return;

  try {
    const data = await api('/api/admin/users');
    const users = data.users || [];

    if (users.length === 0) {
      container.innerHTML = '<div class="muted">No registered users found.</div>';
      return;
    }

    container.innerHTML = `
      <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
        <thead>
          <tr style="text-align: left; border-bottom: 1px solid var(--border);">
            <th style="padding: 8px 6px;">Username</th>
            <th style="padding: 8px 6px;">Current Role</th>
            <th style="padding: 8px 6px;">Change Role</th>
          </tr>
        </thead>
        <tbody>
          ${users.map(u => {
            const isSelf = u.username.toLowerCase() === me.username.toLowerCase();
            return `
              <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 10px 6px;">
                  <b>${esc(u.username)}</b>
                  ${isSelf ? ' <small class="muted">(Current Admin)</small>' : ''}
                </td>
                <td style="padding: 10px 6px;">
                  <span class="role-badge ${esc(u.role.toLowerCase())}">${esc(u.role)}</span>
                </td>
                <td style="padding: 10px 6px;">
                  ${
                    isSelf
                      ? '<span class="muted" style="font-size: 12px;">Locked (Cannot change own role)</span>'
                      : `
                        <select class="admin-user-role-select" data-user="${esc(u.username)}" style="padding: 4px 8px; font-size: 12px; width: auto; display: inline-block;">
                          <option value="Student" ${u.role === 'Student' ? 'selected' : ''}>Student</option>
                          <option value="Faculty" ${u.role === 'Faculty' ? 'selected' : ''}>Faculty</option>
                          <option value="Admin" ${u.role === 'Admin' ? 'selected' : ''}>Admin</option>
                        </select>
                      `
                  }
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;

    container.querySelectorAll('.admin-user-role-select').forEach(sel => {
      sel.onchange = async () => {
        const targetUser = sel.dataset.user;
        const newRole = sel.value;
        try {
          await api(`/api/admin/users/${encodeURIComponent(targetUser)}/role`, {
            method: 'POST',
            body: JSON.stringify({ role: newRole })
          });
          notice(`✅ Role for ${targetUser} changed to ${newRole}.`, 'success');
          await loadAdminUsers();
          await refresh();
          await updateActivity();
        } catch (err) {
          notice(`❌ Failed to update role: ${err.message}`, 'error');
          await loadAdminUsers();
        }
      };
    });
  } catch (err) {
    container.innerHTML = `<div class="muted" style="color: var(--danger);">Failed to load admin users: ${esc(err.message)}</div>`;
  }
}

// Attach admin form event listeners once at script level
const adminCreateForm = $('#adminCreateUserForm');
if (adminCreateForm) {
  adminCreateForm.addEventListener('submit', async e => {
    e.preventDefault();
    const uInput = $('#adminNewUsername');
    const pInput = $('#adminNewPassword');
    const rInput = $('#adminNewRole');

    const username = uInput.value.trim();
    const password = pInput.value;
    const role = rInput.value;

    try {
      await api('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify({ username, password, role })
      });
      notice(`✅ Created user ${username} with role ${role}.`, 'success');
      uInput.value = '';
      pInput.value = '';
      rInput.value = 'Student';
      await loadAdminUsers();
      await refresh();
      await updateActivity();
    } catch (err) {
      notice(`❌ ${err.message}`, 'error');
    }
  });
}

const adminRefreshBtn = $('#adminRefreshUsersBtn');
if (adminRefreshBtn) {
  adminRefreshBtn.addEventListener('click', async () => {
    await loadAdminUsers();
    notice('User list refreshed.', 'info');
  });
}

// Fetch transport information on initial load
(async () => {
  try {
    const t = await api('/api/transport');
    const badge = $('#transportBadge');
    if (badge) {
      badge.textContent = `● LOCAL ONLY · ${t.protocol.toUpperCase()} ${t.host}:${t.port}`;
    }
  } catch {}
})();
