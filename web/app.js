'use strict';

const $ = id => document.getElementById(id);
let csrf = '', peers = [], editing = null, deleting = null;
let account = null, accounts = [], editingAccount = null, deletingAccount = null;
let activityTimer = null, activitySequence = 0, addressesRevision = null;
let shareSequence = 0, settingsSequence = 0, settingsRevision = null, ipv6 = false;
let qrFrames = [], qrPart = 0, qrTimer = null;
let keyPolicy = null, reissuing = null, sharePeerID = '', shareKeyVersion = '', shareNoStoredKey = false;
let issuedConfig = '', shareDeadline = 0, shareExpiryTimer = null;
let currentPanel = 'login-view', deviceOwner = '', pendingActions = 0;
const panelParents = {'account-edit-dialog':'accounts-dialog','account-delete-dialog':'accounts-dialog','admin-totp-dialog':'accounts-dialog','totp-setup-dialog':'security-dialog','recovery-dialog':'security-dialog','purge-dialog':'key-policy-dialog'};
const panelNav = {'accounts-dialog':'accounts','account-edit-dialog':'accounts','account-delete-dialog':'accounts','admin-totp-dialog':'accounts','settings-dialog':'settings','key-policy-dialog':'key-policy','purge-dialog':'key-policy','addresses-dialog':'change-addresses','transfer-dialog':'transfer','audit-dialog':'audit','password-dialog':'own-password','security-dialog':'security','totp-setup-dialog':'security','recovery-dialog':'security'};
function hidePanel(id) {
  const panel = $(id);
  if (!panel || panel.hidden) return;
  panel.hidden = true;
  panel.dispatchEvent(new Event('close'));
}
function openPanel(id) {
  if (!csrf || !account) return;
  if (id !== currentPanel) {
    hidePanel(currentPanel);
    currentPanel = id;
  }
  $(id).hidden = false;
  $('navigation').hidden = false;
  const selected = panelNav[id] || (deviceOwner && deviceOwner !== account.accountId ? 'accounts' : 'my-devices');
  for (const b of $('navigation').querySelectorAll('button')) {
    if (b.id === selected) b.setAttribute('aria-current','page'); else b.removeAttribute('aria-current');
  }
  window.scrollTo(0, 0);
}
function closePanel(id) {
  if ($(id).hidden) return;
  hidePanel(id);
  if (!csrf || !account) return;
  openPanel(panelParents[id] || 'dashboard');
}
function ownDevices() {
  deviceOwner = account.accountId; $('search').value = ''; $('filter').value = 'all'; render(); openPanel('dashboard');
}
async function accountDevices(owner) {
  const updated = await api('/peers');
  if (!csrf) return;
  peers = updated; deviceOwner = owner.id; $('search').value = ''; $('filter').value = 'all'; render(); openPanel('dashboard');
}

const notify = (message, error = false) => {
  $('notice').textContent = message;
  $('notice').className = error ? 'notice error' : 'notice';
  $('notice').hidden = !message;
  const dialog = currentPanel !== 'login-view' ? $(currentPanel) : null;
  if (dialog) {
    let status = dialog.querySelector('.dialog-status');
    if (!status) { status = document.createElement('p'); status.setAttribute('role', 'status'); dialog.append(status); }
    status.className = `dialog-status notice${error ? ' error' : ''}`;
    status.textContent = message; status.hidden = !message;
  }
};
function signedOut() {
 stopNetworkPolling();$('network-status').hidden=true;$('network-reapply-confirm').checked=false;$('network-reapply-options').open=false;
  for (const panel of document.querySelectorAll('.panel')) hidePanel(panel.id);
  currentPanel = 'login-view'; deviceOwner = ''; $('navigation').hidden = true;
  clearTransferSecrets(); clearMFASecrets(); resetLoginStep();
  account = null; accounts = []; editingAccount = null; deletingAccount = null; $('account-form').reset(); $('account-list').replaceChildren(); $('audit-list').replaceChildren();
  for (const id of ['accounts', 'own-password', 'signed-in-as', 'security']) $(id).hidden = true;
  clearTimeout(activityTimer); activitySequence++; keyPolicy = null; reissuing = null; $('purge-confirm').checked = false; $('reissue-confirm').checked = false;
  csrf = ''; peers = []; addressesRevision = null; $('addresses-form').reset(); $('devices').replaceChildren(); settingsSequence++; settingsRevision = null; $('settings').hidden = true; $('settings-form').reset(); document.title = 'AWG Panel';
  $('dashboard').hidden = true; $('logout').hidden = true; $('login-view').hidden = false;

  clearShare();
}
async function api(path, method = 'GET', body, signal) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
  const networkChange = account?.role === 'superadmin' && method !== 'GET' && (path.startsWith('/peers') || path.startsWith('/accounts') || ['/addresses','/transfer/import','/network-reapply'].includes(path));
  if(networkChange){networkChanges++;renderNetworkStatus({state:'applying'});}
  let response,data;
  try {
   response = await fetch(`/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', cache: 'no-store', signal });
   data = await response.json();
  } finally {
   if(networkChange){networkChanges--;if(csrf&&account?.role==='superadmin')void pollNetworkStatus();}
  }
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith('/login')) signedOut();
    const error = new Error(data.error || 'Request failed'); error.status = response.status; throw error;
  }
  return data;
}
async function busy(button, action) {
  button.disabled = true; pendingActions++; $('navigation').inert = true; $('logout').disabled = true;
  for (const control of document.querySelectorAll('.close-dialog, #devices-back')) control.disabled = true;
  try { await action(); } catch (error) { notify(error.message, true); }
  finally {
    button.disabled = false; pendingActions--;
    $('navigation').inert = pendingActions > 0; $('logout').disabled = pendingActions > 0;
    for (const control of document.querySelectorAll('.close-dialog, #devices-back')) control.disabled = pendingActions > 0;
  }
}
async function load() {
  const session = await api('/session'); csrf = session.csrf; account = session;
  accounts = await api('/accounts');
  $('security').hidden = false; $('accounts').hidden = session.role === 'user'; $('own-password').hidden = false; $('signed-in-as').hidden = false; $('signed-in-as').textContent = `${session.login} · ${session.role}`;
  peers = await api('/peers');
  $('login-view').hidden = true; $('navigation').hidden = false; $('server-navigation').hidden = session.role !== 'superadmin'; $('audit').hidden = session.role !== 'superadmin';
  if (!deviceOwner || !accounts.some(a => a.id === deviceOwner)) deviceOwner = session.accountId;
  if (currentPanel === 'login-view') openPanel('dashboard'); $('logout').hidden = false;
  $('network-mode').textContent = session.ipv6 ? 'IPv4 + IPv6' : 'IPv4';
  $('endpoint').textContent = session.endpoint; ipv6 = session.ipv6; $('settings').hidden = session.role !== 'superadmin'; showServerName(session.serverName || 'AWG Panel');
  render(); startActivityPolling();startNetworkPolling();
}
function button(text, handler, className = 'quiet') {
  const b = document.createElement('button'); b.textContent = text; b.className = className;
  b.addEventListener('click', () => busy(b, handler)); return b;
}
function textElement(tag, text, className = '') {
  const e = document.createElement(tag); e.textContent = text; e.className = className; return e;
}
function render() {
  invalidateShare();
  const owned = peers.filter(p => p.ownerId === (deviceOwner || account?.accountId));
  $('devices-title').textContent = !deviceOwner || deviceOwner === account?.accountId ? 'My devices' : `${accounts.find(a => a.id === deviceOwner)?.login || 'Account'} · Devices`;
  $('devices-back').hidden = !deviceOwner || deviceOwner === account?.accountId;
  $('device-count').textContent = owned.length;
  $('enabled-count').textContent = owned.filter(p => p.enabled && !p.accountBlocked).length;
  const query = $('search').value.toLowerCase(), group = $('filter').value;
  const visible = owned.filter(p => (group === 'all' || p.group === group) && `${p.name} ${p.address4} ${p.address6 || ''}`.toLowerCase().includes(query));
  $('empty').hidden = visible.length > 0;
  $('devices').replaceChildren(...visible.map(p => {
    const card = textElement('article', '', `device-card${p.enabled ? '' : ' paused'}`);
    card.dataset.id = p.id;
    const top = textElement('div', '', 'card-top');
    top.append(textElement('span', p.group === 'home' ? 'HOME' : 'GUEST', `badge ${p.group}`), textElement('span', p.accountBlocked ? 'Account blocked' : p.enabled ? 'Enabled' : 'Disabled', 'small muted'));
    card.append(top, textElement('h2', p.name), textElement('p', p.address4, 'mono muted'));

    const activity = textElement('p', '', 'device-activity small'); setActivity(activity, p); card.append(activity);
    if (p.address6) card.append(textElement('p', p.address6, 'mono muted small'));
    const actions = textElement('div', '', 'card-actions');
    if (p.storedPrivateKey) actions.append(button('Connect', () => share(p), 'primary'));
    else card.append(textElement('p', 'Private key not stored. Reissue to get a new profile.', 'small muted'));
    actions.append(button('Reissue', () => reissue(p), 'quiet danger-text'), button('Edit', () => edit(p)), button(p.enabled ? 'Disable' : 'Enable', async () => {
      await api(`/peers/${p.id}`, 'PATCH', { enabled: !p.enabled }); await load(); notify('Device updated.');
    }), button('Remove', () => { deleting = p.id; $('delete-description').textContent = `Remove “${p.name}” from your network?`; openPanel('delete-dialog'); }, 'quiet danger-text'));
    card.append(actions); return card;
  }));
}
// Background refresh changes status text without replacing focused device controls.
function setActivity(element, peer) {
  const activity = peer.activity || {status: 'unavailable'};
  const last = activity.lastHandshake ? new Date(activity.lastHandshake).toLocaleString() : '';
  const status = peer.accountBlocked ? 'blocked' : !peer.enabled ? 'disabled' : activity.status;
  element.className = `device-activity small ${status === 'online' ? 'online' : 'muted'}`;
  element.textContent = status === 'online' ? 'Online'
    : status === 'blocked' ? `Account blocked${last ? ` · Last online: ${last}` : ''}`
    : status === 'disabled' ? `Disabled${last ? ` · Last online: ${last}` : ''}`
    : status === 'never' ? 'Never connected'
    : status === 'offline' && last ? `Last online: ${last}`
    : `Status unavailable${last ? ` · Last online: ${last}` : ''}`;
  element.title = 'Online means a handshake within the last 3 minutes, not guaranteed reachability. Dates use your local time zone.';
}
function unavailableActivity() {
  peers = peers.map(p => ({...p, activity: {...p.activity, status: 'unavailable'}}));
  updateActivityText();
}
function updateActivityText() {
  invalidateShare();
  for (const card of $('devices').children) {
    const peer = peers.find(p => p.id === card.dataset.id);
    if (peer) setActivity(card.querySelector('.device-activity'), peer);
  }
}
function startActivityPolling(immediate = false) {
  clearTimeout(activityTimer);
  const sequence = ++activitySequence;
  const poll = async () => {
    if (!csrf || sequence !== activitySequence) return;
    if (!document.hidden) {
      try {
        const updated = await api('/peers', 'GET', undefined, AbortSignal.timeout(8000));
        if (sequence !== activitySequence) return;
        const metadata = list => JSON.stringify(list.map(({activity, ...p}) => p));
        const changed = metadata(peers) !== metadata(updated);
        peers = updated;
        if (changed) render(); else updateActivityText();
      } catch (_) {
        if (sequence === activitySequence) unavailableActivity();
      }
    }
    if (csrf && sequence === activitySequence) activityTimer = setTimeout(poll, 15000);
  };
  if (immediate) poll(); else activityTimer = setTimeout(poll, 15000);
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && csrf) { unavailableActivity(); startActivityPolling(true); }
});
function edit(peer = null) {
  $('device-owner').replaceChildren(...accounts.map(a => new Option(`${a.login}${a.active ? '' : ' (blocked)'}`, a.id)));
  $('device-owner').value = peer?.ownerId || deviceOwner || account.accountId; $('device-owner-field').hidden = true; $('device-owner').disabled = true;
  editing = peer?.id || null; $('device-title').textContent = peer ? 'Edit device' : 'Add device';
  $('device-name').value = peer?.name || ''; $('device-group').value = peer?.group || 'home';
  openPanel('device-dialog'); notify(''); $('device-name').focus();
}
function clearShare() {
  clearInterval(qrTimer); qrTimer = null;
  clearTimeout(shareExpiryTimer); shareDeadline = 0; issuedConfig = ''; sharePeerID = ''; shareKeyVersion = ''; shareNoStoredKey = false;
  $('share-storage').textContent = '';
  qrFrames.forEach(url => URL.revokeObjectURL(url)); qrFrames = []; qrPart = 0;
  $('qr-controls').hidden = true;
  shareSequence++; $('vpn-link').value = ''; $('qr').removeAttribute('src'); $('download').removeAttribute('href');
}
function showQrPart(part) {
  if (!qrFrames.length) return;
  qrPart = (part + qrFrames.length) % qrFrames.length;
  $('qr').src = qrFrames[qrPart];
  $('qr-count').textContent = `QR ${qrPart + 1} of ${qrFrames.length}`;
}
function pauseQr() {
  clearInterval(qrTimer); qrTimer = null; $('qr-pause').textContent = 'Play';
}
function playQr() {
  if (qrFrames.length < 2) return;
  clearInterval(qrTimer);
  qrTimer = setInterval(() => showQrPart(qrPart + 1), 1500);
  $('qr-pause').textContent = 'Pause';
}
async function share(peer) {
  clearShare();
  const sequence = shareSequence;
  const result = await api(`/peers/${peer.id}/link`);
  if (sequence !== shareSequence) return;
  sharePeerID = peer.id; shareKeyVersion = peer.keyVersion;
  startShareExpiry(false);
  $('share-title').textContent = `Connect ${peer.name}`; $('vpn-link').value = result.link;
  const version = encodeURIComponent(result.version);
  $('download').href = `/api/peers/${peer.id}/config?version=${version}`;
  $('qr').hidden = true; $('qr-error').hidden = true;
  $('qr-help').textContent = 'Loading QR codes…';
  openPanel('share-dialog');
  const frames = [];
  try {
    for (let part = 0; part < result.qrParts; part++) {
      const response = await fetch(`/api/peers/${peer.id}/qr?part=${part}&version=${version}`);
      if (!response.ok) { const failure = await response.json(); throw new Error(failure.error || 'QR export failed'); }
      const blob = await response.blob();
      if (sequence !== shareSequence) return;
      frames.push(URL.createObjectURL(blob));
    }
    if (!frames.length) throw new Error('QR export is unavailable');
    qrFrames = frames; showQrPart(0); $('qr').hidden = false;
    $('qr-controls').hidden = frames.length === 1;
    $('qr-help').textContent = frames.length > 1
      ? `Keep the AmneziaVPN scanner open until all ${frames.length} QR codes are scanned. Codes change automatically.`
      : 'Scan inside AmneziaVPN, or import the connection link.';
    if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) playQr();
    else pauseQr();
  } catch (error) {
    if (sequence === shareSequence) {
      $('qr-help').textContent = error.message; $('qr-error').hidden = false;
    }
  } finally {
    if (qrFrames !== frames) frames.forEach(url => URL.revokeObjectURL(url));
  }
}
function startShareExpiry(notStored) {
  shareNoStoredKey = notStored; shareDeadline = Date.now() + 5 * 60 * 1000;
  $('share-storage').textContent = notStored
    ? 'Private key NOT stored. Save this profile now. Leaving this page, signing out or waiting 5 minutes discards it; recovering access then requires reissuing the profile.'
    : 'Private key stored. This page clears after 5 minutes; you can export again later.';
  shareExpiryTimer = setTimeout(checkShareExpiry, 5 * 60 * 1000);
}
function checkShareExpiry() {
  if (shareDeadline && Date.now() >= shareDeadline) {
    const noKey = shareNoStoredKey;
    closePanel('share-dialog'); clearShare();
    notify(noKey ? 'The one-time profile was cleared. If you did not save it, reissue the device.' : 'The connection page expired. Open Connect to export again.', true);
    return false;
  }
  return Boolean(sharePeerID);
}
function invalidateShare() {
  if (!sharePeerID) return;
  const p = peers.find(p => p.id === sharePeerID);
  if (!p || p.keyVersion !== shareKeyVersion || (!shareNoStoredKey && !p.storedPrivateKey)) {
    closePanel('share-dialog'); clearShare();
    notify('This profile changed or its stored key was deleted. Reload the device before exporting again.', true);
  }
}
function showIssued(result) {
  clearShare();
  sharePeerID = result.id; shareKeyVersion = result.keyVersion; issuedConfig = result.config;
  $('share-title').textContent = `Connect ${result.name}`; $('vpn-link').value = result.link;
  $('download').href = '#'; $('qr').hidden = true; $('qr-error').hidden = true;
  for (const encoded of result.qrFrames || []) {
    const bytes = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
    qrFrames.push(URL.createObjectURL(new Blob([bytes], {type: 'image/png'})));
  }
  $('qr-controls').hidden = qrFrames.length < 2;
  if (qrFrames.length) { showQrPart(0); $('qr').hidden = false; }
  else $('qr-error').hidden = false;
  $('qr-help').textContent = qrFrames.length > 1 ? `Keep the AmneziaVPN scanner open for all ${qrFrames.length} QR codes.` : 'Import the connection link, scan in AmneziaVPN, or download the config.';
  startShareExpiry(!result.storedPrivateKey);
  openPanel('share-dialog'); notify('');
  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) playQr(); else pauseQr();
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) checkShareExpiry(); });
window.addEventListener('pagehide', () => { clearTransferSecrets(); clearMFASecrets(); clearShare(); $('password-form').reset(); $('account-password').value = ''; $('password').value = ''; });
function reissue(peer) {
  reissuing = {id: peer.id, keyVersion: peer.keyVersion};
  $('reissue-name').textContent = peer.name; $('reissue-confirm').checked = false;
  openPanel('reissue-dialog'); notify('');
}
$('reissue-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter, async () => {
    clearTimeout(activityTimer); activitySequence++;
    let result;
    try { result = await api(`/peers/${reissuing.id}/reissue`, 'POST', {keyVersion: reissuing.keyVersion, confirm: $('reissue-confirm').checked}); }
    catch (error) { startActivityPolling(); if (!error.status || error.status >= 500) throw new Error('The reissue result is unknown. Refresh devices; if the new profile was not received, reissue again.'); throw error; }
    closePanel('reissue-dialog'); showIssued(result); result = null;
    await load().catch(() => notify('Profile issued. Save it now; the device list could not refresh.', true));
  });
});
function fillKeyPolicy(result) {
  keyPolicy = result; $('retain-keys').checked = result.retain;
  $('stored-key-count').textContent = `${result.storedKeys} device private keys currently stored on this server.`;
  $('purge-offer').hidden = result.retain || result.storedKeys === 0;
}
async function openKeyPolicy() {
  const result = await api('/key-policy'); if (!csrf) return;
  fillKeyPolicy(result); closePanel('settings-dialog');
  if ($('key-policy-dialog').hidden) openPanel('key-policy-dialog'); notify('');
}
$('key-policy').addEventListener('click', () => busy($('key-policy'), openKeyPolicy));
$('key-policy-reload').addEventListener('click', () => busy($('key-policy-reload'), openKeyPolicy));
$('key-policy-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    const result = await api('/key-policy', 'PUT', {revision: keyPolicy.revision, retain: $('retain-keys').checked});
    fillKeyPolicy(result); notify(result.retain ? 'New device keys will be stored. Previously missing keys remain unavailable.' : 'Storage disabled for new and reissued keys. Existing keys are kept; you can delete them separately below.');
  });
});
$('purge-keys').addEventListener('click', () => busy($('purge-keys'), async () => {
  const result = await api('/key-policy'); if (!csrf) return; fillKeyPolicy(result);
  if (result.retain || !result.storedKeys) { notify('No deletion available. Check the current policy.', true); return; }
  $('purge-count').textContent = `Delete saved private keys for all ${result.storedKeys} devices on this server?`;
  $('purge-confirm').checked = false; closePanel('key-policy-dialog'); openPanel('purge-dialog'); notify('');
}));
$('purge-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    clearShare();
    const result = await api('/keys/stored', 'DELETE', {revision: keyPolicy.revision, deleteVersion: keyPolicy.deleteVersion, confirm: $('purge-confirm').checked});
    closePanel('purge-dialog'); await load(); notify(`${result.deleted} stored private keys deleted. Existing tunnels continue working.`);
  });
});
function showServerName(name) {
  $('server-name-display').textContent = name;
  document.title = `${name} · AWG Panel`;
}
function fillSettings(settings) {
  settingsRevision = settings.revision;
  $('settings-name').value = settings.serverName;
  $('settings-dns1').value = settings.client.dns[0];
  $('settings-dns2').value = settings.client.dns[1] || '';
  $('settings-mtu').value = settings.client.mtu;
  $('settings-keepalive').value = settings.client.persistentKeepalive;
  $('settings-routes').value = settings.client.allowedIPs.join('\n');
  $('settings-ipv6-note').hidden = ipv6;
}
async function openSettings() {
  const sequence = ++settingsSequence;
  const settings = await api('/settings');
  if (!csrf || sequence !== settingsSequence) return;
  fillSettings(settings);
  if ($('settings-dialog').hidden) openPanel('settings-dialog');
  notify('');
  $('settings-name').focus();
}
$('settings').addEventListener('click', () => busy($('settings'), openSettings));
$('settings-reload').addEventListener('click', () => busy($('settings-reload'), openSettings));
$('settings-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter, async () => {
    const dns = [$('settings-dns1').value.trim(), $('settings-dns2').value.trim()].filter(Boolean);
    const settings = await api('/settings', 'PUT', {
      revision: settingsRevision,
      serverName: $('settings-name').value.trim(),
      client: {dns, mtu: Number($('settings-mtu').value), persistentKeepalive: Number($('settings-keepalive').value),
        allowedIPs: $('settings-routes').value.split(/[\s,]+/).filter(Boolean)}
    });
    fillSettings(settings); showServerName(settings.serverName);
    notify('Export defaults saved. Update existing client profiles only if you want them to use the new DNS, MTU, keepalive or routes. Server name changes do not require reconnecting.');
  });
});
async function openAddresses() {
  const result = await api('/addresses');
  if (!csrf) return;
  addressesRevision = result.revision;
  $('vpn-host').value = result.vpnHost; $('panel-origin').value = result.panelOrigin; $('addresses-confirm').checked = false;
  closePanel('settings-dialog');
  if ($('addresses-dialog').hidden) openPanel('addresses-dialog');
  notify(''); $('vpn-host').focus();
}
$('change-addresses').addEventListener('click', () => busy($('change-addresses'), openAddresses));
$('addresses-reload').addEventListener('click', () => busy($('addresses-reload'), openAddresses));
$('addresses-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter, async () => {
    const next = await api('/addresses', 'PUT', {revision: addressesRevision, vpnHost: $('vpn-host').value.trim(), panelOrigin: $('panel-origin').value.trim()});
    signedOut();
    notify(`Addresses saved. Sign in again${next.panelOrigin ? ` at ${next.panelOrigin}` : ' through your VPN or local panel address'}. Update the Endpoint in existing client profiles only if the VPN domain/IP changed; changing the panel address alone does not affect VPN profiles.`);
  });
});
async function openPassword() {
  const status = await api('/account/totp'); $('password-mfa-field').hidden = !status.enabled; $('password-mfa').required = status.enabled;
  closePanel('settings-dialog'); $('password-form').reset();
  openPanel('password-dialog'); notify(''); $('current-password').focus();
}
$('own-password').addEventListener('click', () => busy($('own-password'), openPassword));
$('password-dialog').addEventListener('close', () => $('password-form').reset());
$('password-form').addEventListener('submit', event => {
  event.preventDefault();
  const passwordBytes = new TextEncoder().encode($('new-password').value).length;
  if (passwordBytes < 12 || passwordBytes > 256) { notify('Password must contain 12 to 256 bytes.', true); return; }
  if ($('new-password').value !== $('confirm-password').value) { notify('New passwords do not match.', true); return; }
  busy(event.submitter, async () => {
    await api('/account/password', 'PUT', {currentPassword: $('current-password').value, newPassword: $('new-password').value, confirmPassword: $('confirm-password').value, code: $('password-mfa').value.trim()});
    signedOut(); notify('Password changed. Sign in with your new password.'); $('password').focus();
  });
});
$('qr').addEventListener('error', () => { pauseQr(); $('qr').hidden = true; $('qr-error').hidden = false; });
$('qr-prev').addEventListener('click', () => { pauseQr(); showQrPart(qrPart - 1); });
$('qr-next').addEventListener('click', () => { pauseQr(); showQrPart(qrPart + 1); });
$('qr-pause').addEventListener('click', () => { if (qrTimer) pauseQr(); else playQr(); });
$('share-dialog').addEventListener('close', clearShare);
$('download').addEventListener('click', event => {
  event.preventDefault();
  if ($('download').disabled || !checkShareExpiry()) return;
  const href = $('download').getAttribute('href');
  if (!href) return;
  busy($('download'), async () => {
    let blob;
    const sequence = shareSequence;
    if (issuedConfig) blob = new Blob([issuedConfig], {type: 'text/plain'});
    else {
      const response = await fetch(href, {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) { const failure = await response.json(); throw new Error(failure.error || 'Configuration export failed'); }
      blob = await response.blob();
    }
    if (sequence !== shareSequence || !checkShareExpiry()) return;
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'awg-device.conf';
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
});
$('copy-link').addEventListener('click', () => busy($('copy-link'), async () => {
  if (!checkShareExpiry()) return;
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText($('vpn-link').value); notify('Connection link copied.');
  } else {
    $('vpn-link').focus(); $('vpn-link').select();
    if (document.execCommand('copy')) notify('Connection link copied.');
    else notify('Link selected. Use your device’s Copy command.');
  }
}));
$('login-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    const result = await api('/login', 'POST', { login: $('login-name').value.trim(), password: $('password').value });
    $('password').value = ''; notify('');
    if (result.mfaRequired) { csrf = ''; $('login-form').hidden = true; $('login-mfa-form').hidden = false; $('login-code').value = ''; $('login-code').focus(); return; }
    csrf = result.csrf; resetLoginStep(); await load();
  });
});
$('logout').addEventListener('click', () => busy($('logout'), async () => { await api('/logout', 'POST'); signedOut(); notify('Signed out.'); }));
$('device-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    const wasEditing = Boolean(editing);
    clearTimeout(activityTimer); activitySequence++;
    let result;
    try { result = await api(editing ? `/peers/${editing}` : '/peers', editing ? 'PATCH' : 'POST', { name: $('device-name').value.trim(), group: $('device-group').value, ...(!editing ? {ownerId: $('device-owner').value} : {}) }); }
    catch (error) { startActivityPolling(); if (!wasEditing && (!error.status || error.status >= 500)) throw new Error('Creation result unknown. Refresh devices before trying again. If the device exists but its profile was lost, use Reissue.'); throw error; }
    closePanel('device-dialog');
    if (wasEditing) { await load(); notify('Device saved.'); }
    else { showIssued(result); result = null; await load().catch(() => notify('Profile issued. Save it now; the device list could not refresh.', true)); }
  });
});
$('delete-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    await api(`/peers/${deleting}`, 'DELETE'); closePanel('delete-dialog'); await load(); notify('Device removed.');
  });
});

async function openAccounts() {
  accounts = await api('/accounts');
  $('audit').hidden = account.role !== 'superadmin';
  $('account-list').replaceChildren(...accounts.map(a => {
    const row = textElement('article', '', 'account-row account-card');
    const info = textElement('div', '', 'account-info'); row.dataset.id = a.id;
    const heading = textElement('div', '', 'account-heading');
    heading.append(textElement('h3', a.login), textElement('span', `${a.role} · ${a.active ? 'Active' : a.enabled ? 'Blocked by administrator' : 'Blocked'} · Two-factor: ${a.totpEnabled ? 'Enabled' : 'Off'}`, 'small muted'));
    info.append(heading);
    if (a.managerId) info.append(textElement('p', `Managed by ${accounts.find(m => m.id === a.managerId)?.login || a.managerId}`, 'small muted'));
    const actions = textElement('div', '', 'actions');
    actions.append(button('Devices', () => accountDevices(a), 'primary'), button('Edit', () => editAccount(a)));
    if (a.id !== account.accountId && a.role !== 'superadmin') actions.append(button('Delete', () => {
      deletingAccount = a; $('account-delete-confirm').checked = false; $('account-delete-name').textContent = `Delete “${a.login}”?`;
      closePanel('accounts-dialog'); openPanel('account-delete-dialog'); notify('');
    }, 'quiet danger-text'));
    actions.append(button('Sign out sessions', async () => {
      await api(`/accounts/${a.id}/sessions`, 'DELETE');
      if (a.id === account.accountId) signedOut(); notify('Account sessions signed out.');
    }));
    if (a.totpEnabled && a.id !== account.accountId) actions.append(button('Reset two-factor', () => openAdminTOTP(a), 'quiet danger-text'));
    if (a.note) info.append(textElement('p', a.note, 'account-note muted'));
    row.append(info, actions); return row;
  }));
  if ($('accounts-dialog').hidden) openPanel('accounts-dialog'); notify('');
}
function accountFields() {
  const user = $('account-role').value === 'user';
  $('account-manager-field').hidden = !user || account.role === 'admin';
  $('account-manager').required = user; $('account-manager').disabled = !user;
  const blocking = Boolean(editingAccount?.enabled) && !$('account-enabled').checked;
  $('account-block-field').hidden = !blocking; $('account-block-confirm').required = blocking;
}
function editAccount(value = null) {
  editingAccount = value; $('account-form').reset();
  $('account-note-field').hidden = account.role !== 'superadmin' && value?.id === account.accountId;
  $('account-note').value = value?.note || '';
  const self = value?.id === account.accountId;
  $('account-edit-title').textContent = value ? `Edit ${value.login}` : 'Add account';
  $('account-login').value = value?.login || '';
  $('account-role').value = value?.role || (account.role === 'superadmin' && !accounts.some(a => a.role === 'admin') ? 'admin' : 'user'); $('account-role').disabled = Boolean(value) || account.role !== 'superadmin';
  for (const option of $('account-role').options) option.hidden = option.value === 'superadmin' && value?.role !== 'superadmin';
  $('account-manager').replaceChildren(...accounts.filter(a => a.role === 'admin').map(a => new Option(`${a.login}${a.active ? '' : ' (blocked)'}`, a.id)));
  if (value?.managerId) $('account-manager').value = value.managerId;
  if (account.role === 'admin') $('account-manager').value = account.accountId;
  $('account-enabled').checked = value ? value.enabled : true; $('account-enabled').disabled = self || value?.role === 'superadmin';
  $('account-password-field').hidden = self; $('account-password').required = !value;
  $('account-password').disabled = self; $('account-password-optional').hidden = !value;
  $('account-self-note').hidden = !self; accountFields();
  closePanel('accounts-dialog'); openPanel('account-edit-dialog'); notify(''); $('account-login').focus();
}
$('accounts').addEventListener('click', () => busy($('accounts'), openAccounts));
$('accounts-reload').addEventListener('click', () => busy($('accounts-reload'), openAccounts));
$('account-add').addEventListener('click', () => editAccount());
$('account-role').addEventListener('change', accountFields); $('account-enabled').addEventListener('change', accountFields);
$('account-edit-dialog').addEventListener('close', () => { $('account-password').value = ''; $('account-block-confirm').checked = false; });
$('account-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    const password = $('account-password').value;
    const size = new TextEncoder().encode(password).length;
    if (password && (size < 12 || size > 256)) throw new Error('Password must contain 12 to 256 bytes.');
    const role = $('account-role').value;
    const note = $('account-note').value; if (new TextEncoder().encode(note).length > 2000) throw new Error('Note must not exceed 2000 bytes.');
    const next = {note, login: $('account-login').value.trim(), role, managerId: role === 'user' ? $('account-manager').value : '', enabled: $('account-enabled').checked, revision: editingAccount?.revision || 0, password};
    const self = editingAccount?.id === account.accountId;
    await api(editingAccount ? `/accounts/${editingAccount.id}` : '/accounts', editingAccount ? 'PUT' : 'POST', next);
    $('account-password').value = ''; closePanel('account-edit-dialog');
    if (self) { signedOut(); notify('Account saved. Sign in with your updated login.'); return; }
    await load(); await openAccounts(); notify('Account saved. Affected account sessions have been signed out.');
  });
});
$('account-delete-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    await api(`/accounts/${deletingAccount.id}`, 'DELETE', {revision: deletingAccount.revision, confirm: $('account-delete-confirm').checked});
    closePanel('account-delete-dialog'); deletingAccount = null; await load(); await openAccounts(); notify('Account deleted.');
  });
});
$('audit').addEventListener('click', () => busy($('audit'), async () => {
  const entries = await api('/audit');
  const label = id => accounts.find(a => a.id === id)?.login || peers.find(p => p.id === id)?.name || id;
  $('audit-list').replaceChildren(...entries.map(entry => {
    const row = textElement('article', '', 'account-row');
    row.append(textElement('strong', entry.action), textElement('p', `${label(entry.actor)} → ${label(entry.target)}`), textElement('p', new Date(entry.at).toLocaleString(), 'small muted')); return row;
  }));
  if (!entries.length) $('audit-list').append(textElement('p', 'No changes recorded yet.', 'muted'));
  closePanel('accounts-dialog'); openPanel('audit-dialog'); notify('');
}));

$('add').addEventListener('click', () => edit());
$('refresh').addEventListener('click', () => busy($('refresh'), load));
$('search').addEventListener('input', render); $('filter').addEventListener('change', render);
for (const b of document.querySelectorAll('.close-dialog')) b.addEventListener('click', () => closePanel(b.closest('.panel').id));
try { document.documentElement.dataset.theme = localStorage.getItem('awg-theme') || ''; } catch (_) { /* Storage may be disabled. */ }
$('theme').addEventListener('click', () => {
  const current = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = next;
  try { localStorage.setItem('awg-theme', next); } catch (_) { /* Theme still works for this page. */ }
});
let setupQR = '', setupTimer = null, recoveryTimer = null, setupPending = false, resetTOTPAccount = null;
function resetLoginStep() {
  $('login-form').hidden = false; $('login-mfa-form').hidden = true; $('login-code').value = '';
}
function clearSetup() {
  clearTimeout(setupTimer); setupTimer = null;
  if (setupQR) URL.revokeObjectURL(setupQR); setupQR = ''; setupPending = false;
  $('totp-qr').removeAttribute('src'); $('totp-secret').value = ''; $('totp-confirm-form').reset();
}
function clearMFASecrets() {
  clearSetup(); clearTimeout(recoveryTimer); recoveryTimer = null; resetTOTPAccount = null;
  $('recovery-codes').value = ''; $('login-code').value = '';
  for (const id of ['totp-start-form','totp-manage-form','admin-totp-form']) $(id).reset();
}
$('login-back').addEventListener('click', () => { resetLoginStep(); notify(''); $('password').focus(); });
$('login-mfa-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    const code = $('login-code').value.trim(); $('login-code').value = '';
    const result = await api('/login/verify', 'POST', {code}); csrf = result.csrf; resetLoginStep(); notify(''); await load();
  });
});
async function openSecurity() {
  const status = await api('/account/totp');
  $('totp-status').textContent = status.enabled ? `Enabled · ${status.recoveryRemaining} unused recovery codes` : 'Two-factor is off. An authenticator adds a second step after your password.';
  $('totp-start-form').reset(); $('totp-manage-form').reset();
  $('totp-start-form').hidden = status.enabled; $('totp-manage-form').hidden = !status.enabled;
  openPanel('security-dialog'); notify('');
}
$('security').addEventListener('click', () => busy($('security'), openSecurity));
$('security-dialog').addEventListener('close', () => { $('totp-start-form').reset(); $('totp-manage-form').reset(); });
$('totp-start-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    const password = $('totp-start-password').value; $('totp-start-password').value = '';
    const result = await api('/account/totp/setup', 'POST', {password});
    clearMFASecrets(); setupPending = true;
    $('totp-secret').value = result.secret;
    setupQR = URL.createObjectURL(new Blob([Uint8Array.from(atob(result.qr), c => c.charCodeAt(0))], {type: 'image/png'}));
    $('totp-qr').src = setupQR; closePanel('security-dialog'); openPanel('totp-setup-dialog'); notify(''); $('totp-confirm-code').focus();
    setupTimer = setTimeout(() => { closePanel('totp-setup-dialog'); notify('Authenticator setup expired. Start again.'); }, result.expiresIn * 1000);
  });
});
$('totp-setup-dialog').addEventListener('close', () => {
  const cancel = setupPending; clearSetup();
  if (cancel && csrf) api('/account/totp/setup', 'DELETE').catch(() => {});
});
function showRecoveryCodes(codes) {
  $('recovery-codes').value = codes.join('\n'); openPanel('recovery-dialog'); notify('');
  recoveryTimer = setTimeout(() => { closePanel('recovery-dialog'); notify('Recovery codes cleared from this page. Generate a new set if you did not save them.'); }, 300000);
}
$('totp-confirm-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    const code = $('totp-confirm-code').value; $('totp-confirm-code').value = '';
    const result = await api('/account/totp/confirm', 'POST', {code});
    setupPending = false; closePanel('totp-setup-dialog');
    // close is asynchronous; clear setup material before displaying recovery codes.
    clearMFASecrets(); showRecoveryCodes(result.recoveryCodes); await load();
  });
});
$('recovery-dialog').addEventListener('close', () => { clearTimeout(recoveryTimer); recoveryTimer = null; $('recovery-codes').value = ''; });
$('recovery-done').addEventListener('click', () => closePanel('recovery-dialog'));
$('recovery-download').addEventListener('click', () => {
  const value = $('recovery-codes').value; if (!value) return;
  const url = URL.createObjectURL(new Blob([`AWG Panel recovery codes\nAccount: ${account.login}\nEach code works once, together with your password.\n\n${value}\n`], {type: 'text/plain'}));
  const link = document.createElement('a'); link.href = url; link.download = 'awg-recovery-codes.txt'; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$('totp-manage-form').addEventListener('submit', event => {
  event.preventDefault(); const disable = event.submitter.value === 'disable';
  busy(event.submitter, async () => {
    const password = $('totp-password').value, code = $('totp-code').value.trim(); $('totp-password').value = ''; $('totp-code').value = '';
    const result = await api(`/account/totp${disable ? '' : '/recovery-codes'}`, disable ? 'DELETE' : 'POST', {password, code, confirm: $('totp-manage-confirm').checked});
    closePanel('security-dialog');
    if (disable) notify('Two-factor disabled. Other sessions signed out.'); else showRecoveryCodes(result.recoveryCodes);
    await load();
  });
});
$('sessions-revoke').addEventListener('click', () => busy($('sessions-revoke'), async () => {
  await api('/account/sessions', 'DELETE'); signedOut(); notify('All your sessions have been signed out.');
}));
async function openAdminTOTP(target) {
  const own = await api('/account/totp'); resetTOTPAccount = target; $('admin-totp-form').reset();
  $('admin-totp-target').textContent = `Reset two-factor for “${target.login}”?`;
  $('admin-totp-code-field').hidden = !own.enabled; $('admin-totp-code').required = own.enabled;
  closePanel('accounts-dialog'); openPanel('admin-totp-dialog'); notify('');
}
$('admin-totp-dialog').addEventListener('close', () => { $('admin-totp-form').reset(); resetTOTPAccount = null; });
$('admin-totp-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    const password = $('admin-totp-password').value, code = $('admin-totp-code').value.trim(); $('admin-totp-password').value = ''; $('admin-totp-code').value = '';
    await api(`/accounts/${resetTOTPAccount.id}/totp`, 'DELETE', {password, code, confirm: $('admin-totp-confirm').checked});
    closePanel('admin-totp-dialog'); await load(); await openAccounts(); notify('Second factor reset. Account sessions signed out; the owner can enroll again.');
  });
});


let transferPending = null, transferTimer = null, transferSequence = 0, transferInspection = null;
let accountChoices = [], deviceChoices = [];
const fullImportDescription = $('transfer-import-description').textContent;
function updateImportMode() {
 $('transfer-import-description').textContent = $('transfer-import-mode').value === 'selected'
  ? 'Import only selected settings, accounts and devices. Unselected data stays unchanged. Inspect the archive, resolve conflicts, then review and confirm the plan. Use the external panel address.'
  : fullImportDescription;
}
$('transfer-import-mode').addEventListener('change',updateImportMode);
function clearTransferPreview() {
  transferPending = null; clearTimeout(transferTimer);
  $('transfer-confirm-form').hidden = true; $('transfer-confirm').checked = false;
  $('transfer-summary').replaceChildren();
}
function clearTransferSecrets() {
  transferSequence++; clearTransferPreview(); clearTransferSelection();
  $('transfer-export-form').reset(); $('transfer-import-form').reset(); updateImportMode();
  $('transfer-generate').hidden = true;
}
function downloadTransfer(blob, name) {
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('transfer').addEventListener('click', () => busy($('transfer'), async () => {
  clearTransferSecrets(); const sequence = transferSequence;
  const info = await api('/transfer');
  if (!csrf || sequence !== transferSequence) return;
  const r = info.requirements;
  $('transfer-requirements').textContent = `This server: ${r.protocol}, UDP ${r.udpPort}, panel ${r.panelPort}, ${r.ipv6 ? 'IPv4 + IPv6' : 'IPv4 only'}.`;
  $('transfer-import-form').hidden = !info.importAvailable; $('transfer-unavailable').hidden = info.importAvailable;
  closePanel('settings-dialog'); openPanel('transfer-dialog');
}));
$('transfer-dialog').addEventListener('close', clearTransferSecrets);
$('transfer-mode').addEventListener('change', () => {
  $('transfer-export-secret').value = ''; $('transfer-generate').hidden = $('transfer-mode').value !== 'key';
});
$('transfer-generate').addEventListener('click', () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const key = btoa(String.fromCharCode(...bytes)); bytes.fill(0);
  $('transfer-export-secret').value = key;
  downloadTransfer(new Blob([key + '\n'], {type:'text/plain'}), 'awg-archive-key.txt');
  notify('Key generated. Store the downloaded key separately from the archive.');
});
$('transfer-export-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    const sequence = transferSequence;
    const response = await fetch('/api/transfer/export', {method:'POST',credentials:'same-origin',cache:'no-store',
      headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:JSON.stringify({
        includeClientKeys:$('transfer-keys').checked, mode:$('transfer-mode').value,
        secret:$('transfer-export-secret').value, currentPassword:$('transfer-export-password').value, code:$('transfer-export-code').value
      })});
    $('transfer-export-password').value = ''; $('transfer-export-code').value = '';
    if (!response.ok) { const data = await response.json(); if (response.status === 401) signedOut(); throw new Error(data.error || 'Export failed'); }
    const blob = await response.blob();
    if (!csrf || sequence !== transferSequence) return;
    downloadTransfer(blob, 'awg-configuration.awgbackup'); $('transfer-export-secret').value = '';
    notify('Encrypted archive downloaded. Keep its password or key for import.');
  });
});
for (const id of ['transfer-file','transfer-import-secret','transfer-import-password','transfer-import-code','transfer-import-mode']) {
  $(id).addEventListener('input', () => { transferSequence++; clearTransferPreview(); clearTransferSelection(); });
}
$('transfer-import-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    clearTransferPreview(); const sequence = ++transferSequence, file = $('transfer-file').files[0];
    if (!file || file.size > 8 * 1024 * 1024) throw new Error('Choose an encrypted archive no larger than 8 MiB.');
    const bytes = new Uint8Array(await file.arrayBuffer()); let binary = '';
    for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    const archive = btoa(binary); bytes.fill(0); binary = '';
    if (sequence !== transferSequence || !csrf) return;
    const selected = $('transfer-import-mode').value === 'selected';
    const result = await api(selected ? '/transfer/inspect' : '/transfer/preview', 'POST', {archive, secret:$('transfer-import-secret').value,
      currentPassword:$('transfer-import-password').value, code:$('transfer-import-code').value});
    $('transfer-import-password').value = ''; $('transfer-import-code').value = '';
    if (sequence !== transferSequence || !csrf) return;
    if (selected) {
      renderTransferSelection(result);
      transferInspection = {archive, ticket:result.ticket};
      transferTimer = setTimeout(() => { clearTransferSecrets(); notify('Archive inspection expired. Inspect again.'); }, result.expiresIn * 1000);
    } else showTransferPlan(result, archive, null);
  });
});

function clearTransferSelection() {
 transferInspection = null; accountChoices = []; deviceChoices = [];
 $('transfer-selection-form').hidden = true; $('transfer-selection-form').reset();
 for (const id of ['transfer-selection-settings','transfer-selection-accounts','transfer-selection-devices']) $(id).replaceChildren();
}
function showTransferPlan(result, archive, selection) {
 clearTimeout(transferTimer);
    transferPending = {archive, ticket:result.ticket, ...(selection ? {selection} : {})};
    const s = result.summary, current = result.current;
    const lines = [`Current server: ${current.serverName} · Accounts: ${current.accounts} · Devices: ${current.devices} · Saved client keys: ${current.storedKeys}`,
      `Current addresses: VPN ${current.vpnHost} · Panel ${current.panelOrigin || "VPN access only"}`,
      selection ? "Selective import: unselected data and local activity history are preserved. Only explicitly selected credentials are imported. Compatible saved keys are kept when the archive has none; discarding incompatible keys requires explicit permission." : "Full replacement: settings, server keys, passwords, TOTP and recovery codes come from the archive. Existing saved client keys are removed even if the archive excludes them.",
      "VPN connections may be interrupted. Existing profiles work only with compatible server/device keys, addresses and AWG parameters. All sessions are signed out.",
      ...(result.plan?.changes || []), ...(result.plan?.warnings || []),
      `Incoming server: ${s.serverName}`, `Created: ${new Date(s.createdAt).toLocaleString()}`, `VPN: ${s.vpnHost}`,
      `Panel: ${s.panelOrigin || 'VPN access only'}`, `Superadministrator: ${s.superadminLogin}`,
      `Accounts: ${s.accounts} · Devices: ${s.devices} · TOTP accounts: ${s.totpAccounts}`,
      selection ? `Saved client keys after import: ${s.storedKeys}. Import incoming keys: ${selection.clientKeys ? 'yes, when available' : 'no'}.` : `Saved client private keys: ${s.storedKeys} (${s.clientKeysIncluded ? 'included when available' : 'excluded'})`,
      `Storage for new client keys: ${s.retainKeys ? 'enabled' : 'disabled'}`];
    $('transfer-summary').replaceChildren(...lines.map(line => textElement('p', line)));
    for (const [title, inventory] of [[selection ? 'Current objects' : 'Current objects — replaced or removed', result.currentInventory], ['Result after import', result.resultInventory || result.incomingInventory]]) {
      const details = document.createElement('details');
      details.append(textElement('summary', title));
      for (const a of inventory.accounts) details.append(textElement('p', `${a.login} · ${a.role} · ${a.enabled === "true" ? "Enabled" : "Blocked"} · Manager: ${inventory.accounts.find(m=>m.id===a.managerId)?.login || "—"} · ${a.id}`, 'small'));
      for (const d of inventory.devices) {
        const owner = inventory.accounts.find(a => a.id === d.ownerId);
        details.append(textElement('p', `${d.name} · ${owner?.login || d.ownerId} · ${d.group} · ${d.enabled === "true" ? "Enabled" : "Disabled"} · 10.8.0.${d.slot} · ${d.id}`, 'small'));
      }
      $('transfer-summary').append(details);
    }
    $('transfer-confirm-form').hidden = false;
    $('transfer-confirm-label').textContent = selection ? 'Apply only the selected changes shown above and sign out all sessions.' : 'Replace this installation with the configuration above and sign out all sessions.';
    transferTimer = setTimeout(() => { clearTransferSecrets(); notify('Import preview expired. Select the file and preview again.'); }, result.expiresIn * 1000);
    $('transfer-summary').scrollIntoView({block:'nearest'});
}
function importSelect(label, options) {
 const wrapper = textElement('label', label), input = document.createElement('select');
 for (const [value,text] of options) {const option = textElement('option',text);option.value=value;input.append(option);}
 wrapper.append(input);return {wrapper,input};
}
function importCheck(label) {
 const wrapper = textElement('label','','confirmation'), input=document.createElement('input');input.type='checkbox';wrapper.append(input,document.createTextNode(label));return {wrapper,input};
}
function renderTransferSelection(result) {
 clearTransferSelection();
 // Inspection data stays in memory only until expiry or leaving this section.
 const settings = [['serverName','Server name'],['dns','DNS'],['mtu','MTU'],['keepalive','Keepalive'],['routes','Client routes'],['vpnHost','VPN domain/IP'],['panelOrigin','Panel address'],['keyPolicy','Key storage policy'],['serverKeys','Server keys (all devices)'],['awgProfile','AWG profile (all devices)']];
 for (const [key,label] of settings) {const field=importCheck(label);field.input.value=key;$('transfer-selection-settings').append(field.wrapper);}
 const existing=result.currentInventory;
 for (const a of result.incomingInventory.accounts) {
  const row=textElement('div','','account-row');row.append(textElement('strong',`${a.login} · ${a.role}`));
  const action=importSelect('Action',[['skip','Skip'],['add','Add'],['replace','Replace target'],['map','Map without changing target']]);
  const targets=existing.accounts.filter(x=>x.role===a.role);
  const target=importSelect('Target account',[]);
  const matched=existing.accounts.find(x=>x.id===a.id)||existing.accounts.find(x=>x.login===a.login&&x.role===a.role);if(matched)target.input.value=matched.id;
  const login=document.createElement('input');login.value=a.login;login.maxLength=64;const loginLabel=textElement('label','Imported login');loginLabel.append(login);
  const password=importCheck('Import password'),totp=importCheck('Import TOTP and recovery codes (absence disables TOTP)');
  const updateFields=()=>{
   const mode=action.input.value;target.input.disabled=!['replace','map'].includes(mode);
   if(!target.input.disabled&&!target.input.options.length) {for(const x of targets){const option=textElement('option',x.login);option.value=x.id;target.input.append(option);}if(matched)target.input.value=matched.id;}
   login.disabled=password.input.disabled=totp.input.disabled=['skip','map'].includes(mode);
  };
  action.input.addEventListener('change',updateFields);updateFields();
  row.append(action.wrapper,target.wrapper,loginLabel,password.wrapper,totp.wrapper);$('transfer-selection-accounts').append(row);
  accountChoices.push({id:a.id,action:action.input,target:target.input,login,password:password.input,totp:totp.input});
 }
 for (const d of result.incomingInventory.devices) {
  const row=textElement('div','','account-row');const owner=result.incomingInventory.accounts.find(a=>a.id===d.ownerId);
  row.append(textElement('strong',`${d.name} · ${owner?.login || d.ownerId}`));
  const action=importSelect('Action',[['skip','Skip'],['add','Add'],['replace','Replace target']]);
  const target=importSelect('Target device',existing.devices.map(x=>[x.id,x.name]));if(existing.devices.some(x=>x.id===d.id))target.input.value=d.id;
  const slot=document.createElement('input');slot.type='number';slot.min='2';slot.max='254';slot.value=d.slot;const slotLabel=textElement('label','VPN address slot');slotLabel.append(slot);
  row.append(action.wrapper,target.wrapper,slotLabel);$('transfer-selection-devices').append(row);
  deviceChoices.push({id:d.id,action:action.input,target:target.input,slot});
 }
 $('transfer-selection-form').hidden=false;
}
$('transfer-selection-form').addEventListener('input',()=>{transferSequence++;transferPending=null;$('transfer-confirm-form').hidden=true;$('transfer-confirm').checked=false;$('transfer-summary').replaceChildren();});
$('transfer-selection-form').addEventListener('submit',event=>{
 event.preventDefault();busy(event.submitter,async()=>{
  if(!transferInspection)throw new Error('Inspect the archive again.');
  const sequence=++transferSequence, inspected=transferInspection;
  const selection={settings:[...$('transfer-selection-settings').querySelectorAll('input:checked')].map(x=>x.value),
   accounts:accountChoices.filter(x=>x.action.value!=='skip').map(x=>({id:x.id,action:x.action.value,targetId:x.action.value==='add'?'':x.target.value,login:x.action.value==='map'?'':x.login.value,password:x.action.value==='map'?false:x.password.checked,totp:x.action.value==='map'?false:x.totp.checked})),
   devices:deviceChoices.filter(x=>x.action.value!=='skip').map(x=>({id:x.id,action:x.action.value,targetId:x.action.value==='add'?'':x.target.value,slot:Number(x.slot.value)})),
   clientKeys:$('transfer-selection-keys').checked,dropIncompatibleKeys:$('transfer-selection-drop').checked,acceptDisruption:$('transfer-selection-disruption').checked};
  const result=await api('/transfer/preview','POST',{...inspected,secret:$('transfer-import-secret').value,selection});
  if(sequence!==transferSequence||!csrf)return;
  transferInspection={archive:inspected.archive,ticket:result.ticket};
  showTransferPlan(result,inspected.archive,selection);
 });
});
$('transfer-confirm-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    if (!transferPending || !$('transfer-confirm').checked) throw new Error('Preview the archive and confirm replacement first.');
    const pending = transferPending, secret = $('transfer-import-secret').value;
    clearTransferSecrets();
    try {
      const result = await api('/transfer/import', 'POST', {...pending, secret, confirm:true});
      signedOut();
      notify(`Import complete. Sign in as ${result.login} with the credentials shown in the import plan${result.panelOrigin ? ' at ' + result.panelOrigin : ''}. Update DNS and stop the old VPN server when ready.`);
    } catch (error) {
      if (error.status) throw error;
      signedOut(); throw new Error('Connection interrupted during import. Check the destination and try signing in with the source credentials before attempting another import.');
    }
  });
});

$('my-devices').addEventListener('click', ownDevices);
$('brand').addEventListener('click', event => { event.preventDefault(); if (account && !pendingActions) ownDevices(); });
$('devices-back').addEventListener('click', () => busy($('devices-back'), openAccounts));


let networkTimer=null,networkAbort=null,networkSequence=0,networkChanges=0;
function stopNetworkPolling(){clearTimeout(networkTimer);networkTimer=null;networkSequence++;networkAbort?.abort();networkAbort=null;}
function renderNetworkStatus(status){
 if(!csrf||account?.role!=='superadmin')return;
 $('network-status').hidden=false;
 const state=networkChanges?'applying':status.state;
 const labels={applied:'VPN configuration applied',applying:'Applying VPN configuration…',error:status.restarting?'Application failed — service is restarting':'Network check failed',unknown:'Application status unavailable'};
 $('network-status-text').textContent=labels[state]||labels.unknown;
 $('network-reapply').disabled=state==='applying'||status.restarting||!$('network-reapply-confirm').checked;
 const details=[];
 if(status.lastApplied&&!status.lastApplied.startsWith('0001'))details.push('Last applied: '+new Date(status.lastApplied).toLocaleString());
 if(status.lastFailure&&!status.lastFailure.startsWith('0001'))details.push('Last failure: '+new Date(status.lastFailure).toLocaleString());
 if(state==='error')details.push(status.restarting?'Wait for the application to reload the saved configuration.':'Reapply the saved configuration or check server diagnostics.');
 if(state==='unknown')details.push('The result is not confirmed. Refresh after the service reconnects.');
 $('network-status-detail').textContent=details.join(' · ');
}
async function pollNetworkStatus(){
 if(!csrf||account?.role!=='superadmin'||networkAbort)return;
 const sequence=networkSequence,controller=new AbortController();networkAbort=controller;
 const timeout=setTimeout(()=>controller.abort(),4000);
 try {const result=await api('/network-status','GET',undefined,controller.signal);if(sequence===networkSequence)renderNetworkStatus(result);}
 catch {if(sequence===networkSequence)renderNetworkStatus({state:'unknown'});}
 finally {clearTimeout(timeout);if(networkAbort===controller)networkAbort=null;}
}
function startNetworkPolling(){
 stopNetworkPolling();if(account?.role!=='superadmin')return;
 const sequence=networkSequence;
 const tick=async()=>{await pollNetworkStatus();if(sequence===networkSequence&&csrf)networkTimer=setTimeout(tick,10000);};void tick();
}
$('network-reapply-confirm').addEventListener('change',()=>{void pollNetworkStatus();});
$('network-reapply').addEventListener('click',()=>busy($('network-reapply'),async()=>{
 if(!$('network-reapply-confirm').checked)throw new Error('Confirm the possible VPN interruption first.');
 try {const result=await api('/network-reapply','POST',{confirm:true});renderNetworkStatus(result);notify('Saved VPN configuration reapplied. Keys and settings were not changed.');}
 finally {$('network-reapply-confirm').checked=false;$('network-reapply-options').open=false;void pollNetworkStatus();}
}).finally(()=>{if(!$('network-reapply-confirm').checked)$('network-reapply').disabled=true;}));

load().catch(error => { signedOut(); if (error.message !== 'Authentication required') notify(error.message, true); });
