'use strict';

const $ = id => document.getElementById(id);
let csrf = '', peers = [], editing = null, deleting = null;
let shareSequence = 0;
const notify = (message, error = false) => {
  $('notice').textContent = message;
  $('notice').className = error ? 'notice error' : 'notice';
  $('notice').hidden = !message;
  const dialog = document.querySelector('dialog[open]');
  if (dialog) {
    let status = dialog.querySelector('.dialog-status');
    if (!status) { status = document.createElement('p'); status.setAttribute('role', 'status'); dialog.append(status); }
    status.className = `dialog-status notice${error ? ' error' : ''}`;
    status.textContent = message; status.hidden = !message;
  }
};
function signedOut() {
  csrf = ''; peers = []; $('devices').replaceChildren();
  $('dashboard').hidden = true; $('logout').hidden = true; $('login-view').hidden = false;
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  clearShare();
}
async function api(path, method = 'GET', body) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
  const response = await fetch(`/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', cache: 'no-store' });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== '/login') signedOut();
    throw new Error(data.error || 'Request failed');
  }
  return data;
}
async function busy(button, action) {
  button.disabled = true;
  try { await action(); } catch (error) { notify(error.message, true); }
  finally { button.disabled = false; }
}
async function load() {
  const session = await api('/session'); csrf = session.csrf;
  peers = await api('/peers');
  $('login-view').hidden = true; $('dashboard').hidden = false; $('logout').hidden = false;
  $('network-mode').textContent = session.ipv6 ? 'IPv4 + IPv6' : 'IPv4';
  $('endpoint').textContent = session.endpoint;
  render();
}
function button(text, handler, className = 'quiet') {
  const b = document.createElement('button'); b.textContent = text; b.className = className;
  b.addEventListener('click', () => busy(b, handler)); return b;
}
function textElement(tag, text, className = '') {
  const e = document.createElement(tag); e.textContent = text; e.className = className; return e;
}
function render() {
  $('device-count').textContent = peers.length;
  $('enabled-count').textContent = peers.filter(p => p.enabled).length;
  const query = $('search').value.toLowerCase(), group = $('filter').value;
  const visible = peers.filter(p => (group === 'all' || p.group === group) && `${p.name} ${p.address4} ${p.address6 || ''}`.toLowerCase().includes(query));
  $('empty').hidden = visible.length > 0;
  $('devices').replaceChildren(...visible.map(p => {
    const card = textElement('article', '', `device-card${p.enabled ? '' : ' paused'}`);
    const top = textElement('div', '', 'card-top');
    top.append(textElement('span', p.group === 'home' ? 'HOME' : 'GUEST', `badge ${p.group}`), textElement('span', p.enabled ? 'Enabled' : 'Disabled', 'small muted'));
    card.append(top, textElement('h2', p.name), textElement('p', p.address4, 'mono muted'));
    if (p.address6) card.append(textElement('p', p.address6, 'mono muted small'));
    const actions = textElement('div', '', 'card-actions');
    actions.append(button('Connect', () => share(p), 'primary'), button('Edit', () => edit(p)), button(p.enabled ? 'Disable' : 'Enable', async () => {
      await api(`/peers/${p.id}`, 'PATCH', { enabled: !p.enabled }); await load(); notify('Device updated.');
    }), button('Remove', () => { deleting = p.id; $('delete-description').textContent = `Remove “${p.name}” from your network?`; $('delete-dialog').showModal(); }, 'quiet danger-text'));
    card.append(actions); return card;
  }));
}
function edit(peer = null) {
  editing = peer?.id || null; $('device-title').textContent = peer ? 'Edit device' : 'Add device';
  $('device-name').value = peer?.name || ''; $('device-group').value = peer?.group || 'home';
  $('device-dialog').showModal(); notify(''); $('device-name').focus();
}
function clearShare() {
  shareSequence++; $('vpn-link').value = ''; $('qr').removeAttribute('src'); $('download').removeAttribute('href');
}
async function share(peer) {
  const sequence = ++shareSequence;
  const result = await api(`/peers/${peer.id}/link`);
  if (sequence !== shareSequence) return;
  $('share-title').textContent = `Connect ${peer.name}`; $('vpn-link').value = result.link;
  $('download').href = `/api/peers/${peer.id}/config`;
  $('qr').hidden = false; $('qr-error').hidden = true;
  $('qr').src = `/api/peers/${peer.id}/qr`;
  $('share-dialog').showModal();
}
$('qr').addEventListener('error', () => { $('qr').hidden = true; $('qr-error').hidden = false; });
$('share-dialog').addEventListener('close', clearShare);
$('copy-link').addEventListener('click', () => busy($('copy-link'), async () => {
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
    const result = await api('/login', 'POST', { password: $('password').value });
    csrf = result.csrf; $('password').value = ''; notify(''); await load();
  });
});
$('logout').addEventListener('click', () => busy($('logout'), async () => { await api('/logout', 'POST'); signedOut(); notify('Signed out.'); }));
$('device-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    await api(editing ? `/peers/${editing}` : '/peers', editing ? 'PATCH' : 'POST', { name: $('device-name').value.trim(), group: $('device-group').value });
    $('device-dialog').close(); await load(); notify('Device saved.');
  });
});
$('delete-form').addEventListener('submit', event => {
  event.preventDefault(); busy(event.submitter, async () => {
    await api(`/peers/${deleting}`, 'DELETE'); $('delete-dialog').close(); await load(); notify('Device removed.');
  });
});
$('add').addEventListener('click', () => edit());
$('refresh').addEventListener('click', () => busy($('refresh'), load));
$('search').addEventListener('input', render); $('filter').addEventListener('change', render);
for (const b of document.querySelectorAll('.close-dialog')) b.addEventListener('click', () => b.closest('dialog').close());
try { document.documentElement.dataset.theme = localStorage.getItem('awg-theme') || ''; } catch (_) { /* Storage may be disabled. */ }
$('theme').addEventListener('click', () => {
  const current = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = next;
  try { localStorage.setItem('awg-theme', next); } catch (_) { /* Theme still works for this page. */ }
});
load().catch(error => { signedOut(); if (error.message !== 'Authentication required') notify(error.message, true); });
