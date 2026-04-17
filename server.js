'use strict';

const express  = require('express');
const fetch    = require('node-fetch');
const bcrypt   = require('bcryptjs');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Outreach app credentials (set in Render dashboard, never in client) ──────
const OUTREACH_CLIENT_ID     = process.env.OUTREACH_CLIENT_ID;
const OUTREACH_CLIENT_SECRET = process.env.OUTREACH_CLIENT_SECRET;
const OUTREACH_REDIRECT_URI  = process.env.OUTREACH_REDIRECT_URI;

if (!OUTREACH_CLIENT_ID || !OUTREACH_CLIENT_SECRET || !OUTREACH_REDIRECT_URI) {
  console.warn('[WARN] OUTREACH_CLIENT_ID / OUTREACH_CLIENT_SECRET / OUTREACH_REDIRECT_URI not set — OAuth will fail');
}

// ── Constants ────────────────────────────────────────────────────────────────
const OUTREACH_BASE   = 'https://api.outreach.io';
const OUTREACH_ACCEPT = 'application/vnd.api+json';
const SR_API_BASE     = 'https://api.boomtechinc.com';
const SR_APP_BASE     = 'https://app.boomtechinc.com';
const POLL_INTERVAL_MS = 30 * 60 * 1000; // 30 minutes

// LinkedIn task types in Outreach
const LINKEDIN_TASK_TYPES = new Set([
  'sequence_step_linkedin_send_connection_request',
  'sequence_step_linkedin_send_message',
  'sequence_step_linkedin_view_profile',
  'sequence_step_linkedin_interact_with_post',
  'sequence_step_linkedin_other',
]);

// Connect request types → connect campaign in SalesRobot
const CONNECT_TASK_TYPES = new Set([
  'sequence_step_linkedin_send_connection_request',
]);

// ── File paths ────────────────────────────────────────────────────────────────
const PROFILES_FILE     = path.join(__dirname, 'profiles.json');
const HISTORY_FILE      = path.join(__dirname, 'history.json');
const SYNCED_TASKS_FILE = path.join(__dirname, 'synced_tasks.json');
const LOG_FILE          = path.join(__dirname, 'sync.log');

// ── Helpers ───────────────────────────────────────────────────────────────────
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function log(tag, data) {
  const line = `[${new Date().toISOString()}] [${tag}] ${JSON.stringify(data)}\n`;
  process.stdout.write(line);
  fs.appendFileSync(LOG_FILE, line);
}

// Parse JSON:API response body; return null on non-JSON
async function safeJson(r) {
  const text = await r.text();
  if (!text || !text.trim()) return null;
  try { return JSON.parse(text); } catch { return null; }
}

// Pending OAuth state map: stateKey → { done, accessToken, refreshToken, expiresAt, error }
const pendingOAuth = {};

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Request logger
app.use((req, _res, next) => {
  log('REQ', { method: req.method, path: req.path });
  next();
});

// ── Outreach OAuth ────────────────────────────────────────────────────────────

// Let the frontend know whether env vars are configured
app.get('/api/config', (_req, res) => {
  res.json({ configured: !!(OUTREACH_CLIENT_ID && OUTREACH_CLIENT_SECRET && OUTREACH_REDIRECT_URI) });
});

// Debug: shows partial credentials so you can verify the right values are loaded (safe — secret is masked)
app.get('/api/debug/config', (_req, res) => {
  res.json({
    clientId:     OUTREACH_CLIENT_ID    ? `${OUTREACH_CLIENT_ID.slice(0,6)}…(len ${OUTREACH_CLIENT_ID.length})`    : 'NOT SET',
    clientSecret: OUTREACH_CLIENT_SECRET ? `${OUTREACH_CLIENT_SECRET.slice(0,4)}…(len ${OUTREACH_CLIENT_SECRET.length})` : 'NOT SET',
    redirectUri:  OUTREACH_REDIRECT_URI  || 'NOT SET',
  });
});

// Step 1 — frontend calls this to get the authorization URL
app.post('/api/oauth/initiate', (_req, res) => {
  if (!OUTREACH_CLIENT_ID || !OUTREACH_REDIRECT_URI) {
    return res.status(500).json({ error: 'Server not configured — set OUTREACH_CLIENT_ID and OUTREACH_REDIRECT_URI env vars in Render' });
  }
  const state = crypto.randomUUID();
  pendingOAuth[state] = { done: false };

  const scopes = 'tasks.all prospects.read users.read';
  const url = `${OUTREACH_BASE}/oauth/authorize` +
    `?client_id=${encodeURIComponent(OUTREACH_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(OUTREACH_REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&state=${encodeURIComponent(state)}`;

  res.json({ url, state });
});

// Step 2 — Outreach redirects here; server completes the exchange with its secret
app.get('/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.send(oauthPopupHtml({ error }));
  }
  if (!code || !state) {
    return res.send(oauthPopupHtml({ error: 'Missing code or state from Outreach' }));
  }

  try {
    // Send credentials both in Basic Auth header and body — Outreach accepts either
    const basicAuth = Buffer.from(`${OUTREACH_CLIENT_ID}:${OUTREACH_CLIENT_SECRET}`).toString('base64');
    const r = await fetch(`${OUTREACH_BASE}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basicAuth}`,
      },
      body: new URLSearchParams({
        client_id:     OUTREACH_CLIENT_ID,
        client_secret: OUTREACH_CLIENT_SECRET,
        redirect_uri:  OUTREACH_REDIRECT_URI,
        grant_type:    'authorization_code',
        code,
      }).toString(),
    });
    const data = await safeJson(r);
    log('OAUTH_TOKEN_EXCHANGE', { status: r.status, hasAccessToken: !!data?.access_token, error: data?.error, errorDesc: data?.error_description, redirectUri: OUTREACH_REDIRECT_URI, clientIdPrefix: OUTREACH_CLIENT_ID?.slice(0,6) });
    if (!r.ok || !data?.access_token) {
      throw new Error(data?.error_description || data?.error || `HTTP ${r.status}`);
    }
    const expiresAt = new Date(Date.now() + (data.expires_in - 120) * 1000).toISOString();
    const payload = { accessToken: data.access_token, refreshToken: data.refresh_token, expiresAt };

    // Store for redirect-flow fallback (popup-blocked browsers)
    pendingOAuth[state] = { done: true, ...payload };

    log('OAUTH_CALLBACK_OK', { state });
    res.send(oauthPopupHtml({ ...payload, state }));
  } catch (e) {
    log('OAUTH_CALLBACK_ERROR', { error: e.message });
    res.send(oauthPopupHtml({ error: e.message }));
  }
});

// Fallback: frontend polls this if popup was blocked and page redirected instead
app.get('/api/oauth/result/:state', (req, res) => {
  const p = pendingOAuth[req.params.state];
  if (!p) return res.status(404).json({ error: 'Unknown or expired state' });
  if (!p.done) return res.status(202).json({ pending: true });
  const { accessToken, refreshToken, expiresAt } = p;
  delete pendingOAuth[req.params.state];
  res.json({ accessToken, refreshToken, expiresAt });
});

// Popup HTML — postMessages result to opener, falls back to redirect
function oauthPopupHtml({ error, accessToken, refreshToken, expiresAt, state }) {
  if (error) {
    const msg = JSON.stringify({ type: 'outreach_oauth_error', error });
    return `<!DOCTYPE html><html><body><p style="font-family:sans-serif;padding:2rem">Authorization failed: ${error}</p><script>
      if(window.opener){window.opener.postMessage(${msg},'*');window.close();}
    </script></body></html>`;
  }
  const msg = JSON.stringify({ type: 'outreach_oauth_success', accessToken, refreshToken, expiresAt });
  return `<!DOCTYPE html><html><body><p style="font-family:sans-serif;padding:2rem">Connected! You can close this window.</p><script>
    if(window.opener){window.opener.postMessage(${msg},'*');window.close();}
    else{location.href='/?oauth_state='+encodeURIComponent(${JSON.stringify(state || '')});}
  </script></body></html>`;
}

// Refresh tokens using server-side credentials (no client secret stored in profiles)
async function refreshOutreachToken(profile) {
  if (!profile.outreachRefreshToken) throw new Error('No refresh token stored — user must reconnect Outreach');
  const basicAuth = Buffer.from(`${OUTREACH_CLIENT_ID}:${OUTREACH_CLIENT_SECRET}`).toString('base64');
  const r = await fetch(`${OUTREACH_BASE}/oauth/token`, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basicAuth}`,
    },
    body: new URLSearchParams({
      client_id:     OUTREACH_CLIENT_ID,
      client_secret: OUTREACH_CLIENT_SECRET,
      redirect_uri:  OUTREACH_REDIRECT_URI,
      grant_type:    'refresh_token',
      refresh_token: profile.outreachRefreshToken,
    }).toString(),
  });
  const data = await safeJson(r);
  if (!r.ok || !data?.access_token) throw new Error(data?.error_description || 'Token refresh failed');
  const expiresAt = new Date(Date.now() + (data.expires_in - 120) * 1000).toISOString();
  return { accessToken: data.access_token, refreshToken: data.refresh_token || profile.outreachRefreshToken, expiresAt };
}

// Get a valid Outreach access token for a profile (refresh if needed), mutate profile in place
async function getValidToken(profile) {
  if (!profile.outreachTokenExpiry || new Date(profile.outreachTokenExpiry) < new Date()) {
    log('TOKEN_REFRESH', { profileId: profile.id });
    const { accessToken, refreshToken, expiresAt } = await refreshOutreachToken(profile);
    profile.outreachAccessToken  = accessToken;
    profile.outreachRefreshToken = refreshToken;
    profile.outreachTokenExpiry  = expiresAt;
    // Persist refresh
    const profiles = readJson(PROFILES_FILE, []);
    const idx = profiles.findIndex(p => p.id === profile.id);
    if (idx >= 0) {
      profiles[idx].outreachAccessToken  = accessToken;
      profiles[idx].outreachRefreshToken = refreshToken;
      profiles[idx].outreachTokenExpiry  = expiresAt;
      writeJson(PROFILES_FILE, profiles);
    }
  }
  return profile.outreachAccessToken;
}

// ── Outreach API helpers ──────────────────────────────────────────────────────

function outreachHeaders(token) {
  return {
    'Authorization': `Bearer ${token}`,
    'Accept': OUTREACH_ACCEPT,
    'Content-Type': OUTREACH_ACCEPT,
  };
}

// Fetch all incomplete LinkedIn tasks for a user (cursor-paginated)
async function fetchOutreachLinkedInTasks(token, outreachUserId) {
  const allTasks = [];
  const prospectMap = {}; // id → attributes
  const PAGE_SIZE = 100;
  const MAX_PAGES = 20;

  // No server-side filters — Outreach filter syntax is strict; filter client-side
  let nextUrl = `${OUTREACH_BASE}/api/v2/tasks` +
    `?include=prospect` +
    `&page[size]=${PAGE_SIZE}`;

  let page = 0;
  const allTaskTypes = new Set();

  while (nextUrl && page < MAX_PAGES) {
    page++;
    const r = await fetch(nextUrl, { headers: outreachHeaders(token) });
    const data = await safeJson(r);
    if (!r.ok || !data) {
      log('OUTREACH_TASKS_RAW_ERROR', { status: r.status, body: data });
      throw new Error(`Outreach tasks error (HTTP ${r.status})`);
    }

    // Collect included prospects
    for (const inc of (data.included || [])) {
      if (inc.type === 'prospect') prospectMap[inc.id] = inc.attributes || {};
    }

    const pageTasks = data.data || [];
    log('OUTREACH_TASKS_PAGE', { page, count: pageTasks.length, userId: outreachUserId });

    for (const task of pageTasks) {
      const tt    = task.attributes?.taskType;
      const state = task.attributes?.state;
      if (tt) allTaskTypes.add(tt);

      // Client-side filters: incomplete only, LinkedIn types only, current user only
      if (state === 'complete' || state === 'completed') continue;
      if (!LINKEDIN_TASK_TYPES.has(tt)) continue;
      const taskOwnerId = String(task.relationships?.assignee?.data?.id || '');
      if (outreachUserId && taskOwnerId !== String(outreachUserId)) continue;

      const prospectId = task.relationships?.prospect?.data?.id;
      allTasks.push({ task, prospect: prospectMap[prospectId] || null, prospectId });
    }

    nextUrl = data.links?.next || null;
  }

  log('OUTREACH_TASKS_TYPES_SEEN', { types: [...allTaskTypes], linkedInMatches: allTasks.length });
  return allTasks;
}

// Raw debug: fetch first page of tasks with no filters — shows real task types from Outreach
app.post('/api/debug/raw-tasks', async (req, res) => {
  const { accessToken, outreachUserId } = req.body;
  if (!accessToken) return res.status(400).json({ error: 'accessToken required' });
  try {
    // Two fetches: one unfiltered, one with user filter — to see if user filter is working
    const urlNoFilter  = `${OUTREACH_BASE}/api/v2/tasks?page[size]=5`;
    const urlWithUser  = null;

    const r1 = await fetch(urlNoFilter, { headers: outreachHeaders(accessToken) });
    const d1 = await safeJson(r1);

    const r2 = urlWithUser ? await fetch(urlWithUser, { headers: outreachHeaders(accessToken) }) : null;
    const d2 = r2 ? await safeJson(r2) : null;

    const tasks1 = (d1?.data || []).map(t => ({ id: t.id, taskType: t.attributes?.taskType, state: t.attributes?.state }));
    const tasks2 = (d2?.data || []).map(t => ({ id: t.id, taskType: t.attributes?.taskType, state: t.attributes?.state }));

    res.json({
      noFilter:   { status: r1.status, count: tasks1.length, taskTypes: [...new Set(tasks1.map(t => t.taskType))], sample: tasks1.slice(0,5) },
      withUser:   r2 ? { status: r2.status, count: tasks2.length, taskTypes: [...new Set(tasks2.map(t => t.taskType))], sample: tasks2.slice(0,5) } : 'no userId provided',
      ourLinkedInTypes: [...LINKEDIN_TASK_TYPES],
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Detect org users from tasks
app.post('/api/outreach/detect-users', async (req, res) => {
  const { accessToken } = req.body;
  if (!accessToken) return res.status(400).json({ error: 'accessToken required' });

  try {
    // Fetch page 1 of tasks (no owner filter) to collect unique user IDs
    const r = await fetch(
      `${OUTREACH_BASE}/api/v2/tasks?page[size]=100&fields[task]=taskType&include=owner&fields[user]=firstName,lastName,email`,
      { headers: outreachHeaders(accessToken) }
    );
    const data = await safeJson(r);
    if (!r.ok || !data) return res.status(400).json({ error: `Outreach error (HTTP ${r.status})` });

    const userMap = {};
    for (const inc of (data.included || [])) {
      if (inc.type === 'user') {
        const a = inc.attributes || {};
        userMap[inc.id] = {
          id: String(inc.id),
          name: [a.firstName, a.lastName].filter(Boolean).join(' ') || String(inc.id),
          email: a.email || '',
        };
      }
    }
    // Also collect from task owner relationships
    for (const task of (data.data || [])) {
      const ownerId = task.relationships?.owner?.data?.id;
      if (ownerId && !userMap[ownerId]) {
        userMap[ownerId] = { id: String(ownerId), name: String(ownerId), email: '' };
      }
    }

    const users = Object.values(userMap);
    log('DETECT_USERS', { count: users.length });
    res.json({ users });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Fetch incomplete LinkedIn tasks for the current user
app.post('/api/outreach/tasks', async (req, res) => {
  const { accessToken, outreachUserId } = req.body;
  if (!accessToken) return res.status(400).json({ error: 'accessToken required' });
  if (!outreachUserId) return res.status(400).json({ error: 'outreachUserId required — select your user first' });

  try {
    const items = await fetchOutreachLinkedInTasks(accessToken, outreachUserId);

    // Build clean task list for the frontend
    const tasks = items.map(({ task, prospect }) => {
      const a  = task.attributes || {};
      const p  = prospect || {};
      const li = p.linkedInUrl || '';
      const email  = Array.isArray(p.emails) ? (p.emails[0]?.email || '') : '';
      const phone  = Array.isArray(p.mobilePhones) ? (p.mobilePhones[0] || '') :
                     Array.isArray(p.workPhones)   ? (p.workPhones[0]   || '') : '';
      return {
        id: String(task.id),
        taskType: a.taskType,
        isConnect: CONNECT_TASK_TYPES.has(a.taskType),
        dueAt: a.dueAt,
        note: a.note || '',
        prospect: {
          linkedInUrl: li,
          firstName: p.firstName || '',
          lastName: p.lastName || '',
          fullName: [p.firstName, p.lastName].filter(Boolean).join(' '),
          jobTitle: p.title || p.occupation || '',
          companyName: p.company || '',
          emailId: email,
          phoneNo: phone,
        },
      };
    });

    log('OUTREACH_TASKS', { total: tasks.length, outreachUserId });
    res.json({ tasks });
  } catch (e) {
    log('OUTREACH_TASKS_ERROR', { error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// Mark a task complete in Outreach
app.post('/api/outreach/complete-task', async (req, res) => {
  const { accessToken, taskId } = req.body;
  if (!accessToken || !taskId) return res.status(400).json({ error: 'accessToken and taskId required' });

  try {
    const r = await fetch(`${OUTREACH_BASE}/api/v2/tasks/${taskId}/actions/markComplete`, {
      method: 'POST',
      headers: outreachHeaders(accessToken),
    });
    const data = await safeJson(r);
    if (!r.ok) {
      log('MARK_COMPLETE_ERROR', { taskId, status: r.status, data });
      return res.status(r.status).json({ error: data?.errors?.[0]?.detail || `HTTP ${r.status}` });
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── SalesRobot API ────────────────────────────────────────────────────────────

app.post('/api/salesrobot/accounts', async (req, res) => {
  const { srKey } = req.body;
  if (!srKey) return res.status(400).json({ error: 'srKey required' });

  try {
    const r = await fetch(`${SR_API_BASE}/api/linkedinAccounts?page=1&size=50&searchTerm=&sort=id,desc`, {
      headers: { 'x-api-key': srKey },
    });
    const raw = await r.text();
    log('RAW_RESPONSE', { status: r.status, url: r.url, body: raw.slice(0, 500) });
    if (!r.ok) return res.status(r.status).json({ error: `SalesRobot error (HTTP ${r.status})` });
    let data;
    try { data = JSON.parse(raw); } catch { return res.status(502).json({ error: 'Invalid JSON from SalesRobot' }); }
    if (!data?.success) return res.status(400).json({ error: data?.message || 'SalesRobot accounts failed' });

    const accounts = (data.data?.data || []).map(a => ({
      uuid: a.linkedinAccountUuid,
      name: a.nameOnLinkedinAccount || a.profileUrl,
      profileUrl: a.profileUrl,
      profilePicUrl: a.profilePicUrl || '',
      cookieExpired: a.cookieExpired || false,
    }));
    res.json({ accounts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/salesrobot/campaigns', async (req, res) => {
  const { srKey, linkedinAccountUuid } = req.body;
  if (!srKey || !linkedinAccountUuid) return res.status(400).json({ error: 'srKey and linkedinAccountUuid required' });

  try {
    const allCampaigns = [];
    let page = 1;
    const SIZE = 50;
    let totalFetched = 0;
    let totalElements = Infinity;

    while (totalFetched < totalElements) {
      const r = await fetch(`${SR_APP_BASE}/api/campaigns?linkedinAccountUuid=${linkedinAccountUuid}&page=${page}&size=${SIZE}`, {
        headers: { 'x-api-key': srKey },
      });
      const raw = await r.text();
      log('RAW_RESPONSE', { status: r.status, url: r.url, body: raw.slice(0, 500) });
      if (!r.ok) return res.status(r.status).json({ error: `SalesRobot error (HTTP ${r.status})` });
      let data;
      try { data = JSON.parse(raw); } catch { return res.status(502).json({ error: 'Invalid JSON from SalesRobot' }); }
      if (!data?.success) return res.status(400).json({ error: data?.message || 'Campaigns fetch failed' });

      const campaigns = data.data?.data || [];
      if (!campaigns.length) break;
      allCampaigns.push(...campaigns);
      totalFetched += campaigns.length;
      totalElements = data.data?.totalElements || totalFetched;
      page++;
    }

    const out = allCampaigns.map(c => ({
      uuid: c.uuid,
      name: c.name,
      status: c.campaignStatus,
    }));
    log('CAMPAIGNS_FETCHED', { total: out.length });
    res.json({ campaigns: out });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/salesrobot/add-prospect', async (req, res) => {
  const { srKey, campaignUuid, linkedinAccountUuid, prospect } = req.body;
  if (!srKey || !campaignUuid || !linkedinAccountUuid || !prospect) {
    return res.status(400).json({ error: 'srKey, campaignUuid, linkedinAccountUuid, prospect required' });
  }
  if (!prospect.linkedInUrl) {
    return res.status(400).json({ error: 'Prospect has no LinkedIn URL — cannot add to SalesRobot' });
  }

  log('ADD_PROSPECT', { campaignUuid, linkedinAccountUuid, prospect });

  try {
    const r = await fetch(
      `${SR_API_BASE}/api/add-single-prospect?campaignUuid=${campaignUuid}&linkedinAccountUuid=${linkedinAccountUuid}`,
      {
        method: 'POST',
        headers: { 'x-api-key': srKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profileUrl: prospect.linkedInUrl,
          firstName: prospect.firstName,
          lastName: prospect.lastName,
          fullName: prospect.fullName,
          emailId: prospect.emailId || '',
          jobTitle: prospect.jobTitle || '',
          companyName: prospect.companyName || '',
          phoneNo: prospect.phoneNo || '',
          profilePhoto: '',
          salesNavUrl: null,
        }),
      }
    );

    const raw = await r.text();
    log('SR_RESPONSE', { status: r.status, body: raw.slice(0, 200) });

    // SalesRobot returns plain "Ok" or JSON — treat 2xx as success
    if (r.ok) {
      let parsed = null;
      try { parsed = JSON.parse(raw); } catch { /* plain text */ }
      return res.json({ success: true, message: parsed?.message || raw || 'Ok' });
    }
    let errMsg = raw;
    try { errMsg = JSON.parse(raw)?.message || raw; } catch { /* keep raw */ }
    res.status(r.status).json({ error: errMsg });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Profiles ─────────────────────────────────────────────────────────────────

app.get('/api/profiles', (_req, res) => {
  const profiles = readJson(PROFILES_FILE, []);
  res.json({ profiles: profiles.map(p => ({ id: p.id, name: p.name })) });
});

app.post('/api/profiles', async (req, res) => {
  const {
    name, password, srKey,
    outreachAccessToken, outreachRefreshToken, outreachTokenExpiry,
    outreachUserId, outreachUserName,
  } = req.body;

  if (!name || !password || !srKey || !outreachAccessToken) {
    return res.status(400).json({ error: 'name, password, srKey, and Outreach connection are required' });
  }

  const profiles = readJson(PROFILES_FILE, []);
  const id = 'p' + Date.now();
  const passwordHash = bcrypt.hashSync(password, 10);

  profiles.push({
    id, name: name.trim(), passwordHash,
    srKey,
    outreachAccessToken,
    outreachRefreshToken: outreachRefreshToken || null,
    outreachTokenExpiry: outreachTokenExpiry || null,
    outreachUserId: outreachUserId || null,
    outreachUserName: outreachUserName || null,
  });
  writeJson(PROFILES_FILE, profiles);
  log('PROFILE_SAVED', { id, name: name.trim(), outreachUserId });
  res.json({ success: true, id, name: name.trim() });
});

app.post('/api/profiles/:id/unlock', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const profiles = readJson(PROFILES_FILE, []);
  const p = profiles.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Profile not found' });
  if (!bcrypt.compareSync(password, p.passwordHash)) {
    return res.status(401).json({ error: 'Incorrect password' });
  }
  log('PROFILE_UNLOCKED', { id: p.id, name: p.name });
  res.json({
    srKey: p.srKey,
    outreachAccessToken: p.outreachAccessToken || null,
    outreachRefreshToken: p.outreachRefreshToken || null,
    outreachTokenExpiry: p.outreachTokenExpiry || null,
    outreachUserId: p.outreachUserId || null,
    outreachUserName: p.outreachUserName || null,
  });
});

// Refresh token and return new access token for an unlocked session
app.post('/api/profiles/:id/refresh-token', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const profiles = readJson(PROFILES_FILE, []);
  const p = profiles.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Profile not found' });
  if (!bcrypt.compareSync(password, p.passwordHash)) return res.status(401).json({ error: 'Incorrect password' });
  if (!p.outreachRefreshToken) return res.status(400).json({ error: 'No refresh token stored — reconnect Outreach' });

  try {
    const tokens = await refreshOutreachToken(p);
    p.outreachAccessToken  = tokens.accessToken;
    p.outreachRefreshToken = tokens.refreshToken;
    p.outreachTokenExpiry  = tokens.expiresAt;
    writeJson(PROFILES_FILE, profiles);
    log('TOKEN_REFRESHED_MANUAL', { id: p.id });
    res.json({ accessToken: tokens.accessToken, expiresAt: tokens.expiresAt });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/profiles/:id', (req, res) => {
  const { password, outreachUserId, outreachUserName, outreachAccessToken, outreachRefreshToken, outreachTokenExpiry } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const profiles = readJson(PROFILES_FILE, []);
  const p = profiles.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Profile not found' });
  if (!bcrypt.compareSync(password, p.passwordHash)) return res.status(401).json({ error: 'Incorrect password' });

  if (outreachUserId    !== undefined) p.outreachUserId    = outreachUserId    || null;
  if (outreachUserName  !== undefined) p.outreachUserName  = outreachUserName  || null;
  if (outreachAccessToken  !== undefined) p.outreachAccessToken  = outreachAccessToken  || null;
  if (outreachRefreshToken !== undefined) p.outreachRefreshToken = outreachRefreshToken || null;
  if (outreachTokenExpiry  !== undefined) p.outreachTokenExpiry  = outreachTokenExpiry  || null;
  writeJson(PROFILES_FILE, profiles);
  log('PROFILE_UPDATED', { id: p.id, name: p.name, outreachUserId });
  res.json({ success: true });
});

app.delete('/api/profiles/:id', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  let profiles = readJson(PROFILES_FILE, []);
  const p = profiles.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Profile not found' });
  if (!bcrypt.compareSync(password, p.passwordHash)) return res.status(401).json({ error: 'Incorrect password' });
  profiles = profiles.filter(x => x.id !== req.params.id);
  writeJson(PROFILES_FILE, profiles);
  log('PROFILE_DELETED', { id: req.params.id });
  res.json({ success: true });
});

// ── Auto-sync toggle ──────────────────────────────────────────────────────────

app.post('/api/profiles/:id/autosync', (req, res) => {
  const { enable, connectCampaignUuid, messageCampaignUuid, linkedinAccountUuid,
          connectCampaignName, messageCampaignName, linkedinAccountName } = req.body;
  const profiles = readJson(PROFILES_FILE, []);
  const p = profiles.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Profile not found' });

  p.autoSync = !!enable;
  if (enable) {
    p.connectCampaignUuid  = connectCampaignUuid;
    p.messageCampaignUuid  = messageCampaignUuid;
    p.linkedinAccountUuid  = linkedinAccountUuid;
    p.connectCampaignName  = connectCampaignName || '';
    p.messageCampaignName  = messageCampaignName || '';
    p.linkedinAccountName  = linkedinAccountName || '';
    log('AUTOSYNC_ENABLED', { id: p.id, connectCampaignName, messageCampaignName });
  } else {
    log('AUTOSYNC_DISABLED', { id: p.id });
  }
  writeJson(PROFILES_FILE, profiles);
  res.json({ success: true, autoSync: p.autoSync });
});

app.get('/api/autosync/status', (_req, res) => {
  const profiles = readJson(PROFILES_FILE, []);
  const active = profiles.filter(p => p.autoSync).map(p => ({
    id: p.id,
    name: p.name,
    connectCampaignName: p.connectCampaignName || '',
    messageCampaignName: p.messageCampaignName || '',
    ...autoSyncStatus[p.id],
  }));
  res.json({ status: active });
});

// ── History ───────────────────────────────────────────────────────────────────

app.get('/api/history', (_req, res) => {
  const runs = readJson(HISTORY_FILE, []);
  res.json({ runs: runs.slice().reverse().slice(0, 100) });
});

app.post('/api/history', (req, res) => {
  const { profileName, linkedinAccountName, connectCampaign, messageCampaign, results } = req.body;
  if (!results) return res.status(400).json({ error: 'results required' });
  const runs = readJson(HISTORY_FILE, []);
  const succeeded = results.filter(r => r.success).length;
  const run = {
    id: 'h' + Date.now(),
    timestamp: new Date().toISOString(),
    profileName: profileName || 'Unknown',
    linkedinAccountName: linkedinAccountName || '',
    connectCampaign: connectCampaign || '',
    messageCampaign: messageCampaign || '',
    total: results.length,
    succeeded,
    failed: results.length - succeeded,
    results,
  };
  runs.push(run);
  writeJson(HISTORY_FILE, runs);
  log('HISTORY_SAVED', { id: run.id, total: run.total, succeeded, failed: run.failed });
  res.json({ success: true, id: run.id });
});

// ── Auto-sync engine ──────────────────────────────────────────────────────────

const autoSyncStatus = {};

async function runAutoSyncForProfile(profile) {
  if (autoSyncStatus[profile.id]?.running) return;
  autoSyncStatus[profile.id] = { ...autoSyncStatus[profile.id], running: true };
  log('AUTOSYNC_START', { profileId: profile.id, name: profile.name });

  try {
    if (!profile.outreachUserId) {
      log('AUTOSYNC_SKIP', { profileId: profile.id, reason: 'no outreachUserId set — unlock profile and select your Outreach user' });
      autoSyncStatus[profile.id] = { lastRun: new Date().toISOString(), lastCount: 0, running: false, error: 'Outreach user not selected' };
      return;
    }
    if (!profile.outreachAccessToken) {
      log('AUTOSYNC_SKIP', { profileId: profile.id, reason: 'no Outreach token — reconnect profile' });
      autoSyncStatus[profile.id] = { lastRun: new Date().toISOString(), lastCount: 0, running: false, error: 'No Outreach token' };
      return;
    }

    // Refresh token if needed
    const token = await getValidToken(profile);

    // Load already-synced task IDs
    const syncedTasks = readJson(SYNCED_TASKS_FILE, {});
    const syncedSet = new Set(Object.keys(syncedTasks));

    // Fetch tasks
    const items = await fetchOutreachLinkedInTasks(token, profile.outreachUserId);
    const newItems = items.filter(({ task }) => !syncedSet.has(String(task.id)));

    log('AUTOSYNC_NEW_TASKS', { profileId: profile.id, total: items.length, new: newItems.length });

    const results = [];
    for (const { task, prospect } of newItems) {
      const taskId  = String(task.id);
      const taskType = task.attributes?.taskType;
      const isConnect = CONNECT_TASK_TYPES.has(taskType);
      const campaignUuid = isConnect ? profile.connectCampaignUuid : profile.messageCampaignUuid;

      if (!prospect?.linkedInUrl) {
        results.push({ taskId, success: false, error: 'No LinkedIn URL on prospect' });
        continue;
      }
      if (!campaignUuid) {
        results.push({ taskId, success: false, error: `No ${isConnect ? 'connect' : 'message'} campaign configured` });
        continue;
      }

      try {
        const r = await fetch(
          `${SR_API_BASE}/api/add-single-prospect?campaignUuid=${campaignUuid}&linkedinAccountUuid=${profile.linkedinAccountUuid}`,
          {
            method: 'POST',
            headers: { 'x-api-key': profile.srKey, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              profileUrl: prospect.linkedInUrl,
              firstName: prospect.firstName || '',
              lastName: prospect.lastName || '',
              fullName: [prospect.firstName, prospect.lastName].filter(Boolean).join(' '),
              emailId: (Array.isArray(prospect.emails) ? prospect.emails[0]?.email : '') || '',
              jobTitle: prospect.title || '',
              companyName: prospect.company || '',
              phoneNo: '',
              profilePhoto: '',
              salesNavUrl: null,
            }),
          }
        );
        const raw = await r.text();
        if (!r.ok) throw new Error(`SalesRobot HTTP ${r.status}: ${raw}`);

        // Mark complete in Outreach
        try {
          await fetch(`${OUTREACH_BASE}/api/v2/tasks/${taskId}/actions/markComplete`, {
            method: 'POST',
            headers: outreachHeaders(token),
          });
        } catch (e) {
          log('MARK_COMPLETE_FAIL', { taskId, error: e.message });
        }

        syncedTasks[taskId] = { syncedAt: new Date().toISOString(), campaignUuid };
        results.push({ taskId, success: true });
      } catch (e) {
        log('AUTOSYNC_TASK_ERROR', { taskId, error: e.message });
        results.push({ taskId, success: false, error: e.message });
      }
    }

    writeJson(SYNCED_TASKS_FILE, syncedTasks);

    const succeeded = results.filter(r => r.success).length;
    if (results.length > 0) {
      const runs = readJson(HISTORY_FILE, []);
      runs.push({
        id: 'h' + Date.now(),
        timestamp: new Date().toISOString(),
        profileName: profile.name,
        linkedinAccountName: profile.linkedinAccountName || '',
        connectCampaign: profile.connectCampaignName || '',
        messageCampaign: profile.messageCampaignName || '',
        total: results.length,
        succeeded,
        failed: results.length - succeeded,
        results,
        auto: true,
      });
      writeJson(HISTORY_FILE, runs);
    }

    autoSyncStatus[profile.id] = {
      lastRun: new Date().toISOString(),
      lastCount: succeeded,
      running: false,
      error: null,
    };
    log('AUTOSYNC_DONE', { profileId: profile.id, synced: succeeded, failed: results.length - succeeded });
  } catch (e) {
    log('AUTOSYNC_ERROR', { profileId: profile.id, error: e.message });
    autoSyncStatus[profile.id] = { lastRun: new Date().toISOString(), lastCount: 0, running: false, error: e.message };
  }
}

async function runAutoSync() {
  const profiles = readJson(PROFILES_FILE, []);
  const active = profiles.filter(p => p.autoSync);
  if (active.length) log('AUTOSYNC_POLL', { activeProfiles: active.length });
  for (const profile of active) {
    await runAutoSyncForProfile(profile);
  }
}

setInterval(runAutoSync, POLL_INTERVAL_MS);
setTimeout(runAutoSync, 60_000);

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  const line = `Outreach → SalesRobot sync running on http://localhost:${PORT}\n`;
  process.stdout.write(line);
  fs.appendFileSync(LOG_FILE, line);
});
