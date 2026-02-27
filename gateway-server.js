/**
 * LIONO Gateway Server — Protocol v3
 *
 * Real AI gateway with OpenRouter LLM and tool/skill execution.
 *
 * Protocol:
 *   1. Server sends event: connect.challenge (with nonce)
 *   2. Client sends req: connect (with auth token, client info)
 *   3. Server sends res: hello-ok (with features, snapshot)
 *   4. Client sends req: agents.list, sessions.list, chat.send, etc.
 *   5. Server sends res: with payload
 *   6. Server sends events: chat (delta/final), presence, snapshot
 *
 * Skills are mapped to OpenRouter function-calling tools.
 * The gateway executes tools locally and returns results to the LLM.
 */

const GATEWAY_VERSION = '1.2.0';

const { WebSocketServer } = require('ws');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const { execSync, execFileSync, exec, spawn } = require('child_process');
const os = require('os');
const path = require('path');
const querystring = require('querystring');

// ── Load config ──

const configPath = process.env.OPENCLAW_CONFIG || '/home/seeclaw/.openclaw/config.json';
var config = { gateway: { port: 18789, token: '', host: '0.0.0.0' } };
try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch (e) {
  console.log('[Gateway] No config at ' + configPath + ', using defaults');
}

var PORT = (config.gateway && config.gateway.port) || 18789;
var TOKEN = (config.gateway && config.gateway.token) || '';
var HOST = (config.gateway && config.gateway.host) || '0.0.0.0';
var PLAN = (config.server && config.server.plan) || 'starter';

// OpenRouter config — user-provided key takes priority over platform key
var PLATFORM_OPENROUTER_KEY = (config.llm && config.llm.apiKey) || process.env.OPENROUTER_API_KEY || '';
var USER_OPENROUTER_KEY = (config.llm && config.llm.userApiKey) || '';
var OPENROUTER_KEY = USER_OPENROUTER_KEY || PLATFORM_OPENROUTER_KEY;
var DEFAULT_MODEL = (config.llm && config.llm.model) || 'anthropic/claude-3.5-sonnet';

// Google OAuth config
var GOOGLE_CLIENT_ID = (config.google && config.google.clientId) || process.env.GOOGLE_CLIENT_ID || '';
var GOOGLE_CLIENT_SECRET = (config.google && config.google.clientSecret) || process.env.GOOGLE_CLIENT_SECRET || '';
var GOOGLE_WEB_CLIENT_ID = (config.google && config.google.webClientId) || process.env.GOOGLE_WEB_CLIENT_ID || '';
var GOOGLE_WEB_CLIENT_SECRET = (config.google && config.google.webClientSecret) || process.env.GOOGLE_WEB_CLIENT_SECRET || '';
var GOOGLE_REDIRECT_URI = (config.google && config.google.redirectUri) || process.env.GOOGLE_REDIRECT_URI || 'https://lionoai.com/api/google/callback';
var DATA_DIR = process.env.OPENCLAW_DATA_DIR || path.join(os.homedir(), '.openclaw');
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (_) {}
var GOOGLE_TOKEN_PATH = path.join(DATA_DIR, 'google-tokens.json');
var GOOGLE_USER_PROJECT_PATH = path.join(DATA_DIR, 'google-user-project.json');

// Derive a stable encryption key from the gateway token + machine identity
var TOKEN_ENC_KEY = (function () {
  var material = (TOKEN || 'openclaw') + ':' + os.hostname() + ':' + DATA_DIR;
  return crypto.createHash('sha256').update(material).digest();
})();

function encryptJson(obj) {
  var plaintext = JSON.stringify(obj, null, 2);
  var iv = crypto.randomBytes(12);
  var cipher = crypto.createCipheriv('aes-256-gcm', TOKEN_ENC_KEY, iv);
  var encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  var tag = cipher.getAuthTag();
  return JSON.stringify({ v: 1, iv: iv.toString('base64'), tag: tag.toString('base64'), data: encrypted.toString('base64') });
}

function decryptJson(raw) {
  var envelope = JSON.parse(raw);
  if (!envelope.v || !envelope.iv) return envelope; // plaintext (legacy)
  var decipher = crypto.createDecipheriv('aes-256-gcm', TOKEN_ENC_KEY, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  var decrypted = Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

// Load stored Google tokens (supports both encrypted and legacy plaintext)
var googleTokens = null;
try {
  var rawTokenFile = fs.readFileSync(GOOGLE_TOKEN_PATH, 'utf8');
  googleTokens = decryptJson(rawTokenFile);
  // Re-encrypt legacy plaintext files on first load
  var parsed = JSON.parse(rawTokenFile);
  if (!parsed.v) { try { fs.writeFileSync(GOOGLE_TOKEN_PATH, encryptJson(googleTokens)); } catch (_) {} }
} catch (e) { /* no tokens yet */ }

// Load user's own GCP project credentials (Option 2)
var googleUserProject = null;
try {
  var rawProjectFile = fs.readFileSync(GOOGLE_USER_PROJECT_PATH, 'utf8');
  googleUserProject = decryptJson(rawProjectFile);
  var parsedP = JSON.parse(rawProjectFile);
  if (!parsedP.v) { try { fs.writeFileSync(GOOGLE_USER_PROJECT_PATH, encryptJson(googleUserProject)); } catch (_) {} }
} catch (e) { /* none yet */ }

// ── User Profile / Memories ──
// Persistent user profile that the AI uses to personalize every response.
var USER_PROFILE_PATH = path.join(DATA_DIR, 'user-profile.json');
var userProfile = { preferences: {}, botName: '', memories: [] };
try {
  if (fs.existsSync(USER_PROFILE_PATH)) {
    userProfile = JSON.parse(fs.readFileSync(USER_PROFILE_PATH, 'utf8'));
    console.log('[Gateway] Loaded user profile (' + Object.keys(userProfile.preferences || {}).length + ' preferences, ' + (userProfile.memories || []).length + ' memories)');
  }
} catch (e) { console.log('[Gateway] No user profile yet'); }

function saveUserProfile() {
  try {
    fs.writeFileSync(USER_PROFILE_PATH, JSON.stringify(userProfile, null, 2));
  } catch (e) {
    console.error('[Gateway] Failed to save user profile:', e.message);
  }
}

function buildUserContext() {
  var lines = [];
  var p = userProfile.preferences || {};

  if (userProfile.botName) lines.push('The user has named you "' + userProfile.botName + '". Use this name when referring to yourself.');
  if (p.gender && p.gender[0] && p.gender[0] !== 'Prefer not to say') lines.push('Gender: ' + p.gender[0]);
  if (p.age_range && p.age_range[0]) lines.push('Age range: ' + p.age_range[0]);
  if (p.relationship && p.relationship[0] && p.relationship[0] !== 'Prefer not to say') lines.push('Relationship: ' + p.relationship[0]);
  if (p.family && p.family[0] && p.family[0] !== 'Prefer not to say') lines.push('Family: ' + p.family[0]);
  if (p.location && p.location[0]) lines.push('Location: ' + p.location[0]);
  if (p.language && p.language.length > 0) lines.push('Languages: ' + p.language.join(', '));
  if (p.work_style && p.work_style[0]) lines.push('Work: ' + p.work_style[0]);
  if (p.education && p.education[0] && p.education[0] !== 'Prefer not to say') lines.push('Education: ' + p.education[0]);
  if (p.communication && p.communication[0]) lines.push('Communication preference: ' + p.communication[0]);
  if (p.interests && p.interests.length > 0) lines.push('Interests: ' + p.interests.join(', '));
  if (p.help_with && p.help_with.length > 0) lines.push('Wants help with: ' + p.help_with.join(', '));
  if (p.schedule && p.schedule[0]) lines.push('Peak productivity: ' + p.schedule[0]);

  // Append free-form memories
  var mems = userProfile.memories || [];
  if (mems.length > 0) {
    lines.push('');
    lines.push('## Remembered facts:');
    mems.forEach(function (m) { lines.push('- ' + m); });
  }

  return lines.length > 0 ? '\n\n## About the user:\n' + lines.join('\n') : '';
}

// ── State ──

var sessions = {};       // { sessionKey: { key, label, agentId, ... } }
var sessionHistory = {};  // { sessionKey: [ { role, content }, ... ] }
var sessionCounter = 0;
var startTime = Date.now();
var reminders = [];       // in-memory reminders

// ── Sub-agent state ──
var subagentRuns = {};   // { runId: { runId, parentSessionKey, parentRunId, childSessionKey, agentId, agentName, task, label, status, startedAt, finishedAt, result, error } }
var subagentCounter = 0;
var deviceFlowState = null;  // active Device Flow polling state
var browserSession = null;   // active Playwright browser session

var defaultAgents = [
  {
    id: 'default',
    name: 'LIONO Assistant',
    identity: {
      name: 'LIONO',
      emoji: String.fromCodePoint(0x1F981),
      theme: 'Your personal AI assistant powered by LIONO'
    },
    skills: ['web-search', 'summarizer', 'code-assist', 'writing-assist', 'math-solver', 'system-monitor', 'weather'],
    subagents: { allowAgents: ['*'], maxChildren: 5 }
  }
];

// Sub-agent config defaults
var SUBAGENT_DEFAULTS = {
  maxSpawnDepth: 2,
  maxChildrenPerAgent: 5,
  maxConcurrent: 8,
  runTimeoutSeconds: 300
};

// Load persisted agents or use defaults
var agentsFile = path.join(__dirname, 'agents.json');
var agents = defaultAgents;
try {
  if (fs.existsSync(agentsFile)) {
    agents = JSON.parse(fs.readFileSync(agentsFile, 'utf8'));
    if (!Array.isArray(agents) || agents.length === 0) agents = defaultAgents;
  }
} catch (e) { agents = defaultAgents; }

function saveAgents() {
  try { fs.writeFileSync(agentsFile, JSON.stringify(agents, null, 2)); } catch (e) { /* ignore */ }
}

// Load persisted sessions or start fresh
var sessionsFile = path.join(DATA_DIR, 'sessions.json');
var sessionsHistoryFile = path.join(DATA_DIR, 'sessions-history.json');
try {
  if (fs.existsSync(sessionsFile)) {
    var loaded = JSON.parse(fs.readFileSync(sessionsFile, 'utf8'));
    if (loaded && typeof loaded === 'object' && !Array.isArray(loaded)) {
      sessions = loaded;
      sessionCounter = Object.keys(sessions).length;
    }
  }
} catch (e) { /* start fresh */ }
try {
  if (fs.existsSync(sessionsHistoryFile)) {
    var loadedHistory = JSON.parse(fs.readFileSync(sessionsHistoryFile, 'utf8'));
    if (loadedHistory && typeof loadedHistory === 'object') {
      sessionHistory = loadedHistory;
    }
  }
} catch (e) { /* start fresh */ }

function saveSessions() {
  try { fs.writeFileSync(sessionsFile, JSON.stringify(sessions, null, 2)); } catch (e) { /* ignore */ }
  try { fs.writeFileSync(sessionsHistoryFile, JSON.stringify(sessionHistory, null, 2)); } catch (e) { /* ignore */ }
}

// ── Helpers ──

function uuid() { return crypto.randomUUID(); }
function now() { return Date.now(); }

function sendJSON(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch (e) { /* ignore */ }
}

function sendRes(ws, id, ok, payload, error) {
  var msg = { type: 'res', id: id, ok: ok };
  if (ok && payload !== undefined) msg.payload = payload;
  if (!ok && error) msg.error = error;
  sendJSON(ws, msg);
}

function sendEvent(ws, eventName, payload, seq) {
  var msg = { type: 'event', event: eventName };
  if (payload !== undefined) msg.payload = payload;
  if (seq !== undefined) msg.seq = seq;
  sendJSON(ws, msg);
}

// ══════════════════════════════════════════════════════════════
//  GOOGLE OAUTH & API HELPERS
// ══════════════════════════════════════════════════════════════

function httpsRequest(options, body) {
  return new Promise(function (resolve, reject) {
    var req = https.request(options, function (res) {
      var data = '';
      res.on('data', function (chunk) { data += chunk; });
      res.on('end', function () {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch (e) { resolve({ status: res.statusCode, data: data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function saveGoogleTokens(tokens) {
  googleTokens = tokens;
  try { fs.writeFileSync(GOOGLE_TOKEN_PATH, encryptJson(tokens)); } catch (e) {
    console.log('[Google] Failed to save tokens:', e.message);
  }
}

function saveUserProjectConfig(projectConfig) {
  googleUserProject = projectConfig;
  try { fs.writeFileSync(GOOGLE_USER_PROJECT_PATH, encryptJson(projectConfig)); } catch (e) {
    console.log('[Google] Failed to save user project config:', e.message);
  }
}

// Refresh Google access token using refresh_token
function refreshGoogleToken(callback) {
  if (!googleTokens || !googleTokens.refresh_token) {
    return callback(new Error('No refresh token available'));
  }
  // Use the same client credentials that were used to obtain the tokens
  var clientId, clientSecret;
  if (googleTokens.clientType === 'web' && GOOGLE_WEB_CLIENT_ID) {
    clientId = GOOGLE_WEB_CLIENT_ID;
    clientSecret = GOOGLE_WEB_CLIENT_SECRET;
  } else if (googleUserProject && googleUserProject.clientId) {
    clientId = googleUserProject.clientId;
    clientSecret = googleUserProject.clientSecret;
  } else {
    clientId = GOOGLE_CLIENT_ID;
    clientSecret = GOOGLE_CLIENT_SECRET;
  }
  var postData = querystring.stringify({
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: googleTokens.refresh_token,
    grant_type: 'refresh_token'
  });
  httpsRequest({
    hostname: 'oauth2.googleapis.com',
    path: '/token',
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData) }
  }, postData).then(function (res) {
    if (res.status === 200 && res.data.access_token) {
      googleTokens.access_token = res.data.access_token;
      googleTokens.expires_at = Date.now() + (res.data.expires_in * 1000);
      saveGoogleTokens(googleTokens);
      callback(null, googleTokens.access_token);
    } else {
      callback(new Error('Token refresh failed: ' + JSON.stringify(res.data)));
    }
  }).catch(callback);
}

// Get a valid Google access token (refresh if expired)
function getGoogleAccessToken(callback) {
  if (!googleTokens) return callback(new Error('Not authenticated with Google'));
  if (googleTokens.expires_at && Date.now() < googleTokens.expires_at - 60000) {
    return callback(null, googleTokens.access_token);
  }
  refreshGoogleToken(callback);
}

// Make authenticated Google API call
function googleApi(method, host, apiPath, body, callback) {
  getGoogleAccessToken(function (err, token) {
    if (err) return callback(err);
    var bodyStr = body ? JSON.stringify(body) : null;
    var headers = {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json',
    };
    if (bodyStr) headers['Content-Length'] = Buffer.byteLength(bodyStr);
    httpsRequest({
      hostname: host,
      path: apiPath,
      method: method,
      headers: headers
    }, bodyStr).then(function (res) {
      callback(null, res);
    }).catch(callback);
  });
}

// ── Device Flow (Option 1: Users 1-100) ──

function startDeviceFlow(scopes, callback) {
  var clientId = GOOGLE_CLIENT_ID;
  if (!clientId) return callback(new Error('GOOGLE_CLIENT_ID not configured'));
  var postData = querystring.stringify({
    client_id: clientId,
    scope: scopes.join(' ')
  });
  httpsRequest({
    hostname: 'oauth2.googleapis.com',
    path: '/device/code',
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData) }
  }, postData).then(function (res) {
    if (res.status === 200) {
      callback(null, res.data);
    } else {
      callback(new Error('Device flow start failed: ' + JSON.stringify(res.data)));
    }
  }).catch(callback);
}

function pollDeviceFlow(deviceCode, interval, callback) {
  var clientId = GOOGLE_CLIENT_ID;
  var clientSecret = GOOGLE_CLIENT_SECRET;
  var postData = querystring.stringify({
    client_id: clientId,
    client_secret: clientSecret,
    device_code: deviceCode,
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
  });
  httpsRequest({
    hostname: 'oauth2.googleapis.com',
    path: '/token',
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData) }
  }, postData).then(function (res) {
    if (res.status === 200 && res.data.access_token) {
      callback(null, 'complete', res.data);
    } else if (res.data.error === 'authorization_pending') {
      callback(null, 'pending', null);
    } else if (res.data.error === 'slow_down') {
      callback(null, 'slow_down', null);
    } else if (res.data.error === 'access_denied') {
      callback(null, 'denied', null);
    } else if (res.data.error === 'expired_token') {
      callback(null, 'expired', null);
    } else {
      callback(new Error('Poll error: ' + JSON.stringify(res.data)));
    }
  }).catch(callback);
}

// ── GCP Project Automation (Option 2: User 101+) ──

function createGcpProject(accessToken, projectId, callback) {
  var bodyStr = JSON.stringify({ projectId: projectId, name: 'LIONO' });
  httpsRequest({
    hostname: 'cloudresourcemanager.googleapis.com',
    path: '/v1/projects',
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + accessToken,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyStr)
    }
  }, bodyStr).then(function (res) {
    callback(null, res);
  }).catch(callback);
}

function batchEnableApis(accessToken, projectId, services, callback) {
  var bodyStr = JSON.stringify({ serviceIds: services });
  httpsRequest({
    hostname: 'serviceusage.googleapis.com',
    path: '/v1/projects/' + projectId + '/services:batchEnable',
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + accessToken,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyStr)
    }
  }, bodyStr).then(function (res) {
    callback(null, res);
  }).catch(callback);
}

// ── Direct Google API calls (replacing gogcli) ──

function gmailApiCall(action, args, callback) {
  var userEmail = (googleTokens && googleTokens.email) || 'me';
  switch (action) {
    case 'list':
      googleApi('GET', 'gmail.googleapis.com', '/gmail/v1/users/me/messages?maxResults=' + (args.max_results || 10), null, function (err, res) {
        if (err) return callback(err);
        if (res.status !== 200) return callback(new Error('Gmail list failed: ' + JSON.stringify(res.data)));
        // Fetch message details for each ID
        var messages = (res.data.messages || []).slice(0, args.max_results || 10);
        var results = [];
        var pending = messages.length;
        if (pending === 0) return callback(null, { messages: [] });
        messages.forEach(function (m) {
          googleApi('GET', 'gmail.googleapis.com', '/gmail/v1/users/me/messages/' + m.id + '?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date', null, function (err2, res2) {
            if (!err2 && res2.status === 200) {
              var headers = {};
              ((res2.data.payload && res2.data.payload.headers) || []).forEach(function (h) { headers[h.name.toLowerCase()] = h.value; });
              results.push({ id: m.id, threadId: m.threadId, subject: headers.subject || '', from: headers.from || '', date: headers.date || '', snippet: res2.data.snippet || '' });
            }
            pending--;
            if (pending <= 0) callback(null, { messages: results });
          });
        });
      });
      break;
    case 'search':
      var q = encodeURIComponent(args.query || '');
      googleApi('GET', 'gmail.googleapis.com', '/gmail/v1/users/me/messages?q=' + q + '&maxResults=' + (args.max_results || 10), null, function (err, res) {
        if (err) return callback(err);
        if (res.status !== 200) return callback(new Error('Gmail search failed: ' + JSON.stringify(res.data)));
        callback(null, res.data);
      });
      break;
    case 'read':
      if (!args.message_id) return callback(new Error('message_id required'));
      googleApi('GET', 'gmail.googleapis.com', '/gmail/v1/users/me/messages/' + args.message_id + '?format=full', null, function (err, res) {
        if (err) return callback(err);
        callback(null, res.data);
      });
      break;
    case 'send':
      if (!args.to) return callback(new Error('to address required'));
      var rawEmail = 'To: ' + args.to + '\r\nSubject: ' + (args.subject || '') + '\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n' + (args.body || '');
      var encoded = Buffer.from(rawEmail).toString('base64url');
      googleApi('POST', 'gmail.googleapis.com', '/gmail/v1/users/me/messages/send', { raw: encoded }, function (err, res) {
        if (err) return callback(err);
        callback(null, res.data);
      });
      break;
    case 'labels':
      googleApi('GET', 'gmail.googleapis.com', '/gmail/v1/users/me/labels', null, function (err, res) {
        if (err) return callback(err);
        callback(null, res.data);
      });
      break;
    default:
      callback(new Error('Unknown gmail action: ' + action));
  }
}

function calendarApiCall(action, args, callback) {
  switch (action) {
    case 'list':
    case 'upcoming':
      var days = args.days || 7;
      var timeMin = new Date().toISOString();
      var timeMax = new Date(Date.now() + days * 86400000).toISOString();
      googleApi('GET', 'www.googleapis.com', '/calendar/v3/calendars/primary/events?timeMin=' + encodeURIComponent(timeMin) + '&timeMax=' + encodeURIComponent(timeMax) + '&singleEvents=true&orderBy=startTime&maxResults=20', null, function (err, res) {
        if (err) return callback(err);
        if (res.status !== 200) return callback(new Error('Calendar list failed: ' + JSON.stringify(res.data)));
        var events = (res.data.items || []).map(function (e) {
          return { id: e.id, summary: e.summary || '', start: (e.start && (e.start.dateTime || e.start.date)) || '', end: (e.end && (e.end.dateTime || e.end.date)) || '', location: e.location || '', status: e.status || '' };
        });
        callback(null, { events: events });
      });
      break;
    case 'create':
      if (!args.title) return callback(new Error('title required'));
      var event = {
        summary: args.title,
        start: { dateTime: args.start || new Date(Date.now() + 3600000).toISOString() },
        end: { dateTime: args.end || new Date(Date.now() + 7200000).toISOString() }
      };
      googleApi('POST', 'www.googleapis.com', '/calendar/v3/calendars/primary/events', event, function (err, res) {
        if (err) return callback(err);
        callback(null, res.data);
      });
      break;
    default:
      callback(new Error('Unknown calendar action: ' + action));
  }
}

// ── Playwright Browser Automation (Option 2: CDP Screencast) ──

var playwrightAvailable = false;
try { require.resolve('playwright-core'); playwrightAvailable = true; } catch (e) { /* not installed */ }

function launchBrowserSession(callback) {
  if (!playwrightAvailable) {
    return callback(new Error('Playwright not installed. Run: npm install playwright-core'));
  }
  var pw = require('playwright-core');
  var chromiumPath = '';
  // Prefer Google Chrome (works in systemd), then fall back to chromium-browser (snap may fail in services)
  try { chromiumPath = execSync('which google-chrome-stable 2>/dev/null || which google-chrome 2>/dev/null || which chromium-browser 2>/dev/null || which chromium 2>/dev/null', { encoding: 'utf8' }).trim(); } catch (e) { }
  if (!chromiumPath) return callback(new Error('No browser found. Install Google Chrome or Chromium.'));

  pw.chromium.launch({
    executablePath: chromiumPath,
    headless: true,
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage']
  }).then(function (browser) {
    browser.newPage({ viewport: { width: 390, height: 844 } }).then(function (page) {
      var cdpSession = null;
      page.context().newCDPSession(page).then(function (session) {
        cdpSession = session;
        browserSession = { browser: browser, page: page, cdp: session, frames: [], lastFrame: null };
        // Start screencast
        session.send('Page.startScreencast', { format: 'jpeg', quality: 60, maxWidth: 390, maxHeight: 844 }).then(function () {
          session.on('Page.screencastFrame', function (params) {
            browserSession.lastFrame = params.data;
            session.send('Page.screencastFrameAck', { sessionId: params.sessionId }).catch(function () { });
          });
          callback(null, browserSession);
        }).catch(callback);
      }).catch(callback);
    }).catch(callback);
  }).catch(callback);
}

function closeBrowserSession() {
  if (browserSession) {
    try { browserSession.cdp.send('Page.stopScreencast').catch(function () { }); } catch (e) { }
    try { browserSession.browser.close().catch(function () { }); } catch (e) { }
    browserSession = null;
  }
}

// Automate GCP consent screen + credentials creation after user signs in
function automateGcpConsoleSetup(projectId, userEmail, statusCallback, doneCallback) {
  if (!browserSession || !browserSession.page) return doneCallback(new Error('No browser session'));
  var page = browserSession.page;

  statusCallback('Navigating to consent screen...');
  page.goto('https://console.cloud.google.com/auth/branding?project=' + projectId, { waitUntil: 'networkidle', timeout: 30000 })
    .then(function () {
      statusCallback('Configuring consent screen...');
      return page.waitForTimeout(3000);
    })
    .then(function () {
      // Click "External" radio if visible
      return page.locator('text=External').first().click({ timeout: 5000 }).catch(function () {
        statusCallback('External type selection not found, may already be set');
      });
    })
    .then(function () {
      return page.waitForTimeout(1000);
    })
    .then(function () {
      // Click "Create" button
      return page.locator('button:has-text("Create")').first().click({ timeout: 5000 }).catch(function () {
        statusCallback('Create button not found, trying to proceed...');
      });
    })
    .then(function () {
      return page.waitForTimeout(2000);
    })
    .then(function () {
      // Fill support email if visible
      return page.locator('input[type="email"]').first().fill(userEmail, { timeout: 5000 }).catch(function () {
        statusCallback('Email field not found, may already be filled');
      });
    })
    .then(function () {
      // Click Save
      return page.locator('button:has-text("Save")').first().click({ timeout: 5000 }).catch(function () {
        statusCallback('Save button not found, trying to continue...');
      });
    })
    .then(function () {
      statusCallback('Consent screen configured. Creating credentials...');
      return page.waitForTimeout(2000);
    })
    .then(function () {
      // Navigate to credentials page
      return page.goto('https://console.cloud.google.com/apis/credentials/oauthclient?project=' + projectId, { waitUntil: 'networkidle', timeout: 30000 });
    })
    .then(function () {
      return page.waitForTimeout(3000);
    })
    .then(function () {
      // Select "Desktop app" type
      return page.locator('text=Desktop app').first().click({ timeout: 5000 }).catch(function () {
        statusCallback('Trying to find application type dropdown...');
        return page.locator('[role="listbox"]').first().click({ timeout: 3000 }).then(function () {
          return page.locator('text=Desktop app').first().click({ timeout: 3000 });
        });
      });
    })
    .then(function () {
      return page.waitForTimeout(1000);
    })
    .then(function () {
      // Click "Create"
      return page.locator('button:has-text("Create")').first().click({ timeout: 5000 });
    })
    .then(function () {
      statusCallback('Extracting credentials...');
      return page.waitForTimeout(3000);
    })
    .then(function () {
      // Try to extract the client ID and secret from the dialog
      return page.locator('text=/\\d+-[a-z0-9]+\\.apps\\.googleusercontent\\.com/').first().textContent({ timeout: 8000 });
    })
    .then(function (clientId) {
      statusCallback('Got client ID: ' + clientId.substring(0, 20) + '...');
      // Try to get client secret
      return page.locator('[aria-label*="client secret"], [aria-label*="Client secret"]').first().textContent({ timeout: 5000 })
        .then(function (secret) { return { clientId: clientId.trim(), clientSecret: secret.trim() }; })
        .catch(function () {
          // Try clicking "Download JSON" or copying from the page
          return page.locator('text=/[a-zA-Z0-9_-]{24,}/').nth(1).textContent({ timeout: 3000 })
            .then(function (secret) { return { clientId: clientId.trim(), clientSecret: secret.trim() }; })
            .catch(function () { return { clientId: clientId.trim(), clientSecret: '' }; });
        });
    })
    .then(function (creds) {
      statusCallback('Credentials created successfully!');
      doneCallback(null, creds);
    })
    .catch(function (err) {
      statusCallback('Automation error: ' + err.message);
      doneCallback(err);
    });
}

// ══════════════════════════════════════════════════════════════
//  SKILL TOOL DEFINITIONS
//  These map skill IDs to OpenRouter function-calling tools.
// ══════════════════════════════════════════════════════════════

var SKILL_TOOLS = {
  'web-search': {
    type: 'function',
    function: {
      name: 'web_search',
      description: 'Search the web for current information. Use this for any question about recent events, facts, prices, news, or anything that requires up-to-date data.',
      parameters: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'The search query' }
        },
        required: ['query']
      }
    }
  },
  'system-monitor': {
    type: 'function',
    function: {
      name: 'system_monitor',
      description: 'Get current system stats: CPU usage, memory, disk, uptime, running processes, and service status.',
      parameters: {
        type: 'object',
        properties: {
          detail: { type: 'string', enum: ['summary', 'processes', 'services', 'disk', 'network'], description: 'What level of detail to return' }
        },
        required: []
      }
    }
  },
  'weather': {
    type: 'function',
    function: {
      name: 'get_weather',
      description: 'Get current weather and forecast for a location.',
      parameters: {
        type: 'object',
        properties: {
          location: { type: 'string', description: 'City name or location (e.g. "London", "New York", "Tokyo")' }
        },
        required: ['location']
      }
    }
  },
  'api-tester': {
    type: 'function',
    function: {
      name: 'http_request',
      description: 'Make an HTTP request to test APIs. Supports GET, POST, PUT, DELETE with headers and body.',
      parameters: {
        type: 'object',
        properties: {
          method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], description: 'HTTP method' },
          url: { type: 'string', description: 'The URL to request' },
          headers: { type: 'object', description: 'HTTP headers as key-value pairs' },
          body: { type: 'string', description: 'Request body (for POST/PUT/PATCH)' }
        },
        required: ['method', 'url']
      }
    }
  },
  'math-solver': {
    type: 'function',
    function: {
      name: 'calculate',
      description: 'Evaluate a mathematical expression. Supports basic arithmetic, powers, sqrt, trig, log, etc.',
      parameters: {
        type: 'object',
        properties: {
          expression: { type: 'string', description: 'Math expression to evaluate (e.g. "sqrt(144) + 2^10")' }
        },
        required: ['expression']
      }
    }
  },
  'reminder': {
    type: 'function',
    function: {
      name: 'set_reminder',
      description: 'Set a reminder that will be shown to the user after a specified delay.',
      parameters: {
        type: 'object',
        properties: {
          message: { type: 'string', description: 'Reminder message' },
          delay_minutes: { type: 'number', description: 'Minutes from now to trigger the reminder' }
        },
        required: ['message', 'delay_minutes']
      }
    }
  },
  'notification': {
    type: 'function',
    function: {
      name: 'send_notification',
      description: 'Log a notification or alert for the user.',
      parameters: {
        type: 'object',
        properties: {
          title: { type: 'string', description: 'Notification title' },
          message: { type: 'string', description: 'Notification body' },
          priority: { type: 'string', enum: ['low', 'normal', 'high', 'urgent'], description: 'Priority level' }
        },
        required: ['title', 'message']
      }
    }
  },
  'log-analyzer': {
    type: 'function',
    function: {
      name: 'read_logs',
      description: 'Read system or application log files. Can read journalctl, syslog, or specific log files.',
      parameters: {
        type: 'object',
        properties: {
          source: { type: 'string', description: 'Log source: "system", "openclaw", "nginx", or a file path' },
          lines: { type: 'number', description: 'Number of recent lines to read (default 50)' },
          filter: { type: 'string', description: 'Optional grep filter pattern' }
        },
        required: ['source']
      }
    }
  },
  'timezone': {
    type: 'function',
    function: {
      name: 'timezone_convert',
      description: 'Convert time between timezones or get current time in a timezone.',
      parameters: {
        type: 'object',
        properties: {
          timezone: { type: 'string', description: 'Target timezone (e.g. "America/New_York", "Europe/London", "Asia/Tokyo")' },
          time: { type: 'string', description: 'Optional time to convert (ISO 8601). If omitted, returns current time.' }
        },
        required: ['timezone']
      }
    }
  },
  'gmail': {
    type: 'function',
    function: {
      name: 'gmail',
      description: 'Interact with Gmail via Google API. Can list, search, read, compose, and send emails. Requires Google account to be connected via the LIONO app.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'search', 'read', 'compose', 'send', 'labels'], description: 'Gmail action to perform' },
          query: { type: 'string', description: 'Search query (for search action)' },
          message_id: { type: 'string', description: 'Message ID (for read action)' },
          to: { type: 'string', description: 'Recipient email (for compose/send)' },
          subject: { type: 'string', description: 'Email subject (for compose/send)' },
          body: { type: 'string', description: 'Email body (for compose/send)' },
          max_results: { type: 'number', description: 'Maximum results to return (default 10)' }
        },
        required: ['action']
      }
    }
  },
  'calendar-manage': {
    type: 'function',
    function: {
      name: 'calendar',
      description: 'Manage Google Calendar via Google API. List events, create events, check availability. Requires Google account to be connected via the LIONO app.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'create', 'delete', 'upcoming'], description: 'Calendar action' },
          title: { type: 'string', description: 'Event title (for create)' },
          start: { type: 'string', description: 'Start time ISO 8601 (for create)' },
          end: { type: 'string', description: 'End time ISO 8601 (for create)' },
          days: { type: 'number', description: 'Number of days to look ahead (for list/upcoming, default 7)' }
        },
        required: ['action']
      }
    }
  },
  'web-fetch': {
    type: 'function',
    function: {
      name: 'web_fetch',
      description: 'Fetch a URL and convert the page to clean readable text or markdown. Use this to read articles, documentation, or any webpage.',
      parameters: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'The URL to fetch' },
          format: { type: 'string', enum: ['text', 'markdown', 'html'], description: 'Output format (default: text)' }
        },
        required: ['url']
      }
    }
  },
  'exec': {
    type: 'function',
    function: {
      name: 'exec_command',
      description: 'Execute a shell command on the server. Use for system tasks, file operations, installing packages, or running scripts.',
      parameters: {
        type: 'object',
        properties: {
          command: { type: 'string', description: 'Shell command to execute' },
          timeout: { type: 'number', description: 'Timeout in seconds (default 30, max 120)' }
        },
        required: ['command']
      }
    }
  },
  'sessions-spawn': {
    type: 'function',
    function: {
      name: 'sessions_spawn',
      description: 'Spawn a sub-agent to handle a complex task in the background. The sub-agent runs independently and returns results when done.',
      parameters: {
        type: 'object',
        properties: {
          task: { type: 'string', description: 'Task description for the sub-agent' },
          agent: { type: 'string', description: 'Agent ID to use (optional, defaults to current)' }
        },
        required: ['task']
      }
    }
  },
  'process': {
    type: 'function',
    function: {
      name: 'process_manage',
      description: 'Manage background processes. List running processes, check status, or kill a specific process.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'status', 'kill'], description: 'Process action' },
          pid: { type: 'number', description: 'Process ID (for status/kill)' }
        },
        required: ['action']
      }
    }
  },
  'cron': {
    type: 'function',
    function: {
      name: 'cron_manage',
      description: 'Schedule recurring background tasks. Create, list, or remove cron-style scheduled jobs.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'add', 'remove'], description: 'Cron action' },
          schedule: { type: 'string', description: 'Cron expression (e.g. "0 9 * * *" for 9am daily)' },
          task: { type: 'string', description: 'Task to execute on schedule' },
          id: { type: 'string', description: 'Job ID (for remove)' }
        },
        required: ['action']
      }
    }
  },
  'image-analysis': {
    type: 'function',
    function: {
      name: 'analyze_image',
      description: 'Analyze and describe images using the vision model. Can identify objects, read text, and provide detailed descriptions.',
      parameters: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Image URL or base64 data to analyze' },
          prompt: { type: 'string', description: 'Specific question or instruction about the image' }
        },
        required: ['url']
      }
    }
  },
  'web-browse': {
    type: 'function',
    function: {
      name: 'web_browse',
      description: 'Control a headless browser: navigate pages, click elements, fill forms, take screenshots, and extract data.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['navigate', 'click', 'type', 'screenshot', 'content', 'evaluate'], description: 'Browser action' },
          url: { type: 'string', description: 'URL to navigate to' },
          selector: { type: 'string', description: 'CSS selector for element interactions' },
          text: { type: 'string', description: 'Text to type or JS to evaluate' }
        },
        required: ['action']
      }
    }
  },
  'hackernews-digest': {
    type: 'function',
    function: {
      name: 'hackernews_digest',
      description: 'Fetch and summarize the top stories from Hacker News. Get trending tech news and discussions.',
      parameters: {
        type: 'object',
        properties: {
          count: { type: 'number', description: 'Number of stories to fetch (default 10, max 30)' },
          type: { type: 'string', enum: ['top', 'new', 'best', 'ask', 'show'], description: 'Story type (default: top)' }
        },
        required: []
      }
    }
  },
  'stock-ticker': {
    type: 'function',
    function: {
      name: 'stock_ticker',
      description: 'Get real-time stock price, change, and basic info for a ticker symbol using Yahoo Finance.',
      parameters: {
        type: 'object',
        properties: {
          symbol: { type: 'string', description: 'Stock ticker symbol (e.g. AAPL, TSLA, MSFT)' }
        },
        required: ['symbol']
      }
    }
  },
  'currency-converter': {
    type: 'function',
    function: {
      name: 'convert_currency',
      description: 'Convert between currencies using live exchange rates.',
      parameters: {
        type: 'object',
        properties: {
          amount: { type: 'number', description: 'Amount to convert' },
          from: { type: 'string', description: 'Source currency code (e.g. USD, EUR, GBP)' },
          to: { type: 'string', description: 'Target currency code' }
        },
        required: ['amount', 'from', 'to']
      }
    }
  },
  'youtube-transcription': {
    type: 'function',
    function: {
      name: 'youtube_transcript',
      description: 'Extract the transcript/subtitles from a YouTube video URL for summarization and analysis.',
      parameters: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'YouTube video URL' }
        },
        required: ['url']
      }
    }
  },
  'github-trending': {
    type: 'function',
    function: {
      name: 'github_trending',
      description: 'List currently trending repositories on GitHub, optionally filtered by programming language.',
      parameters: {
        type: 'object',
        properties: {
          language: { type: 'string', description: 'Programming language filter (e.g. python, javascript, rust)' },
          since: { type: 'string', enum: ['daily', 'weekly', 'monthly'], description: 'Time range (default: daily)' }
        },
        required: []
      }
    }
  },
  'json-validator': {
    type: 'function',
    function: {
      name: 'validate_json',
      description: 'Validate and pretty-print a JSON string. Reports parsing errors with line numbers.',
      parameters: {
        type: 'object',
        properties: {
          json: { type: 'string', description: 'JSON string to validate' }
        },
        required: ['json']
      }
    }
  },
  'base64-codec': {
    type: 'function',
    function: {
      name: 'base64_codec',
      description: 'Encode or decode strings to/from Base64 format.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['encode', 'decode'], description: 'Encode or decode' },
          text: { type: 'string', description: 'Text to encode or Base64 string to decode' }
        },
        required: ['action', 'text']
      }
    }
  },
  'uuid-generator': {
    type: 'function',
    function: {
      name: 'generate_uuid',
      description: 'Generate random UUID v4 identifiers for testing or database seeding.',
      parameters: {
        type: 'object',
        properties: {
          count: { type: 'number', description: 'Number of UUIDs to generate (default 1, max 50)' }
        },
        required: []
      }
    }
  },
  'password-generator': {
    type: 'function',
    function: {
      name: 'generate_password',
      description: 'Generate strong, secure random passwords with configurable length and character sets.',
      parameters: {
        type: 'object',
        properties: {
          length: { type: 'number', description: 'Password length (default 20, max 128)' },
          count: { type: 'number', description: 'Number of passwords (default 1)' },
          symbols: { type: 'boolean', description: 'Include symbols (default true)' }
        },
        required: []
      }
    }
  },
  'qr-code': {
    type: 'function',
    function: {
      name: 'generate_qr',
      description: 'Generate a QR code image URL for any text, URL, or data.',
      parameters: {
        type: 'object',
        properties: {
          data: { type: 'string', description: 'Text or URL to encode in the QR code' },
          size: { type: 'number', description: 'Image size in pixels (default 300)' }
        },
        required: ['data']
      }
    }
  },
  'port-scanner': {
    type: 'function',
    function: {
      name: 'scan_ports',
      description: 'Check if specific TCP ports are open on a target host. Useful for network diagnostics.',
      parameters: {
        type: 'object',
        properties: {
          host: { type: 'string', description: 'Target hostname or IP address' },
          ports: { type: 'string', description: 'Comma-separated port numbers (e.g. "80,443,8080")' }
        },
        required: ['host', 'ports']
      }
    }
  },
  'whois-lookup': {
    type: 'function',
    function: {
      name: 'whois_lookup',
      description: 'Retrieve domain registration information including registrar, creation date, and nameservers.',
      parameters: {
        type: 'object',
        properties: {
          domain: { type: 'string', description: 'Domain name to look up (e.g. example.com)' }
        },
        required: ['domain']
      }
    }
  },
  'ip-info': {
    type: 'function',
    function: {
      name: 'ip_info',
      description: 'Get geolocation, ISP, and network information for an IP address.',
      parameters: {
        type: 'object',
        properties: {
          ip: { type: 'string', description: 'IP address to look up (omit for current server IP)' }
        },
        required: []
      }
    }
  },
  'dns-lookup': {
    type: 'function',
    function: {
      name: 'dns_lookup',
      description: 'Perform DNS lookups for a domain. Returns A, AAAA, MX, TXT, NS, and CNAME records.',
      parameters: {
        type: 'object',
        properties: {
          domain: { type: 'string', description: 'Domain name to look up' },
          type: { type: 'string', enum: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'ALL'], description: 'Record type (default: ALL)' }
        },
        required: ['domain']
      }
    }
  },
  'file-manager': {
    type: 'function',
    function: {
      name: 'file_manage',
      description: 'Read, write, list, or search files in the workspace. Manage the agent data directory.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['read', 'write', 'list', 'search', 'delete', 'mkdir'], description: 'File operation' },
          path: { type: 'string', description: 'File or directory path (relative to workspace)' },
          content: { type: 'string', description: 'Content to write (for write action)' },
          pattern: { type: 'string', description: 'Search pattern (for search action)' }
        },
        required: ['action']
      }
    }
  },
  'text-transform': {
    type: 'function',
    function: {
      name: 'text_transform',
      description: 'Transform text: count words, extract emails/URLs, convert case, find/replace, generate lorem ipsum, hash strings.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['wordcount', 'uppercase', 'lowercase', 'titlecase', 'extract_emails', 'extract_urls', 'find_replace', 'lorem', 'hash', 'slug'], description: 'Transformation to apply' },
          text: { type: 'string', description: 'Input text' },
          find: { type: 'string', description: 'Find string (for find_replace)' },
          replace: { type: 'string', description: 'Replace string (for find_replace)' },
          paragraphs: { type: 'number', description: 'Number of paragraphs (for lorem, default 1)' }
        },
        required: ['action']
      }
    }
  },
  'unit-converter': {
    type: 'function',
    function: {
      name: 'convert_units',
      description: 'Convert between units of measurement: temperature, distance, weight, volume, speed, data size, and more.',
      parameters: {
        type: 'object',
        properties: {
          value: { type: 'number', description: 'Value to convert' },
          from: { type: 'string', description: 'Source unit (e.g. km, miles, celsius, kg, lbs, GB, MB)' },
          to: { type: 'string', description: 'Target unit' }
        },
        required: ['value', 'from', 'to']
      }
    }
  },
  'summarizer': {
    type: 'function',
    function: {
      name: 'summarize',
      description: 'Summarize long text, articles, or documents into concise key points. Supports bullet points, paragraph, or TL;DR format.',
      parameters: {
        type: 'object',
        properties: {
          text: { type: 'string', description: 'Text to summarize' },
          format: { type: 'string', enum: ['bullets', 'paragraph', 'tldr'], description: 'Output format (default: bullets)' },
          max_points: { type: 'number', description: 'Max number of bullet points (default 5)' }
        },
        required: ['text']
      }
    }
  },
  'writing-assist': {
    type: 'function',
    function: {
      name: 'writing_assist',
      description: 'Improve writing: fix grammar, adjust tone, rephrase, expand, or condense text.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['grammar', 'rephrase', 'formal', 'casual', 'expand', 'condense', 'proofread'], description: 'Writing action' },
          text: { type: 'string', description: 'Text to process' }
        },
        required: ['action', 'text']
      }
    }
  },
  'code-assist': {
    type: 'function',
    function: {
      name: 'code_assist',
      description: 'Code assistance: explain code, find bugs, suggest improvements, generate tests, convert between languages, or run code snippets.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['explain', 'review', 'test', 'convert', 'run', 'debug'], description: 'Code action' },
          code: { type: 'string', description: 'Source code' },
          language: { type: 'string', description: 'Programming language' },
          target_language: { type: 'string', description: 'Target language (for convert)' }
        },
        required: ['action', 'code']
      }
    }
  },
  'drive': {
    type: 'function',
    function: {
      name: 'google_drive',
      description: 'Manage Google Drive: list files, search, read documents, upload, and organize folders. Requires Google account connection.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'search', 'read', 'upload', 'create_folder'], description: 'Drive action' },
          query: { type: 'string', description: 'Search query' },
          file_id: { type: 'string', description: 'File ID (for read)' },
          folder_id: { type: 'string', description: 'Parent folder ID' }
        },
        required: ['action']
      }
    }
  }
};

// ══════════════════════════════════════════════════════════════
//  TOOL EXECUTION ENGINE
// ══════════════════════════════════════════════════════════════

function executeToolCall(name, args) {
  try {
    switch (name) {

      case 'web_search': {
        var query = args.query || '';
        var encoded = encodeURIComponent(query);
        var safeQuery = Buffer.from(query).toString('base64');
        var searchScript = [
          'var https=require("https"),qs=require("querystring");',
          'var query=Buffer.from("' + safeQuery + '","base64").toString();',
          'var postData=qs.stringify({q:query});',
          'var opts={hostname:"html.duckduckgo.com",path:"/html/",method:"POST",',
          'headers:{"Content-Type":"application/x-www-form-urlencoded",',
          '"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",',
          '"Content-Length":Buffer.byteLength(postData)}};',
          'var req=https.request(opts,function(res){',
          'var b="";res.on("data",function(c){b+=c});',
          'res.on("end",function(){',
          'var R=[],m,re=/<a[^>]*class="result__a"[^>]*>([\\s\\S]*?)<\\/a>/gi;',
          'while((m=re.exec(b))!==null)R.push({title:m[1].replace(/<[^>]+>/g,"").trim()});',
          'var re2=/<a[^>]*class="result__snippet"[^>]*>([\\s\\S]*?)<\\/a>/gi,i=0;',
          'while((m=re2.exec(b))!==null){if(R[i])R[i].snippet=m[1].replace(/<[^>]+>/g,"").trim();i++}',
          'process.stdout.write(JSON.stringify({q:query,s:"ddg",r:R.slice(0,8)}))});',
          '});req.write(postData);req.end();'
        ].join('');

        try {
          var output = execSync('node -e ' + JSON.stringify(searchScript), { timeout: 15000, encoding: 'utf8' });
          var parsed = JSON.parse(output.trim());
          if (parsed.r && parsed.r.length > 0) {
            return JSON.stringify({ query: parsed.q, source: parsed.s, results: parsed.r });
          }
        } catch (e) { /* DDG failed, try fallbacks */ }

        try {
          var wikiRaw = execSync(
            'curl -sf "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=' + encoded + '&format=json&srlimit=5&srprop=snippet" 2>/dev/null',
            { timeout: 8000, encoding: 'utf8' }
          );
          var wikiData = JSON.parse(wikiRaw);
          var wikiResults = (wikiData.query && wikiData.query.search) || [];
          if (wikiResults.length > 0) {
            return JSON.stringify({
              query: query, source: 'wikipedia',
              results: wikiResults.map(function (s) {
                return { title: s.title, snippet: (s.snippet || '').replace(/<[^>]+>/g, '').trim(), url: 'https://en.wikipedia.org/wiki/' + encodeURIComponent(s.title.replace(/ /g, '_')) };
              })
            });
          }
        } catch (e) { /* wiki failed */ }

        return JSON.stringify({ query: query, error: 'Search temporarily unavailable. Try again in a moment.' });
      }

      case 'system_monitor': {
        var detail = args.detail || 'summary';
        var info = {};
        try {
          var cpus = os.cpus();
          var totalMem = os.totalmem();
          var freeMem = os.freemem();
          info.hostname = os.hostname();
          info.platform = os.platform() + ' ' + os.release();
          info.uptime = Math.round(os.uptime()) + 's (' + Math.round(os.uptime() / 3600) + 'h)';
          info.cpu = { cores: cpus.length, model: cpus[0] ? cpus[0].model : 'unknown', loadAvg: os.loadavg() };
          info.memory = { totalMB: Math.round(totalMem / 1048576), usedMB: Math.round((totalMem - freeMem) / 1048576), freePercent: Math.round(freeMem / totalMem * 100) };

          if (detail === 'processes' || detail === 'summary') {
            try { info.topProcesses = execSync('ps aux --sort=-%cpu | head -8', { timeout: 5000, encoding: 'utf8' }); } catch (e) { /* skip */ }
          }
          if (detail === 'disk' || detail === 'summary') {
            try { info.disk = execSync('df -h / /home 2>/dev/null', { timeout: 5000, encoding: 'utf8' }); } catch (e) { /* skip */ }
          }
          if (detail === 'services') {
            try { info.services = execSync('systemctl list-units --type=service --state=running --no-pager | head -20', { timeout: 5000, encoding: 'utf8' }); } catch (e) { /* skip */ }
          }
          if (detail === 'network') {
            try { info.network = execSync('ss -tlnp 2>/dev/null | head -15', { timeout: 5000, encoding: 'utf8' }); } catch (e) { /* skip */ }
          }
        } catch (e) { info.error = e.message; }
        return JSON.stringify(info);
      }

      case 'get_weather': {
        var location = args.location || 'London';
        try {
          var weather = execSync(
            'curl -sf "https://wttr.in/' + encodeURIComponent(location) + '?format=j1" 2>/dev/null',
            { timeout: 8000, encoding: 'utf8' }
          );
          var wd = JSON.parse(weather);
          var current = wd.current_condition && wd.current_condition[0];
          var forecast = (wd.weather || []).slice(0, 3);
          return JSON.stringify({
            location: location,
            current: current ? {
              temp_C: current.temp_C,
              temp_F: current.temp_F,
              feels_like_C: current.FeelsLikeC,
              humidity: current.humidity + '%',
              description: current.weatherDesc && current.weatherDesc[0] ? current.weatherDesc[0].value : '',
              wind_kmph: current.windspeedKmph,
              wind_dir: current.winddir16Point,
              uv_index: current.uvIndex
            } : null,
            forecast: forecast.map(function (d) {
              return {
                date: d.date,
                max_C: d.maxtempC, min_C: d.mintempC,
                description: d.hourly && d.hourly[4] && d.hourly[4].weatherDesc ? d.hourly[4].weatherDesc[0].value : ''
              };
            })
          });
        } catch (e) {
          return JSON.stringify({ location: location, error: 'Weather lookup failed: ' + e.message });
        }
      }

      case 'http_request': {
        var method = (args.method || 'GET').toUpperCase();
        var url = args.url || '';
        if (!url) return JSON.stringify({ error: 'URL is required' });
        try {
          var curlArgs = ['curl', '-sf', '-X', method, '-w', '\\n---HTTP_CODE:%{http_code}---'];
          if (args.headers) {
            Object.keys(args.headers).forEach(function (k) {
              curlArgs.push('-H');
              curlArgs.push(k + ': ' + args.headers[k]);
            });
          }
          if (args.body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
            curlArgs.push('-d');
            curlArgs.push(args.body);
          }
          curlArgs.push(url);
          var raw = execFileSync('curl', curlArgs.slice(1), { timeout: 15000, encoding: 'utf8' });
          var codeMatch = raw.match(/---HTTP_CODE:(\d+)---/);
          var httpCode = codeMatch ? parseInt(codeMatch[1]) : 0;
          var body = raw.replace(/\n?---HTTP_CODE:\d+---\s*$/, '');
          if (body.length > 5000) body = body.substring(0, 5000) + '\n...(truncated)';
          return JSON.stringify({ status: httpCode, body: body });
        } catch (e) {
          return JSON.stringify({ error: 'Request failed: ' + e.message });
        }
      }

      case 'calculate': {
        var expr = args.expression || '';
        try {
          var allowedIds = ['sqrt', 'sin', 'cos', 'tan', 'abs', 'log', 'log2', 'log10', 'pow', 'round', 'floor', 'ceil', 'min', 'max', 'PI', 'E'];
          var safeExpr = expr.replace(/\^/g, '**').replace(/\s+/g, ' ');
          var words = safeExpr.match(/[a-zA-Z_][a-zA-Z0-9_]*/g) || [];
          for (var w = 0; w < words.length; w++) {
            if (allowedIds.indexOf(words[w]) === -1) {
              return JSON.stringify({ expression: expr, error: 'Invalid identifier. Allowed: ' + allowedIds.join(', ') });
            }
          }
          safeExpr = safeExpr.replace(/[^0-9+\-*\/().%\sa-zA-Z_]/g, '');
          var mathFuncs = 'var sqrt=Math.sqrt,sin=Math.sin,cos=Math.cos,tan=Math.tan,abs=Math.abs,log=Math.log,log2=Math.log2,log10=Math.log10,pow=Math.pow,PI=Math.PI,E=Math.E,round=Math.round,floor=Math.floor,ceil=Math.ceil,min=Math.min,max=Math.max;';
          var result = new Function(mathFuncs + 'return (' + safeExpr + ');')();
          return JSON.stringify({ expression: expr, result: result });
        } catch (e) {
          return JSON.stringify({ expression: expr, error: 'Could not evaluate: ' + e.message });
        }
      }

      case 'set_reminder': {
        var message = args.message || 'Reminder';
        var delay = (args.delay_minutes || 5) * 60000;
        var reminder = { id: uuid(), message: message, triggersAt: Date.now() + delay };
        reminders.push(reminder);
        return JSON.stringify({ success: true, reminder: message, triggersIn: args.delay_minutes + ' minutes' });
      }

      case 'send_notification': {
        console.log('[Notification] ' + (args.priority || 'normal').toUpperCase() + ': ' + args.title + ' — ' + args.message);
        return JSON.stringify({ sent: true, title: args.title, priority: args.priority || 'normal' });
      }

      case 'read_logs': {
        var source = args.source || 'system';
        var LOG_SOURCE_WHITELIST = ['system', 'openclaw', 'nginx'];
        if (!LOG_SOURCE_WHITELIST.includes(source)) {
          return JSON.stringify({ error: 'Invalid source. Allowed: ' + LOG_SOURCE_WHITELIST.join(', ') });
        }
        var lines = parseInt(args.lines, 10) || 50;
        if (isNaN(lines) || lines < 1 || lines > 1000) lines = 50;
        var filter = (args.filter || '').replace(/[^a-zA-Z0-9_\-\s.,:;/]/g, '');
        try {
          var cmd;
          if (source === 'system') cmd = 'journalctl --no-pager -n ' + lines;
          else if (source === 'openclaw') cmd = 'journalctl -u openclaw --no-pager -n ' + lines;
          else if (source === 'nginx') cmd = 'tail -n ' + lines + ' /var/log/nginx/access.log 2>/dev/null || tail -n ' + lines + ' /var/log/syslog';
          if (filter) cmd += ' | grep -F "' + filter.replace(/"/g, '\\"') + '"';
          var output = execSync(cmd, { timeout: 10000, encoding: 'utf8' });
          if (output.length > 5000) output = output.substring(output.length - 5000);
          return JSON.stringify({ source: source, lines: output });
        } catch (e) {
          return JSON.stringify({ source: source, error: e.message });
        }
      }

      case 'timezone_convert': {
        var tz = args.timezone || 'UTC';
        try {
          var now = new Date();
          var timeStr = now.toLocaleString('en-US', { timeZone: tz, weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
          return JSON.stringify({ timezone: tz, currentTime: timeStr, utc: now.toISOString() });
        } catch (e) {
          return JSON.stringify({ timezone: tz, error: 'Invalid timezone: ' + e.message });
        }
      }

      case 'gmail': {
        var gmailAction = args.action;
        var GMAIL_WHITELIST = ['list', 'search', 'labels', 'read', 'send'];
        if (!GMAIL_WHITELIST.includes(gmailAction)) {
          return JSON.stringify({ error: 'Invalid gmail action. Allowed: ' + GMAIL_WHITELIST.join(', ') });
        }
        if (!googleTokens) {
          return JSON.stringify({ error: 'Google not connected. Use the "Connect Google" button in the LIONO app to sign in.' });
        }
        // Use async wrapper since tool execution is synchronous but API calls are async
        try {
          var result = execSync('node -e "' +
            "var https=require('https');" +
            "var token=process.env._SC_TOKEN;" +
            "var action='" + gmailAction + "';" +
            "var args=" + JSON.stringify(args).replace(/"/g, '\\"') + ";" +
            // Simple inline Gmail API call
            "var opts={hostname:'gmail.googleapis.com',method:'GET',headers:{'Authorization':'Bearer '+token}};" +
            "if(action==='list'){opts.path='/gmail/v1/users/me/messages?maxResults='+(args.max_results||10);}" +
            "else if(action==='search'){opts.path='/gmail/v1/users/me/messages?q='+encodeURIComponent(args.query||'')+'&maxResults='+(args.max_results||10);}" +
            "else if(action==='labels'){opts.path='/gmail/v1/users/me/labels';}" +
            "else if(action==='read'&&args.message_id){opts.path='/gmail/v1/users/me/messages/'+args.message_id+'?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date';}" +
            "else if(action==='send'&&args.to){" +
              "var raw=Buffer.from('To: '+args.to+'\\r\\nSubject: '+(args.subject||'')+'\\r\\nContent-Type: text/plain; charset=utf-8\\r\\n\\r\\n'+(args.body||'')).toString('base64url');" +
              "opts.method='POST';opts.path='/gmail/v1/users/me/messages/send';opts.headers['Content-Type']='application/json';" +
              "var body=JSON.stringify({raw:raw});opts.headers['Content-Length']=Buffer.byteLength(body);" +
            "}" +
            "else{process.stdout.write(JSON.stringify({error:'Invalid action'}));process.exit(0);}" +
            "var req=https.request(opts,function(res){var d='';res.on('data',function(c){d+=c});res.on('end',function(){process.stdout.write(d.substring(0,5000))})});" +
            "req.on('error',function(e){process.stdout.write(JSON.stringify({error:e.message}))});" +
            "if(action==='send'&&args.to){req.write(body);}" +
            "req.end();" +
          '"', { timeout: 15000, encoding: 'utf8', env: Object.assign({}, process.env, { _SC_TOKEN: googleTokens.access_token }) });
          return result || JSON.stringify({ error: 'Empty response from Gmail API' });
        } catch (e) {
          return JSON.stringify({ error: 'Gmail API error: ' + e.message.substring(0, 200) });
        }
      }

      case 'calendar': {
        var calAction = args.action;
        var CAL_WHITELIST = ['list', 'upcoming', 'create'];
        if (!CAL_WHITELIST.includes(calAction)) {
          return JSON.stringify({ error: 'Invalid calendar action. Allowed: ' + CAL_WHITELIST.join(', ') });
        }
        if (!googleTokens) {
          return JSON.stringify({ error: 'Google not connected. Use the "Connect Google" button in the LIONO app to sign in.' });
        }
        try {
          var days = args.days || 7;
          var result = execSync('node -e "' +
            "var https=require('https');" +
            "var token=process.env._SC_TOKEN;" +
            "var action='" + calAction + "';" +
            "var args=" + JSON.stringify(args).replace(/"/g, '\\"') + ";" +
            "var opts={hostname:'www.googleapis.com',method:'GET',headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'}};" +
            "if(action==='list'||action==='upcoming'){" +
              "var now=new Date().toISOString();" +
              "var later=new Date(Date.now()+(args.days||7)*86400000).toISOString();" +
              "opts.path='/calendar/v3/calendars/primary/events?timeMin='+encodeURIComponent(now)+'&timeMax='+encodeURIComponent(later)+'&singleEvents=true&orderBy=startTime&maxResults=20';" +
            "}else if(action==='create'&&args.title){" +
              "opts.method='POST';opts.path='/calendar/v3/calendars/primary/events';" +
              "var body=JSON.stringify({summary:args.title,start:{dateTime:args.start||new Date(Date.now()+3600000).toISOString()},end:{dateTime:args.end||new Date(Date.now()+7200000).toISOString()}});" +
              "opts.headers['Content-Length']=Buffer.byteLength(body);" +
            "}else{process.stdout.write(JSON.stringify({error:'Invalid action'}));process.exit(0);}" +
            "var req=https.request(opts,function(res){var d='';res.on('data',function(c){d+=c});res.on('end',function(){process.stdout.write(d.substring(0,5000))})});" +
            "req.on('error',function(e){process.stdout.write(JSON.stringify({error:e.message}))});" +
            "if(action==='create'&&args.title){req.write(body);}" +
            "req.end();" +
          '"', { timeout: 15000, encoding: 'utf8', env: Object.assign({}, process.env, { _SC_TOKEN: googleTokens.access_token }) });
          return result || JSON.stringify({ error: 'Empty response from Calendar API' });
        } catch (e) {
          return JSON.stringify({ error: 'Calendar API error: ' + e.message.substring(0, 200) });
        }
      }

      case 'web_fetch': {
        var fetchUrl = args.url || '';
        if (!fetchUrl) return JSON.stringify({ error: 'URL is required' });
        try {
          var html = execSync('curl -sf -L -A "Mozilla/5.0" ' + JSON.stringify(fetchUrl) + ' 2>/dev/null | head -c 50000', { timeout: 15000, encoding: 'utf8' });
          var text = html.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
          return text.substring(0, 8000) || 'Empty page';
        } catch (e) {
          return JSON.stringify({ error: 'Failed to fetch: ' + e.message.substring(0, 200) });
        }
      }

      case 'exec_command': {
        var cmd = args.command || '';
        if (!cmd) return JSON.stringify({ error: 'Command is required' });
        var timeout = Math.min((args.timeout || 30) * 1000, 120000);
        try {
          var output = execSync(cmd, { timeout: timeout, encoding: 'utf8', cwd: DATA_DIR });
          return output.substring(0, 10000) || '(no output)';
        } catch (e) {
          return JSON.stringify({ exitCode: e.status, stderr: (e.stderr || '').substring(0, 2000), stdout: (e.stdout || '').substring(0, 2000) });
        }
      }

      case 'process_manage': {
        var pAction = args.action;
        if (pAction === 'list') {
          try {
            var ps = execSync('ps aux --sort=-%mem | head -20', { timeout: 5000, encoding: 'utf8' });
            return ps;
          } catch (e) { return JSON.stringify({ error: e.message }); }
        } else if (pAction === 'kill' && args.pid) {
          try { process.kill(args.pid); return JSON.stringify({ killed: args.pid }); }
          catch (e) { return JSON.stringify({ error: e.message }); }
        }
        return JSON.stringify({ error: 'Unknown process action' });
      }

      case 'hackernews_digest': {
        var hnCount = Math.min(args.count || 10, 30);
        var HN_TYPE_WHITELIST = ['top', 'new', 'best', 'ask', 'show', 'job'];
        var hnType = args.type || 'top';
        if (!HN_TYPE_WHITELIST.includes(hnType)) {
          return JSON.stringify({ error: 'Invalid type. Allowed: ' + HN_TYPE_WHITELIST.join(', ') });
        }
        try {
          var hnJson = execSync('curl -sf "https://hacker-news.firebaseio.com/v0/' + hnType + 'stories.json" 2>/dev/null', { timeout: 10000, encoding: 'utf8' });
          var hnIds = JSON.parse(hnJson).slice(0, hnCount);
          var stories = [];
          hnIds.slice(0, 10).forEach(function (storyId) {
            try {
              var s = JSON.parse(execSync('curl -sf "https://hacker-news.firebaseio.com/v0/item/' + storyId + '.json" 2>/dev/null', { timeout: 5000, encoding: 'utf8' }));
              stories.push({ title: s.title, url: s.url, score: s.score, by: s.by, comments: s.descendants || 0 });
            } catch (e) {}
          });
          return JSON.stringify({ type: hnType, stories: stories });
        } catch (e) { return JSON.stringify({ error: 'HN fetch error: ' + e.message }); }
      }

      case 'stock_ticker': {
        var sym = (args.symbol || '').toUpperCase().replace(/[^A-Z0-9.]/g, '');
        if (!sym) return JSON.stringify({ error: 'Invalid symbol' });
        try {
          var stockHtml = execSync('curl -sf -L "https://finance.yahoo.com/quote/' + sym + '/" -A "Mozilla/5.0" 2>/dev/null | head -c 50000', { timeout: 10000, encoding: 'utf8' });
          var priceMatch = stockHtml.match(/data-field="regularMarketPrice"[^>]*value="([^"]+)"/);
          var changeMatch = stockHtml.match(/data-field="regularMarketChange"[^>]*value="([^"]+)"/);
          return JSON.stringify({ symbol: sym, price: priceMatch ? priceMatch[1] : 'N/A', change: changeMatch ? changeMatch[1] : 'N/A' });
        } catch (e) { return JSON.stringify({ symbol: sym, error: 'Could not fetch quote' }); }
      }

      case 'convert_currency': {
        var amt = args.amount || 0;
        var fromC = (args.from || 'USD').toUpperCase();
        var toC = (args.to || 'EUR').toUpperCase();
        try {
          var rateJson = execSync('curl -sf "https://open.er-api.com/v6/latest/' + fromC + '" 2>/dev/null', { timeout: 10000, encoding: 'utf8' });
          var rates = JSON.parse(rateJson);
          if (rates.rates && rates.rates[toC]) {
            var converted = amt * rates.rates[toC];
            return JSON.stringify({ amount: amt, from: fromC, to: toC, rate: rates.rates[toC], result: Math.round(converted * 100) / 100 });
          }
          return JSON.stringify({ error: 'Currency not found: ' + toC });
        } catch (e) { return JSON.stringify({ error: 'Exchange rate error: ' + e.message }); }
      }

      case 'github_trending': {
        var lang = args.language || '';
        var since = args.since || 'daily';
        try {
          var ghUrl = 'https://github.com/trending' + (lang ? '/' + encodeURIComponent(lang) : '') + '?since=' + since;
          var ghHtml = execSync('curl -sf -L ' + JSON.stringify(ghUrl) + ' -A "Mozilla/5.0" 2>/dev/null | head -c 100000', { timeout: 10000, encoding: 'utf8' });
          var repos = [];
          var repoRe = /href="\/([^"]+\/[^"]+)"[^>]*class="[^"]*Link[^"]*"/g;
          var rm;
          while ((rm = repoRe.exec(ghHtml)) !== null && repos.length < 15) {
            var rname = rm[1];
            if (rname.indexOf('/') > 0 && !rname.includes('/issues') && !rname.includes('/pull')) {
              if (repos.indexOf(rname) === -1) repos.push(rname);
            }
          }
          return JSON.stringify({ language: lang || 'all', since: since, repos: repos });
        } catch (e) { return JSON.stringify({ error: 'GitHub trending error: ' + e.message }); }
      }

      case 'validate_json': {
        try { var parsed = JSON.parse(args.json); return JSON.stringify(parsed, null, 2); }
        catch (e) { return JSON.stringify({ valid: false, error: e.message }); }
      }

      case 'base64_codec': {
        if (args.action === 'encode') return Buffer.from(args.text || '').toString('base64');
        if (args.action === 'decode') return Buffer.from(args.text || '', 'base64').toString('utf8');
        return JSON.stringify({ error: 'Unknown base64 action' });
      }

      case 'generate_uuid': {
        var count = Math.min(args.count || 1, 50);
        var uuids = [];
        for (var u = 0; u < count; u++) {
          uuids.push(crypto.randomUUID());
        }
        return uuids.length === 1 ? uuids[0] : JSON.stringify(uuids);
      }

      case 'generate_password': {
        var pwLen = Math.min(args.length || 20, 128);
        var pwCount = Math.min(args.count || 1, 10);
        var useSymbols = args.symbols !== false;
        var charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        if (useSymbols) charset += '!@#$%^&*()-_=+[]{}|;:,.<>?';
        var pws = [];
        for (var p = 0; p < pwCount; p++) {
          var pw = '';
          for (var i = 0; i < pwLen; i++) pw += charset[crypto.randomInt(0, charset.length)];
          pws.push(pw);
        }
        return pws.length === 1 ? pws[0] : JSON.stringify(pws);
      }

      case 'generate_qr': {
        var qrData = encodeURIComponent(args.data || '');
        var qrSize = args.size || 300;
        return JSON.stringify({ url: 'https://api.qrserver.com/v1/create-qr-code/?size=' + qrSize + 'x' + qrSize + '&data=' + qrData });
      }

      case 'scan_ports': {
        var targetHost = (args.host || '').replace(/[^a-zA-Z0-9.-]/g, '');
        if (!targetHost) return JSON.stringify({ error: 'Invalid host' });
        var portList = (args.ports || '80,443').split(',').map(function (p) { return parseInt(p.trim(), 10); }).filter(function (p) { return !isNaN(p) && p >= 1 && p <= 65535; }).slice(0, 20);
        var portResults = [];
        portList.forEach(function (port) {
          try {
            execSync('timeout 2 bash -c "echo >/dev/tcp/' + targetHost + '/' + port + '" 2>/dev/null', { timeout: 3000 });
            portResults.push({ port: port, status: 'open' });
          } catch (e) {
            portResults.push({ port: port, status: 'closed' });
          }
        });
        return JSON.stringify({ host: targetHost, results: portResults });
      }

      case 'whois_lookup': {
        var whoisDomain = (args.domain || '').replace(/[^a-zA-Z0-9.-]/g, '');
        if (!whoisDomain) return JSON.stringify({ error: 'Invalid domain' });
        try {
          var whoisResult = execSync('whois ' + whoisDomain + ' 2>/dev/null | head -80', { timeout: 10000, encoding: 'utf8' });
          return whoisResult || 'No WHOIS data found';
        } catch (e) { return JSON.stringify({ error: 'WHOIS lookup failed: ' + e.message.substring(0, 200) }); }
      }

      case 'ip_info': {
        var targetIp = args.ip || '';
        try {
          var ipUrl = targetIp ? 'http://ip-api.com/json/' + targetIp : 'http://ip-api.com/json/';
          var ipResult = execSync('curl -sf ' + JSON.stringify(ipUrl) + ' 2>/dev/null', { timeout: 10000, encoding: 'utf8' });
          return ipResult;
        } catch (e) { return JSON.stringify({ error: 'IP info error: ' + e.message }); }
      }

      case 'dns_lookup': {
        var dnsDomain = (args.domain || '').replace(/[^a-zA-Z0-9.-]/g, '');
        if (!dnsDomain) return JSON.stringify({ error: 'Invalid domain' });
        var DNS_TYPE_WHITELIST = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'ANY', 'ALL'];
        var dnsType = (args.type || 'ALL').toUpperCase();
        if (!DNS_TYPE_WHITELIST.includes(dnsType)) {
          return JSON.stringify({ error: 'Invalid DNS type. Allowed: ' + DNS_TYPE_WHITELIST.join(', ') });
        }
        try {
          var dnsCmd = dnsType === 'ALL'
            ? 'dig ' + dnsDomain + ' ANY +short 2>/dev/null; dig ' + dnsDomain + ' MX +short 2>/dev/null'
            : 'dig ' + dnsDomain + ' ' + dnsType + ' +short 2>/dev/null';
          var dnsResult = execSync(dnsCmd, { timeout: 10000, encoding: 'utf8' });
          return dnsResult || 'No records found';
        } catch (e) { return JSON.stringify({ error: 'DNS lookup failed: ' + e.message.substring(0, 200) }); }
      }

      case 'file_manage': {
        var fAction = args.action;
        var fPath = path.resolve(DATA_DIR, args.path || '');
        var dataDirResolved = path.resolve(DATA_DIR);
        if (fPath !== dataDirResolved && !fPath.startsWith(dataDirResolved + path.sep)) return JSON.stringify({ error: 'Path outside workspace' });
        try {
          if (fAction === 'list') { return JSON.stringify(fs.readdirSync(fPath)); }
          if (fAction === 'read') { return fs.readFileSync(fPath, 'utf8').substring(0, 20000); }
          if (fAction === 'write') { fs.writeFileSync(fPath, args.content || ''); return JSON.stringify({ written: fPath }); }
          if (fAction === 'delete') { fs.unlinkSync(fPath); return JSON.stringify({ deleted: fPath }); }
          if (fAction === 'mkdir') { fs.mkdirSync(fPath, { recursive: true }); return JSON.stringify({ created: fPath }); }
          if (fAction === 'search') { var grepR = execSync('grep -rl ' + JSON.stringify(args.pattern || '') + ' ' + JSON.stringify(DATA_DIR) + ' 2>/dev/null | head -20', { timeout: 5000, encoding: 'utf8' }); return grepR || 'No matches'; }
        } catch (e) { return JSON.stringify({ error: e.message }); }
        return JSON.stringify({ error: 'Unknown file action' });
      }

      case 'text_transform': {
        var tAction = args.action;
        var tText = args.text || '';
        if (tAction === 'wordcount') return JSON.stringify({ words: tText.split(/\s+/).filter(Boolean).length, chars: tText.length, lines: tText.split('\n').length });
        if (tAction === 'uppercase') return tText.toUpperCase();
        if (tAction === 'lowercase') return tText.toLowerCase();
        if (tAction === 'titlecase') return tText.replace(/\w\S*/g, function (t) { return t.charAt(0).toUpperCase() + t.substr(1).toLowerCase(); });
        if (tAction === 'extract_emails') { var emails = tText.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g); return JSON.stringify(emails || []); }
        if (tAction === 'extract_urls') { var urls = tText.match(/https?:\/\/[^\s<>"']+/g); return JSON.stringify(urls || []); }
        if (tAction === 'find_replace') return tText.split(args.find || '').join(args.replace || '');
        if (tAction === 'slug') return tText.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
        if (tAction === 'hash') { var crypto = require('crypto'); return JSON.stringify({ md5: crypto.createHash('md5').update(tText).digest('hex'), sha256: crypto.createHash('sha256').update(tText).digest('hex') }); }
        if (tAction === 'lorem') { var lp = args.paragraphs || 1; var lorem = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.'; var out = []; for (var li = 0; li < lp; li++) out.push(lorem); return out.join('\n\n'); }
        return JSON.stringify({ error: 'Unknown transform action' });
      }

      case 'convert_units': {
        var val = args.value || 0;
        var fromU = (args.from || '').toLowerCase();
        var toU = (args.to || '').toLowerCase();
        var conversions = {
          'km_miles': 0.621371, 'miles_km': 1.60934,
          'kg_lbs': 2.20462, 'lbs_kg': 0.453592,
          'celsius_fahrenheit': function (v) { return v * 9/5 + 32; },
          'fahrenheit_celsius': function (v) { return (v - 32) * 5/9; },
          'l_gal': 0.264172, 'gal_l': 3.78541,
          'm_ft': 3.28084, 'ft_m': 0.3048,
          'cm_in': 0.393701, 'in_cm': 2.54,
          'gb_mb': 1024, 'mb_gb': 1/1024,
          'tb_gb': 1024, 'gb_tb': 1/1024,
          'kph_mph': 0.621371, 'mph_kph': 1.60934
        };
        var key = fromU + '_' + toU;
        if (conversions[key]) {
          var result = typeof conversions[key] === 'function' ? conversions[key](val) : val * conversions[key];
          return JSON.stringify({ value: val, from: fromU, to: toU, result: Math.round(result * 10000) / 10000 });
        }
        return JSON.stringify({ error: 'Unknown conversion: ' + fromU + ' to ' + toU });
      }

      case 'summarize':
      case 'writing_assist':
      case 'code_assist':
      case 'sessions_spawn':
      case 'cron_manage':
      case 'analyze_image':
      case 'web_browse':
      case 'youtube_transcript':
      case 'google_drive': {
        return JSON.stringify({ note: 'This skill is handled natively by the LLM. The model processes the request directly using its built-in capabilities.' });
      }

      default:
        return JSON.stringify({ error: 'Unknown tool: ' + name });
    }
  } catch (e) {
    return JSON.stringify({ error: 'Tool execution error: ' + e.message });
  }
}

// ══════════════════════════════════════════════════════════════
//  Sub-Agent Spawning
// ══════════════════════════════════════════════════════════════

// sessions_spawn tool definition (added to LLM tools when agent has subagent delegation)
var SESSIONS_SPAWN_TOOL = {
  type: 'function',
  function: {
    name: 'sessions_spawn',
    description: 'Spawn a sub-agent to handle a task in the background. The sub-agent runs independently and reports back when done. Use this to delegate specific tasks to specialized agents (e.g. research, data gathering, code review) while you continue helping the user.',
    parameters: {
      type: 'object',
      properties: {
        task: { type: 'string', description: 'Clear description of the task for the sub-agent to complete' },
        agentId: { type: 'string', description: 'ID of the agent to spawn (use agents_list to discover available agents). Defaults to the current agent.' },
        label: { type: 'string', description: 'Short label for this sub-agent run (e.g. "research", "weather check")' }
      },
      required: ['task']
    }
  }
};

/**
 * Spawn a sub-agent run. The sub-agent gets its own session and runs chatWithLLM
 * independently. When done, it announces back to the parent via a WebSocket event.
 */
function spawnSubagent(ws, parentSessionKey, parentRunId, task, targetAgentId, label, seqCounterRef) {
  var subRunId = uuid();
  var childAgent = agents.find(function (a) { return a.id === targetAgentId; }) || agents[0];
  var childSessionKey = parentSessionKey + '::subagent:' + subRunId.substring(0, 8);

  var run = {
    runId: subRunId,
    parentSessionKey: parentSessionKey,
    parentRunId: parentRunId,
    childSessionKey: childSessionKey,
    agentId: childAgent.id,
    agentName: childAgent.identity ? childAgent.identity.name : childAgent.name || childAgent.id,
    agentEmoji: childAgent.identity ? childAgent.identity.emoji : null,
    task: task,
    label: label || task.substring(0, 40),
    status: 'running',
    startedAt: Date.now(),
    finishedAt: null,
    result: null,
    error: null
  };
  subagentRuns[subRunId] = run;

  // Notify client: subagent spawned
  sendEvent(ws, 'subagent', {
    type: 'spawned',
    runId: subRunId,
    parentSessionKey: parentSessionKey,
    parentRunId: parentRunId,
    childSessionKey: childSessionKey,
    agentId: childAgent.id,
    agentName: run.agentName,
    agentEmoji: run.agentEmoji,
    task: task,
    label: run.label,
    status: 'running',
    startedAt: run.startedAt
  }, ++seqCounterRef.val);

  // Create child session
  sessions[childSessionKey] = {
    key: childSessionKey,
    label: run.label,
    agentId: childAgent.id,
    channel: 'subagent',
    parentSessionKey: parentSessionKey,
    updatedAt: Date.now()
  };
  sessionHistory[childSessionKey] = [];

  // Build sub-agent system prompt
  var subSystemPrompt = '';
  if (childAgent.systemPrompt && childAgent.systemPrompt.trim()) {
    subSystemPrompt = childAgent.systemPrompt + '\n\n';
  } else {
    subSystemPrompt = 'You are ' + (childAgent.identity ? childAgent.identity.name : 'an assistant') + '.\n\n';
  }
  subSystemPrompt += 'You are running as a sub-agent. Complete the following task concisely and thoroughly.\n';
  subSystemPrompt += 'When finished, provide a clear summary of your findings or results.\n\n';

  // Add the task as the user message
  sessionHistory[childSessionKey].push({ role: 'user', content: task });

  var childSkills = childAgent.skills || ['web-search', 'summarizer', 'code-assist', 'math-solver', 'weather'];

  // Stream progress events
  chatWithLLM(
    sessionHistory[childSessionKey],
    subSystemPrompt,
    childAgent.model || DEFAULT_MODEL,
    childSkills,
    // stream callback — send progress updates
    function (chunk) {
      // Send periodic progress (every few chunks)
      run.result = (run.result || '') + chunk;
      sendEvent(ws, 'subagent', {
        type: 'progress',
        runId: subRunId,
        parentSessionKey: parentSessionKey,
        text: run.result
      }, ++seqCounterRef.val);
    },
    // done callback — announce result
    function (err, fullText) {
      if (err) {
        run.status = 'error';
        run.error = err.message;
        run.result = 'Error: ' + err.message;
      } else {
        run.status = 'done';
        run.result = fullText || '';
      }
      run.finishedAt = Date.now();
      subagentRuns[subRunId] = run;

      sessionHistory[childSessionKey].push({ role: 'assistant', content: fullText || '' });
      saveSessions();

      // Announce back to parent
      sendEvent(ws, 'subagent', {
        type: 'announce',
        runId: subRunId,
        parentSessionKey: parentSessionKey,
        parentRunId: parentRunId,
        childSessionKey: childSessionKey,
        agentId: childAgent.id,
        agentName: run.agentName,
        agentEmoji: run.agentEmoji,
        task: task,
        label: run.label,
        status: run.status,
        result: run.result,
        error: run.error,
        startedAt: run.startedAt,
        finishedAt: run.finishedAt,
        runtimeMs: run.finishedAt - run.startedAt
      }, ++seqCounterRef.val);
    },
    null // no tool callback for sub-agents (keep it simple)
  );

  return { status: 'accepted', runId: subRunId, childSessionKey: childSessionKey };
}

// ══════════════════════════════════════════════════════════════
//  OpenRouter LLM Chat (with tool-calling loop)
// ══════════════════════════════════════════════════════════════

function getToolsForSkills(skills) {
  var tools = [];
  var added = {};
  (skills || []).forEach(function (skillId) {
    var tool = SKILL_TOOLS[skillId];
    if (tool && !added[tool.function.name]) {
      tools.push(tool);
      added[tool.function.name] = true;
    }
  });
  // Skills that the LLM handles natively (no tool needed):
  // summarizer, code-assist, writing-assist, grammar-check, research-assist,
  // data-analyst, json-formatter, task-planner, document-reader, image-describe,
  // news-digest, travel-planner, finance-tracker, social-media, email-compose,
  // meeting-notes, pdf-reader, spreadsheet
  return tools;
}

function chatWithLLM(messages, systemPrompt, model, skills, streamCallback, doneCallback, toolCallback, spawnContext) {
  if (!OPENROUTER_KEY) {
    doneCallback(null, 'I am your LIONO AI assistant. The gateway is running but no OpenRouter API key is configured yet.\n\nTo enable AI:\n1. Get a key at https://openrouter.ai\n2. Add it to /home/liono/.liono/config.json under llm.apiKey\n3. Restart the gateway: sudo systemctl restart liono');
    return;
  }

  var tools = getToolsForSkills(skills);
  // If spawn context is provided, add the sessions_spawn tool so the LLM can delegate
  if (spawnContext && agents.length > 1) {
    tools.push(SESSIONS_SPAWN_TOOL);
  }
  var callMessages = [];
  if (systemPrompt) callMessages.push({ role: 'system', content: systemPrompt });
  callMessages = callMessages.concat(messages);

  var maxToolRounds = 5;
  var toolRound = 0;

  function doRequest() {
    toolRound++;
    recursing = false;
    var body = {
      model: model || DEFAULT_MODEL,
      messages: callMessages,
      stream: true,
      max_tokens: 4096,
    };
    if (tools.length > 0 && toolRound <= maxToolRounds) {
      body.tools = tools;
    }

    var bodyStr = JSON.stringify(body);
    var options = {
      hostname: 'openrouter.ai',
      port: 443,
      path: '/api/v1/chat/completions',
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + OPENROUTER_KEY,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://lionoai.com',
        'X-Title': 'LIONO Gateway',
        'Content-Length': Buffer.byteLength(bodyStr),
      },
    };

    var fullText = '';
    var toolCalls = [];
    var currentToolCall = null;
    var sentDone = false;
    var recursing = false;

    var req = https.request(options, function (res) {
      var buffer = '';

      if (res.statusCode !== 200) {
        var errBody = '';
        res.on('data', function (chunk) { errBody += chunk; });
        res.on('end', function () {
          var errMsg = 'OpenRouter API error (HTTP ' + res.statusCode + ')';
          try { errMsg = JSON.parse(errBody).error.message || errMsg; } catch (e) { }
          doneCallback(new Error(errMsg));
        });
        return;
      }

      res.on('data', function (chunk) {
        buffer += chunk.toString();
        var lines = buffer.split('\n');
        buffer = lines.pop();

        for (var i = 0; i < lines.length; i++) {
          var line = lines[i].trim();
          if (!line || line.startsWith(':')) continue;
          if (!line.startsWith('data: ')) continue;
          var data = line.slice(6);
          if (data === '[DONE]') {
            // Check if we have tool calls to execute
            if (toolCalls.length > 0 && toolRound <= maxToolRounds) {
              // Add assistant message with tool calls
              callMessages.push({
                role: 'assistant',
                content: fullText || null,
                tool_calls: toolCalls.map(function (tc) {
                  return { id: tc.id, type: 'function', function: { name: tc.name, arguments: tc.arguments } };
                })
              });

              // Execute each tool and add results
              toolCalls.forEach(function (tc) {
                var toolArgs;
                try { toolArgs = JSON.parse(tc.arguments); } catch (e) { toolArgs = {}; }
                // Notify tool usage via the toolCallback (not in the text stream)
                if (typeof toolCallback === 'function') {
                  toolCallback({ name: tc.name, phase: 'start', toolCallId: tc.id });
                }
                var result;
                // Handle sessions_spawn specially — needs WebSocket context
                if (tc.name === 'sessions_spawn' && spawnContext) {
                  var targetAgentId = toolArgs.agentId || spawnContext.agentId || 'default';
                  var spawnResult = spawnSubagent(
                    spawnContext.ws,
                    spawnContext.sessionKey,
                    spawnContext.runId,
                    toolArgs.task || '',
                    targetAgentId,
                    toolArgs.label || null,
                    spawnContext.seqRef
                  );
                  result = JSON.stringify(spawnResult);
                } else {
                  result = executeToolCall(tc.name, toolArgs);
                }
                if (typeof toolCallback === 'function') {
                  toolCallback({ name: tc.name, phase: 'result', toolCallId: tc.id, result: result });
                }
                callMessages.push({ role: 'tool', tool_call_id: tc.id, content: result });
              });

              // Stream a separator so text doesn't run together between rounds
              if (fullText && fullText.length > 0) {
                streamCallback('\n\n');
              }

              // Reset and call LLM again with tool results
              fullText = '';
              toolCalls = [];
              currentToolCall = null;
              recursing = true;
              doRequest();
              return;
            }

            if (!sentDone) {
              sentDone = true;
              doneCallback(null, fullText);
            }
            return;
          }

          try {
            var parsed = JSON.parse(data);
            var choice = parsed.choices && parsed.choices[0];
            if (!choice) continue;
            var delta = choice.delta;
            if (!delta) continue;

            // Handle text content
            if (delta.content) {
              fullText += delta.content;
              streamCallback(delta.content);
            }

            // Handle tool calls
            if (delta.tool_calls) {
              delta.tool_calls.forEach(function (tc) {
                if (tc.index !== undefined) {
                  while (toolCalls.length <= tc.index) {
                    toolCalls.push({ id: '', name: '', arguments: '' });
                  }
                  if (tc.id) toolCalls[tc.index].id = tc.id;
                  if (tc.function) {
                    if (tc.function.name) toolCalls[tc.index].name = tc.function.name;
                    if (tc.function.arguments) toolCalls[tc.index].arguments += tc.function.arguments;
                  }
                }
              });
            }
          } catch (e) { /* skip unparseable */ }
        }
      });

      res.on('end', function () {
        // If we already started a recursive tool-call round, ignore this end event
        if (recursing) return;

        // Handle tool calls from non-streaming completion
        if (toolCalls.length > 0 && toolRound <= maxToolRounds) {
          callMessages.push({
            role: 'assistant',
            content: fullText || null,
            tool_calls: toolCalls.map(function (tc) {
              return { id: tc.id, type: 'function', function: { name: tc.name, arguments: tc.arguments } };
            })
          });
          toolCalls.forEach(function (tc) {
            var toolArgs;
            try { toolArgs = JSON.parse(tc.arguments); } catch (e) { toolArgs = {}; }
            if (typeof toolCallback === 'function') {
              toolCallback({ name: tc.name, phase: 'start', toolCallId: tc.id });
            }
            var result;
            if (tc.name === 'sessions_spawn' && spawnContext) {
              var targetAgentId2 = toolArgs.agentId || spawnContext.agentId || 'default';
              var spawnResult2 = spawnSubagent(
                spawnContext.ws, spawnContext.sessionKey, spawnContext.runId,
                toolArgs.task || '', targetAgentId2, toolArgs.label || null, spawnContext.seqRef
              );
              result = JSON.stringify(spawnResult2);
            } else {
              result = executeToolCall(tc.name, toolArgs);
            }
            if (typeof toolCallback === 'function') {
              toolCallback({ name: tc.name, phase: 'result', toolCallId: tc.id, result: result });
            }
            callMessages.push({ role: 'tool', tool_call_id: tc.id, content: result });
          });

          // Stream a separator so text doesn't run together between rounds
          if (fullText && fullText.length > 0) {
            streamCallback('\n\n');
          }

          fullText = '';
          toolCalls = [];
          recursing = true;
          doRequest();
          return;
        }
        if (!sentDone) {
          sentDone = true;
          doneCallback(null, fullText);
        }
      });
    });

    req.on('error', function (err) {
      doneCallback(err);
    });

    req.write(bodyStr);
    req.end();
  }

  doRequest();
}

// ══════════════════════════════════════════════════════════════
//  WebSocket Server
// ══════════════════════════════════════════════════════════════

var wss = new WebSocketServer({ host: HOST, port: PORT });
console.log('[Gateway] LIONO gateway listening on ' + HOST + ':' + PORT);
console.log('[Gateway] Plan: ' + PLAN + ' | Token: ' + (TOKEN ? TOKEN.substring(0, 8) + '...' : 'none'));
console.log('[Gateway] LLM: ' + (OPENROUTER_KEY ? 'OpenRouter (' + DEFAULT_MODEL + ')' + (USER_OPENROUTER_KEY ? ' [user key]' : ' [platform key]') : 'NOT CONFIGURED'));
console.log('[Gateway] Skills: ' + Object.keys(SKILL_TOOLS).length + ' tool-backed skills loaded');
console.log('[Gateway] Google: ' + (GOOGLE_WEB_CLIENT_ID ? 'Web client configured (Auth Code Flow)' : (GOOGLE_CLIENT_ID ? 'Device Flow client configured' : 'No client ID')) + ' | ' + (googleTokens ? 'Connected as ' + (googleTokens.email || 'unknown') : 'Not connected'));
console.log('[Gateway] Playwright: ' + (playwrightAvailable ? 'Available' : 'Not installed'));

wss.on('connection', function (ws) {
  var authenticated = false;
  var clientInfo = null;
  var instanceId = uuid();
  var seqCounter = 0;

  var nonce = crypto.randomBytes(16).toString('hex');
  sendEvent(ws, 'connect.challenge', { nonce: nonce });

  ws.on('message', function (raw) {
    var msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    var msgType = msg.type;
    var method = msg.method;
    var id = msg.id;
    var params = msg.params || {};

    if (method && method !== 'google.browser.frame') {
      console.log('[RPC] ← ' + method + ' (id=' + (id || 'none').toString().substring(0,8) + ')');
    }

    if (msgType === 'req' || (id !== undefined && method)) {

      // ── connect ──
      if (method === 'connect') {
        var authObj = params.auth || {};
        var providedToken = authObj.token || '';
        if (!TOKEN || providedToken !== TOKEN) {
          sendRes(ws, id, false, null, { code: 'AUTH_FAILED', message: 'Invalid authentication token' });
          setTimeout(function () { ws.close(); }, 100);
          return;
        }
        authenticated = true;
        clientInfo = params.client || {};

        sendRes(ws, id, true, {
          type: 'hello-ok',
          protocol: 3,
          features: {
            methods: ['sessions.list', 'subagents.list', 'agents.list', 'agents.files.get', 'agents.create', 'agents.update', 'agents.delete', 'chat.send', 'chat.history', 'health', 'system-presence',
                       'skills.list', 'skills.install', 'skills.uninstall',
                       'gateway.version', 'gateway.update',
                       'cron.list', 'cron.add', 'cron.update', 'cron.delete', 'cron.run',
                       'tasks.list', 'tasks.create', 'tasks.update', 'tasks.delete', 'tasks.run',
                       'user.profile.set', 'user.profile.get', 'user.apikey.set', 'user.apikey.get',
                       'gateway.model.get', 'gateway.model.set', 'models.list',
                       'google.auth.start', 'google.auth.poll', 'google.auth.status', 'google.auth.revoke', 'google.auth.exchange',
                       'google.project.create', 'google.project.credentials',
                       'google.browser.install', 'google.browser.start', 'google.browser.autosetup', 'google.browser.frame', 'google.browser.click', 'google.browser.type', 'google.browser.key', 'google.browser.automate', 'google.browser.stop'],
            events: ['presence', 'snapshot', 'chat', 'agent', 'subagent', 'google.project', 'google.browser']
          },
          snapshot: {
            presence: [{
              instanceId: instanceId,
              host: os.hostname(),
              ip: HOST,
              version: GATEWAY_VERSION,
              platform: 'linux',
              deviceFamily: 'server',
              roles: ['gateway'],
              connectedAtMs: now()
            }],
            health: { ok: true, version: GATEWAY_VERSION, uptimeMs: now() - startTime, nodes: [] },
            sessionDefaults: { defaultAgentId: 'default' }
          },
          auth: {
            deviceToken: uuid(),
            role: 'operator',
            scopes: ['operator.admin', 'operator.approvals', 'operator.pairing'],
            issuedAtMs: now()
          },
          policy: { tickIntervalMs: 5000 }
        });
        return;
      }

      if (!authenticated) {
        sendRes(ws, id, false, null, { code: 'NOT_AUTHENTICATED', message: 'Connect first' });
        return;
      }

      // ── agents.list ──
      if (method === 'agents.list') {
        sendRes(ws, id, true, { defaultId: 'default', mainKey: 'default', scope: 'all', agents: agents });
        return;
      }

      // ── agents.files.get ──
      if (method === 'agents.files.get') {
        var agentId = params.agentId || 'default';
        var fileName = params.name || '';
        if (fileName === 'IDENTITY.md') {
          var agent = agents.find(function (a) { return a.id === agentId; }) || agents[0];
          sendRes(ws, id, true, { file: { name: 'IDENTITY.md', content: '# ' + agent.identity.name + '\n\n' + agent.identity.theme + '\n' } });
        } else {
          sendRes(ws, id, false, null, { code: 'NOT_FOUND', message: 'File not found' });
        }
        return;
      }

      // ── user.profile.set — Save user preferences and memories ──
      if (method === 'user.profile.set') {
        if (params.preferences) userProfile.preferences = params.preferences;
        if (params.botName !== undefined) userProfile.botName = params.botName;
        if (params.addMemory) {
          if (!userProfile.memories) userProfile.memories = [];
          userProfile.memories.push(params.addMemory);
          // Keep last 100 memories
          if (userProfile.memories.length > 100) userProfile.memories = userProfile.memories.slice(-100);
        }
        if (params.removeMemory !== undefined && userProfile.memories) {
          userProfile.memories = userProfile.memories.filter(function (m, idx) {
            return idx !== params.removeMemory && m !== params.removeMemory;
          });
        }
        if (params.memories) {
          userProfile.memories = params.memories;
        }
        saveUserProfile();

        // If bot name changed, update default agent identity
        if (params.botName && agents.length > 0) {
          agents[0].identity.name = params.botName;
          try { fs.writeFileSync(agentsFile, JSON.stringify(agents, null, 2)); } catch (e) { /* ok */ }
        }

        console.log('[Gateway] User profile updated (' + Object.keys(userProfile.preferences).length + ' preferences, ' + (userProfile.memories || []).length + ' memories)');
        sendRes(ws, id, true, { saved: true, profileSize: Object.keys(userProfile.preferences).length, memoryCount: (userProfile.memories || []).length });
        return;
      }

      // ── user.profile.get — Retrieve user profile ──
      if (method === 'user.profile.get') {
        sendRes(ws, id, true, {
          preferences: userProfile.preferences || {},
          botName: userProfile.botName || '',
          memories: userProfile.memories || [],
          contextPreview: buildUserContext(),
        });
        return;
      }

      // ── user.apikey.set — Allow user to provide their own OpenRouter key ──
      if (method === 'user.apikey.set') {
        var newKey = params.openRouterKey || '';
        try {
          var cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
          if (!cfg.llm) cfg.llm = {};
          if (newKey) {
            cfg.llm.userApiKey = newKey;
            USER_OPENROUTER_KEY = newKey;
            OPENROUTER_KEY = newKey;
          } else {
            delete cfg.llm.userApiKey;
            USER_OPENROUTER_KEY = '';
            OPENROUTER_KEY = PLATFORM_OPENROUTER_KEY;
          }
          fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2));
          console.log('[Gateway] User API key ' + (newKey ? 'set (using personal key)' : 'cleared (using platform key)'));
          sendRes(ws, id, true, { saved: true, usingPersonalKey: !!newKey });
        } catch (e) {
          sendRes(ws, id, false, null, { code: 'SAVE_FAILED', message: e.message });
        }
        return;
      }

      // ── user.apikey.get — Check API key status ──
      if (method === 'user.apikey.get') {
        sendRes(ws, id, true, {
          usingPersonalKey: !!USER_OPENROUTER_KEY,
          keyPreview: USER_OPENROUTER_KEY ? USER_OPENROUTER_KEY.slice(0, 8) + '...' : null,
          platformKeyConfigured: !!PLATFORM_OPENROUTER_KEY,
        });
        return;
      }

      // ── gateway.model.get — Get current default model ──
      if (method === 'gateway.model.get') {
        sendRes(ws, id, true, {
          defaultModel: DEFAULT_MODEL,
          agents: agents.map(function (a) {
            return { id: a.id, name: a.name || a.id, model: a.model || '' };
          }),
        });
        return;
      }

      // ── gateway.model.set — Set the default model ──
      if (method === 'gateway.model.set') {
        var newModel = params.model || '';
        if (!newModel) {
          sendRes(ws, id, false, null, { code: 'MISSING_MODEL', message: 'model parameter required' });
          return;
        }
        try {
          var cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
          if (!cfg.llm) cfg.llm = {};
          cfg.llm.model = newModel;
          fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2));
          DEFAULT_MODEL = newModel;
          console.log('[Gateway] Default model changed to: ' + newModel);
          sendRes(ws, id, true, { saved: true, defaultModel: newModel });
        } catch (e) {
          sendRes(ws, id, false, null, { code: 'SAVE_FAILED', message: e.message });
        }
        return;
      }

      // ── models.list — Proxy the OpenRouter models catalog ──
      if (method === 'models.list') {
        var https = require('https');
        var modelsReq = https.request({
          hostname: 'openrouter.ai',
          port: 443,
          path: '/api/v1/models',
          method: 'GET',
          headers: { 'Accept': 'application/json' },
        }, function (modelsRes) {
          var chunks = [];
          modelsRes.on('data', function (c) { chunks.push(c); });
          modelsRes.on('end', function () {
            try {
              var body = JSON.parse(Buffer.concat(chunks).toString());
              var models = (body.data || []).map(function (m) {
                return {
                  id: m.id,
                  name: m.name,
                  contextLength: m.context_length,
                  pricing: {
                    prompt: m.pricing && m.pricing.prompt,
                    completion: m.pricing && m.pricing.completion,
                  },
                  architecture: m.architecture && m.architecture.modality,
                };
              });
              sendRes(ws, id, true, { models: models, total: models.length });
            } catch (e) {
              sendRes(ws, id, false, null, { code: 'PARSE_ERROR', message: e.message });
            }
          });
        });
        modelsReq.on('error', function (e) {
          sendRes(ws, id, false, null, { code: 'FETCH_ERROR', message: e.message });
        });
        modelsReq.end();
        return;
      }

      // ── agents.create — Create a new agent ──
      if (method === 'agents.create') {
        var newName = params.name || 'New Agent';
        var newIdentity = params.identity || {};
        var newSkills = params.skills || [];
        var newId = (params.id || newName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')).substring(0, 40);
        // Ensure unique ID
        var baseId = newId;
        var suffix = 1;
        while (agents.find(function (a) { return a.id === newId; })) {
          newId = baseId + '-' + suffix;
          suffix++;
        }
        var agentObj = {
          id: newId,
          name: newName,
          identity: {
            name: newIdentity.name || newName,
            emoji: newIdentity.emoji || String.fromCodePoint(0x1F916),
            theme: newIdentity.theme || ''
          },
          skills: newSkills,
          systemPrompt: params.systemPrompt || '',
          model: params.model || '',
          createdAt: new Date().toISOString(),
          subagents: { allowAgents: ['*'], maxChildren: 5 }
        };
        agents.push(agentObj);
        saveAgents();
        console.log('[Gateway] Agent created: ' + newId);
        sendRes(ws, id, true, { agent: agentObj });
        return;
      }

      // ── agents.update — Update an existing agent ──
      if (method === 'agents.update') {
        var updId = params.id || '';
        var agentIdx = agents.findIndex(function (a) { return a.id === updId; });
        if (agentIdx === -1) {
          sendRes(ws, id, false, null, { code: 'NOT_FOUND', message: 'Agent not found' });
          return;
        }
        var ag = agents[agentIdx];
        if (params.name !== undefined) ag.name = params.name;
        if (params.identity) {
          if (!ag.identity) ag.identity = {};
          if (params.identity.name !== undefined) ag.identity.name = params.identity.name;
          if (params.identity.emoji !== undefined) ag.identity.emoji = params.identity.emoji;
          if (params.identity.theme !== undefined) ag.identity.theme = params.identity.theme;
        }
        if (params.skills !== undefined) ag.skills = params.skills;
        if (params.systemPrompt !== undefined) ag.systemPrompt = params.systemPrompt;
        if (params.model !== undefined) ag.model = params.model;
        agents[agentIdx] = ag;
        saveAgents();
        console.log('[Gateway] Agent updated: ' + updId);
        sendRes(ws, id, true, { agent: ag });
        return;
      }

      // ── agents.delete — Delete an agent ──
      if (method === 'agents.delete') {
        var delId = params.id || '';
        if (delId === 'default') {
          sendRes(ws, id, false, null, { code: 'CANNOT_DELETE', message: 'Cannot delete the default agent' });
          return;
        }
        var delIdx = agents.findIndex(function (a) { return a.id === delId; });
        if (delIdx === -1) {
          sendRes(ws, id, false, null, { code: 'NOT_FOUND', message: 'Agent not found' });
          return;
        }
        agents.splice(delIdx, 1);
        saveAgents();
        console.log('[Gateway] Agent deleted: ' + delId);
        sendRes(ws, id, true, { deleted: delId });
        return;
      }

      // ── sessions.list ──
      if (method === 'sessions.list') {
        sendRes(ws, id, true, { sessions: Object.keys(sessions).map(function (k) { return sessions[k]; }) });
        return;
      }

      // ── subagents.list — List active/recent sub-agent runs ──
      if (method === 'subagents.list') {
        var parentKey = params.sessionKey || '';
        var runs = Object.values(subagentRuns);
        if (parentKey) {
          runs = runs.filter(function (r) { return r.parentSessionKey === parentKey; });
        }
        runs.sort(function (a, b) { return (b.startedAt || 0) - (a.startedAt || 0); });
        sendRes(ws, id, true, { subagents: runs });
        return;
      }

      // ── chat.send — Real AI with tool calling ──
      if (method === 'chat.send') {
        var sessionKey = params.sessionKey || ('session-' + (++sessionCounter));
        var userMessage = params.message || '';
        var chatAgentId = params.agentId || 'default';

        if (!sessions[sessionKey]) {
          sessions[sessionKey] = {
            key: sessionKey,
            label: userMessage.substring(0, 40) || 'Chat',
            agentId: chatAgentId,
            channel: 'chat',
            updatedAt: Date.now()
          };
          sessionHistory[sessionKey] = [];
        }
        sessions[sessionKey].updatedAt = Date.now();
        saveSessions();

        if (!sessionHistory[sessionKey]) sessionHistory[sessionKey] = [];
        var attachments = params.attachments || [];
        var userContent;
        if (attachments.length > 0) {
          userContent = [];
          attachments.forEach(function (att) {
            if (att.type === 'image' && att.data) {
              var mime = att.mime || 'image/jpeg';
              userContent.push({ type: 'image_url', image_url: { url: 'data:' + mime + ';base64,' + att.data } });
            }
          });
          if (userMessage) userContent.push({ type: 'text', text: userMessage });
          if (userContent.length === 0) userContent = userMessage;
        } else {
          userContent = userMessage;
        }
        sessionHistory[sessionKey].push({ role: 'user', content: userContent });
        if (sessionHistory[sessionKey].length > 30) {
          sessionHistory[sessionKey] = sessionHistory[sessionKey].slice(-30);
        }

        sendRes(ws, id, true, { sessionKey: sessionKey, status: 'ok' });

        var runId = uuid();
        var chatAgent = agents.find(function (a) { return a.id === chatAgentId; }) || agents[0];
        var agentSkills = (chatAgent.skills || ['web-search', 'summarizer', 'code-assist', 'math-solver', 'weather', 'system-monitor']).slice();
        if (googleTokens) {
          if (agentSkills.indexOf('gmail') === -1) agentSkills.push('gmail');
          if (agentSkills.indexOf('calendar-manage') === -1) agentSkills.push('calendar-manage');
        }

        var systemPrompt = '';

        // Use the agent's custom system prompt if provided, otherwise build a default one
        if (chatAgent.systemPrompt && chatAgent.systemPrompt.trim()) {
          systemPrompt = chatAgent.systemPrompt + '\n\n';
          systemPrompt += 'Your name is ' + chatAgent.identity.name + '.\n';
          if (chatAgent.identity.theme) {
            systemPrompt += chatAgent.identity.theme + '\n';
          }
        } else {
          systemPrompt = 'You are ' + chatAgent.identity.name + ', ' + chatAgent.identity.theme + '.\n\n';
        }

        systemPrompt += '\nYou are running on a LIONO managed server. You have access to real tools that you can invoke to help the user.\n\n';
        systemPrompt += '## Your capabilities:\n';
        systemPrompt += '- Search the web for current information\n';
        systemPrompt += '- Check weather for any location\n';
        systemPrompt += '- Monitor this server (CPU, memory, disk, services)\n';
        systemPrompt += '- Make HTTP requests to test APIs\n';
        systemPrompt += '- Solve math problems\n';
        systemPrompt += '- Read system and application logs\n';
        systemPrompt += '- Set reminders\n';
        if (googleTokens && googleTokens.email) {
          systemPrompt += '- Access Gmail and Google Calendar — **currently connected** as ' + googleTokens.email + '\n\n';
          systemPrompt += '## Google Services Status: CONNECTED\n';
          systemPrompt += 'You have ACTIVE access to the user\'s Google account (' + googleTokens.email + ').\n';
          systemPrompt += 'You CAN read emails, search inbox, send emails, read/create calendar events, etc.\n';
          systemPrompt += 'Use the "gmail" and "calendar" tools directly when the user asks about email or calendar.\n';
          systemPrompt += 'Do NOT tell the user to connect Google — it is already connected.\n\n';
        } else {
          systemPrompt += '- Access Gmail and Google Calendar (not yet connected)\n\n';
          systemPrompt += '## Google Services Status: NOT CONNECTED\n';
          systemPrompt += 'Google is not connected yet. If the user asks about email or calendar, tell them to open the LIONO app side menu, go to settings, and tap "Connect Google" to authenticate.\n\n';
        }
        systemPrompt += '## Guidelines:\n';
        systemPrompt += '- Be helpful, concise, and friendly\n';
        systemPrompt += '- Use tools when they can provide real, accurate data (e.g. use web_search for current events)\n';
        systemPrompt += '- Always prefer giving factual answers backed by tool results\n';
        systemPrompt += '\n## Response Formatting (IMPORTANT):\n';
        systemPrompt += 'Your responses are rendered in a mobile app with rich markdown support. Format beautifully:\n';
        systemPrompt += '- Use **## headings** for major sections (e.g. ## Weather, ## Top News)\n';
        systemPrompt += '- Use **bold text** for emphasis and key terms\n';
        systemPrompt += '- Use bullet points (- ) for lists, not dense paragraphs\n';
        systemPrompt += '- Add a blank line between sections for visual breathing room\n';
        systemPrompt += '- Use > blockquotes for notable quotes or highlights\n';
        systemPrompt += '- Keep paragraphs short (2-3 sentences max)\n';
        systemPrompt += '- NEVER mention tool names, tool calls, or internal processes in your response — just present the results naturally\n';
        systemPrompt += '- For news/briefings: use ## Section Headings, then bullet points with **bold titles** — e.g.:\n';
        systemPrompt += '  ## Top News\n';
        systemPrompt += '  - **US-Iran nuclear talks** — High-stakes negotiations continue in Geneva...\n';
        systemPrompt += '  - **Tech earnings season** — Apple reports record Q1 revenue...\n';

        // Inject user profile context (preferences, memories)
        systemPrompt += buildUserContext();

        chatWithLLM(
          sessionHistory[sessionKey],
          systemPrompt,
          DEFAULT_MODEL,
          agentSkills,
          // stream callback — sends each chunk as a delta event
          function (chunk) {
            sendEvent(ws, 'chat', {
              runId: runId,
              sessionKey: sessionKey,
              state: 'delta',
              message: chunk
            }, ++seqCounter);
          },
          // done callback — sends final event and saves history
          function (err, fullText) {
            if (err) {
              sendEvent(ws, 'chat', {
                runId: runId,
                sessionKey: sessionKey,
                state: 'delta',
                message: 'Sorry, I encountered an error: ' + err.message
              }, ++seqCounter);
              fullText = 'Error: ' + err.message;
            }
            sendEvent(ws, 'chat', {
              runId: runId,
              sessionKey: sessionKey,
              state: 'final'
            }, ++seqCounter);
            sessionHistory[sessionKey].push({ role: 'assistant', content: fullText || '' });
            saveSessions();
          },
          // tool callback — sends tool usage as agent events (not in chat text)
          function (info) {
            sendEvent(ws, 'agent', {
              runId: runId,
              stream: 'tool',
              data: {
                toolCallId: info.toolCallId || uuid(),
                name: info.name,
                phase: info.phase || 'start',
                result: info.result || null
              }
            }, ++seqCounter);
          },
          // spawn context — enables sessions_spawn tool for sub-agent delegation
          {
            ws: ws,
            sessionKey: sessionKey,
            runId: runId,
            agentId: chatAgentId,
            seqRef: { get val() { return seqCounter; }, set val(v) { seqCounter = v; } }
          }
        );
        return;
      }

      // ── chat.history ──
      if (method === 'chat.history') {
        var sk = params.sessionKey || '';
        sendRes(ws, id, true, { messages: sessionHistory[sk] || [] });
        return;
      }

      // ══════════════════════════════════════════════════════════
      // CRON JOB MANAGEMENT
      // ══════════════════════════════════════════════════════════

      var CRON_FILE = path.join(DATA_DIR || '/home/seeclaw/.openclaw', 'cron', 'jobs.json');

      function loadCronJobs() {
        try {
          if (fs.existsSync(CRON_FILE)) return JSON.parse(fs.readFileSync(CRON_FILE, 'utf8'));
        } catch (e) {}
        return [];
      }

      function saveCronJobs(jobs) {
        try {
          var dir = path.dirname(CRON_FILE);
          if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(CRON_FILE, JSON.stringify(jobs, null, 2), 'utf8');
        } catch (e) {
          console.log('[Cron] Failed to save: ' + e.message);
        }
      }

      if (method === 'cron.list') {
        sendRes(ws, id, true, { jobs: loadCronJobs() });
        return;
      }

      if (method === 'cron.add') {
        var jobs = loadCronJobs();
        var newJob = {
          id: params.id || ('job-' + Date.now()),
          name: params.name || 'Untitled',
          schedule: params.schedule || '0 9 * * *',
          scheduleType: params.scheduleType || 'cron',
          message: params.message || '',
          agent: params.agent || 'default',
          session: params.session || 'isolated',
          delivery: params.delivery || 'none',
          channel: params.channel || '',
          enabled: params.enabled !== false,
          createdAt: new Date().toISOString()
        };
        jobs.push(newJob);
        saveCronJobs(jobs);
        sendRes(ws, id, true, { job: newJob });
        return;
      }

      if (method === 'cron.update') {
        var jobs = loadCronJobs();
        var idx = jobs.findIndex(function (j) { return j.id === params.id; });
        if (idx === -1) { sendRes(ws, id, false, { error: 'Job not found' }); return; }
        if (params.name !== undefined) jobs[idx].name = params.name;
        if (params.schedule !== undefined) jobs[idx].schedule = params.schedule;
        if (params.message !== undefined) jobs[idx].message = params.message;
        if (params.agent !== undefined) jobs[idx].agent = params.agent;
        if (params.session !== undefined) jobs[idx].session = params.session;
        if (params.delivery !== undefined) jobs[idx].delivery = params.delivery;
        if (params.channel !== undefined) jobs[idx].channel = params.channel;
        if (params.enabled !== undefined) jobs[idx].enabled = params.enabled;
        saveCronJobs(jobs);
        sendRes(ws, id, true, { job: jobs[idx] });
        return;
      }

      if (method === 'cron.delete') {
        var jobs = loadCronJobs();
        jobs = jobs.filter(function (j) { return j.id !== params.id; });
        saveCronJobs(jobs);
        sendRes(ws, id, true, { ok: true });
        return;
      }

      if (method === 'cron.run') {
        var jobs = loadCronJobs();
        var job = jobs.find(function (j) { return j.id === params.id; });
        if (!job) { sendRes(ws, id, false, { error: 'Job not found' }); return; }
        sendRes(ws, id, true, { status: 'triggered', jobId: job.id });
        return;
      }

      // ══════════════════════════════════════════════════════════
      // KANBAN TASK MANAGEMENT
      // ══════════════════════════════════════════════════════════

      var TASKS_FILE = path.join(DATA_DIR || '/home/seeclaw/.openclaw', 'tasks', 'tasks.json');

      function loadTasks() {
        try {
          if (fs.existsSync(TASKS_FILE)) return JSON.parse(fs.readFileSync(TASKS_FILE, 'utf8'));
        } catch (e) {}
        return [];
      }

      function saveTasks(tasks) {
        try {
          var dir = path.dirname(TASKS_FILE);
          if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(TASKS_FILE, JSON.stringify(tasks, null, 2), 'utf8');
        } catch (e) {
          console.log('[Tasks] Failed to save: ' + e.message);
        }
      }

      if (method === 'tasks.list') {
        sendRes(ws, id, true, { tasks: loadTasks() });
        return;
      }

      if (method === 'tasks.create') {
        var tasks = loadTasks();
        var colTasks = tasks.filter(function (t) { return t.column === (params.column || 'backlog'); });
        var maxOrder = colTasks.reduce(function (m, t) { return Math.max(m, t.order || 0); }, -1);
        var newTask = {
          id: 'task-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6),
          title: params.title || 'Untitled',
          description: params.description || '',
          column: params.column || 'backlog',
          priority: params.priority || 'medium',
          labels: params.labels || [],
          agentId: params.agentId || null,
          dueDate: params.dueDate || null,
          order: maxOrder + 1,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        tasks.push(newTask);
        saveTasks(tasks);
        sendRes(ws, id, true, { task: newTask });
        return;
      }

      if (method === 'tasks.update') {
        var tasks = loadTasks();
        var idx = tasks.findIndex(function (t) { return t.id === params.id; });
        if (idx === -1) { sendRes(ws, id, false, { error: 'Task not found' }); return; }
        if (params.title !== undefined) tasks[idx].title = params.title;
        if (params.description !== undefined) tasks[idx].description = params.description;
        if (params.column !== undefined) tasks[idx].column = params.column;
        if (params.priority !== undefined) tasks[idx].priority = params.priority;
        if (params.labels !== undefined) tasks[idx].labels = params.labels;
        if (params.agentId !== undefined) tasks[idx].agentId = params.agentId;
        if (params.dueDate !== undefined) tasks[idx].dueDate = params.dueDate;
        if (params.order !== undefined) tasks[idx].order = params.order;
        tasks[idx].updatedAt = new Date().toISOString();
        saveTasks(tasks);
        sendRes(ws, id, true, { task: tasks[idx] });
        return;
      }

      if (method === 'tasks.delete') {
        var tasks = loadTasks();
        tasks = tasks.filter(function (t) { return t.id !== params.id; });
        saveTasks(tasks);
        sendRes(ws, id, true, { ok: true });
        return;
      }

      if (method === 'tasks.run') {
        var tasks = loadTasks();
        var taskIdx = tasks.findIndex(function (t) { return t.id === params.id; });
        if (taskIdx === -1) { sendRes(ws, id, false, { error: 'Task not found' }); return; }
        var task = tasks[taskIdx];

        // Move to in_progress
        tasks[taskIdx].column = 'in_progress';
        tasks[taskIdx].status = 'running';
        tasks[taskIdx].updatedAt = new Date().toISOString();
        var taskSessionKey = 'task-' + task.id;
        tasks[taskIdx].sessionKey = taskSessionKey;
        saveTasks(tasks);

        sendRes(ws, id, true, { task: tasks[taskIdx], status: 'started' });

        // Build session + history
        if (!sessions[taskSessionKey]) {
          sessions[taskSessionKey] = {
            key: taskSessionKey,
            label: 'Task: ' + task.title.substring(0, 30),
            agentId: task.agentId || 'default',
            channel: 'task',
            updatedAt: Date.now()
          };
          sessionHistory[taskSessionKey] = [];
        }
        sessions[taskSessionKey].updatedAt = Date.now();

        var taskMessage = 'Please complete this task:\n\n**' + task.title + '**\n\n' + (task.description || '');
        if (task.labels && task.labels.length > 0) {
          taskMessage += '\n\nLabels: ' + task.labels.join(', ');
        }
        sessionHistory[taskSessionKey].push({ role: 'user', content: taskMessage });

        var taskRunId = uuid();
        var taskAgentId = task.agentId || 'default';
        var taskAgent = agents.find(function (a) { return a.id === taskAgentId; }) || agents[0];
        var taskAgentSkills = (taskAgent.skills || ['web-search', 'summarizer', 'code-assist', 'math-solver', 'weather', 'system-monitor']).slice();
        if (googleTokens) {
          if (taskAgentSkills.indexOf('gmail') === -1) taskAgentSkills.push('gmail');
          if (taskAgentSkills.indexOf('calendar-manage') === -1) taskAgentSkills.push('calendar-manage');
        }

        var taskSystemPrompt = '';
        if (taskAgent.systemPrompt && taskAgent.systemPrompt.trim()) {
          taskSystemPrompt = taskAgent.systemPrompt + '\n\n';
        } else {
          taskSystemPrompt = 'You are ' + taskAgent.identity.name + ', ' + (taskAgent.identity.theme || 'a helpful AI assistant') + '.\n\n';
        }
        taskSystemPrompt += 'You are executing a kanban board task. Complete the task thoroughly and provide a clear summary of what you did.\n';
        taskSystemPrompt += 'Use your available tools when needed. Be concise but comprehensive.\n';
        taskSystemPrompt += buildUserContext();

        var taskFullText = '';

        chatWithLLM(
          sessionHistory[taskSessionKey],
          taskSystemPrompt,
          DEFAULT_MODEL,
          taskAgentSkills,
          function (chunk) {
            taskFullText += chunk;
            sendEvent(ws, 'task.progress', {
              taskId: task.id,
              runId: taskRunId,
              state: 'delta',
              message: chunk
            }, ++seqCounter);
          },
          function (err, fullText) {
            if (err) {
              taskFullText = 'Error: ' + err.message;
            }
            // Update task with result
            var updated = loadTasks();
            var ui = updated.findIndex(function (t) { return t.id === task.id; });
            if (ui !== -1) {
              updated[ui].result = (fullText || taskFullText).substring(0, 5000);
              updated[ui].column = err ? 'review' : 'done';
              updated[ui].status = err ? 'error' : 'completed';
              updated[ui].updatedAt = new Date().toISOString();
              saveTasks(updated);
            }
            sessionHistory[taskSessionKey].push({ role: 'assistant', content: fullText || taskFullText });
            saveSessions();
            sendEvent(ws, 'task.progress', {
              taskId: task.id,
              runId: taskRunId,
              state: 'final',
              result: (fullText || taskFullText).substring(0, 5000),
              column: err ? 'review' : 'done'
            }, ++seqCounter);
          },
          function (info) {
            sendEvent(ws, 'task.progress', {
              taskId: task.id,
              runId: taskRunId,
              state: 'tool',
              tool: info.name,
              phase: info.phase || 'start'
            }, ++seqCounter);
          },
          null
        );
        return;
      }

      // ══════════════════════════════════════════════════════════
      // SKILLS MANAGEMENT
      // ══════════════════════════════════════════════════════════

      // ── skills.list — Return installed skills with metadata ──
      if (method === 'skills.list') {
        var skillsList = Object.keys(SKILL_TOOLS).map(function (skillId) {
          var tool = SKILL_TOOLS[skillId];
          var fn = tool.function || {};
          var enabledOnDefault = (agents[0] && agents[0].skills || []).indexOf(skillId) !== -1;
          return {
            id: skillId,
            name: fn.name || skillId,
            description: fn.description || '',
            source: 'bundled',
            enabled: true,
            enabledOnDefault: enabledOnDefault,
            parameters: fn.parameters || null
          };
        });

        var seenIds = {};
        skillsList.forEach(function (s) { seenIds[s.id] = true; });

        // Scan user-installed skills from ~/.openclaw/skills and DATA_DIR/skills
        var scanDirs = [
          path.join(os.homedir(), '.openclaw', 'skills'),
          path.join(DATA_DIR, 'skills')
        ];
        scanDirs.forEach(function (dir) {
          var sourceLabel = dir.indexOf(DATA_DIR) !== -1 ? 'clawhub' : 'managed';
          try {
            var entries = fs.readdirSync(dir, { withFileTypes: true });
            entries.forEach(function (entry) {
              if (!entry.isDirectory()) return;
              if (seenIds[entry.name]) return;
              var skillMd = path.join(dir, entry.name, 'SKILL.md');
              if (!fs.existsSync(skillMd)) return;
              try {
                var content = fs.readFileSync(skillMd, 'utf8');
                var nameMatch = content.match(/^name:\s*(.+)/m);
                var descMatch = content.match(/^description:\s*(.+)/m);
                var skillName = nameMatch ? nameMatch[1].trim() : entry.name;
                var skillDesc = descMatch ? descMatch[1].trim() : '';
                seenIds[entry.name] = true;
                skillsList.push({
                  id: entry.name,
                  name: skillName,
                  description: skillDesc,
                  source: sourceLabel,
                  enabled: true,
                  enabledOnDefault: false,
                  parameters: null
                });
              } catch (readErr) {}
            });
          } catch (scanErr) {}
        });

        sendRes(ws, id, true, { skills: skillsList, total: skillsList.length });
        return;
      }

      // ── skills.install — Install a skill from ClawHub by slug ──
      if (method === 'skills.install') {
        var slug = (params.slug || '').replace(/[^a-zA-Z0-9_-]/g, '');
        if (!slug) {
          sendRes(ws, id, false, null, { code: 'MISSING_SLUG', message: 'Skill slug is required' });
          return;
        }
        var installDir = path.join(DATA_DIR, 'skills');
        try { fs.mkdirSync(installDir, { recursive: true }); } catch (e) {}

        try {
          var installResult = execSync(
            'npx clawhub@latest install ' + slug + ' --workdir ' + JSON.stringify(installDir) + ' --no-input 2>&1',
            { timeout: 30000, encoding: 'utf8', cwd: installDir }
          );
          console.log('[Gateway] Skill installed: ' + slug);
          sendRes(ws, id, true, { slug: slug, installed: true, output: installResult.substring(0, 500) });
        } catch (e) {
          console.log('[Gateway] Skill install failed: ' + slug + ' — ' + (e.message || ''));
          sendRes(ws, id, false, null, { code: 'INSTALL_FAILED', message: 'Failed to install ' + slug + ': ' + (e.stderr || e.message || '').substring(0, 300) });
        }
        return;
      }

      // ── skills.uninstall — Remove an installed skill ──
      if (method === 'skills.uninstall') {
        var rmSlug = (params.slug || '').replace(/[^a-zA-Z0-9_-]/g, '');
        if (!rmSlug) {
          sendRes(ws, id, false, null, { code: 'MISSING_SLUG', message: 'Skill slug is required' });
          return;
        }
        var skillDir = path.join(DATA_DIR, 'skills', rmSlug);
        var skillsDirResolved = path.resolve(path.join(DATA_DIR, 'skills'));
        var skillDirResolved = path.resolve(skillDir);
        if (skillDirResolved !== skillsDirResolved && !skillDirResolved.startsWith(skillsDirResolved + path.sep)) {
          sendRes(ws, id, false, null, { code: 'INVALID_PATH', message: 'Path traversal not allowed' });
          return;
        }
        try {
          fs.rmSync(skillDir, { recursive: true, force: true });
          console.log('[Gateway] Skill uninstalled: ' + rmSlug);
          sendRes(ws, id, true, { slug: rmSlug, uninstalled: true });
        } catch (e) {
          sendRes(ws, id, false, null, { code: 'UNINSTALL_FAILED', message: e.message || 'Unknown error' });
        }
        return;
      }

      // ── gateway.version — Check for updates ──
      if (method === 'gateway.version') {
        var checkUrl = 'https://lionoai.com/api/gateway/latest-version';
        try {
          var versionJson = execSync('curl -sf ' + JSON.stringify(checkUrl) + ' 2>/dev/null', { timeout: 10000, encoding: 'utf8' });
          var versionInfo = JSON.parse(versionJson);
          sendRes(ws, id, true, {
            current: GATEWAY_VERSION,
            latest: versionInfo.version || GATEWAY_VERSION,
            updateAvailable: versionInfo.version && versionInfo.version !== GATEWAY_VERSION,
            changelog: versionInfo.changelog || '',
            downloadUrl: versionInfo.downloadUrl || ''
          });
        } catch (e) {
          sendRes(ws, id, true, {
            current: GATEWAY_VERSION,
            latest: GATEWAY_VERSION,
            updateAvailable: false,
            error: 'Could not check for updates'
          });
        }
        return;
      }

      // ── gateway.update — Download and apply update, then restart ──
      if (method === 'gateway.update') {
        var updateUrl = params.url || 'https://lionoai.com/api/gateway/server.js';
        sendRes(ws, id, true, { status: 'downloading', current: GATEWAY_VERSION });

        try {
          var serverJsPath = path.resolve(__filename);
          var backupPath = serverJsPath + '.backup';

          fs.copyFileSync(serverJsPath, backupPath);
          console.log('[Gateway] Backup created: ' + backupPath);

          var newCode = execSync('curl -sf ' + JSON.stringify(updateUrl) + ' 2>/dev/null', { timeout: 30000, encoding: 'utf8' });

          if (!newCode || newCode.length < 1000 || !newCode.includes('GATEWAY_VERSION')) {
            console.log('[Gateway] Update rejected: downloaded file looks invalid (' + newCode.length + ' bytes)');
            wss.clients.forEach(function (c) {
              if (c.readyState === 1) sendEvent(c, 'gateway.update', { status: 'failed', error: 'Downloaded file invalid' });
            });
            return;
          }

          var versionMatch = newCode.match(/GATEWAY_VERSION\s*=\s*'([^']+)'/);
          var newVersion = versionMatch ? versionMatch[1] : 'unknown';

          fs.writeFileSync(serverJsPath, newCode, 'utf8');
          console.log('[Gateway] Updated server.js to version ' + newVersion);

          wss.clients.forEach(function (c) {
            if (c.readyState === 1) {
              sendEvent(c, 'gateway.update', { status: 'restarting', from: GATEWAY_VERSION, to: newVersion });
            }
          });

          setTimeout(function () {
            console.log('[Gateway] Restarting process after update...');
            process.exit(0);
          }, 1000);
        } catch (e) {
          console.log('[Gateway] Update failed: ' + e.message);
          try { fs.copyFileSync(backupPath, serverJsPath); console.log('[Gateway] Rolled back to backup'); } catch (rb) {}
          wss.clients.forEach(function (c) {
            if (c.readyState === 1) sendEvent(c, 'gateway.update', { status: 'failed', error: e.message.substring(0, 200) });
          });
        }
        return;
      }

      // ── health ──
      if (method === 'health') {
        var cpus = os.cpus();
        var totalMem = os.totalmem();
        var freeMem = os.freemem();
        var gogcliInstalled = false;
        try { execSync('which gogcli', { timeout: 2000 }); gogcliInstalled = true; } catch (e) { }

        sendRes(ws, id, true, {
          ok: true,
          version: GATEWAY_VERSION,
          uptimeMs: now() - startTime,
          llmConfigured: !!OPENROUTER_KEY,
          llmModel: DEFAULT_MODEL,
          skillsLoaded: Object.keys(SKILL_TOOLS).length,
          gogcliInstalled: gogcliInstalled,
          googleConnected: !!googleTokens,
          googleEmail: (googleTokens && googleTokens.email) || null,
          googleClientIdConfigured: !!GOOGLE_CLIENT_ID,
          webClientIdConfigured: !!GOOGLE_WEB_CLIENT_ID,
          playwrightAvailable: playwrightAvailable,
          nodes: [{
            id: 'gateway',
            name: 'Gateway',
            status: 'ok',
            uptimeMs: now() - startTime,
            cpu: cpus.length > 0 ? Math.round((1 - (cpus[0].times.idle / (cpus[0].times.user + cpus[0].times.nice + cpus[0].times.sys + cpus[0].times.idle))) * 100) : 0,
            memUsedMB: Math.round((totalMem - freeMem) / 1048576),
            memTotalMB: Math.round(totalMem / 1048576)
          }]
        });
        return;
      }

      // ══════════════════════════════════════════════════════════
      // GOOGLE AUTH METHODS
      // ══════════════════════════════════════════════════════════

      // ── google.auth.start — Begin Device Flow (Option 2 / Advanced Setup) ──
      // Device Flow only supports basic scopes (openid, email, profile).
      // All other scopes (Gmail, Calendar, Drive, cloud-platform) must use Auth Code Flow.
      if (method === 'google.auth.start') {
        var scopes = ['openid', 'email', 'profile'];
        startDeviceFlow(scopes, function (err, data) {
          if (err) {
            sendRes(ws, id, false, null, { code: 'DEVICE_FLOW_ERROR', message: err.message });
            return;
          }
          // Store the device code for polling
          deviceFlowState = {
            deviceCode: data.device_code,
            userCode: data.user_code,
            verificationUrl: data.verification_url,
            expiresAt: Date.now() + (data.expires_in * 1000),
            interval: (data.interval || 5) * 1000
          };
          sendRes(ws, id, true, {
            userCode: data.user_code,
            verificationUrl: data.verification_url,
            expiresIn: data.expires_in
          });
        });
        return;
      }

      // ── google.auth.poll — Poll Device Flow for completion ──
      if (method === 'google.auth.poll') {
        if (!deviceFlowState) {
          sendRes(ws, id, false, null, { code: 'NO_FLOW', message: 'No active Device Flow. Call google.auth.start first.' });
          return;
        }
        if (Date.now() > deviceFlowState.expiresAt) {
          deviceFlowState = null;
          sendRes(ws, id, true, { status: 'expired' });
          return;
        }
        pollDeviceFlow(deviceFlowState.deviceCode, deviceFlowState.interval, function (err, status, tokenData) {
          if (err) {
            sendRes(ws, id, false, null, { code: 'POLL_ERROR', message: err.message });
            return;
          }
          if (status === 'complete') {
            // Save tokens
            var tokens = {
              access_token: tokenData.access_token,
              refresh_token: tokenData.refresh_token,
              expires_at: Date.now() + (tokenData.expires_in * 1000),
              scope: tokenData.scope,
              token_type: tokenData.token_type
            };
            // Fetch user email
            httpsRequest({
              hostname: 'www.googleapis.com',
              path: '/oauth2/v2/userinfo',
              method: 'GET',
              headers: { 'Authorization': 'Bearer ' + tokens.access_token }
            }, null).then(function (res) {
              if (res.status === 200 && res.data.email) {
                tokens.email = res.data.email;
                tokens.name = res.data.name || '';
              }
              saveGoogleTokens(tokens);
              deviceFlowState = null;
              sendRes(ws, id, true, { status: 'complete', email: tokens.email || '', name: tokens.name || '' });
            }).catch(function () {
              saveGoogleTokens(tokens);
              deviceFlowState = null;
              sendRes(ws, id, true, { status: 'complete' });
            });
          } else {
            sendRes(ws, id, true, { status: status });
          }
        });
        return;
      }

      // ── google.auth.status — Check if Google is connected ──
      if (method === 'google.auth.status') {
        sendRes(ws, id, true, {
          connected: !!googleTokens,
          email: (googleTokens && googleTokens.email) || null,
          name: (googleTokens && googleTokens.name) || null,
          hasUserProject: !!googleUserProject,
          clientIdConfigured: !!GOOGLE_CLIENT_ID,
          webClientIdConfigured: !!GOOGLE_WEB_CLIENT_ID,
          scopes: (googleTokens && googleTokens.scope) || null
        });
        return;
      }

      // ── google.auth.revoke — Disconnect Google ──
      if (method === 'google.auth.revoke') {
        if (googleTokens && googleTokens.access_token) {
          httpsRequest({
            hostname: 'oauth2.googleapis.com',
            path: '/revoke?token=' + googleTokens.access_token,
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
          }, '').catch(function () { });
        }
        googleTokens = null;
        try { fs.unlinkSync(GOOGLE_TOKEN_PATH); } catch (e) { }
        sendRes(ws, id, true, { disconnected: true });
        return;
      }

      // ── google.auth.exchange — Exchange auth code for tokens (Authorization Code Flow) ──
      if (method === 'google.auth.exchange') {
        var authCode = params.code || '';
        if (!authCode) {
          sendRes(ws, id, false, null, { code: 'MISSING_CODE', message: 'Authorization code required' });
          return;
        }
        var webClientId = GOOGLE_WEB_CLIENT_ID;
        var webClientSecret = GOOGLE_WEB_CLIENT_SECRET;
        if (!webClientId || !webClientSecret) {
          sendRes(ws, id, false, null, { code: 'NOT_CONFIGURED', message: 'Web client credentials not configured on this server' });
          return;
        }
        var redirectUri = GOOGLE_REDIRECT_URI;
        var exchangeBody = querystring.stringify({
          code: authCode,
          client_id: webClientId,
          client_secret: webClientSecret,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code'
        });
        console.log('[Google] Exchanging auth code for tokens...');
        httpsRequest({
          hostname: 'oauth2.googleapis.com',
          path: '/token',
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(exchangeBody) }
        }, exchangeBody).then(function (res) {
          if (res.status === 200 && res.data.access_token) {
            var tokens = {
              access_token: res.data.access_token,
              refresh_token: res.data.refresh_token,
              expires_at: Date.now() + (res.data.expires_in * 1000),
              scope: res.data.scope,
              token_type: res.data.token_type,
              clientType: 'web'
            };
            // Fetch user info
            httpsRequest({
              hostname: 'www.googleapis.com',
              path: '/oauth2/v2/userinfo',
              method: 'GET',
              headers: { 'Authorization': 'Bearer ' + tokens.access_token }
            }, null).then(function (userRes) {
              if (userRes.status === 200 && userRes.data.email) {
                tokens.email = userRes.data.email;
                tokens.name = userRes.data.name || '';
              }
              saveGoogleTokens(tokens);
              deviceFlowState = null;
              console.log('[Google] Auth code exchange successful — connected as ' + (tokens.email || 'unknown'));
              sendRes(ws, id, true, {
                status: 'complete',
                connected: true,
                email: tokens.email || null,
                name: tokens.name || null,
                scopes: tokens.scope || null
              });
            }).catch(function () {
              saveGoogleTokens(tokens);
              console.log('[Google] Auth code exchange successful (user info fetch failed)');
              sendRes(ws, id, true, {
                status: 'complete',
                connected: true,
                email: null,
                name: null,
                scopes: tokens.scope || null
              });
            });
          } else {
            console.log('[Google] Token exchange failed:', JSON.stringify(res.data));
            sendRes(ws, id, false, null, {
              code: 'TOKEN_EXCHANGE_FAILED',
              message: 'Google token exchange failed: ' + (res.data.error_description || res.data.error || 'Unknown error')
            });
          }
        }).catch(function (err) {
          sendRes(ws, id, false, null, { code: 'TOKEN_EXCHANGE_ERROR', message: err.message });
        });
        return;
      }

      // ══════════════════════════════════════════════════════════
      // OPTION 2: GCP PROJECT AUTOMATION + PLAYWRIGHT BROWSER
      // ══════════════════════════════════════════════════════════

      // ── google.project.create — Create user's own GCP project ──
      if (method === 'google.project.create') {
        if (!googleTokens || !googleTokens.access_token) {
          sendRes(ws, id, false, null, { code: 'NOT_AUTHENTICATED', message: 'Connect Google first (with cloud-platform scope)' });
          return;
        }
        var projectId = 'liono-' + crypto.randomBytes(4).toString('hex');
        sendEvent(ws, 'google.project', { step: 'creating', message: 'Creating GCP project ' + projectId + '...' });

        createGcpProject(googleTokens.access_token, projectId, function (err, res) {
          if (err || (res.status !== 200 && res.status !== 409)) {
            sendRes(ws, id, false, null, { code: 'PROJECT_CREATE_FAILED', message: (err ? err.message : JSON.stringify(res.data)) });
            return;
          }
          sendEvent(ws, 'google.project', { step: 'enabling_apis', message: 'Enabling Gmail, Calendar, Drive, and other APIs...' });

          // Wait a bit for project to be ready
          setTimeout(function () {
            var services = [
              'gmail.googleapis.com',
              'calendar-json.googleapis.com'
            ];
            batchEnableApis(googleTokens.access_token, projectId, services, function (err2, res2) {
              if (err2 || (res2.status !== 200 && res2.status !== 409)) {
                sendEvent(ws, 'google.project', { step: 'apis_warning', message: 'Some APIs may need manual enabling. Continuing...' });
              } else {
                sendEvent(ws, 'google.project', { step: 'apis_enabled', message: 'APIs enabled successfully' });
              }
              sendRes(ws, id, true, {
                projectId: projectId,
                status: 'created',
                message: 'Project created. Next: configure consent screen and create credentials via browser.'
              });
            });
          }, 5000);
        });
        return;
      }

      // ── google.browser.install — Install Chrome & Playwright on this server ──
      if (method === 'google.browser.install') {
        sendEvent(ws, 'google.browser', { step: 'installing', message: 'Installing browser dependencies...' });
        var installScript = [
          'apt-get update -qq',
          'apt-get install -y -qq wget gnupg ca-certificates fonts-liberation libasound2t64 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdbus-1-3 libgbm1 libgtk-3-0 libnspr4 libnss3 libx11-xcb1 libxcomposite1 libxdamage1 libxrandr2 xdg-utils 2>/dev/null || apt-get install -y -qq wget gnupg ca-certificates fonts-liberation libasound2 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdbus-1-3 libgbm1 libgtk-3-0 libnspr4 libnss3 libx11-xcb1 libxcomposite1 libxdamage1 libxrandr2 xdg-utils 2>/dev/null || true',
          'wget -q -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb',
          'dpkg -i /tmp/chrome.deb || apt-get install -f -y -qq',
          'rm -f /tmp/chrome.deb',
          'cd ' + __dirname + ' && npm install playwright-core 2>&1'
        ].join(' && ');

        exec(installScript, { timeout: 180000 }, function (err, stdout, stderr) {
          if (err) {
            console.error('[Gateway] Browser install failed:', err.message);
            sendRes(ws, id, false, null, { code: 'INSTALL_FAILED', message: 'Installation failed: ' + (err.message || '').substring(0, 200) });
            return;
          }

          // Reload playwright availability
          try { require.resolve('playwright-core'); playwrightAvailable = true; } catch (e) { playwrightAvailable = false; }

          // Verify chrome installed
          var chromePath = '';
          try { chromePath = execSync('which google-chrome-stable 2>/dev/null || which google-chrome 2>/dev/null', { encoding: 'utf8' }).trim(); } catch (e) { }

          if (playwrightAvailable && chromePath) {
            console.log('[Gateway] Browser installed successfully. Chrome: ' + chromePath);
            sendRes(ws, id, true, { status: 'installed', message: 'Chrome & Playwright installed successfully', chromePath: chromePath });
          } else {
            sendRes(ws, id, false, null, { code: 'INSTALL_INCOMPLETE', message: 'Installation completed but verification failed. Playwright: ' + playwrightAvailable + ', Chrome: ' + (chromePath || 'not found') });
          }
        });
        return;
      }

      // ── google.browser.start — Launch Playwright browser ──
      if (method === 'google.browser.start') {
        if (browserSession) {
          closeBrowserSession();
        }
        sendEvent(ws, 'google.browser', { step: 'launching', message: 'Launching browser...' });
        launchBrowserSession(function (err, session) {
          if (err) {
            sendRes(ws, id, false, null, { code: 'BROWSER_LAUNCH_FAILED', message: err.message });
            return;
          }
          var url = params.url || 'https://accounts.google.com';
          session.page.goto(url, { waitUntil: 'networkidle', timeout: 30000 }).then(function () {
            sendRes(ws, id, true, { status: 'launched', message: 'Browser ready. Sign in to Google.' });
          }).catch(function (navErr) {
            sendRes(ws, id, true, { status: 'launched', message: 'Browser launched but navigation slow: ' + navErr.message });
          });
        });
        return;
      }

      // ── google.browser.autosetup — AI-driven GCP setup using Claude Opus 4.6 ──
      if (method === 'google.browser.autosetup') {
        if (!browserSession || !browserSession.page) {
          sendRes(ws, id, false, null, { code: 'NO_BROWSER', message: 'No browser session active' });
          return;
        }
        sendRes(ws, id, true, { status: 'started', message: 'AI automation started' });

        var page = browserSession.page;
        var autosetupEmail = ((googleTokens && googleTokens.email) || '').trim();

        function sendStep(msg) {
          console.log('[AI-Setup] ' + msg);
          sendEvent(ws, 'google.browser', { step: 'autosetup', message: msg });
        }

        async function runBrandingWizardDeterministic(pid) {
          try {
            sendStep('Running deterministic Google Auth Platform setup...');
            var brandingUrl = pid
              ? 'https://console.cloud.google.com/auth/branding?project=' + encodeURIComponent(pid)
              : 'https://console.cloud.google.com/auth/branding';
            await page.goto(brandingUrl, {
              waitUntil: 'domcontentloaded',
              timeout: 30000
            });
            await page.waitForTimeout(2500);

            // Click "Get started" if quick-start panel is visible.
            await page.locator('button:has-text("Get started"), a:has-text("Get started"), [role="button"]:has-text("Get started")')
              .first()
              .click({ timeout: 4000, force: true })
              .catch(async function() {
                return page.evaluate(function() {
                  var nodes = document.querySelectorAll('button, a, [role="button"]');
                  for (var i = 0; i < nodes.length; i++) {
                    var txt = (nodes[i].textContent || '').trim().toLowerCase();
                    if (txt.indexOf('get started') !== -1) {
                      try { nodes[i].click(); return true; } catch (e) {}
                    }
                  }
                  return false;
                }).catch(function() { return false; });
              });
            await page.waitForTimeout(2200);

            // Step 1: App name
            await page.evaluate(function() {
              function setVal(el, val) {
                if (!el) return false;
                el.focus();
                el.value = '';
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.value = val;
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
                return true;
              }
              var labels = Array.from(document.querySelectorAll('label, span, div'));
              for (var i = 0; i < labels.length; i++) {
                var t = (labels[i].textContent || '').trim().toLowerCase();
                if (t.indexOf('app name') !== -1) {
                  var wrap = labels[i].closest('form, section, div') || document.body;
                  var input = wrap.querySelector('input[type="text"], input:not([type]), textarea');
                  if (setVal(input, 'LIONO')) return true;
                }
              }
              var fallback = document.querySelector('input[aria-label*="app name" i], input[placeholder*="app name" i], input[type="text"]');
              return setVal(fallback, 'LIONO');
            }).catch(function() {});

            // Step 1: support email selector if available
            await page.locator('[role="combobox"], mat-select, div[aria-haspopup="listbox"]').first()
              .click({ timeout: 2500 })
              .catch(function() { return null; });
            await page.waitForTimeout(800);
            await page.locator('[role="option"]:has-text("@"), mat-option:has-text("@"), li:has-text("@")').first()
              .click({ timeout: 2500, force: true })
              .catch(function() { return null; });

            // Next
            await page.locator('button:has-text("Next"), button:has-text("Save and continue"), button:has-text("Continue")').first()
              .click({ timeout: 5000, force: true })
              .catch(function() { return null; });
            await page.waitForTimeout(1800);

            // Step 2: Audience -> External
            await page.locator('label:has-text("External"), [role="radio"]:has-text("External"), mat-radio-button:has-text("External")').first()
              .click({ timeout: 3000, force: true })
              .catch(function() { return null; });
            await page.locator('button:has-text("Next"), button:has-text("Save and continue"), button:has-text("Continue")').first()
              .click({ timeout: 5000, force: true })
              .catch(function() { return null; });
            await page.waitForTimeout(1800);

            // Step 3: Contact info
            if (autosetupEmail) {
              await page.locator('input[type="email"], input[aria-label*="email" i], input[placeholder*="email" i]').first()
                .fill(autosetupEmail, { timeout: 4000 })
                .catch(function() { return null; });
              await page.keyboard.press('Enter').catch(function() { return null; });
            }
            await page.locator('button:has-text("Next"), button:has-text("Save and continue"), button:has-text("Continue")').first()
              .click({ timeout: 5000, force: true })
              .catch(function() { return null; });
            await page.waitForTimeout(2000);

            // Step 4: Finish
            await page.locator('button:has-text("Create"), button:has-text("Save"), button:has-text("Done"), button:has-text("Continue")').first()
              .click({ timeout: 6000, force: true })
              .catch(function() { return null; });
            await page.waitForTimeout(2500);

            var stillUnconfigured = await page.evaluate(function() {
              var body = (document.body && document.body.innerText ? document.body.innerText : '').toLowerCase();
              return body.indexOf('google auth platform not configured yet') !== -1;
            }).catch(function() { return false; });

            if (!stillUnconfigured) {
              sendStep('Google Auth Platform configured deterministically.');
              return true;
            }

            sendStep('Deterministic branding setup incomplete; falling back to AI step planning.');
            return false;
          } catch (e) {
            sendStep('Deterministic branding setup failed: ' + e.message.substring(0, 120));
            return false;
          }
        }

        async function runAuthClientsQuickStartDeterministic(pid) {
          try {
            var clientsUrl = pid
              ? 'https://console.cloud.google.com/auth/clients?project=' + encodeURIComponent(pid)
              : 'https://console.cloud.google.com/auth/clients';
            sendStep('Running deterministic Clients quick-start handling...');
            await page.goto(clientsUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
            await page.waitForTimeout(2200);

            // Prefer direct selector click first.
            await page.locator('button:has-text("Get started"), a:has-text("Get started"), [role="button"]:has-text("Get started")')
              .first()
              .click({ timeout: 5000, force: true })
              .catch(function() { return null; });
            await page.waitForTimeout(1800);

            var stillNeedsStart = await page.evaluate(function() {
              var body = (document.body && document.body.innerText ? document.body.innerText : '').toLowerCase();
              return body.indexOf('google auth platform not configured yet') !== -1;
            }).catch(function() { return false; });

            if (!stillNeedsStart) return true;

            // JS fallback click.
            await page.evaluate(function() {
              var nodes = document.querySelectorAll('button, a, [role="button"]');
              for (var i = 0; i < nodes.length; i++) {
                var txt = (nodes[i].textContent || '').trim().toLowerCase();
                if (txt.indexOf('get started') !== -1) {
                  try {
                    nodes[i].scrollIntoView({ block: 'center', inline: 'center' });
                    nodes[i].click();
                    return true;
                  } catch (e) {}
                }
              }
              return false;
            }).catch(function() { return false; });
            await page.waitForTimeout(1800);

            stillNeedsStart = await page.evaluate(function() {
              var body = (document.body && document.body.innerText ? document.body.innerText : '').toLowerCase();
              return body.indexOf('google auth platform not configured yet') !== -1;
            }).catch(function() { return false; });

            return !stillNeedsStart;
          } catch (e) {
            sendStep('Deterministic Clients quick-start handling failed: ' + e.message.substring(0, 120));
            return false;
          }
        }

        // ── AI Agent Loop using Claude Opus 4.6 via OpenRouter ──
        var AI_MODEL = 'anthropic/claude-opus-4-6';
        var MAX_STEPS = 150;
        var SYSTEM_PROMPT = [
          'You are an AI agent controlling a browser (390×844 viewport) to set up Google Cloud OAuth credentials.',
          '',
          'YOUR TASK — complete these steps IN ORDER. Do NOT skip steps. Use "navigate" actions with full URLs whenever possible instead of clicking through menus.',
          '',
          'STEP 1 — CREATE PROJECT (skip if context says "Known project ID"):',
          '  Navigate to https://console.cloud.google.com/projectcreate',
          '  Fill "liono" as the project name, click Create, wait 10 seconds.',
          '  The project ID will be auto-generated (e.g. "liono-447318"). Note it from the URL after redirect.',
          '',
          'STEP 2 — ENABLE APIs (use navigate action for each):',
          '  Navigate to https://console.cloud.google.com/apis/library/gmail.googleapis.com?project=PROJECT_ID',
          '  If you see "Enable" button, click it and wait 8 seconds. If it says "Enabled" or "Manage", skip to next.',
          '  Then: https://console.cloud.google.com/apis/library/calendar-json.googleapis.com?project=PROJECT_ID',
          '  Then: https://console.cloud.google.com/apis/library/drive.googleapis.com?project=PROJECT_ID',
          '',
          'STEP 3 — CONFIGURE AUTH PLATFORM:',
          '  Navigate directly to https://console.cloud.google.com/auth/branding?project=PROJECT_ID',
          '  If the page says "Google auth platform not configured yet", click "Get started".',
          '  If "Get started" does not respond, use a different method (JS click, keyboard Enter, or navigate to /auth/branding/edit?project=PROJECT_ID).',
          '  If you see "Go to OAuth consent screen" or "Configure Consent Screen", click it.',
          '  Fill the branding form steps:',
          '    Step 1 (App Info): Type "LIONO" in App name. Click the email dropdown, select the email. Click Next.',
          '    Step 2 (Audience): Select External. Click Next.',
          '    Step 3 (Contact Info): Type the user email in the email field, press Enter to add it as a chip. Click Next.',
          '    Step 4 (Finish): Click Create/Save.',
          '',
          'STEP 4 — PUBLISH THE APP (CRITICAL — tokens expire after 7 days if skipped):',
          '  Navigate to https://console.cloud.google.com/auth/audience?project=PROJECT_ID',
          '  Look for the "Publishing status" section. If it says "Testing", click "PUBLISH APP".',
          '  A confirmation dialog will appear — click "CONFIRM" or "PUBLISH" to move the app to Production.',
          '  If it already says "In production", skip to the next step.',
          '  If you cannot find the publish button on this page, try:',
          '    https://console.cloud.google.com/apis/credentials/consent?project=PROJECT_ID',
          '  Look for a "PUBLISH APP" button and click it, then confirm.',
          '',
          'STEP 5 — CREATE OAUTH CLIENT:',
          '  Navigate to https://console.cloud.google.com/auth/clients/create?project=PROJECT_ID',
          '  Select "Web application" as application type.',
          '  Name it "LIONO".',
          '  Click Create.',
          '  A dialog appears with Client ID and Client Secret. Read BOTH values carefully and return them with "done".',
          '',
          'CRITICAL RULES:',
          '- IGNORE cookie banners, "Got it" popups, and notification overlays. They are auto-dismissed. Do NOT waste actions on them.',
          '- NEVER click the same coordinates more than twice. If something did not work, try a DIFFERENT approach (navigate to a URL, scroll, or try different coordinates).',
          '- Use "navigate" action whenever you know the target URL. This is faster and more reliable than clicking links.',
          '- Google Cloud uses Material Design. Dropdowns are mat-select — click, wait for panel, click option.',
          '- For email "chip" fields: type the email, then press Enter.',
          '- If a page is loading (spinner visible), use "wait" with duration 5.',
          '- The viewport is 390px wide. Elements are stacked. Scroll if needed.',
          '- All coordinates must be NUMBERS (not strings). Example: [195, 400] not [195, "400"].',
          '- If you see "Select a project" at the top, the project context was lost — use navigate with ?project=PROJECT_ID.',
          '- STEP 4 (Publish App) is MANDATORY. Do NOT skip it. Without publishing, OAuth tokens expire after 7 days.',
          '',
          'RESPONSE FORMAT — respond with EXACTLY ONE JSON object:',
          '{"action":"left_click","coordinate":[x,y],"reasoning":"..."}',
          '{"action":"double_click","coordinate":[x,y],"reasoning":"..."}',
          '{"action":"triple_click","coordinate":[x,y],"reasoning":"..."}',
          '{"action":"type","text":"...","reasoning":"..."}',
          '{"action":"key","key":"Enter","reasoning":"..."}',
          '{"action":"scroll","coordinate":[x,y],"direction":"down","amount":3,"reasoning":"..."}',
          '{"action":"wait","duration":5,"reasoning":"..."}',
          '{"action":"navigate","url":"https://...","reasoning":"..."}',
          '{"action":"done","result":{"clientId":"...","clientSecret":"...","projectId":"..."},"reasoning":"..."}',
          '{"action":"error","message":"...","reasoning":"..."}',
          '',
          'Output ONLY the JSON. No markdown, no text, no code fences.'
        ].join('\n');

        (async function aiAgentLoop() {
          var actionHistory = [];
          var projectId = browserSession._autosetupProjectName || '';
          var lastActionKey = '';
          var sameActionCount = 0;
          var authClientsStallCount = 0;
          var brandingStallCount = 0;

          // Pre-flight: dismiss cookies and navigate to starting point
          try {
            await page.evaluate(function() {
              try {
                document.querySelectorAll('[aria-label="Hide"], [aria-label="Dismiss"], [aria-label="Close"]').forEach(function(el) { el.click(); });
                var btns = document.querySelectorAll('button');
                btns.forEach(function(b) { var t = (b.textContent || '').trim().toLowerCase(); if (t === 'hide' || t === 'got it' || t === 'accept all') b.click(); });
                document.querySelectorAll('[class*="cookie"], [id*="cookie"], [class*="consent"]').forEach(function(el) { el.remove(); });
              } catch(e) {}
            }).catch(function() {});

            if (projectId) {
              sendStep('Resuming setup for project: ' + projectId);
              await page.goto('https://console.cloud.google.com/apis/library/gmail.googleapis.com?project=' + projectId, { waitUntil: 'domcontentloaded', timeout: 30000 });
            } else {
              sendStep('Creating new project...');
              await page.goto('https://console.cloud.google.com/projectcreate', { waitUntil: 'domcontentloaded', timeout: 30000 });
            }
            await page.waitForTimeout(4000);
          } catch(navErr) {
            console.error('[AI-Setup] Pre-flight nav error:', navErr.message);
          }

          for (var step = 0; step < MAX_STEPS; step++) {
            try {
              // 0. Auto-dismiss cookie banners and popups via JS (before every screenshot)
              await page.evaluate(function() {
                try {
                  document.querySelectorAll('[aria-label="Hide"], [aria-label="Dismiss"], [aria-label="Close"], [aria-label="Got it"]').forEach(function(el) { el.click(); });
                  var btns = document.querySelectorAll('button');
                  btns.forEach(function(b) {
                    var t = (b.textContent || '').trim().toLowerCase();
                    if (t === 'hide' || t === 'got it' || t === 'dismiss' || t === 'accept all' || t === 'i understand') b.click();
                  });
                  document.querySelectorAll('.cookieBarConsentContent, [class*="cookie"], [id*="cookie"], [class*="consent"]').forEach(function(el) { el.remove(); });
                } catch(e) {}
              }).catch(function() {});
              await page.waitForTimeout(300);

              // 1. Capture screenshot (JPEG to save memory)
              var screenshotBuf = await page.screenshot({ type: 'jpeg', quality: 55 });
              var screenshotB64 = screenshotBuf.toString('base64');
              screenshotBuf = null;
              var currentUrl = page.url();
              var urlProjectMatch = currentUrl.match(/[?&]project=([a-z0-9-]+)/i);
              if (urlProjectMatch && urlProjectMatch[1]) {
                projectId = urlProjectMatch[1];
                browserSession._autosetupProjectName = projectId;
              }
              if (!projectId) {
                var inferredProjectId = await page.evaluate(function() {
                  try {
                    // 1) Any link containing ?project=...
                    var links = document.querySelectorAll('a[href*="project="], button[aria-label*="project"]');
                    for (var i = 0; i < links.length; i++) {
                      var href = links[i].href || links[i].getAttribute('href') || '';
                      var m = href.match(/[?&]project=([a-z0-9-]+)/i);
                      if (m && m[1]) return m[1];
                    }
                    // 2) Fallback: scan page text for openclaw-* style IDs
                    var txt = (document.body && document.body.innerText) ? document.body.innerText : '';
                    var m2 = txt.match(/\b(liono-[a-z0-9-]{4,})\b/i);
                    if (m2 && m2[1]) return m2[1];
                  } catch (e) {}
                  return '';
                }).catch(function() { return ''; });
                if (inferredProjectId) {
                  projectId = inferredProjectId;
                  browserSession._autosetupProjectName = inferredProjectId;
                  sendStep('Detected project ID from page: ' + inferredProjectId);
                }
              }

              // Deterministic helper for the exact screen shown in user reports:
              // Google Auth Platform / Branding page with "Google auth platform not configured yet"
              // and a centered "Get started" button. Use selector click instead of AI coordinates.
              if (currentUrl.indexOf('/auth/branding') !== -1) {
                var needsBrandingStart = await page.evaluate(function() {
                  try {
                    var body = (document.body && document.body.innerText ? document.body.innerText : '').toLowerCase();
                    if (body.indexOf('google auth platform not configured yet') === -1) return false;
                    var candidates = document.querySelectorAll('button, a, [role="button"]');
                    for (var i = 0; i < candidates.length; i++) {
                      var txt = (candidates[i].textContent || '').trim().toLowerCase();
                      if (txt === 'get started' || txt.indexOf('get started') !== -1) return true;
                    }
                  } catch (e) {}
                  return false;
                }).catch(function() { return false; });

                if (needsBrandingStart) {
                  brandingStallCount++;
                  if (brandingStallCount >= 2) {
                    sendStep('AI appears stuck on Get started. Falling back to deterministic branding setup...');
                    var deterministicOk = await runBrandingWizardDeterministic(projectId);
                    brandingStallCount = 0;
                    if (deterministicOk && projectId) {
                      await page.goto('https://console.cloud.google.com/auth/audience?project=' + encodeURIComponent(projectId), {
                        waitUntil: 'domcontentloaded',
                        timeout: 30000
                      }).catch(function() { return null; });
                      await page.waitForTimeout(1800);
                      continue;
                    }
                  } else {
                    if (projectId) {
                      sendStep('Branding quick-start detected. Letting AI attempt Get started first...');
                    } else {
                      sendStep('Branding quick-start detected without project ID. Letting AI proceed first...');
                    }
                  }
                } else {
                  brandingStallCount = 0;
                }
              }

              // Deterministic fallback:
              // If Auth Clients "Get started" is visible but appears stuck, bypass it by
              // navigating directly to the branding page.
              if (currentUrl.indexOf('/auth/clients') !== -1) {
                var hasGetStarted = await page.evaluate(function() {
                  try {
                    var all = document.querySelectorAll('button, a, [role="button"]');
                    for (var i = 0; i < all.length; i++) {
                      var el = all[i];
                      var txt = (el.textContent || '').trim().toLowerCase();
                      if (!txt) continue;
                      if (txt.indexOf('get started') !== -1 || txt.indexOf('oauth consent') !== -1 || txt.indexOf('configure consent') !== -1) {
                        var style = window.getComputedStyle(el);
                        if (style && style.display !== 'none' && style.visibility !== 'hidden') return true;
                      }
                    }
                  } catch (e) {}
                  return false;
                }).catch(function() { return false; });

                if (hasGetStarted) {
                  authClientsStallCount++;
                  sendStep('Clients quick-start detected. Switching to deterministic setup from this page...');
                  var handledClientsQuickStart = await runAuthClientsQuickStartDeterministic(projectId);
                  if (!handledClientsQuickStart) {
                    sendStep('Clients quick-start click did not advance. Proceeding directly with deterministic branding flow...');
                  }

                  var deterministicBrandingOk = await runBrandingWizardDeterministic(projectId);
                  if (deterministicBrandingOk && projectId) {
                    await page.goto('https://console.cloud.google.com/auth/audience?project=' + encodeURIComponent(projectId), {
                      waitUntil: 'domcontentloaded',
                      timeout: 30000
                    }).catch(function() { return null; });
                    await page.waitForTimeout(1800);
                  }
                  authClientsStallCount = 0;
                  continue;
                } else {
                  authClientsStallCount = 0;
                }
              } else {
                authClientsStallCount = 0;
              }

              // 2. Build context message
              var contextLines = ['Step ' + (step + 1) + ' of ' + MAX_STEPS];
              contextLines.push('Current URL: ' + currentUrl);
              if (projectId) contextLines.push('Known project ID: ' + projectId);
              if (actionHistory.length > 0) {
                contextLines.push('');
                contextLines.push('Actions taken so far:');
                var recentActions = actionHistory.slice(-10);
                recentActions.forEach(function(a, i) {
                  contextLines.push((actionHistory.length - recentActions.length + i + 1) + '. ' + a);
                });
              }
              if (sameActionCount >= 2) {
                contextLines.push('');
                contextLines.push('WARNING: You have repeated the same action ' + sameActionCount + ' times. It is NOT working. You MUST try a completely different approach — use "navigate" to go to the correct URL directly, or try different coordinates, or scroll first.');
              }
              contextLines.push('');
              contextLines.push('Look at the screenshot and decide the next action. Ignore cookie banners — they are auto-dismissed.');

              sendStep('AI thinking... (step ' + (step + 1) + ')');

              // 3. Call Claude Opus 4.6 via OpenRouter
              var apiResponse;
              try {
                var aiController = new AbortController();
                var aiStartTs = Date.now();
                var aiHeartbeat = setInterval(function() {
                  var elapsedSec = Math.floor((Date.now() - aiStartTs) / 1000);
                  sendStep('AI still thinking... step ' + (step + 1) + ' (' + elapsedSec + 's)');
                }, 5000);
                var aiTimeout = setTimeout(function() { aiController.abort(); }, 30000);
                apiResponse = await fetch('https://openrouter.ai/api/v1/chat/completions', {
                  method: 'POST',
                  headers: {
                    'Authorization': 'Bearer ' + OPENROUTER_KEY,
                    'Content-Type': 'application/json',
                    'HTTP-Referer': 'https://lionoai.com',
                    'X-Title': 'LIONO GCP Setup'
                  },
                  body: JSON.stringify({
                    model: AI_MODEL,
                    max_tokens: 512,
                    temperature: 0,
                    messages: [
                      { role: 'system', content: SYSTEM_PROMPT },
                      { role: 'user', content: [
                        { type: 'image_url', image_url: { url: 'data:image/jpeg;base64,' + screenshotB64 } },
                        { type: 'text', text: contextLines.join('\n') }
                      ]}
                    ]
                  }),
                  signal: aiController.signal
                });
                clearInterval(aiHeartbeat);
                clearTimeout(aiTimeout);
              } catch (aiErr) {
                try { clearInterval(aiHeartbeat); } catch (e) {}
                if (aiErr && aiErr.name === 'AbortError') {
                  sendStep('AI response timeout at step ' + (step + 1) + '. Retrying...');
                  // If timeout happens on branding quick-start, force deterministic fallback immediately.
                  if (projectId && currentUrl.indexOf('/auth/branding') !== -1) {
                    sendStep('Timeout on branding screen. Switching to deterministic setup...');
                    await runBrandingWizardDeterministic(projectId);
                  }
                  await page.waitForTimeout(1200);
                  continue;
                }
                sendStep('AI request error: ' + (aiErr && aiErr.message ? aiErr.message.substring(0, 100) : 'unknown'));
                await page.waitForTimeout(1200);
                continue;
              }

              screenshotB64 = null;
              if (!apiResponse || !apiResponse.ok) {
                var statusCode = apiResponse ? apiResponse.status : 'n/a';
                sendStep('AI provider returned HTTP ' + statusCode + '. Retrying...');
                await page.waitForTimeout(1500);
                continue;
              }
              var apiBody = await apiResponse.json();
              apiResponse = null;
              var content = apiBody.choices && apiBody.choices[0] && apiBody.choices[0].message && apiBody.choices[0].message.content;
              apiBody = null;

              if (!content) {
                console.log('[AI-Setup] Empty response:', JSON.stringify(apiBody).substring(0, 300));
                sendStep('AI returned empty response, retrying...');
                await page.waitForTimeout(2000);
                continue;
              }

              console.log('[AI-Setup] Step ' + (step + 1) + ' raw (' + content.length + ' chars): ' + content.substring(0, 500));

              // 4. Parse JSON action — use balanced-brace extraction (not greedy regex)
              var jsonStr = null;
              (function() {
                var start = content.indexOf('{');
                if (start === -1) return;
                var depth = 0, inStr = false, esc = false;
                for (var i = start; i < content.length; i++) {
                  var c = content[i];
                  if (esc) { esc = false; continue; }
                  if (c === '\\' && inStr) { esc = true; continue; }
                  if (c === '"') { inStr = !inStr; continue; }
                  if (inStr) continue;
                  if (c === '{') depth++;
                  if (c === '}') { depth--; if (depth === 0) { jsonStr = content.substring(start, i + 1); return; } }
                }
              })();

              if (!jsonStr) {
                console.log('[AI-Setup] No JSON found in response');
                sendStep('No JSON in AI response, retrying...');
                await page.waitForTimeout(1000);
                continue;
              }

              console.log('[AI-Setup] Extracted JSON (' + jsonStr.length + ' chars): ' + jsonStr.substring(0, 300));

              var action;
              try { action = JSON.parse(jsonStr); } catch (e) {
                console.log('[AI-Setup] JSON.parse error: ' + e.message);
                console.log('[AI-Setup] JSON string was: ' + jsonStr.substring(0, 500));
                sendStep('JSON parse error: ' + e.message.substring(0, 80));
                await page.waitForTimeout(1000);
                continue;
              }

              var desc = action.reasoning || action.action;
              sendStep(desc);
              actionHistory.push(desc);

              // 5. Coerce coordinates to numbers
              if (action.coordinate && Array.isArray(action.coordinate)) {
                action.coordinate[0] = Number(action.coordinate[0]);
                action.coordinate[1] = Number(action.coordinate[1]);
              }

              // 5b. Stuck-loop detection: if same action+coordinate 3+ times, force navigate
              var actionKey = action.action + ':' + JSON.stringify(action.coordinate || []) + ':' + (action.text || '');
              if (actionKey === lastActionKey) {
                sameActionCount++;
                if (sameActionCount >= 3) {
                  console.log('[AI-Setup] STUCK DETECTED: same action ' + sameActionCount + ' times: ' + actionKey);
                  if (currentUrl.indexOf('/auth/clients') !== -1) {
                    sendStep('Stuck on Auth Clients page. Forcing deterministic quick-start handling...');
                    var handledClientsStuck = await runAuthClientsQuickStartDeterministic(projectId);
                    if (!handledClientsStuck) {
                      await runBrandingWizardDeterministic(projectId);
                    }
                  } else {
                    sendStep('Stuck detected — skipping repeated action and trying a different approach');
                  }
                  sameActionCount = 0;
                  lastActionKey = '';
                  await page.waitForTimeout(1000);
                  continue;
                }
              } else {
                lastActionKey = actionKey;
                sameActionCount = 1;
              }

              // 6. Execute the action
              console.log('[AI-Setup] Executing: ' + action.action + (action.coordinate ? ' at (' + action.coordinate + ')' : '') + (action.text ? ' text="' + action.text + '"' : ''));

              if (action.action === 'left_click' || action.action === 'click') {
                var cx = action.coordinate[0], cy = action.coordinate[1];
                await page.mouse.click(cx, cy);
                await page.waitForTimeout(2000);

              } else if (action.action === 'double_click') {
                var dcx = action.coordinate[0], dcy = action.coordinate[1];
                await page.mouse.dblclick(dcx, dcy);
                await page.waitForTimeout(1500);

              } else if (action.action === 'triple_click') {
                var tcx = action.coordinate[0], tcy = action.coordinate[1];
                await page.mouse.click(tcx, tcy, { clickCount: 3 });
                await page.waitForTimeout(1000);

              } else if (action.action === 'right_click') {
                var rcx = action.coordinate[0], rcy = action.coordinate[1];
                await page.mouse.click(rcx, rcy, { button: 'right' });
                await page.waitForTimeout(1500);

              } else if (action.action === 'type') {
                console.log('[AI-Setup] Type: "' + action.text + '"');
                await page.keyboard.type(action.text, { delay: 50 });
                await page.waitForTimeout(500);

              } else if (action.action === 'key') {
                console.log('[AI-Setup] Key: ' + action.key);
                await page.keyboard.press(action.key);
                await page.waitForTimeout(1000);

              } else if (action.action === 'scroll') {
                var sx = action.coordinate ? Number(action.coordinate[0]) : 195;
                var sy = action.coordinate ? Number(action.coordinate[1]) : 422;
                var scrollDir = action.direction === 'up' ? -1 : 1;
                var scrollAmt = scrollDir * (Number(action.amount) || 3) * 100;
                console.log('[AI-Setup] Scroll ' + action.direction + ' by ' + scrollAmt + ' at (' + sx + ',' + sy + ')');
                await page.mouse.move(sx, sy);
                await page.mouse.wheel(0, scrollAmt);
                await page.waitForTimeout(1000);

              } else if (action.action === 'wait') {
                var waitSec = Math.min(Number(action.duration) || 3, 10);
                console.log('[AI-Setup] Wait ' + waitSec + 's');
                await page.waitForTimeout(waitSec * 1000);

              } else if (action.action === 'navigate') {
                console.log('[AI-Setup] Navigate: ' + action.url);
                await page.goto(action.url, { waitUntil: 'domcontentloaded', timeout: 30000 });
                await page.waitForTimeout(4000);
                // Extract project ID from URL if present
                var urlMatch = action.url.match(/project=([a-z0-9-]+)/);
                if (urlMatch) projectId = urlMatch[1];

              } else if (action.action === 'done') {
                var creds = action.result || {};
                console.log('[AI-Setup] DONE! Client ID: ' + (creds.clientId || '').substring(0, 30) + '...');
                GOOGLE_WEB_CLIENT_ID = creds.clientId || '';
                GOOGLE_WEB_CLIENT_SECRET = creds.clientSecret || '';
                if (creds.projectId) browserSession._autosetupProjectName = creds.projectId;
                try {
                  var envPath = require('path').join(__dirname, '.env');
                  var envContent = '';
                  try { envContent = require('fs').readFileSync(envPath, 'utf8'); } catch(e) {}
                  if (envContent.indexOf('GOOGLE_WEB_CLIENT_ID') === -1) envContent += '\nGOOGLE_WEB_CLIENT_ID=' + creds.clientId;
                  else envContent = envContent.replace(/GOOGLE_WEB_CLIENT_ID=.*/, 'GOOGLE_WEB_CLIENT_ID=' + creds.clientId);
                  if (envContent.indexOf('GOOGLE_WEB_CLIENT_SECRET') === -1) envContent += '\nGOOGLE_WEB_CLIENT_SECRET=' + creds.clientSecret;
                  else envContent = envContent.replace(/GOOGLE_WEB_CLIENT_SECRET=.*/, 'GOOGLE_WEB_CLIENT_SECRET=' + creds.clientSecret);
                  require('fs').writeFileSync(envPath, envContent);
                } catch(e) { console.error('[AI-Setup] .env save failed:', e.message); }
                sendEvent(ws, 'google.browser', { step: 'complete', message: 'Setup complete! Credentials saved.', projectId: creds.projectId, clientId: creds.clientId });
                closeBrowserSession();
                return;

              } else if (action.action === 'error') {
                console.error('[AI-Setup] AI reported error:', action.message);
                sendEvent(ws, 'google.browser', { step: 'error', message: 'AI: ' + action.message });
                return;

              } else {
                sendStep('Unknown action: ' + action.action);
              }

              // Track project ID if mentioned in reasoning
              if (action.reasoning) {
                var pidMatch = action.reasoning.match(/project[- _]?(?:id|ID)?[:\s]+([a-z][a-z0-9-]+)/);
                if (pidMatch && pidMatch[1].length > 5) {
                  projectId = pidMatch[1];
                  browserSession._autosetupProjectName = projectId;
                }
              }

            } catch (err) {
              console.error('[AI-Setup] Step ' + (step + 1) + ' error:', err.message);
              sendStep('Error: ' + err.message.substring(0, 100));
              await page.waitForTimeout(2000);
            }
          }

          sendEvent(ws, 'google.browser', { step: 'error', message: 'AI automation reached max steps (' + MAX_STEPS + ') without completing.' });
        })().catch(function(err) {
          console.error('[AI-Setup] Fatal:', err.message);
          sendEvent(ws, 'google.browser', { step: 'error', message: 'AI error: ' + err.message });
        });
        return;
      }

      // ── google.browser.frame — Get current screenshot frame ──
      if (method === 'google.browser.frame') {
        if (!browserSession || !browserSession.lastFrame) {
          sendRes(ws, id, true, { frame: null, status: 'no_frame' });
          return;
        }
        sendRes(ws, id, true, { frame: browserSession.lastFrame, status: 'ok' });
        return;
      }

      // ── google.browser.click — Click at coordinates ──
      if (method === 'google.browser.click') {
        if (!browserSession || !browserSession.page) {
          sendRes(ws, id, false, null, { code: 'NO_BROWSER', message: 'No browser session active' });
          return;
        }
        var x = params.x || 0;
        var y = params.y || 0;
        browserSession.page.mouse.click(x, y).then(function () {
          sendRes(ws, id, true, { clicked: true, x: x, y: y });
        }).catch(function (err) {
          sendRes(ws, id, false, null, { code: 'CLICK_FAILED', message: err.message });
        });
        return;
      }

      // ── google.browser.type — Type text ──
      if (method === 'google.browser.type') {
        if (!browserSession || !browserSession.page) {
          sendRes(ws, id, false, null, { code: 'NO_BROWSER', message: 'No browser session active' });
          return;
        }
        var text = params.text || '';
        browserSession.page.keyboard.type(text, { delay: 50 }).then(function () {
          sendRes(ws, id, true, { typed: true });
        }).catch(function (err) {
          sendRes(ws, id, false, null, { code: 'TYPE_FAILED', message: err.message });
        });
        return;
      }

      // ── google.browser.key — Press a key ──
      if (method === 'google.browser.key') {
        if (!browserSession || !browserSession.page) {
          sendRes(ws, id, false, null, { code: 'NO_BROWSER', message: 'No browser session active' });
          return;
        }
        var key = params.key || 'Enter';
        browserSession.page.keyboard.press(key).then(function () {
          sendRes(ws, id, true, { pressed: key });
        }).catch(function (err) {
          sendRes(ws, id, false, null, { code: 'KEY_FAILED', message: err.message });
        });
        return;
      }

      // ── google.browser.automate — Run GCP console automation ──
      if (method === 'google.browser.automate') {
        if (!browserSession || !browserSession.page) {
          sendRes(ws, id, false, null, { code: 'NO_BROWSER', message: 'No browser session active' });
          return;
        }
        var gcpProjectId = params.projectId || '';
        var gcpEmail = params.email || (googleTokens && googleTokens.email) || '';
        if (!gcpProjectId) {
          sendRes(ws, id, false, null, { code: 'MISSING_PROJECT', message: 'projectId required' });
          return;
        }
        automateGcpConsoleSetup(gcpProjectId, gcpEmail, function (statusMsg) {
          sendEvent(ws, 'google.browser', { step: 'automating', message: statusMsg });
        }, function (err, creds) {
          if (err) {
            sendRes(ws, id, false, null, { code: 'AUTOMATE_FAILED', message: err.message });
            return;
          }
          // Save the user's project credentials
          if (creds && creds.clientId) {
            saveUserProjectConfig({
              projectId: gcpProjectId,
              clientId: creds.clientId,
              clientSecret: creds.clientSecret || '',
              createdAt: new Date().toISOString()
            });
          }
          sendRes(ws, id, true, {
            status: 'complete',
            projectId: gcpProjectId,
            clientId: creds ? creds.clientId : null,
            message: 'GCP project fully configured with OAuth credentials'
          });
          closeBrowserSession();
        });
        return;
      }

      // ── google.browser.stop — Close browser ──
      if (method === 'google.browser.stop') {
        closeBrowserSession();
        sendRes(ws, id, true, { stopped: true });
        return;
      }

      // ── google.project.credentials — Manually set user project credentials ──
      if (method === 'google.project.credentials') {
        var clientId = params.clientId || '';
        var clientSecret = params.clientSecret || '';
        var projId = params.projectId || '';
        if (!clientId) {
          sendRes(ws, id, false, null, { code: 'MISSING_CLIENT_ID', message: 'clientId is required' });
          return;
        }
        saveUserProjectConfig({
          projectId: projId,
          clientId: clientId,
          clientSecret: clientSecret,
          createdAt: new Date().toISOString()
        });
        sendRes(ws, id, true, { saved: true, message: 'User project credentials saved' });
        return;
      }

      // ── system-presence ──
      if (method === 'system-presence') {
        sendRes(ws, id, true, {
          presence: [{
            instanceId: instanceId,
            host: os.hostname(),
            ip: HOST,
            version: GATEWAY_VERSION,
            platform: 'linux',
            deviceFamily: 'server',
            roles: ['gateway'],
            connectedAtMs: now()
          }]
        });
        return;
      }

      sendRes(ws, id, false, null, { code: 'UNKNOWN_METHOD', message: 'Method not supported: ' + method });
      return;
    }

    // Legacy connect
    if (msgType === 'connect') {
      var legacyToken = (params && params.token) || '';
      if (TOKEN && legacyToken !== TOKEN) {
        sendJSON(ws, { type: 'error', error: 'Invalid token' });
        ws.close();
        return;
      }
      authenticated = true;
      sendJSON(ws, { type: 'hello-ok', features: { agents: true, sessions: true, presence: true, health: true }, version: 3 });
      setTimeout(function () {
        sendJSON(ws, { type: 'snapshot', agents: agents, sessions: Object.keys(sessions).map(function (k) { return sessions[k]; }), defaults: { agentId: 'default' } });
      }, 100);
    }
  });

  ws.on('close', function () { });
});

// Presence tick
setInterval(function () {
  wss.clients.forEach(function (ws) {
    if (ws.readyState === 1) {
      sendEvent(ws, 'snapshot', {
        presence: [{ instanceId: 'gateway-' + process.pid, host: os.hostname(), version: GATEWAY_VERSION, platform: 'linux', deviceFamily: 'server', roles: ['gateway'], connectedAtMs: startTime }],
        health: { ok: true, version: GATEWAY_VERSION, uptimeMs: now() - startTime, nodes: [] }
      });
    }
  });
}, 30000);

// Reminder check
setInterval(function () {
  var now = Date.now();
  reminders = reminders.filter(function (r) {
    if (r.triggersAt <= now) {
      console.log('[Reminder] ' + r.message);
      wss.clients.forEach(function (ws) {
        if (ws.readyState === 1) {
          sendEvent(ws, 'notification', { type: 'reminder', message: r.message, id: r.id });
        }
      });
      return false;
    }
    return true;
  });
}, 10000);

process.on('SIGTERM', function () { wss.close(); process.exit(0); });
process.on('SIGINT', function () { wss.close(); process.exit(0); });
