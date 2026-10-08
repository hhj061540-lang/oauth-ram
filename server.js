const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5900;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --------------------------------------------------
// Files & Directories
// --------------------------------------------------
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const APPS_FILE = path.join(DATA_DIR, 'oauth-apps.json');
const SECRET_FILE = path.join(DATA_DIR, 'oauth-secret.key');
const REVOKED_TOKENS_FILE = path.join(DATA_DIR, 'revoked-tokens.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function ensureFile(filePath, defaultValue = []) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2), 'utf-8');
  }
}

ensureFile(USERS_FILE);
ensureFile(APPS_FILE);
ensureFile(REVOKED_TOKENS_FILE);

// --------------------------------------------------
// OAuth secret
// --------------------------------------------------
let OAUTH_SECRET = null;
if (fs.existsSync(SECRET_FILE)) {
  OAUTH_SECRET = fs.readFileSync(SECRET_FILE, 'utf-8').trim();
}
if (!OAUTH_SECRET) {
  OAUTH_SECRET = crypto.randomBytes(64).toString('hex');
  fs.writeFileSync(SECRET_FILE, OAUTH_SECRET, { encoding: 'utf-8', mode: 0o600 });
}
console.log('OAuth secret key loaded/generated.');

// --------------------------------------------------
// Temporary storage
// --------------------------------------------------
const deviceCodes = {};
const authorizationCodes = {};

// --------------------------------------------------
// Helpers
// --------------------------------------------------
function readJson(filePath) {
  try {
    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2), 'utf-8');
}

function randomHex(bytesLen) {
  return crypto.randomBytes(bytesLen).toString('hex');
}

function randomBase64Url(bytesLen = 32) {
  const raw = crypto.randomBytes(bytesLen);
  return raw.toString('base64url').replace(/=/g, '');
}

function generateClientId() {
  return 'client_' + randomHex(16);
}

function generateClientSecret() {
  return 'secret_' + randomHex(32);
}

function generateDeviceCode() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

function generateAuthorizationCode() {
  return randomBase64Url(32);
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password || '').digest('hex');
}

function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}`;
}

// --------------------------------------------------
// PKCE
// --------------------------------------------------
function base64UrlSha256(value) {
  const digest = crypto.createHash('sha256').update(value, 'utf-8').digest();
  return digest.toString('base64url').replace(/=/g, '');
}

function verifyPkce(codeVerifier, codeChallenge, method) {
  if (!codeVerifier || !codeChallenge) return false;
  if (method !== 'S256') return false;
  return base64UrlSha256(codeVerifier) === codeChallenge;
}

// --------------------------------------------------
// Token revocation
// --------------------------------------------------
function isTokenRevoked(jti) {
  if (!jti) return false;
  const revoked = readJson(REVOKED_TOKENS_FILE);
  return revoked.some(item => item.jti === jti);
}

function revokeToken(jti, exp) {
  const revoked = readJson(REVOKED_TOKENS_FILE);
  if (revoked.some(item => item.jti === jti)) return;
  revoked.push({
    jti: jti,
    exp: exp || null,
    revokedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
  });
  writeJson(REVOKED_TOKENS_FILE, revoked);
}

// --------------------------------------------------
// HTML Templates
// --------------------------------------------------
const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Account</title>
<style>
body { background:#111; color:#00ff66; font-family:monospace; padding:25px; }
.container { max-width:520px; margin:auto; background:#1b1b1b; padding:25px; border-radius:8px; }
h1,h2 { border-bottom:1px solid #333; padding-bottom:8px; }
input, button { width:100%; box-sizing:border-box; padding:12px; margin:6px 0; background:#222; color:white; border:1px solid #444; font-family:monospace; }
button { background:#0088cc; cursor:pointer; font-weight:bold; }
button:hover { background:#00aaff; }
hr { border:0; border-top:1px solid #333; margin:25px 0; }
</style>
</head>
<body>
<div class="container">
<h1>Connect Account</h1>
<p> Enter your device code to connect your account. </p>
<form method="POST" action="/login/device">
<input name="device_code" placeholder="Enter your device code" required>
<h2>Login</h2>
<input name="username" placeholder="Enter username" required>
<input type="password" name="password" placeholder="Enter password" required>
<button type="submit"> Connect Account </button>
</form>
<hr>
<h2>Register Account</h2>
<form method="POST" action="/api/auth/register">
<input name="username" placeholder="Enter username" required>
<input type="password" name="password" placeholder="Enter password" required>
<button type="submit"> Create Account </button>
</form>
</div>
</body>
</html>
`;

// --------------------------------------------------
// Device pages
// --------------------------------------------------
app.get(['/oauth/device', '/login/device'], (req, res) => {
  res.send(htmlContent);
});

// --------------------------------------------------
// Device code endpoint
// --------------------------------------------------
app.post('/oauth/device/code', (req, res) => {
  const deviceCode = randomHex(32);
  const userCode = generateDeviceCode();
  const expiresIn = 600;
  const clientId = req.body.client_id || (req.is('json') ? req.body.client_id : null);

  const entry = {
    deviceCode: deviceCode,
    userCode: userCode,
    clientId: clientId,
    username: null,
    status: 'pending',
    createdAt: Date.now(),
    expiresAt: Date.now() + expiresIn * 1000
  };

  deviceCodes[deviceCode] = entry;
  const bUrl = baseUrl(req);

  res.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${bUrl}/oauth/device`,
    verification_uri_complete: `${bUrl}/oauth/device?code=${userCode}`,
    expires_in: expiresIn,
    interval: 5
  });
});

// --------------------------------------------------
// Register
// --------------------------------------------------
app.post('/api/auth/register', (req, res) => {
  const data = req.body || {};
  const username = data.username;
  const password = data.password;

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username_and_password_required' });
  }

  if (username.length < 3 || password.length < 8) {
    return res.status(400).json({
      error: 'invalid_registration',
      message: 'Username must contain at least 3 characters and password at least 8 characters.'
    });
  }

  const users = readJson(USERS_FILE);
  if (users.some(u => u.username === username)) {
    return res.status(409).json({ error: 'username_already_exists' });
  }

  const user = {
    id: randomHex(16),
    username: username,
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
  };

  users.push(user);
  writeJson(USERS_FILE, users);

  res.status(201).json({ status: 'success', message: 'Account created', username: username });
});

// --------------------------------------------------
// Login
// --------------------------------------------------
app.post('/api/auth/login', (req, res) => {
  const data = req.body || {};
  const username = data.username;
  const password = data.password;

  const users = readJson(USERS_FILE);
  const user = users.find(u => u.username === username);

  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  const payload = {
    sub: user.id,
    username: user.username,
    jti: randomHex(32),
    exp: Math.floor(Date.now() / 1000) + 3600
  };

  const accessToken = jwt.sign(payload, OAUTH_SECRET, { algorithm: 'HS256' });
  res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
});

// --------------------------------------------------
// Device login
// --------------------------------------------------
app.post('/login/device', (req, res) => {
  const deviceCodeInput = req.body.device_code;
  const username = req.body.username;
  const password = req.body.password;

  if (!deviceCodeInput || !username || !password) {
    return res.status(400).send('Device code, username and password are required.');
  }

  let device = null;
  for (const item of Object.values(deviceCodes)) {
    if (item.deviceCode === deviceCodeInput || item.userCode === deviceCodeInput.toUpperCase()) {
      device = item;
      break;
    }
  }

  if (!device) return res.status(400).send('Invalid device code.');
  if (Date.now() > device.expiresAt) return res.status(400).send('Device code expired.');

  const users = readJson(USERS_FILE);
  const user = users.find(u => u.username === username);

  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).send('Invalid username or password.');
  }

  device.status = 'approved';
  device.username = username;
  res.redirect(`/login/device/success?device_code=${device.deviceCode}`);
});

// --------------------------------------------------
// Device success
// --------------------------------------------------
app.get('/login/device/success', (req, res) => {
  const deviceCode = req.query.device_code;
  const device = deviceCodes[deviceCode];

  if (!device) return res.status(404).send('Device code not found.');
  const usernameEscaped = device.username;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
    <title>Device Connected</title>
    <style>
    body { background:#111; color:#00ff66; font-family:monospace; padding:30px; }
    .box { max-width:600px; margin:auto; background:#1b1b1b; padding:25px; }
    </style>
    </head>
    <body>
    <div class="box">
    <h1>Device Connected</h1>
    <p> Account successfully connected. </p>
    <p> Username: <strong>${usernameEscaped}</strong> </p>
    <p> You can return to your application. </p>
    </div>
    </body>
    </html>
  `);
});

// --------------------------------------------------
// OAuth application creation
// --------------------------------------------------
app.post(['/oauth/apps', '/create'], (req, res) => {
  const data = req.body || {};
  const name = data.name;
  const redirectUri = data.redirect_uri;

  if (typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'application_name_required' });
  }

  const clientId = generateClientId();
  const clientSecret = generateClientSecret();
  const apps = readJson(APPS_FILE);

  const oauthApp = {
    id: randomHex(16),
    name: name.trim(),
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri || null,
    createdAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
  };

  apps.push(oauthApp);
  writeJson(APPS_FILE, apps);

  res.status(201).json({
    status: 'success',
    name: oauthApp.name,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: oauthApp.redirect_uri
  });
});

// --------------------------------------------------
// Create app HTML
// --------------------------------------------------
app.get('/create', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
    <title>Create OAuth App</title>
    </head>
    <body style=" background:#111; color:#00ff66; font-family:monospace; padding:30px; ">
    <h2>Register OAuth App</h2>
    <form method="POST" action="/create" >
    <input name="name" placeholder="App Name" required style=" padding:10px; background:#222; color:#fff; border:1px solid #444; margin-bottom:10px; display:block; ">
    <input name="redirect_uri" placeholder="Redirect URI" style=" padding:10px; background:#222; color:#fff; border:1px solid #444; margin-bottom:10px; display:block; ">
    <button type="submit" style=" padding:10px 20px; background:#0088cc; color:#fff; border:none; cursor:pointer; " > Create App </button>
    </form>
    </body>
    </html>
  `);
});

// --------------------------------------------------
// JWT authentication middleware
// --------------------------------------------------
function authenticateJwt(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Bearer access token required' });
  }

  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, OAUTH_SECRET, { algorithms: ['HS256'] });
    if (decoded.jti && isTokenRevoked(decoded.jti)) {
      return res.status(401).json({ error: 'invalid_token', message: 'Token has been logged out' });
    }
    req.user = decoded;
    req.accessToken = token;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token', message: 'Invalid or expired access token' });
  }
}

// --------------------------------------------------
// GET /oauth/apps
// --------------------------------------------------
app.get('/oauth/apps', authenticateJwt, (req, res) => {
  const apps = readJson(APPS_FILE);
  const safeApps = apps.map(item => ({
    id: item.id,
    name: item.name,
    client_id: item.client_id,
    redirect_uri: item.redirect_uri,
    createdAt: item.createdAt
  }));
  res.json({ count: safeApps.length, apps: safeApps });
});

// --------------------------------------------------
// GET /oauth/apps/:client_id
// --------------------------------------------------
app.get('/oauth/apps/:client_id', authenticateJwt, (req, res) => {
  const apps = readJson(APPS_FILE);
  const oauthApp = apps.find(item => item.client_id === req.params.client_id);
  if (!oauthApp) return res.status(404).json({ error: 'oauth_app_not_found' });

  res.json({
    id: oauthApp.id,
    name: oauthApp.name,
    client_id: oauthApp.client_id,
    redirect_uri: oauthApp.redirect_uri,
    createdAt: oauthApp.createdAt
  });
});

// --------------------------------------------------
// DELETE /oauth/apps/:client_id
// --------------------------------------------------
app.delete('/oauth/apps/:client_id', authenticateJwt, (req, res) => {
  const apps = readJson(APPS_FILE);
  const index = apps.findIndex(item => item.client_id === req.params.client_id);
  if (index === -1) return res.status(404).json({ error: 'oauth_app_not_found' });

  const deleted = apps.splice(index, 1)[0];
  writeJson(APPS_FILE, apps);

  res.json({ status: 'success', message: 'OAuth application deleted', client_id: deleted.client_id });
});

// --------------------------------------------------
// OAuth authorization endpoint
// --------------------------------------------------
app.get('/oauth/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, scope = '', code_challenge, code_challenge_method, state = '' } = req.query;

  if (response_type !== 'code') return res.status(400).json({ error: 'unsupported_response_type' });
  if (!client_id) return res.status(400).json({ error: 'client_id_required' });

  const apps = readJson(APPS_FILE);
  const oauthApp = apps.find(item => item.client_id === client_id);
  if (!oauthApp) return res.status(400).json({ error: 'invalid_client' });
  if (!redirect_uri) return res.status(400).json({ error: 'redirect_uri_required' });
  if (oauthApp.redirect_uri && oauthApp.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'redirect_uri_mismatch' });
  }
  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'invalid_request', message: 'PKCE S256 code_challenge is required' });
  }

  const requestedScopes = scope ? scope.split(' ') : [];
  const scopesHtml = requestedScopes.length
    ? requestedScopes.map(s => `<div class="scope">${s}</div>`).join('')
    : '<div class="scope">No scopes requested</div>';

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Authorize Application</title>
    <style>
    body { background:#111; color:#00ff66; font-family:monospace; padding:30px; }
    .box { max-width:650px; margin:auto; background:#1b1b1b; padding:25px; border-radius:8px; }
    input, button { width:100%; box-sizing:border-box; padding:12px; margin:7px 0; background:#222; color:white; border:1px solid #444; font-family:monospace; }
    button { background:#0088cc; cursor:pointer; }
    .scope { background:#222; padding:8px; margin:5px 0; }
    </style>
    </head>
    <body>
    <div class="box">
    <h1>Authorize Application</h1>
    <p> Application: <strong>${oauthApp.name}</strong> </p>
    <p> Client ID: ${client_id} </p>
    <h3>Requested permissions</h3>
    ${scopesHtml}
    <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="client_id" value="${client_id}">
    <input type="hidden" name="redirect_uri" value="${redirect_uri}">
    <input type="hidden" name="scope" value="${scope}">
    <input type="hidden" name="code_challenge" value="${code_challenge}">
    <input type="hidden" name="code_challenge_method" value="S256">
    <input type="hidden" name="state" value="${state}">
    <h3>Login</h3>
    <input name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit"> Authorize </button>
    </form>
    </div>
    </body>
    </html>
  `);
});

// --------------------------------------------------
// OAuth authorization approval POST
// --------------------------------------------------
app.post('/oauth/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, scope = '', code_challenge, code_challenge_method, state = '', username, password } = req.body;

  if (response_type !== 'code') return res.status(400).json({ error: 'unsupported_response_type' });
  if (!client_id || !redirect_uri) return res.status(400).json({ error: 'invalid_request' });

  const apps = readJson(APPS_FILE);
  const oauthApp = apps.find(item => item.client_id === client_id);
  if (!oauthApp) return res.status(400).json({ error: 'invalid_client' });
  if (oauthApp.redirect_uri && oauthApp.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'redirect_uri_mismatch' });
  }
  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'invalid_request', message: 'PKCE S256 is required' });
  }

  const users = readJson(USERS_FILE);
  const user = users.find(item => item.username === username);

  if (!user || user.passwordHash !== hashPassword(password || '')) {
    return res.status(401).send(`
      <!DOCTYPE html>
      <html>
      <body style=" background:#111; color:#ff4444; font-family:monospace; padding:30px; ">
      <h1>Login Failed</h1>
      <p>Invalid username or password.</p>
      <a href="javascript:history.back()" style="color:#00ff66"> Go Back </a>
      </body>
      </html>
    `);
  }

  const authorizationCode = generateAuthorizationCode();
  authorizationCodes[authorizationCode] = {
    code: authorizationCode,
    clientId: client_id,
    userId: user.id,
    username: user.username,
    redirectUri: redirect_uri,
    scope: scope || '',
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    createdAt: Date.now(),
    expiresAt: Date.now() + 5 * 60 * 1000
  };

  const sep = redirect_uri.includes('?') ? '&' : '?';
  let callback = `${redirect_uri}${sep}code=${authorizationCode}`;
  if (state) callback += `&state=${state}`;

  res.redirect(callback);
});

// --------------------------------------------------
// OAuth token endpoint
// --------------------------------------------------
app.post('/oauth2/token', (req, res) => {
  const data = req.body || {};
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, device_code } = data;

  // Authorization code grant
  if (grant_type === 'authorization_code' || code) {
    if (!code) return res.status(400).json({ error: 'code_required' });
    const authorization = authorizationCodes[code];
    if (!authorization) return res.status(400).json({ error: 'invalid_grant' });

    if (Date.now() > authorization.expiresAt) {
      delete authorizationCodes[code];
      return res.status(400).json({ error: 'expired_authorization_code' });
    }
    if (client_id && client_id !== authorization.clientId) {
      return res.status(400).json({ error: 'invalid_client' });
    }
    if (redirect_uri && redirect_uri !== authorization.redirectUri) {
      return res.status(400).json({ error: 'redirect_uri_mismatch' });
    }
    if (!verifyPkce(code_verifier, authorization.codeChallenge, authorization.codeChallengeMethod)) {
      return res.status(400).json({ error: 'invalid_grant', message: 'PKCE verification failed' });
    }

    delete authorizationCodes[code];

    const payload = {
      sub: authorization.userId,
      username: authorization.username,
      client_id: authorization.clientId,
      scope: authorization.scope,
      jti: randomHex(32),
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    const accessToken = jwt.sign(payload, OAUTH_SECRET, { algorithm: 'HS256' });
    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: authorization.scope
    });
  }

  // Device code grant
  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code' || device_code) {
    if (!device_code) return res.status(400).json({ error: 'device_code_required' });

    if (client_id) {
      const apps = readJson(APPS_FILE);
      const oauthApp = apps.find(item => item.client_id === client_id && (!client_secret || item.client_secret === client_secret));
      if (!oauthApp) return res.status(401).json({ error: 'invalid_client' });
    }

    const device = deviceCodes[device_code];
    if (!device) return res.status(400).json({ error: 'invalid_device_code' });

    if (Date.now() > device.expiresAt) {
      delete deviceCodes[device_code];
      return res.status(400).json({ error: 'expired_device_code' });
    }
    if (device.status === 'pending') {
      return res.status(428).json({ error: 'authorization_pending' });
    }
    if (device.status !== 'approved') {
      return res.status(400).json({ error: 'invalid_device_state' });
    }

    const payload = {
      sub: device.username,
      username: device.username,
      device_code: device.deviceCode,
      jti: randomHex(32),
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    const accessToken = jwt.sign(payload, OAUTH_SECRET, { algorithm: 'HS256' });
    delete deviceCodes[device_code];

    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

// --------------------------------------------------
// Logout
// --------------------------------------------------
app.post('/api/auth/logout', authenticateJwt, (req, res) => {
  if (!req.user.jti) return res.status(400).json({ error: 'token_missing_jti' });
  revokeToken(req.user.jti, req.user.exp);
  res.json({ status: 'success', message: 'Logged out successfully' });
});

// --------------------------------------------------
// Userinfo
// --------------------------------------------------
app.get(['/api/auth/me', '/api/whoami', '/oauth/userinfo'], authenticateJwt, (req, res) => {
  res.json({
    authenticated: true,
    sub: req.user.sub,
    username: req.user.username,
    token_type: 'Bearer',
    scope: req.user.scope
  });
});

// --------------------------------------------------
// RAM
// --------------------------------------------------
app.get('/api/get-ram', authenticateJwt, (req, res) => {
  res.json({ ram_mb: 1024, username: req.user.username });
});

// --------------------------------------------------
// OAuth status
// --------------------------------------------------
app.get('/api/oauth/status', authenticateJwt, (req, res) => {
  res.json({
    authenticated: true,
    username: req.user.username,
    token_type: 'Bearer',
    ram_mb: 1024
  });
});

// --------------------------------------------------
// OAuth discovery metadata
// --------------------------------------------------
function oauthMetadata(req) {
  const issuer = baseUrl(req);
  return {
    issuer: issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth2/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    device_authorization_endpoint: `${issuer}/oauth/device/code`,
    registration_endpoint: `${issuer}/oauth/apps`,
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256'],
    claims_supported: ['sub', 'username', 'email']
  };
}

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json(oauthMetadata(req));
});

app.get('/.well-known/openid-configuration', (req, res) => {
  const metadata = oauthMetadata(req);
  metadata.jwks_uri = `${baseUrl(req)}/oauth/jwks`;
  res.json(metadata);
});

app.get('/oauth/metadata', (req, res) => {
  res.json(oauthMetadata(req));
});

app.get('/oauth/jwks', (req, res) => {
  res.json({ keys: [] });
});

// --------------------------------------------------
// Health
// --------------------------------------------------
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'oauth-device-server', version: '1.0.0', pkce: 'S256' });
});

// --------------------------------------------------
// 404 Handler
// --------------------------------------------------
app.use((req, res) => {
  res.status(404).json({ error: 'not_found' });
});

// --------------------------------------------------
// Start
// --------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`OAuth server running on port ${PORT}`);
  console.log(`Device login: http://localhost:${PORT}/oauth/device`);
  console.log(`Create App: http://localhost:${PORT}/create`);
  console.log(`OAuth authorize: http://localhost:${PORT}/oauth/authorize`);
  console.log(`OAuth token: http://localhost:${PORT}/oauth2/token`);
});
