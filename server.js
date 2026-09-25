require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const DB = {
  users: path.join(DATA_DIR, 'users.json'),
  assets: path.join(DATA_DIR, 'assets.json')
};
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-development-secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'owner@dragonvault.local';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'dragon-admin';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const SITE_URL = (process.env.SITE_URL || '').replace(/\/$/, '');
const ALLOWED_TYPES = new Set(['anime-clips', 'sfx', 'presets', 'projects', 'lili-remake', 'nevonae-remake']);
const MAX_FILE_SIZE = 500 * 1024 * 1024;

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(ROOT, { index: false }));

const storage = multer.diskStorage({
  destination: (_request, _file, callback) => callback(null, UPLOAD_DIR),
  filename: (_request, file, callback) => {
    const safeName = path.basename(file.originalname).replace(/[^a-z0-9._-]/gi, '-');
    callback(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}-${safeName}`);
  }
});
const upload = multer({ storage, limits: { fileSize: MAX_FILE_SIZE } });

async function readJson(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await fs.writeFile(file, JSON.stringify(fallback, null, 2));
    return fallback;
  }
}

async function writeJson(file, value) {
  await fs.writeFile(file, JSON.stringify(value, null, 2));
}

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, role: user.role };
}

async function findOrCreateGoogleUser(userInfo) {
  const users = await readJson(DB.users, []);
  const normalizedEmail = String(userInfo.email || '').trim().toLowerCase();
  if (!normalizedEmail) throw new Error('Google account email is required.');

  let user = users.find((item) => item.email === normalizedEmail);
  if (!user) {
    user = {
      id: crypto.randomUUID(),
      name: userInfo.name || 'Google User',
      email: normalizedEmail,
      passwordHash: null,
      googleSub: userInfo.sub || null,
      picture: userInfo.picture || null,
      role: 'user',
      createdAt: new Date().toISOString()
    };
    users.push(user);
    await writeJson(DB.users, users);
  } else {
    user.name = user.name || userInfo.name || 'Google User';
    user.googleSub = user.googleSub || userInfo.sub || null;
    user.picture = userInfo.picture || user.picture || null;
    await writeJson(DB.users, users);
  }

  return user;
}

function issueToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

async function authenticate(request, response, next) {
  const header = request.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return response.status(401).json({ error: 'Authentication required.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const users = await readJson(DB.users, []);
    const user = users.find((item) => item.id === payload.sub);
    if (!user) return response.status(401).json({ error: 'Session is no longer valid.' });
    request.user = user;
    return next();
  } catch (_error) {
    return response.status(401).json({ error: 'Invalid or expired session.' });
  }
}

function requirePublisher(request, response, next) {
  if (!['admin', 'owner'].includes(request.user.role)) return response.status(403).json({ error: 'Only admins and owners can upload assets.' });
  return next();
}

function requireOwner(request, response, next) {
  if (request.user.role !== 'owner') return response.status(403).json({ error: 'Only the owner can manage admin accounts.' });
  return next();
}

app.get('/api/health', (_request, response) => response.json({ ok: true, service: 'dragon-edit-assets' }));

app.get('/robots.txt', (_request, response) => {
  const sitemap = SITE_URL ? SITE_URL + '/sitemap.xml' : '/sitemap.xml';
  response.type('text/plain').send('User-agent: *\nAllow: /\nSitemap: ' + sitemap + '\n');
});

app.get('/sitemap.xml', (request, response) => {
  const location = SITE_URL || request.protocol + '://' + request.get('host');
  response.type('application/xml').send('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>' + location + '/</loc></url></urlset>');
});
app.post('/api/auth/register', async (request, response, next) => {
  try {
    const { name, email, password } = request.body;
    if (!name || !email || !password || password.length < 6) return response.status(400).json({ error: 'Name, valid email, and a 6-character password are required.' });
    const users = await readJson(DB.users, []);
    const normalizedEmail = email.trim().toLowerCase();
    if (users.some((user) => user.email === normalizedEmail)) return response.status(409).json({ error: 'An account with that email already exists.' });
    const user = { id: crypto.randomUUID(), name: name.trim(), email: normalizedEmail, passwordHash: await bcrypt.hash(password, 12), role: 'user', createdAt: new Date().toISOString() };
    users.push(user);
    await writeJson(DB.users, users);
    return response.status(201).json({ token: issueToken(user), user: publicUser(user) });
  } catch (error) { return next(error); }
});

app.post('/api/auth/login', async (request, response, next) => {
  try {
    const { email, password } = request.body;
    const users = await readJson(DB.users, []);
    const user = users.find((item) => item.email === String(email || '').trim().toLowerCase());
    if (!user || !(await bcrypt.compare(password || '', user.passwordHash))) return response.status(401).json({ error: 'Incorrect email or password.' });
    return response.json({ token: issueToken(user), user: publicUser(user) });
  } catch (error) { return next(error); }
});

app.post('/api/auth/google', async (request, response, next) => {
  try {
    const { token } = request.body || {};
    if (!token) return response.status(400).json({ error: 'Google sign-in token is required.' });
    if (!GOOGLE_CLIENT_ID) return response.status(501).json({ error: 'Google OAuth is not configured on this server.' });

    const googleResponse = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(token)}`);
    if (!googleResponse.ok) return response.status(401).json({ error: 'Google token verification failed.' });

    const payload = await googleResponse.json();
    if (payload.aud !== GOOGLE_CLIENT_ID || payload.email_verified !== 'true' && payload.email_verified !== true) {
      return response.status(401).json({ error: 'Google account verification failed.' });
    }

    const user = await findOrCreateGoogleUser({
      email: payload.email,
      name: payload.name || payload.given_name || 'Google User',
      picture: payload.picture,
      sub: payload.sub
    });

    return response.json({ token: issueToken(user), user: publicUser(user) });
  } catch (error) { return next(error); }
});

app.get('/api/me', authenticate, (request, response) => response.json({ user: publicUser(request.user) }));

app.post('/api/admin/accounts', authenticate, requireOwner, async (request, response, next) => {
  try {
    const { name, email, password } = request.body;
    if (!name || !email || !password || password.length < 6) return response.status(400).json({ error: 'Name, email, and a 6-character key are required.' });
    const users = await readJson(DB.users, []);
    const normalizedEmail = email.trim().toLowerCase();
    if (users.some((user) => user.email === normalizedEmail)) return response.status(409).json({ error: 'An account with that email already exists.' });
    const admin = { id: crypto.randomUUID(), name: name.trim(), email: normalizedEmail, passwordHash: await bcrypt.hash(password, 12), role: 'admin', createdAt: new Date().toISOString() };
    users.push(admin);
    await writeJson(DB.users, users);
    return response.status(201).json({ user: publicUser(admin) });
  } catch (error) { return next(error); }
});

app.get('/api/assets', async (request, response, next) => {
  try {
    const assets = await readJson(DB.assets, []);
    return response.json({ assets });
  } catch (error) { return next(error); }
});

app.get('/api/assets/:id/download', async (request, response, next) => {
  try {
    const assets = await readJson(DB.assets, []);
    const asset = assets.find((item) => item.id === request.params.id);
    if (!asset) return response.status(404).json({ error: 'Asset not found.' });
    return response.download(path.join(UPLOAD_DIR, asset.fileName), asset.originalName);
  } catch (error) { return next(error); }
});

app.post('/api/assets', authenticate, requirePublisher, upload.single('assetFile'), async (request, response, next) => {
  try {
    const { name, type } = request.body;
    if (!request.file || !name || !ALLOWED_TYPES.has(type)) {
      if (request.file) await fs.rm(request.file.path, { force: true });
      return response.status(400).json({ error: 'Asset name, category, and a file are required.' });
    }
    const assets = await readJson(DB.assets, []);
    const asset = {
      id: crypto.randomUUID(),
      name: name.trim(),
      type,
      label: type === 'anime-clips' ? 'CLIP' : type === 'projects' ? 'PROJECT' : type.toUpperCase().slice(0, 8),
      size: `${(request.file.size / 1024 / 1024).toFixed(1)} MB`,
      meta: request.file.mimetype,
      originalName: request.file.originalname,
      fileName: request.file.filename,
      uploaderId: request.user.id,
      createdAt: new Date().toISOString()
    };
    assets.unshift(asset);
    await writeJson(DB.assets, assets);
    return response.status(201).json({ asset });
  } catch (error) { return next(error); }
});

app.get('/', async (_request, response) => {
  let html = await fs.readFile(path.join(ROOT, 'Dragon Editing Assets.html'), 'utf8');
  html = html.replace(/__GOOGLE_CLIENT_ID__/g, GOOGLE_CLIENT_ID);
  response.send(html);
});

app.use((error, _request, response, _next) => {
  console.error(error);
  if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') return response.status(413).json({ error: 'File is larger than 500 MB.' });
  return response.status(500).json({ error: 'Server error.' });
});

async function start() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.mkdir(UPLOAD_DIR, { recursive: true });
  const users = await readJson(DB.users, []);
  if (!users.some((user) => user.email === ADMIN_EMAIL.toLowerCase())) {
    users.push({ id: crypto.randomUUID(), name: 'Vault Owner', email: ADMIN_EMAIL.toLowerCase(), passwordHash: await bcrypt.hash(ADMIN_PASSWORD, 12), role: 'owner', createdAt: new Date().toISOString() });
    await writeJson(DB.users, users);
  }
  await readJson(DB.assets, []);
  app.listen(PORT, () => console.log(`Dragon Unit backend running at http://localhost:${PORT}`));
}

start().catch((error) => { console.error(error); process.exit(1); });


