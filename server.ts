/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from "express";
import path from "path";
import crypto from "crypto";
import { createServer as createViteServer } from "vite";
import { 
  seedDatabase, 
  findUserByUsername, 
  addUser, 
  getNotes, 
  getSecrets, 
  addNote,
  querySecretsVulnerable,
  querySecretsSecure
} from "./server/db";
import { 
  hashPassword, 
  verifyPassword, 
  signJwt, 
  verifyJwt, 
  decodeJwtUnverified,
  sanitizeInput 
} from "./server/crypto-utils";

// Ensure state is loaded
seedDatabase();

const app = express();
const PORT = 3000;

// Set up security headers demo conceptually via standard middlewares.
// We explicitly outline what some security headers are for education.
app.use((req, res, next) => {
  // Adding defensive headers to demonstrate OWASP A05:2021-Security Misconfiguration prevention
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'");
  next();
});

app.use(express.json());

// Helper middleware to authenticate JWT from headers
function authenticateToken(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    res.status(401).json({ error: 'Unauthorized: Authorization header is required.' });
    return;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    res.status(401).json({ error: 'Unauthorized: Access token must be a Bearer token.' });
    return;
  }

  const token = parts[1];
  const payload = verifyJwt(token);

  if (!payload) {
    res.status(403).json({ error: 'Forbidden: Invalid or expired security token.' });
    return;
  }

  // Attach token payload to request context
  (req as any).user = payload;
  next();
}

// ==========================================
// STANDARD CORE API ENDPOINTS
// ==========================================

// Auth Profile
app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: (req as any).user });
});

// Create User
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password || username.trim().length < 3 || password.trim().length < 6) {
    res.status(400).json({ error: 'Validation Error: Username must be 3+ chars and Password must be 6+ chars.' });
    return;
  }

  const normalizedUser = username.trim().toLowerCase();
  const existing = findUserByUsername(normalizedUser);
  if (existing) {
    res.status(400).json({ error: 'Conflict: Username is already registered.' });
    return;
  }

  // Register user securely
  const { hash, salt } = hashPassword(password);
  const newUser = addUser(normalizedUser, hash, salt, 'user');

  // Sign standard JWT
  const tokenPayload = {
    id: newUser.id,
    username: newUser.username,
    role: newUser.role,
    iss: 'gai_security_lab',
    exp: Math.floor(Date.now() / 1000) + (1 * 3600) // 1 Hour lifespan
  };
  const token = signJwt(tokenPayload);

  res.status(201).json({
    message: 'Registration successful!',
    user: newUser,
    token
  });
});

// Login User
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ error: 'Username and password are required.' });
    return;
  }

  const target = findUserByUsername(username.trim());
  if (!target || !target.passwordHash || !target.salt) {
    // Return generic error to prevent account enumeration (OWASP A02:2021)
    res.status(401).json({ error: 'Invalid username or password.' });
    return;
  }

  const isValid = verifyPassword(password, target.salt, target.passwordHash);
  if (!isValid) {
    res.status(401).json({ error: 'Invalid username or password.' });
    return;
  }

  const tokenPayload = {
    id: target.id,
    username: target.username,
    role: target.role,
    iss: 'gai_security_lab',
    exp: Math.floor(Date.now() / 1000) + (1 * 3600) // 1 Hour lifespan
  };
  const token = signJwt(tokenPayload);

  res.json({
    message: 'Authenticated successfully!',
    user: {
      id: target.id,
      username: target.username,
      role: target.role,
      bio: target.bio
    },
    token
  });
});

// Get Standard Notes
app.get('/api/notes', (req, res) => {
  res.json({ notes: getNotes() });
});

// Add Standard Note
app.post('/api/notes', authenticateToken, (req, res) => {
  const { content, isPublic } = req.body;
  const sessionUser = (req as any).user;

  if (!content || content.trim().length === 0) {
    res.status(400).json({ error: 'Note content cannot be empty.' });
    return;
  }

  // To prevent XSS, we store as-is but sanitization can happen on storage or display.
  // Standard React handles escaping on render securely, but here we can record the exact note.
  const note = addNote(sessionUser.id, sessionUser.username, content, !!isPublic);
  res.status(201).json({ message: 'Note created successfully.', note });
});

// Admin Classified Secrets Access
app.get('/api/secrets', authenticateToken, (req, res) => {
  const sessionUser = (req as any).user;

  // STRICT RBAC CHECK - Mitigates Broken Access Control
  if (sessionUser.role !== 'admin') {
    res.status(403).json({ 
      error: 'Access Denied: Administrative role required.',
      details: `Your current session role is [${sessionUser.role}]. This API requires [admin].`
    });
    return;
  }

  try {
    const secrets = getSecrets(true);
    res.json({ secrets });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// INTERACTIVE SECURITY PLAYGROUND ENDPOINTS
// ==========================================

// 1. SQL Injection Lab
app.post('/api/security/sql-lab', (req, res) => {
  const { searchParam, mode } = req.body;

  if (typeof searchParam !== 'string') {
    res.status(400).json({ error: 'Search string must be a string parameter.' });
    return;
  }

  if (mode === 'vulnerable') {
    const data = querySecretsVulnerable(searchParam);
    res.json(data);
  } else {
    const data = querySecretsSecure(searchParam);
    res.json(data);
  }
});

// 2. JWT Verification & Tamper Lab
app.post('/api/security/jwt-tamper-lab', (req, res) => {
  const { token, attemptKeySignature } = req.body;

  if (!token) {
    res.status(400).json({ error: 'JWT token string required for verification.' });
    return;
  }

  const unverified = decodeJwtUnverified(token);
  if (!unverified) {
    res.status(400).json({ error: 'Invalid format. A JWT must consist of three Base64URL dot-separated fragments.' });
    return;
  }

  // Verify token
  let parsedPayload: Record<string, any> | null = null;
  let matchesSignature = false;

  if (attemptKeySignature) {
    // User tries to verify with a custom signature secret key
    parsedPayload = verifyJwt(token, attemptKeySignature);
    matchesSignature = parsedPayload !== null;
  } else {
    // Verify with internal Server secret key
    parsedPayload = verifyJwt(token);
    matchesSignature = parsedPayload !== null;
  }

  res.json({
    decoded: unverified,
    isValid: matchesSignature,
    checkedWithCustomKey: !!attemptKeySignature,
    message: matchesSignature 
      ? 'SUCCESS: Signature cryptographic MAC matches header + payload.' 
      : 'FAILURE: Signature validation failed. Signature does not match computed HMAC hash or token has expired.'
  });
});

// 3. Password Hashing Lab
// Simulates Key Derivation delay to teach users how iteration count is vital against offline dictionary attacks.
app.post('/api/security/hash-lab', (req, res) => {
  const { password, iterations, salt } = req.body;

  if (!password || typeof password !== 'string') {
    res.status(400).json({ error: 'A password string is required.' });
    return;
  }

  const iter = Number(iterations) || 10000;
  // Bound iteration counts to protect applet container limits
  if (iter < 1 || iter > 200000) {
    res.status(400).json({ error: 'Iterations limit must be between 1 and 200,000 for server CPU safety.' });
    return;
  }

  const activeSalt = salt || crypto.randomBytes(16).toString('hex');
  const startTime = performance.now();
  
  // Custom PBKDF2
  const hash = crypto.pbkdf2Sync(password, activeSalt, iter, 64, 'sha512').toString('hex');
  const durationMs = parseFloat((performance.now() - startTime).toFixed(2));

  res.json({
    password,
    salt: activeSalt,
    iterations: iter,
    hash,
    durationMs,
    explanation: `PBKDF2 uses repeated salted hashing. With ${iter.toLocaleString()} rounds, computation took ${durationMs}ms. For attackers trying 10,000,000 password dictionary candidates, this delays their cracking pipeline to ${((iter * 10000000 * 0.0001) / 3600).toFixed(1)} CPU-hours!`
  });
});

// 4. Input Sanitization (XSS) Lab
app.post('/api/security/xss-sanitize-lab', (req, res) => {
  const { htmlContent } = req.body;

  if (typeof htmlContent !== 'string') {
    res.status(400).json({ error: 'Text input target is required.' });
    return;
  }

  const sanitized = sanitizeInput(htmlContent);
  res.json({
    original: htmlContent,
    sanitized,
    explanation: 'Sanitization converts HTML control characters like < and > into harmless entity sequences. The browser will render them as strings rather than executing the tags in the document object representation.'
  });
});

// ==========================================
// VITE CLIENT DEV SERVER / BUNDLE CONFIGURATION
// ==========================================

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    // Mount Vite dev server middleware to handle index.html and module imports
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[SECURE APP SERVER] Active on http://0.0.0.0:${PORT}`);
  });
}

startServer();
