import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import multer from 'multer';
import Database from 'better-sqlite3';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ADMIN_EMAIL = 'panthisushil2035@gmail.com';
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Ensure uploads directory exists
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Database setup
let db: Database.Database;
try {
  db = new Database('files.db');
  console.log('Database connected successfully');
} catch (err) {
  console.error('Failed to connect to database:', err);
  process.exit(1);
}

// Migration: Handle schema changes
const tableInfo = (name: string) => {
  try {
    return db.prepare(`PRAGMA table_info(${name})`).all() as any[];
  } catch (err) {
    return [];
  }
};

// Check sessions table
const sessionsCols = tableInfo('sessions');
if (sessionsCols.length > 0 && !sessionsCols.some(c => c.name === 'user_id')) {
  console.log('Migrating sessions table...');
  db.exec('DROP TABLE sessions');
}

// Check files table
const filesCols = tableInfo('files');
if (filesCols.length > 0 && !filesCols.some(c => c.name === 'category')) {
  console.log('Migrating files table...');
  db.exec("ALTER TABLE files ADD COLUMN category TEXT DEFAULT 'Documents'");
}
if (filesCols.length > 0 && !filesCols.some(c => c.name === 'expiry_date')) {
  console.log('Migrating files table for expiry_date...');
  db.exec("ALTER TABLE files ADD COLUMN expiry_date DATETIME");
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  );

  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    category TEXT DEFAULT 'Documents',
    expiry_date DATETIME,
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    expiry DATETIME NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

const cleanupExpiredFiles = () => {
  const now = new Date().toISOString();
  const expiredFiles = db.prepare('SELECT * FROM files WHERE expiry_date IS NOT NULL AND expiry_date < ?').all(now) as any[];
  
  if (expiredFiles.length > 0) {
    console.log(`Found ${expiredFiles.length} expired files to clean up.`);
  }

  for (const file of expiredFiles) {
    const filePath = path.join(UPLOADS_DIR, file.name);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch (err) {
        console.error(`Failed to delete file from disk: ${filePath}`, err);
      }
    }
    db.prepare('DELETE FROM files WHERE id = ?').run(file.id);
    console.log(`Deleted expired file: ${file.original_name} (Expired at: ${file.expiry_date})`);
  }
};

// Ensure admin user exists
const existingAdmin = db.prepare('SELECT * FROM users WHERE email = ?').get(ADMIN_EMAIL);
if (!existingAdmin) {
  const hashedPassword = bcrypt.hashSync('admin123', 10); // Default password for admin
  db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run(ADMIN_EMAIL, hashedPassword, 'admin');
  console.log('Admin user created with default password: admin123');
}

const app = express();
app.use(express.json());

// Request Logger
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Auth Middleware
const getSession = (req: express.Request) => {
  const sessionId = req.headers['x-session-id'] as string;
  if (!sessionId) {
    console.log('No session ID provided in headers');
    return null;
  }
  
  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as any;
  if (!session) {
    console.log(`Session not found for ID: ${sessionId}`);
    return null;
  }
  
  const now = new Date();
  const expiry = new Date(session.expiry);
  if (expiry < now) {
    console.log(`Session expired for ID: ${sessionId} (Expired at: ${session.expiry})`);
    return null;
  }
  
  console.log(`Session valid for user: ${session.email}, Role: ${session.role}`);
  return session;
};

const isAdmin = (req: express.Request) => {
  const session = getSession(req);
  return session && session.role === 'admin';
};

// API Routes

// API Routes
const apiRouter = express.Router();

// Health check (no DB dependency)
apiRouter.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Local Auth
apiRouter.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const role = email.toLowerCase() === ADMIN_EMAIL.toLowerCase() ? 'admin' : 'user';
    db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run(email, hashedPassword, role);
    res.json({ success: true });
  } catch (err: any) {
    console.error('Registration error:', err);
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

apiRouter.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const sessionId = Math.random().toString(36).substring(2) + Date.now().toString(36);
    const expiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    
    db.prepare('INSERT INTO sessions (id, user_id, email, role, expiry) VALUES (?, ?, ?, ?, ?)').run(
      sessionId, user.id, user.email, user.role, expiry
    );

    res.json({ sessionId, email: user.email, role: user.role });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Google OAuth URL
apiRouter.get('/auth/url', (req, res) => {
  const appUrl = (process.env.APP_URL || '').replace(/\/$/, '');
  if (!appUrl) {
    console.error('APP_URL is not set in environment variables');
    return res.status(500).json({ error: 'Server configuration error: APP_URL missing' });
  }

  const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  const clientId = process.env.VITE_GOOGLE_CLIENT_ID || '';
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
  
  if (!clientId || !clientSecret) {
    console.error(`Google Auth Configuration Missing: ClientID: ${!!clientId}, Secret: ${!!clientSecret}`);
    return res.status(500).json({ 
      error: 'Google Auth not fully configured. Please check VITE_GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Secrets.' 
    });
  }

  console.log(`Initiating Google Auth with Client ID starting with: ${clientId.substring(0, 5)}...`);

  const options = {
    redirect_uri: `${appUrl}/auth/callback`,
    client_id: clientId,
    access_type: 'offline',
    response_type: 'code',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email',
    ].join(' '),
  };

  console.log(`Generating Google Auth URL with redirect_uri: ${options.redirect_uri}`);
  const qs = new URLSearchParams(options);
  res.json({ url: `${rootUrl}?${qs.toString()}` });
});

apiRouter.get('/user', (req, res) => {
  try {
    const session = getSession(req);
    if (!session) return res.status(401).json({ error: 'Not authenticated' });
    res.json({ email: session.email, isAdmin: session.role === 'admin', role: session.role });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

apiRouter.post('/upload', upload.single('file'), (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const { filename, originalname, mimetype, size } = req.file;
    const category = req.body.category || 'Documents';
    const expiry_date = req.body.expiry_date || null;
    
    db.prepare('INSERT INTO files (name, original_name, mime_type, size, category, expiry_date) VALUES (?, ?, ?, ?, ?, ?)').run(
      filename, originalname, mimetype, size, category, expiry_date
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

apiRouter.get('/files', (req, res) => {
  try {
    cleanupExpiredFiles();
    const allFiles = db.prepare('SELECT * FROM files ORDER BY upload_date DESC').all() as any[];
    const activeFiles = allFiles.filter(f => !f.expiry_date || new Date(f.expiry_date) > new Date());
    res.json(activeFiles);
  } catch (err) {
    console.error('Error fetching files:', err);
    res.status(500).json({ error: 'Failed to fetch files' });
  }
});

apiRouter.get('/files/:id/preview', (req, res) => {
  try {
    const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id) as any;
    if (!file) return res.status(404).send('File not found');

    const filePath = path.join(UPLOADS_DIR, file.name);
    if (!fs.existsSync(filePath)) return res.status(404).send('File not found on disk');

    res.setHeader('Content-Type', file.mime_type);
    res.setHeader('Content-Disposition', 'inline');
    res.sendFile(filePath);
  } catch (err) {
    console.error('Preview error:', err);
    res.status(500).send('Preview failed');
  }
});

apiRouter.get('/files/:id/download', (req, res) => {
  try {
    const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id) as any;
    if (!file) return res.status(404).send('File not found');

    const filePath = path.join(UPLOADS_DIR, file.name);
    if (!fs.existsSync(filePath)) return res.status(404).send('File not found on disk');

    res.download(filePath, file.original_name);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).send('Download failed');
  }
});

apiRouter.delete('/files/:id', (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });

    const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id) as any;
    if (!file) return res.status(404).json({ error: 'File not found' });

    const filePath = path.join(UPLOADS_DIR, file.name);
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch (err) {}
    }

    db.prepare('DELETE FROM files WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

apiRouter.delete('/files', (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });

    const { ids } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'No IDs provided' });
    }

    const placeholders = ids.map(() => '?').join(',');
    const files = db.prepare(`SELECT * FROM files WHERE id IN (${placeholders})`).all(...ids) as any[];

    for (const file of files) {
      const filePath = path.join(UPLOADS_DIR, file.name);
      if (fs.existsSync(filePath)) {
        try { fs.unlinkSync(filePath); } catch (err) {}
      }
    }

    db.prepare(`DELETE FROM files WHERE id IN (${placeholders})`).run(...ids);
    res.json({ success: true, count: ids.length });
  } catch (err) {
    console.error('Bulk delete error:', err);
    res.status(500).json({ error: 'Bulk deletion failed' });
  }
});

// Mount API router
app.use('/api', apiRouter);

// Fallback for missing API routes - ALWAYS return JSON
app.all('/api/*', (req, res) => {
  console.log(`404 - API route not found: ${req.method} ${req.url}`);
  res.status(404).json({ error: `API route not found: ${req.method} ${req.url}` });
});

// Global Error Handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Unhandled Server Error:', err);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
