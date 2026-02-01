// index.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;

const app = express();
app.use(express.json());
app.use(cors());
app.use(passport.initialize());

// --- 1. CONFIGURATION MONGODB ROBUSTE ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI) {
  throw new Error("❌ ERREUR CRITIQUE: MONGO_URI manquant !");
}

let cached = global.mongoose;
if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (cached.conn) return cached.conn;
  if (!cached.promise) {
    const opts = { bufferCommands: false, serverSelectionTimeoutMS: 5000 };
    console.log("⏳ Connexion à MongoDB...");
    cached.promise = mongoose.connect(MONGO_URI, opts).then((mongoose) => {
      console.log("✅ Connecté à MongoDB");
      return mongoose;
    });
  }
  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null;
    console.error("❌ Erreur connexion MongoDB:", e);
    throw e;
  }
  return cached.conn;
}

// --- 2. MODÈLE UTILISATEUR ---
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String }, 
  googleId: { type: String, sparse: true, unique: true },
  githubId: { type: String, sparse: true, unique: true },
  name: { type: String },
  avatar: { type: String },
  authProvider: { type: String, enum: ['local', 'google', 'github'], default: 'local' },
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- 3. CONFIGURATION PASSPORT ---
const GOOGLE_ENABLED = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
const GITHUB_ENABLED = !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET);

console.log('🔐 Configuration OAuth:');
console.log(`  - Google: ${GOOGLE_ENABLED ? '✅ Activé' : '❌ Désactivé'}`);
console.log(`  - GitHub: ${GITHUB_ENABLED ? '✅ Activé' : '❌ Désactivé'}`);

const getFrontendUrl = () => {
  let url = process.env.FRONTEND_URL || 'http://localhost:8081'; // Fallback for dev
  return url.replace(/\/+$/, '');
};

// 3.1 Google Strategy (UNCHANGED for brevity, keeping your existing logic)
if (GOOGLE_ENABLED) {
  // Login Strategy
  passport.use('google', new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.API_URL}/api/auth/google/callback`,
      proxy: true
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        await connectDB();
        let user = await User.findOne({ googleId: profile.id });
        if (!user) user = await User.findOne({ email: profile.emails[0].value });
        if (!user) return done(null, false, { message: 'unregistered_user' });
        
        if (!user.googleId) {
            user.googleId = profile.id;
            user.avatar = user.avatar || profile.photos[0]?.value;
            await user.save();
        }
        return done(null, user);
      } catch (error) { return done(error, null); }
    }
  ));

  // Register Strategy
  passport.use('google-register', new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.API_URL}/api/auth/google/register/callback`,
      proxy: true
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        await connectDB();
        const email = profile.emails[0].value;
        let user = await User.findOne({ $or: [{ googleId: profile.id }, { email }] });
        if (user) return done(null, false, { message: 'user_already_exists' });
        
        user = await User.create({
          email, googleId: profile.id, name: profile.displayName,
          avatar: profile.photos[0]?.value, authProvider: 'google'
        });
        return done(null, user);
      } catch (error) { return done(error, null); }
    }
  ));
}

// 3.2 GitHub Strategy (UNIFIED: HANDLES BOTH LOGIN AND REGISTER)
if (GITHUB_ENABLED) {
  passport.use('github', new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      // IMPORTANT: Only ONE callback URL for GitHub
      callbackURL: `${process.env.API_URL}/api/auth/github/callback`,
      passReqToCallback: true, // Allows us to access req.query.state
      proxy: true
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        await connectDB();

        // Check if we are in 'register' mode or 'login' mode based on the state passed
        const mode = req.query.state === 'register' ? 'register' : 'login';
        
        const email = profile.emails?.[0]?.value || `${profile.username}@github.user`;
        let user = await User.findOne({ $or: [{ githubId: profile.id }, { email }] });

        // --- REGISTER MODE ---
        if (mode === 'register') {
          if (user) {
            console.warn(`⚠️ Register: User already exists: ${email}`);
            // Pass 'register' context in info so we know where to redirect error
            return done(null, false, { message: 'user_already_exists', context: 'register' });
          }

          // Create New User
          user = await User.create({
            email,
            githubId: profile.id,
            name: profile.displayName || profile.username,
            avatar: profile.photos?.[0]?.value,
            authProvider: 'github'
          });
          console.log(`✅ New user created via GitHub: ${email}`);
          return done(null, user);
        } 
        
        // --- LOGIN MODE (Default) ---
        else {
          if (!user) {
            return done(null, false, { message: 'unregistered_user', context: 'login' });
          }

          // Link GitHub ID if missing
          if (!user.githubId) {
            user.githubId = profile.id;
            user.avatar = user.avatar || profile.photos?.[0]?.value;
            await user.save();
          }
          return done(null, user);
        }

      } catch (error) {
        console.error("Erreur GitHub Strategy:", error);
        return done(error, null);
      }
    }
  ));
}

// --- 4. ROUTES ---

// Global Middleware
app.use('/api', async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (error) {
    res.status(500).json({ message: "Erreur DB" });
  }
});

// Classical Auth Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Email introuvable." });
    if (!user.password) return res.status(400).json({ message: `Utilisez ${user.authProvider}.` });
    if (!(await bcrypt.compare(password, user.password))) return res.status(400).json({ message: "Mot de passe incorrect." });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, email: user.email, name: user.name, avatar: user.avatar } });
  } catch (e) { res.status(500).json({ message: "Erreur serveur." }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (await User.findOne({ email })) {
      return res.status(400).json({ message: "Email déjà utilisé." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      email,
      password: hashedPassword,
      name,
      authProvider: 'local'
    });

    // ✅ PAS DE TOKEN
    res.status(201).json({ success: true });

  } catch (e) {
    res.status(500).json({ message: "Erreur serveur." });
  }
});


// --- GOOGLE ROUTES (Keep existing) ---
app.get('/api/auth/google', (req, res, next) => {
  if (!GOOGLE_ENABLED) return res.status(503).json({ message: "Google OFF" });
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })(req, res, next);
});

app.get('/api/auth/google/callback', (req, res, next) => {
  const baseUrl = getFrontendUrl();
  passport.authenticate('google', { session: false }, (err, user, info) => {
    if (err) return res.redirect(`${baseUrl}/login?error=server_error`);
    if (!user) {
      const msg = info?.message === 'unregistered_user' ? 'user_not_found' : 'auth_failed';
      return res.redirect(`${baseUrl}/login?error=${msg}`);
    }
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`${baseUrl}/login?token=${token}`);
  })(req, res, next);
});

app.get('/api/auth/google/register', (req, res, next) => {
  if (!GOOGLE_ENABLED) return res.status(503).json({ message: "Google OFF" });
  passport.authenticate('google-register', { scope: ['profile', 'email'], session: false })(req, res, next);
});

app.get('/api/auth/google/register/callback', (req, res, next) => {
  const baseUrl = getFrontendUrl();
  passport.authenticate('google-register', { session: false }, (err, user, info) => {
    if (err) return res.redirect(`${baseUrl}/register?error=server_error`);
    if (!user) {
      const msg = info?.message === 'user_already_exists' ? 'user_already_exists' : 'auth_failed';
      return res.redirect(`${baseUrl}/register?error=${msg}`);
    }
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`${baseUrl}/register?token=${token}`);
  })(req, res, next);
});

// --- GITHUB ROUTES (UPDATED) ---

// 1. GitHub Login Route
app.get('/api/auth/github', (req, res, next) => {
  if (!GITHUB_ENABLED) return res.status(503).json({ message: "GitHub OFF" });
  // Pass 'login' state
  passport.authenticate('github', { scope: ['user:email'], session: false, state: 'login' })(req, res, next);
});

// 2. GitHub Register Route (Uses same strategy, different state)
app.get('/api/auth/github/register', (req, res, next) => {
  if (!GITHUB_ENABLED) return res.status(503).json({ message: "GitHub OFF" });
  // Pass 'register' state
  passport.authenticate('github', { scope: ['user:email'], session: false, state: 'register' })(req, res, next);
});

// 3. Unified GitHub Callback
app.get('/api/auth/github/callback', (req, res, next) => {
  const baseUrl = getFrontendUrl();
  
  // Determine intention from state parameter returned by GitHub
  const mode = req.query.state === 'register' ? 'register' : 'login';
  const redirectPage = mode === 'register' ? '/register' : '/login';

  passport.authenticate('github', { session: false }, (err, user, info) => {
    // A. Handle Server Errors
    if (err) {
      console.error("❌ GitHub Callback Error:", err);
      return res.redirect(`${baseUrl}${redirectPage}?error=server_error`);
    }
    
    // B. Handle Auth Failures (User exists/doesn't exist)
    if (!user) {
      let errorMsg = 'auth_failed';
      if (info?.message === 'user_already_exists') errorMsg = 'user_already_exists';
      if (info?.message === 'unregistered_user') errorMsg = 'user_not_found';
      
      return res.redirect(`${baseUrl}${redirectPage}?error=${errorMsg}`);
    }
    
    // C. Success
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`${baseUrl}${redirectPage}?token=${token}`);
  })(req, res, next);
});

// --- UTILS ---
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token manquant' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Token invalide' });
    req.userId = decoded.id;
    next();
  });
};

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  res.json({ user });
});

app.get('/', (req, res) => res.send("API EauSûre Online 💧"));

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`🚀 Server on http://localhost:${PORT}`));
}
