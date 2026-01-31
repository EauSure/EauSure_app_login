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

// --- 1. CONFIGURATION MONGODB ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI) {
  console.error("❌ ERREUR: MONGO_URI est manquant dans les variables d'environnement !");
} else {
  mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connecté à MongoDB'))
    .catch(err => console.error('❌ Erreur MongoDB:', err));
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

// --- FONCTION UTILITAIRE POUR URL FRONTEND ---
const getFrontendUrl = () => {
  // Récupère l'URL définie dans Vercel (ex: eausureapp://)
  const url = process.env.FRONTEND_URL || 'eausureapp://';
  // S'assure qu'elle finit par un slash pour éviter eausureapp://--/auth...
  return url.endsWith('/') ? url : `${url}/`;
};

// 3.1 Google Strategy (MODE STRICT)
if (GOOGLE_ENABLED) {
  passport.use('google', new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.API_URL}/api/auth/google/callback`,
      proxy: true
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // 1. Chercher par Google ID
        let user = await User.findOne({ googleId: profile.id });
        
        // 2. Chercher par Email
        if (!user) {
          user = await User.findOne({ email: profile.emails[0].value });
        }

        // 3. STRICT : Si pas d'user, on refuse l'accès
        if (!user) {
          return done(null, false, { message: 'unregistered_user' });
        }
        
        // 4. Lier le compte si nécessaire
        if (!user.googleId) {
            user.googleId = profile.id;
            user.avatar = user.avatar || profile.photos[0]?.value;
            await user.save();
        }
        
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  ));
}

// 3.2 GitHub Strategy (MODE STRICT)
if (GITHUB_ENABLED) {
  passport.use('github', new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: `${process.env.API_URL}/api/auth/github/callback`,
      proxy: true
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ githubId: profile.id });
        
        if (!user) {
          const email = profile.emails?.[0]?.value || `${profile.username}@github.user`;
          user = await User.findOne({ email });
        }

        // STRICT : Refus si inconnu
        if (!user) {
          return done(null, false, { message: 'unregistered_user' });
        }
        
        if (!user.githubId) {
            user.githubId = profile.id;
            user.avatar = user.avatar || profile.photos?.[0]?.value;
            await user.save();
        }
        
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  ));
}

// --- 4. ROUTES AUTHENTIFICATION ---

// Login classique
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Email introuvable." });
    if (!user.password) return res.status(400).json({ message: `Utilisez la connexion ${user.authProvider}.` });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Mot de passe incorrect." });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, email: user.email, name: user.name, avatar: user.avatar } });
  } catch (error) {
    res.status(500).json({ message: "Erreur serveur." });
  }
});

// Register classique
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ message: "Email déjà utilisé." });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ email, password: hashedPassword, name, authProvider: 'local' });
    const token = jwt.sign({ id: newUser._id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({ token, user: { id: newUser._id, email: newUser.email, name: newUser.name } });
  } catch (error) {
    res.status(500).json({ message: "Erreur serveur." });
  }
});

// --- ROUTES GOOGLE ---
app.get('/api/auth/google', (req, res, next) => {
  if (!GOOGLE_ENABLED) return res.status(503).json({ message: "Google non configuré" });
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })(req, res, next);
});

app.get('/api/auth/google/callback', (req, res, next) => {
  const baseUrl = getFrontendUrl();
  passport.authenticate('google', { session: false }, (err, user, info) => {
    if (err) return res.redirect(`${baseUrl}--/auth/callback?error=server_error`);
    
    // GESTION ERREUR "USER NOT FOUND"
    if (!user) {
      const errorMsg = info?.message === 'unregistered_user' ? 'user_not_found' : 'auth_failed';
      return res.redirect(`${baseUrl}--/auth/callback?error=${errorMsg}`);
    }
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`${baseUrl}--/auth/callback?token=${token}`);
  })(req, res, next);
});

// --- ROUTES GITHUB ---
app.get('/api/auth/github', (req, res, next) => {
  if (!GITHUB_ENABLED) return res.status(503).json({ message: "GitHub non configuré" });
  passport.authenticate('github', { scope: ['user:email'], session: false })(req, res, next);
});

app.get('/api/auth/github/callback', (req, res, next) => {
  const baseUrl = getFrontendUrl();
  passport.authenticate('github', { session: false }, (err, user, info) => {
    if (err) return res.redirect(`${baseUrl}--/auth/callback?error=server_error`);
    
    if (!user) {
      const errorMsg = info?.message === 'unregistered_user' ? 'user_not_found' : 'auth_failed';
      return res.redirect(`${baseUrl}--/auth/callback?error=${errorMsg}`);
    }
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`${baseUrl}--/auth/callback?token=${token}`);
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
  if (!user) return res.status(404).json({ message: 'Utilisateur introuvable' });
  res.json({ user });
});

app.get('/', (req, res) => res.send("API EauSûre Online 💧"));

module.exports = app;
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`🚀 Server on http://localhost:${PORT}`));
}
