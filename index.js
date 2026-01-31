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
const JWT_SECRET = process.env.JWT_SECRET || 'SECRET_TEMP_KEY';

if (!MONGO_URI) {
  console.error("❌ ERREUR: MONGO_URI est manquant dans les variables d'environnement !");
} else {
  mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connecté à MongoDB'))
    .catch(err => console.error('❌ Erreur MongoDB:', err));
}

// --- 2. MODÈLE UTILISATEUR (avec champs OAuth ajoutés) ---
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String }, // Maintenant optionnel (pas requis pour OAuth)
  // NOUVEAUX CHAMPS POUR OAUTH
  googleId: { type: String, sparse: true, unique: true },
  githubId: { type: String, sparse: true, unique: true },
  name: { type: String },
  avatar: { type: String },
  authProvider: { type: String, enum: ['local', 'google', 'github'], default: 'local' },
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- 3. CONFIGURATION PASSPORT ---

// Vérifier si OAuth est configuré
const GOOGLE_ENABLED = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
const GITHUB_ENABLED = !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET);

console.log('🔐 Configuration OAuth:');
console.log(`  - Google: ${GOOGLE_ENABLED ? '✅ Activé' : '❌ Désactivé (credentials manquants)'}`);
console.log(`  - GitHub: ${GITHUB_ENABLED ? '✅ Activé' : '❌ Désactivé (credentials manquants)'}`);

// Google OAuth Strategy
if (GOOGLE_ENABLED) {
  passport.use('google', new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.API_URL || 'http://localhost:3000'}/api/auth/google/callback`,
      proxy: true
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        
        if (!user) {
          const existingUser = await User.findOne({ email: profile.emails[0].value });
          if (existingUser) {
            existingUser.googleId = profile.id;
            existingUser.name = existingUser.name || profile.displayName;
            existingUser.avatar = existingUser.avatar || profile.photos[0]?.value;
            await existingUser.save();
            return done(null, existingUser);
          }
          
          user = await User.create({
            googleId: profile.id,
            email: profile.emails[0].value,
            name: profile.displayName,
            avatar: profile.photos[0]?.value,
            authProvider: 'google'
          });
        }
        
        return done(null, user);
      } catch (error) {
        console.error('Google OAuth error:', error);
        return done(error, null);
      }
    }
  ));
}

// GitHub OAuth Strategy
if (GITHUB_ENABLED) {
  passport.use('github', new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: `${process.env.API_URL || 'http://localhost:3000'}/api/auth/github/callback`,
      proxy: true
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ githubId: profile.id });
        
        if (!user) {
          const email = profile.emails?.[0]?.value || `${profile.username}@github.user`;
          const existingUser = await User.findOne({ email });
          
          if (existingUser) {
            existingUser.githubId = profile.id;
            existingUser.name = existingUser.name || profile.displayName || profile.username;
            existingUser.avatar = existingUser.avatar || profile.photos?.[0]?.value;
            await existingUser.save();
            return done(null, existingUser);
          }
          
          user = await User.create({
            githubId: profile.id,
            email,
            name: profile.displayName || profile.username,
            avatar: profile.photos?.[0]?.value,
            authProvider: 'github'
          });
        }
        
        return done(null, user);
      } catch (error) {
        console.error('GitHub OAuth error:', error);
        return done(error, null);
      }
    }
  ));
}

// --- 4. ROUTES DE TEST (INCHANGÉES) ---
app.get('/', (req, res) => {
  res.send("API EauSûre est en ligne 💧");
});

app.get('/api', (req, res) => {
  res.json({ 
    status: "API Working", 
    time: new Date(),
    oauth: {
      google: GOOGLE_ENABLED,
      github: GITHUB_ENABLED
    }
  });
});

// --- 5. ROUTE DE LOGIN (LÉGÈREMENT MODIFIÉE) ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Email introuvable." });
    }

    // Vérifier que ce n'est pas un compte OAuth uniquement
    if (!user.password) {
      return res.status(400).json({ 
        message: `Ce compte utilise ${user.authProvider}. Veuillez vous connecter avec ${user.authProvider}.` 
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(400).json({ message: "Mot de passe incorrect." });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { 
        id: user._id, 
        email: user.email,
        name: user.name,
        avatar: user.avatar
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur." });
  }
});

// --- 6. ROUTE DE REGISTER ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email déjà utilisé." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = await User.create({
      email,
      password: hashedPassword,
      name,
      authProvider: 'local'
    });

    const token = jwt.sign({ id: newUser._id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      token,
      user: { 
        id: newUser._id, 
        email: newUser.email,
        name: newUser.name
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur." });
  }
});

// --- 7. ROUTES OAUTH GOOGLE ---

app.get('/api/auth/google', (req, res, next) => {
  if (!GOOGLE_ENABLED) {
    return res.status(503).json({ 
      message: "Google OAuth n'est pas configuré. Veuillez ajouter GOOGLE_CLIENT_ID et GOOGLE_CLIENT_SECRET dans les variables d'environnement." 
    });
  }
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    session: false 
  })(req, res, next);
});

app.get('/api/auth/google/callback', (req, res, next) => {
  if (!GOOGLE_ENABLED) {
    return res.redirect(`${process.env.FRONTEND_URL || 'eausure://'}--/auth/callback?error=google_not_configured`);
  }
  
  passport.authenticate('google', { session: false }, (err, user, info) => {
    if (err || !user) {
      console.error('Google auth error:', err);
      return res.redirect(`${process.env.FRONTEND_URL || 'eausure://'}--/auth/callback?error=auth_failed`);
    }
    
    try {
      const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
      const redirectUrl = `${process.env.FRONTEND_URL || 'eausure://'}--/auth/callback?token=${token}`;
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('Token generation error:', error);
      res.redirect(`${process.env.FRONTEND_URL || 'eausure://'}--/auth/callback?error=token_error`);
    }
  })(req, res, next);
});

// --- 8. ROUTES OAUTH GITHUB ---

app.get('/api/auth/github', (req, res, next) => {
  if (!GITHUB_ENABLED) {
    return res.status(503).json({ 
      message: "GitHub OAuth n'est pas configuré. Veuillez ajouter GITHUB_CLIENT_ID et GITHUB_CLIENT_SECRET dans les variables d'environnement." 
    });
  }
  passport.authenticate('github', { 
    scope: ['user:email'],
    session: false 
  })(req, res, next);
});

app.get('/api/auth/github/callback', (req, res, next) => {
  if (!GITHUB_ENABLED) {
    return res.redirect(`${process.env.FRONTEND_URL || 'eausure://'}--/auth/callback?error=github_not_configured`);
  }
  
  passport.authenticate('github', { session: false }, (err, user, info) => {
    if (err || !user) {
      console.error('GitHub auth error:', err);
      return res.redirect(`${process.env.FRONTEND_URL || 'eausure://'}--/auth/callback?error=auth_failed`);
    }
    
    try {
      const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
      const redirectUrl = `${process.env.FRONTEND_URL || 'eausure://'}--/auth/callback?token=${token}`;
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('Token generation error:', error);
      res.redirect(`${process.env.FRONTEND_URL || 'eausure://'}--/auth/callback?error=token_error`);
    }
  })(req, res, next);
});

// --- 9. ROUTE POUR OBTENIR L'UTILISATEUR ACTUEL ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token manquant' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token invalide' });
    }
    req.userId = decoded.id;
    next();
  });
};

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'Utilisateur introuvable' });
    }

    res.json({
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        avatar: user.avatar,
        authProvider: user.authProvider
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

// --- 10. EXPORT POUR VERCEL (INCHANGÉ) ---
module.exports = app;

// Lancement local seulement
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Serveur lancé sur http://localhost:${PORT}`);
  });
}
