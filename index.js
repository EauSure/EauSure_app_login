// index.js (Mise à jour complète)
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

// --- 1. CONNEXION MONGODB ---
const MONGO_URI = process.env.MONGO_URI;

// --- 2. MODÈLE UTILISATEUR (Adapté à water_quality) ---
// On définit tous les champs visibles dans votre capture d'écran
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String },              // Ajouté : Mohamed Rayen...
  role: { type: String, default: 'user' }, // Ajouté : "user"
  isProfileComplete: { type: Boolean, default: false }, // Ajouté
  lastLogin: { type: Date },           // Ajouté
  createdAt: { type: Date, default: Date.now }
});

// IMPORTANT : On force le nom de la collection pour être sûr qu'il tape dans 'users'
const User = mongoose.models.User || mongoose.model('User', UserSchema, 'users');

// --- 3. ROUTES ---

app.get('/', (req, res) => {
  res.send("API EauSûre (Water Quality) est en ligne 💧");
});

app.get('/api', (req, res) => {
  res.json({ status: "API Working", db: "water_quality" });
});

// ROUTE DE LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    // Connexion à la volée pour le Serverless
    if (mongoose.connection.readyState !== 1) {
      await mongoose.connect(MONGO_URI);
    }

    const { email, password } = req.body;

    // A. Chercher l'utilisateur
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Email introuvable." });
    }

    // B. Vérifier le mot de passe
    // Note : Vos mots de passe en base sont bien hashés (commencent par $2b$...), donc bcrypt fonctionnera.
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(400).json({ message: "Mot de passe incorrect." });
    }

    // C. Mettre à jour la date de dernière connexion (Optionnel mais sympa)
    user.lastLogin = new Date();
    await user.save();

    // D. Générer le token
    const SECRET = process.env.JWT_SECRET || 'secret_temp_key';
    const token = jwt.sign({ id: user._id, role: user.role }, SECRET, { expiresIn: '7d' });

    // E. Répondre avec plus d'infos (nom, role) pour l'appli mobile
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name, // On renvoie le nom pour l'afficher sur l'accueil !
        role: user.role,
        isProfileComplete: user.isProfileComplete
      }
    });

  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Erreur serveur." });
  }
});

module.exports = app;
