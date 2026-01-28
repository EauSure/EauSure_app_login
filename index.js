// index.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

// --- 1. CONFIGURATION MONGODB ---
const MONGO_URI = process.env.MONGO_URI;

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
  password: { type: String, required: true },
});

// Vérification pour éviter de recompiler le modèle si Vercel relance le script
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- 3. ROUTE DE TEST ---
app.get('/', (req, res) => {
  res.send("API EauSûre est en ligne 💧");
});

app.get('/api', (req, res) => {
  res.json({ status: "API Working", time: new Date() });
});

// --- 4. ROUTE DE LOGIN ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // A. Chercher l'utilisateur
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Email introuvable." });
    }

    // B. Vérifier le mot de passe
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(400).json({ message: "Mot de passe incorrect." });
    }

    // C. Générer le token
    const token = jwt.sign({ id: user._id }, 'SECRET_TEMP_KEY', { expiresIn: '1d' });

    res.json({
      token,
      user: { id: user._id, email: user.email }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur." });
  }
});

// --- 5. EXPORT POUR VERCEL ---
module.exports = app;

// Lancement local seulement
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Serveur lancé sur http://localhost:${PORT}`);
  });
}