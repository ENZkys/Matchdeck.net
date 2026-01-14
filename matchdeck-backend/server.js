// ===== SERVER.JS =====
// Main server file - Run with: node server.js

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const sharp = require('sharp');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/matchdeck', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ===== MODELS =====

// User Schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  username: {
    type: String,
    required: true,
    trim: true
  },
  bio: {
    type: String,
    default: 'No bio provided',
    maxlength: 500
  },
  profilePicURL: {
    type: String,
    default: ''
  },
  socials: [{
    platform: {
      type: String,
      required: true
    },
    username: {
      type: String,
      required: true
    }
  }],
  googleId: String,
  discordId: String,
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Card Schema (for public cards)
const cardSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  username: {
    type: String,
    required: true
  },
  bio: {
    type: String,
    default: 'No bio provided'
  },
  profilePicURL: {
    type: String,
    default: ''
  },
  socials: [{
    platform: String,
    username: String
  }],
  isPublic: {
    type: Boolean,
    default: true
  },
  views: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const Card = mongoose.model('Card', cardSchema);

// ===== MIDDLEWARE =====

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key-change-this');
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Content moderation middleware
const blockedWords = [
  'fuck','fucker','fucking','motherfucker','shit','shitty','bitch','bastard','ass','asshole',
  'dick','dickhead','cock','cocksucker','pussy','cunt','twat','prick','wank','wanker',
  'bollocks','arse','arsehole','whore','slut','hoe','cum','jizz','piss','porn','rape',
  'nigger','nigga','coon','kike','chink','gook','spic','wetback','beaner',
  'faggot','fag','dyke','tranny','nazi','hitler'
];

const containsBlockedWords = (text) => {
  if (!text) return false;
  const lowerText = text.toLowerCase();
  return blockedWords.some(word => {
    const regex = new RegExp(`\\b${word}\\b|${word}`, 'i');
    return regex.test(lowerText);
  });
};

const moderateContent = (req, res, next) => {
  const { username, bio, socials } = req.body;
  
  if (containsBlockedWords(username)) {
    return res.status(400).json({ error: 'Username contains inappropriate language' });
  }
  
  if (containsBlockedWords(bio)) {
    return res.status(400).json({ error: 'Bio contains inappropriate language' });
  }
  
  if (socials && Array.isArray(socials)) {
    for (let social of socials) {
      if (containsBlockedWords(social.username)) {
        return res.status(400).json({ error: 'Social media username contains inappropriate language' });
      }
    }
  }
  
  next();
};

// ===== ROUTES =====

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'MatchDeck API is running' });
});

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, username } = req.body;

    // Validation
    if (!email || !password || !username) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Content moderation
    if (containsBlockedWords(username)) {
      return res.status(400).json({ error: 'Username contains inappropriate language' });
    }

    // Create user
    const user = new User({
      email,
      password,
      username
    });

    await user.save();

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key-change-this',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        username: user.username
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = Date.now();
    await user.save();

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key-change-this',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        bio: user.bio,
        profilePicURL: user.profilePicURL,
        socials: user.socials
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== CARD ROUTES =====

// Create/Update card
app.post('/api/cards', authenticateToken, moderateContent, async (req, res) => {
  try {
    const { username, bio, profilePicURL, socials, isPublic } = req.body;

    // Validate
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    // Check if card exists
    let card = await Card.findOne({ userId: req.user.userId });

    if (card) {
      // Update existing card
      card.username = username;
      card.bio = bio || 'No bio provided';
      card.profilePicURL = profilePicURL || '';
      card.socials = socials || [];
      card.isPublic = isPublic !== undefined ? isPublic : true;
      card.updatedAt = Date.now();
    } else {
      // Create new card
      card = new Card({
        userId: req.user.userId,
        username,
        bio: bio || 'No bio provided',
        profilePicURL: profilePicURL || '',
        socials: socials || [],
        isPublic: isPublic !== undefined ? isPublic : true
      });
    }

    await card.save();

    // Also update user profile
    await User.findByIdAndUpdate(req.user.userId, {
      username,
      bio: bio || 'No bio provided',
      profilePicURL: profilePicURL || '',
      socials: socials || []
    });

    res.json({
      message: 'Card saved successfully',
      card
    });
  } catch (error) {
    console.error('Save card error:', error);
    res.status(500).json({ error: 'Server error while saving card' });
  }
});

// Get user's own card
app.get('/api/cards/me', authenticateToken, async (req, res) => {
  try {
    const card = await Card.findOne({ userId: req.user.userId });
    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }
    res.json(card);
  } catch (error) {
    console.error('Get card error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all public cards
app.get('/api/cards', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const cards = await Card.find({ isPublic: true })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-userId');

    const total = await Card.countDocuments({ isPublic: true });

    res.json({
      cards,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get cards error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get card by ID
app.get('/api/cards/:id', async (req, res) => {
  try {
    const card = await Card.findById(req.params.id);
    
    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    if (!card.isPublic) {
      return res.status(403).json({ error: 'This card is private' });
    }

    // Increment view count
    card.views += 1;
    await card.save();

    res.json(card);
  } catch (error) {
    console.error('Get card error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete card
app.delete('/api/cards', authenticateToken, async (req, res) => {
  try {
    const card = await Card.findOneAndDelete({ userId: req.user.userId });
    
    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    res.json({ message: 'Card deleted successfully' });
  } catch (error) {
    console.error('Delete card error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Search cards
app.get('/api/cards/search', async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q || q.trim().length === 0) {
      return res.status(400).json({ error: 'Search query is required' });
    }

    const cards = await Card.find({
      isPublic: true,
      $or: [
        { username: { $regex: q, $options: 'i' } },
        { bio: { $regex: q, $options: 'i' } }
      ]
    })
    .limit(20)
    .select('-userId');

    res.json({ cards });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== IMAGE UPLOAD =====

// Configure multer for memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// Upload profile picture
app.post('/api/upload/profile', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    // Process image with sharp (resize, compress)
    const processedImage = await sharp(req.file.buffer)
      .resize(600, 600, { fit: 'cover' })
      .jpeg({ quality: 90 })
      .toBuffer();

    // Convert to base64
    const base64Image = `data:image/jpeg;base64,${processedImage.toString('base64')}`;

    res.json({
      message: 'Image uploaded successfully',
      imageUrl: base64Image
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Error processing image' });
  }
});

// ===== USER MANAGEMENT =====

// Update user profile
app.put('/api/users/profile', authenticateToken, moderateContent, async (req, res) => {
  try {
    const { username, bio, profilePicURL, socials } = req.body;

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      {
        username: username || undefined,
        bio: bio || undefined,
        profilePicURL: profilePicURL || undefined,
        socials: socials || undefined
      },
      { new: true, runValidators: true }
    ).select('-password');

    res.json({
      message: 'Profile updated successfully',
      user
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete user account
app.delete('/api/users/account', authenticateToken, async (req, res) => {
  try {
    // Delete user's card first
    await Card.findOneAndDelete({ userId: req.user.userId });
    
    // Delete user
    await User.findByIdAndDelete(req.user.userId);

    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== ANALYTICS =====

// Get user stats
app.get('/api/stats/me', authenticateToken, async (req, res) => {
  try {
    const card = await Card.findOne({ userId: req.user.userId });
    
    if (!card) {
      return res.json({
        views: 0,
        socialCount: 0,
        createdAt: null
      });
    }

    res.json({
      views: card.views,
      socialCount: card.socials.length,
      createdAt: card.createdAt,
      updatedAt: card.updatedAt
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== ERROR HANDLING =====

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ===== START SERVER =====

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 MatchDeck server running on port ${PORT}`);
  console.log(`📡 API available at http://localhost:${PORT}/api`);
});

module.exports = app;