const express = require('express');
require('dotenv').config();
const authRoutes = require('./routes/authRoutes');
const authMiddleware = require('./middleware/authMiddleware');

const app = express();
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);

// Example secure route
app.get('/secure', authMiddleware, (req, res) => {
    res.json({ message: 'You are authorized', user: req.user });
  });

app.listen(5000, () => console.log('Server running on port 5000'));
