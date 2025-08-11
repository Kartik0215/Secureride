const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');

// Example secure route
router.get('/profile', auth, (req, res) => {
  res.json({
    message: 'You are authorized',
    user: req.user
  });
});

module.exports = router;
