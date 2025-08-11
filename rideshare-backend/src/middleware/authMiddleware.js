// middleware/auth.js
const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    // 1️⃣ No Authorization header at all
    if (!authHeader) {
      return res.status(401).json({ message: 'Authorization header missing' });
    }

    // 2️⃣ Must start with "Bearer "
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Invalid token format' });
    }

    // 3️⃣ Extract token part after "Bearer "
    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Token missing after Bearer' });
    }

    // 4️⃣ Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Save decoded payload in req.user

    next(); // ✅ Go to next middleware/route
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired token', error: err.message });
  }
};
