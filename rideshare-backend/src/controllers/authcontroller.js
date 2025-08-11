const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');

exports.register = async (req, res) => {
  const { full_name, email, phone, password } = req.body;
  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into DB
    const result = await pool.query(
      `INSERT INTO users (full_name, email, phone, password_hash)
       VALUES ($1, $2, $3, $4) RETURNING id, full_name, email`,
      [full_name, email, phone, hashedPassword]
    );

    res.status(201).json({
      message: 'User registered successfully',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Register Error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1️⃣ Check if email exists
    const result = await pool.query(
      `SELECT id, full_name, email, password_hash, role
       FROM users WHERE email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // 2️⃣ Compare password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // 3️⃣ Create JWT token
    const token = jwt.sign(
      { id: user.id, role: user.role || 'user' }, // default role if null
      process.env.JWT_SECRET || 'secretkey',
      { expiresIn: '7d' }
    );

    // 4️⃣ Send response
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        role: user.role || 'user'
      }
    });

  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};
