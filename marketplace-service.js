require('dotenv').config();
const express = require('express');
const { body, validationResult } = require('express-validator');
const db = require('./database');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

// Security: Verify requests come from the Gateway
const verifyGateway = (req, res, next) => {
  const secret = req.header('X-Gateway-Secret');
  if (secret !== process.env.GATEWAY_SECRET) {
    return res.status(403).json({ error: 'Direct access to microservice forbidden.' });
  }
  next();
};
app.use(verifyGateway);

// --- Endpoints ---

// 1. Get all products (Public via Gateway)
app.get('/api/products', (req, res) => {
  db.all('SELECT * FROM Products', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 2. Add a new product (Admin Only - Enforced by Gateway)
app.post(
  '/api/products',
  [
    body('name').trim().notEmpty().escape(), // Sanitize input
    body('description').trim().escape(),
    body('price').isFloat({ gt: 0 }),
    body('imageUrl').trim() // Minimal sanitization for URL
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, description, price, imageUrl } = req.body;
    db.run(
      'INSERT INTO Products (name, description, price, imageUrl) VALUES (?, ?, ?, ?)',
      [name, description, price, imageUrl],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, name, description, price, imageUrl });
      }
    );
  }
);

// 3. Buy a product (Student Only - Enforced by Gateway)
app.post(
  '/api/buy',
  [
    body('productId').isInt(),
    body('bankingDetails').trim().notEmpty().escape() // Simple sanitization
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Extract studentId from headers (passed by the gateway after JWT verification)
    const studentId = req.header('X-User-Id');
    const { productId, bankingDetails } = req.body;

    if (!studentId) return res.status(400).json({ error: 'User ID missing' });

    db.run(
      'INSERT INTO Orders (studentId, productId, bankingDetails) VALUES (?, ?, ?)',
      [studentId, productId, bankingDetails],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'Order placed successfully!', orderId: this.lastID });
      }
    );
  }
);

// 4. Register a Student (Simulated Auth Registration)
app.post(
  '/api/register',
  [
    body('username').trim().notEmpty().escape(),
    body('password').isLength({ min: 5 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 10);

    db.run(
      "INSERT INTO Users (username, password, role) VALUES (?, ?, 'Student')",
      [username, hash],
      function (err) {
        if (err) return res.status(400).json({ error: 'Username already exists or database error.' });
        res.status(201).json({ message: 'Student registered successfully', id: this.lastID });
      }
    );
  }
);

// 5. Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM Users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    if (bcrypt.compareSync(password, user.password)) {
      res.json({ id: user.id, username: user.username, role: user.role });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

const PORT = process.env.PORT_SERVICE || 3000;
app.listen(PORT, () => {
  console.log(`Marketplace Microservice running on port ${PORT}`);
});
