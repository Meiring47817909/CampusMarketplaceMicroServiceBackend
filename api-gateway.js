require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

const app = express();
const PORT = process.env.PORT_GATEWAY || 4000;
const SERVICE_URL = `http://localhost:${process.env.PORT_SERVICE || 3000}`;

// --- Logging with Winston ---
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'gateway-security.log' })
  ]
});

// Middleware to log all incoming requests
app.use((req, res, next) => {
  logger.info({ message: 'Incoming request', method: req.method, url: req.url, ip: req.ip });
  next();
});

// --- Security: CORS ---
app.use(cors());

// --- Security: Rate Limiting (DDoS Protection) ---
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

// --- Parse JSON for local routes ---
app.use(express.json());

// --- Authentication & Authorization ---
// Generate JWT (Called internally by Gateway after successful login on microservice)
app.post('/api/auth/login', async (req, res) => {
  // We forward the login request manually to the microservice to verify credentials
  try {
    const response = await fetch(`${SERVICE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Gateway-Secret': process.env.GATEWAY_SECRET },
      body: JSON.stringify(req.body)
    });
    
    const data = await response.json();
    
    if (response.ok) {
      // Create JWT token
      const token = jwt.sign(
        { id: data.id, username: data.username, role: data.role },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
      );
      logger.info({ message: 'Successful login', user: data.username, role: data.role });
      res.json({ token, role: data.role, username: data.username });
    } else {
      logger.warn({ message: 'Failed login attempt', username: req.body.username });
      res.status(response.status).json(data);
    }
  } catch (err) {
    logger.error({ message: 'Login forwarding error', error: err.message });
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// JWT Verification Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.warn({ message: 'Missing token access attempt', url: req.url });
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn({ message: 'Invalid token access attempt', url: req.url });
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Role-Based Access Control (RBAC) Middleware
const requireRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      logger.warn({ message: `Forbidden access attempt`, requiredRole: role, actualRole: req.user.role, url: req.url });
      return res.status(403).json({ error: `Requires ${role} privileges` });
    }
    next();
  };
};

// --- Proxy Configuration ---
const proxyOptions = {
  target: SERVICE_URL,
  changeOrigin: true,
  onProxyReq: (proxyReq, req, res) => {
    // Inject Gateway Secret so microservice knows it's from the gateway
    proxyReq.setHeader('X-Gateway-Secret', process.env.GATEWAY_SECRET);
    // Inject User ID if authenticated, so microservice can track who bought what
    if (req.user) {
      proxyReq.setHeader('X-User-Id', req.user.id);
      proxyReq.setHeader('X-User-Role', req.user.role);
    }
  }
};

// Routes going to microservice
// 1. Public: Register and View Products
app.use('/api/register', createProxyMiddleware(proxyOptions));
app.use('/api/products', (req, res, next) => {
  if (req.method === 'GET') {
    return createProxyMiddleware(proxyOptions)(req, res, next);
  }
  next();
});

// 2. Admin Only: Add Products
app.post('/api/products', authenticateToken, requireRole('Admin'), createProxyMiddleware(proxyOptions));

// 3. Student Only: Buy Products
app.post('/api/buy', authenticateToken, requireRole('Student'), createProxyMiddleware(proxyOptions));

app.listen(PORT, () => {
  console.log(`Secure API Gateway running on port ${PORT}`);
  logger.info({ message: 'API Gateway started', port: PORT });
});
