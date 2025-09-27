require('dotenv').config();     // Add this at the very top

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const app = express();

const PORT = process.env.PORT || 8080;
const SECRET = process.env.SECRET || "default_secret_if_none_set";

app.use(cors({
  origin: 'https://your-netlify-site.netlify.app', // Update to your Netlify frontend URL
  credentials: true
}));
app.use(bodyParser.json());

const USER = { id: 1, email: "workchopoff@gmail.com", password: "password123_zMq-h5*wE-FdUk" };

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (email === USER.email && password === USER.password) {
    const token = jwt.sign({ id: USER.id, email: USER.email }, SECRET, { expiresIn: "2h" });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: "Invalid credentials" });
  }
});

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
