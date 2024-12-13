const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
app.use(helmet());

// Rate limiting to mitigate DDoS attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Serve traffic over SSL/TLS
const options = {
  key: fs.readFileSync(path.join(__dirname, 'ssl', 'private-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'ssl', 'certificate.pem'))
};

https.createServer(options, app).listen(443, () => {
  console.log('Server is running on port 443');
});

// Input validation using regex patterns
const validateInput = (input, pattern) => pattern.test(input);

// Password hashing and salting
const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};

// Example route with input validation and password hashing
app.post('/register', async (req, res) => {
  const usernamePattern = /^[a-zA-Z0-9_]{3,30}$/;
  const passwordPattern = /^[a-zA-Z0-9!@#$%^&*]{6,30}$/;

  const { username, password } = req.body;

  if (!validateInput(username, usernamePattern) || !validateInput(password, passwordPattern)) {
    return res.status(400).send('Invalid input');
  }

  const hashedPassword = await hashPassword(password);
  // Store hashedPassword in the database
  // ...existing code...
  res.send('User registered successfully');
});

// ...existing code...
