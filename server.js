const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based wrapper
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
app.use(express.json());

// Setup Session Middleware
app.use(session({
    secret: 'your-secure-random-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false } // Set secure: true in production (HTTPS)
}));

// Database Connection
const db = mysql.createPool({ host: 'localhost', user: 'root', password: '', database: 'auth_db' });

// Registration Route (Hashing & Prepared Statements)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Using Prepared Statement to prevent SQL Injection
    const sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    try {
        await db.execute(sql, [username, hashedPassword]);
        res.status(201).send("User registered.");
    } catch (err) {
        res.status(500).send("Database error.");
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    const [rows] = await db.execute("SELECT * FROM users WHERE username = ?", [username]);
    
    if (rows.length > 0) {
        const isMatch = await bcrypt.compare(password, rows[0].password);
        if (isMatch) {
            req.session.userId = rows[0].id;
            res.send("Logged in!");
        } else {
            res.status(401).send("Invalid credentials.");
        }
    } else {
        res.status(401).send("Invalid credentials.");
    }
});

// Logout Route
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.send("Logged out.");
    });
});

app.listen(3000, () => console.log('Server running on port 3000'));
// Add this route to your server.js file
app.get('/', (req, res) => {
    res.send('<h1>Welcome to the Secure Login System</h1><p>Go to /register or /login</p>');
});