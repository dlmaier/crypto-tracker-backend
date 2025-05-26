const express = require("express");
const session = require("express-session");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const app = express();
const db = new sqlite3.Database("db.sqlite");

app.use(cors({
  origin: "http://localhost:5173",
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: "secret-key",
  resave: false,
  saveUninitialized: false
}));

// Create tables
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);
db.run(`CREATE TABLE IF NOT EXISTS wallets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  address TEXT,
  network TEXT
)`);

// Register
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], (err) => {
    if (err) return res.status(400).json({ error: "Username taken" });
    res.json({ success: true });
  });
});

// Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (!user) return res.status(401).json({ error: "Invalid login" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid login" });
    req.session.userId = user.id;
    res.json({ success: true });
  });
});

// Get wallets
app.get("/api/wallets", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  db.all("SELECT * FROM wallets WHERE user_id = ?", [req.session.userId], (err, rows) => {
    res.json(rows);
  });
});

// Add wallet
app.post("/api/wallets", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  const { address, network } = req.body;
  db.run("INSERT INTO wallets (user_id, address, network) VALUES (?, ?, ?)",
    [req.session.userId, address, network], err => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ success: true });
    });
});

// Start server
app.listen(3001, () => console.log("Server running on http://localhost:3001"));
