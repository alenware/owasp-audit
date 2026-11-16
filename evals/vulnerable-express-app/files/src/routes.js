const express = require("express");
const db = require("./db");
const { hashPassword, verifyPassword, issueToken, requireAuth, requireRole } = require("./auth");

const router = express.Router();

router.post("/auth/register", (req, res) => {
  const { email, password, name } = req.body;
  const info = db
    .prepare("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)")
    .run(email, hashPassword(password), name);
  res.status(201).json({ id: info.lastInsertRowid });
});

router.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: "credenciales incorrectas" });
  }
  res.json({ token: issueToken(user) });
});

router.get("/products", (req, res) => {
  const search = req.query.search || "";
  const rows = db.prepare(`SELECT id, name, price_cents FROM products WHERE name LIKE '%${search}%'`).all();
  res.json(rows);
});

router.get("/orders", requireAuth, (req, res) => {
  const rows = db.prepare("SELECT * FROM orders WHERE user_id = ?").all(req.user.sub);
  res.json(rows);
});

router.get("/orders/:id", requireAuth, (req, res) => {
  const order = db.prepare("SELECT * FROM orders WHERE id = ?").get(req.params.id);
  if (!order) return res.status(404).json({ error: "no encontrado" });
  res.json(order);
});

router.patch("/users/me", requireAuth, (req, res) => {
  const current = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.sub);
  const updated = { ...current, ...req.body };
  db.prepare("UPDATE users SET email = ?, name = ?, role = ? WHERE id = ?").run(
    updated.email,
    updated.name,
    updated.role,
    req.user.sub
  );
  res.json({ id: updated.id, email: updated.email, name: updated.name, role: updated.role });
});

router.get("/admin/users", requireAuth, requireRole("admin"), (req, res) => {
  res.json(db.prepare("SELECT id, email, name, role FROM users").all());
});

module.exports = router;
