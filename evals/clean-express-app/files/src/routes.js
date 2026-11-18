const express = require("express");
const rateLimit = require("express-rate-limit");
const db = require("./db");
const log = require("./log");
const { hashPassword, verifyPassword, issueToken, requireAuth, requireRole } = require("./auth");

const router = express.Router();
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

const SORTABLE = { name: "name", price: "price_cents" };
const PROFILE_FIELDS = ["email", "name"]; // campos que el usuario puede cambiar de sí mismo

router.post("/auth/register", (req, res) => {
  const { email, password, name } = req.body;
  if (typeof email !== "string" || typeof password !== "string" || password.length < 12) {
    return res.status(400).json({ error: "datos inválidos" });
  }
  const info = db
    .prepare("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)")
    .run(email, hashPassword(password), name || null);
  res.status(201).json({ id: info.lastInsertRowid });
});

router.post("/auth/login", loginLimiter, (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(String(email || ""));
  if (!user || !verifyPassword(String(password || ""), user.password_hash)) {
    log.security("auth.login_failed", { email: String(email || "").slice(0, 120), ip: req.ip });
    return res.status(401).json({ error: "credenciales incorrectas" });
  }
  log.security("auth.login_ok", { userId: user.id, ip: req.ip });
  res.json({ token: issueToken(user) });
});

router.get("/products", (req, res) => {
  const search = String(req.query.search || "");
  const column = SORTABLE[req.query.sort] || "name";
  // `column` solo puede ser un valor de la lista SORTABLE; el texto del usuario va como parámetro.
  const rows = db.prepare(`SELECT id, name, price_cents FROM products WHERE name LIKE ? ORDER BY ${column}`).all(`%${search}%`);
  res.json(rows);
});

router.get("/orders", requireAuth, (req, res) => {
  const rows = db.prepare("SELECT id, total_cents, created_at FROM orders WHERE user_id = ?").all(req.user.id);
  res.json(rows);
});

router.get("/orders/:id", requireAuth, (req, res) => {
  const order = db
    .prepare("SELECT id, total_cents, shipping_address, created_at FROM orders WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user.id);
  if (!order) return res.status(404).json({ error: "no encontrado" });
  res.json(order);
});

router.patch("/users/me", requireAuth, (req, res) => {
  const changes = {};
  for (const field of PROFILE_FIELDS) {
    if (typeof req.body[field] === "string") changes[field] = req.body[field];
  }
  const current = db.prepare("SELECT id, email, name FROM users WHERE id = ?").get(req.user.id);
  const updated = { ...current, ...changes };
  db.prepare("UPDATE users SET email = ?, name = ? WHERE id = ?").run(updated.email, updated.name, req.user.id);
  res.json({ id: updated.id, email: updated.email, name: updated.name });
});

// Todas las rutas /admin exigen sesión y rol admin a nivel de router.
const admin = express.Router();
admin.use(requireAuth, requireRole("admin"));
admin.get("/users", (req, res) => {
  res.json(db.prepare("SELECT id, email, name, role FROM users").all());
});
admin.get("/stats", (req, res) => {
  res.json(db.prepare("SELECT COUNT(*) AS orders, SUM(total_cents) AS revenue FROM orders").get());
});
router.use("/admin", admin);

module.exports = router;
