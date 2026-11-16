const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("./config");
const db = require("./db");
const log = require("./log");

const BCRYPT_ROUNDS = 12;

function hashPassword(password) {
  return bcrypt.hashSync(password, BCRYPT_ROUNDS);
}

function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

function issueToken(user) {
  return jwt.sign({ sub: user.id }, config.jwtSecret, { expiresIn: config.tokenTtl, algorithm: "HS256" });
}

// Middleware: exige un token válido y carga el usuario actual desde la base de datos
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  try {
    const claims = jwt.verify(token, config.jwtSecret, { algorithms: ["HS256"] });
    const user = db.prepare("SELECT id, role FROM users WHERE id = ?").get(claims.sub);
    if (!user) throw new Error("usuario inexistente");
    req.user = user;
    next();
  } catch (err) {
    log.security("auth.token_rejected", { ip: req.ip, reason: err.message });
    res.status(401).json({ error: "no autenticado" });
  }
}

// Middleware: exige un rol concreto. Ante cualquier error, deniega (fail-closed).
function requireRole(role) {
  return (req, res, next) => {
    try {
      if (req.user && req.user.role === role) return next();
      log.security("authz.denied", { userId: req.user && req.user.id, required: role, path: req.path });
      return res.status(403).json({ error: "prohibido" });
    } catch (err) {
      log.security("authz.error", { path: req.path });
      return res.status(403).json({ error: "prohibido" });
    }
  };
}

module.exports = { hashPassword, verifyPassword, issueToken, requireAuth, requireRole };
