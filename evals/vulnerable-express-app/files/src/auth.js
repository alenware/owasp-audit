const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const config = require("./config");

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}

function issueToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, config.jwtSecret, { expiresIn: config.tokenTtl });
}

// Middleware: exige un token válido
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, config.jwtSecret);
    next();
  } catch (err) {
    res.status(401).json({ error: "token inválido" });
  }
}

// Middleware: exige un rol concreto (consulta el rol actual en la base de datos)
function requireRole(role) {
  return (req, res, next) => {
    try {
      const db = require("./db");
      const user = db.prepare("SELECT role FROM users WHERE id = ?").get(req.user.sub);
      if (user.role !== role) {
        return res.status(403).json({ error: "prohibido" });
      }
      next();
    } catch (err) {
      console.error("error comprobando rol", err);
      next();
    }
  };
}

module.exports = { hashPassword, verifyPassword, issueToken, requireAuth, requireRole };
