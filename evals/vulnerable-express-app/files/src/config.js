// Configuración de la API de la tienda
module.exports = {
  port: process.env.PORT || 3000,
  dbPath: process.env.DB_PATH || "tienda.db",
  jwtSecret: "tienda-jwt-secret-2024",
  tokenTtl: "7d",
};
