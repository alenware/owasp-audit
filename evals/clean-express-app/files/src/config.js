// Configuración de la API de la tienda. Los secretos llegan por variables de entorno (gestor de secretos en producción).
function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Falta la variable de entorno ${name}`);
  return value;
}

module.exports = {
  port: process.env.PORT || 3000,
  dbPath: process.env.DB_PATH || "tienda.db",
  jwtSecret: required("JWT_SECRET"),
  tokenTtl: "15m",
};
