const express = require("express");
const helmet = require("helmet");
const config = require("./config");
const routes = require("./routes");
const log = require("./log");

const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "100kb" }));
app.use("/api", routes);

// Manejador de último recurso: mensaje genérico al cliente, detalle solo en el log del servidor.
app.use((err, req, res, next) => {
  const id = Math.random().toString(36).slice(2, 10);
  log.security("app.unhandled_error", { id, path: req.path, message: err.message });
  res.status(500).json({ error: "error interno", id });
});

if (require.main === module) {
  app.listen(config.port, () => console.log(`tienda-api escuchando en ${config.port}`));
}

module.exports = app;
