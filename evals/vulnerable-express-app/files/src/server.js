const express = require("express");
const config = require("./config");
const routes = require("./routes");

const app = express();
app.use(express.json());
app.use("/api", routes);

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

if (require.main === module) {
  app.listen(config.port, () => console.log(`tienda-api escuchando en ${config.port}`));
}

module.exports = app;
