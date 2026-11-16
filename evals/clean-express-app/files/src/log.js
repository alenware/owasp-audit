// Logging estructurado de eventos de seguridad. Nunca registra contraseñas ni tokens.
function security(event, fields = {}) {
  const entry = { ts: new Date().toISOString(), level: "warn", type: "security", event, ...fields };
  delete entry.password;
  delete entry.token;
  process.stdout.write(JSON.stringify(entry) + "\n");
}

module.exports = { security };
