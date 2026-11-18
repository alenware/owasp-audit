process.env.DB_PATH = ":memory:";
process.env.JWT_SECRET = "test-only-secret";
const request = require("supertest");
const app = require("../src/server");
const db = require("../src/db");
const { hashPassword, issueToken } = require("../src/auth");

function seedUser(email, role = "customer") {
  const id = db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)").run(email, hashPassword("x".repeat(12)), role).lastInsertRowid;
  return { id, token: issueToken({ id }) };
}

describe("pedidos", () => {
  it("un cliente no puede leer el pedido de otro", async () => {
    const alice = seedUser("alice@example.test");
    const bob = seedUser("bob@example.test");
    const orderId = db.prepare("INSERT INTO orders (user_id, total_cents, shipping_address) VALUES (?, 100, 'calle 1')").run(alice.id).lastInsertRowid;
    const res = await request(app).get(`/api/orders/${orderId}`).set("Authorization", `Bearer ${bob.token}`);
    expect(res.status).toBe(404);
  });
});
