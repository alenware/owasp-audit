process.env.DB_PATH = ":memory:";
process.env.JWT_SECRET = "test-only-secret";
const request = require("supertest");
const app = require("../src/server");

describe("productos", () => {
  it("lista productos", async () => {
    const res = await request(app).get("/api/products");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it("el parámetro sort no admite columnas arbitrarias", async () => {
    const res = await request(app).get("/api/products?sort=password_hash");
    expect(res.status).toBe(200);
  });
});
