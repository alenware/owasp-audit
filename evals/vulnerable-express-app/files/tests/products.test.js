process.env.DB_PATH = ":memory:";
const request = require("supertest");
const app = require("../src/server");

describe("productos", () => {
  it("lista productos", async () => {
    const res = await request(app).get("/api/products");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});
