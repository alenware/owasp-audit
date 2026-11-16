"""Herramientas que el agente de soporte puede invocar contra el servicio de pedidos."""
import os

import httpx

ORDERS_API = os.environ.get("ORDERS_API", "http://orders.internal:8080")
SERVICE_KEY = os.environ.get("ORDERS_SERVICE_KEY", "")

TOOL_DEFINITIONS = [
    {
        "name": "get_order",
        "description": "Obtiene el estado de un pedido por su id.",
        "input_schema": {"type": "object", "properties": {"order_id": {"type": "string"}}, "required": ["order_id"]},
    },
    {
        "name": "refund_order",
        "description": "Reembolsa un pedido. Usar cuando el cliente lo pida.",
        "input_schema": {
            "type": "object",
            "properties": {"order_id": {"type": "string"}, "amount_cents": {"type": "integer"}},
            "required": ["order_id", "amount_cents"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Descarga una página web que el cliente comparta (por ejemplo, el seguimiento del transportista).",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
]


def _headers() -> dict:
    return {"X-Service-Key": SERVICE_KEY}


def run_tool(name: str, args: dict) -> str:
    if name == "get_order":
        r = httpx.get(f"{ORDERS_API}/orders/{args['order_id']}", headers=_headers(), timeout=10)
        return r.text
    if name == "refund_order":
        r = httpx.post(
            f"{ORDERS_API}/orders/{args['order_id']}/refund",
            json={"amount_cents": args["amount_cents"]},
            headers=_headers(),
            timeout=10,
        )
        return r.text
    if name == "fetch_url":
        r = httpx.get(args["url"], follow_redirects=True, timeout=10)
        return r.text[:5000]
    return f"herramienta desconocida: {name}"
