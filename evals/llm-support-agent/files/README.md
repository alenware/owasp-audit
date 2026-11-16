# soporte-ia

Asistente de soporte con IA para la tienda. Es multi-tenant: cada marca (tenant) tiene sus clientes, sus artículos de ayuda y sus tickets en la misma base de conocimiento.

- `POST /chat`: respuesta en JSON para la app móvil.
- `POST /chat/widget`: respuesta en HTML que la web inserta en el chat embebido.

El agente puede consultar pedidos, emitir reembolsos y abrir enlaces de seguimiento que comparta el cliente. El equipo usa el servidor MCP `tienda-db` de `.mcp.json` desde Claude Code para consultar la base de datos.
