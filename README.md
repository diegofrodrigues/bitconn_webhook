# Bitconn Webhook – JSON Examples

Use these examples to call the webhook from any HTTP client (curl, Postman, Zapier, custom apps).

Endpoint
- POST JSON to: `http(s)://<your-odoo>/bitconn/webhook/<webhook_uuid>`
- GET schema: `http(s)://<your-odoo>/bitconn/webhook/<webhook_uuid>/schema?model=<model>&method=create|write` (returns required fields, defaults, and field meta)
- GET required: `http(s)://<your-odoo>/bitconn/webhook/<webhook_uuid>/required?model=<model>&values=<json>` (retorna apenas uma lista dos campos que você deve enviar)

Required headers
- Prefer: `Authorization: Bearer <secret_key>`
- Fallback: `Webhook-Key: <secret_key>` (legacy: `X-Webhook-Key` also accepted)

Notes
- Auth is via headers; you do not need to send secret/user in the JSON body.
- `domain` is a standard Odoo domain (list of predicates).
- Methods supported: `create`, `write`, `unlink` (needs can_unlink enabled), `search` (ids or records), `read`, and `default_payload` (returns a template payload + header hints).
 - Use the schema endpoint para metadados completos; o required retorna só o que falta (must_provide), sem defaults.

Quick JSON bodies
- Create: `examples/create.json`
- Write: `examples/write.json`
- Unlink: `examples/unlink.json`
- Search (recommended): `examples/search.json`
- Read: `examples/read.json`
- Default Payload: `examples/default_payload.json`

Optional curl example (create)

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <secret_key>" \
  -d @docs/examples/create.json \
  http://localhost:8069/bitconn/webhook/<webhook_uuid>
```

Optional search curl (ids only)

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <secret_key>" \
  -d '{
    "method": "search",
    "model": "res.partner",
    "domain": [["email","=","cliente@example.com"]],
    "limit": 5
  }' \
  http://localhost:8069/bitconn/webhook/<webhook_uuid>
```

Optional schema curl

```bash
curl -X GET \
  -H "Authorization: Bearer <secret_key>" \
  "http://localhost:8069/bitconn/webhook/<webhook_uuid>/schema?model=res.partner&method=create"
```

Optional required curl (minimal)

```bash
curl -G \
  -H "Authorization: Bearer <secret_key>" \
  --data-urlencode 'model=res.partner' \
  --data-urlencode 'values={"type":"contact"}' \
  "http://localhost:8069/bitconn/webhook/<webhook_uuid>/required"
```
Resposta típica (exemplo):

[
  "name"
]
