<h1 align="center">Bitconn Webhook</h1>
<p align="center">Inbound & outbound Webhook API for Odoo 18 – simple JSON calls in, structured data & automation events out.</p>

## 1. What this module does
Inbound: exposes a secure HTTP JSON API so external systems (n8n, Zapier, custom apps, other SaaS) can Create / Write / Unlink / Read / Search Odoo records, fetch schema metadata, and request a default/template payload.

Outbound: lets you trigger HTTP POST callbacks (webhooks) from Server Actions or manual actions, building payloads with an advanced field extraction engine (nested relations, placeholders, and manual payload specs).

Status: Focused, minimal dependency, pure Odoo ORM usage. Suitable for integration “glue” without needing full RPC clients.

## 2. Core inbound endpoints
Base URL pattern (always replace `<webhook_uuid>` & host):

POST  /bitconn/webhook/<webhook_uuid>
GET   /bitconn/webhook/<webhook_uuid>/schema?model=<model>&method=<create|write>
GET   /bitconn/webhook/<webhook_uuid>/required?model=<model>&values=<json-encoded-values>

### 2.1 Supported methods (POST body: JSON)
create | write | unlink | search | read | default_payload | search_advanced (alias: search with advanced fields spec)

### 2.2 Authentication headers
Preferred: Authorization: Bearer <secret_key>
Fallback: Webhook-Key: <secret_key>  (legacy X-Webhook-Key also accepted)

No credentials go inside the JSON body. Missing/invalid key ⇒ 401.

### 2.3 JSON payload basics
Common root keys: model, method, domain, ids, values, fields, limit, offset, order.

Domains follow standard Odoo syntax (list of triplets / logical operators). Examples are compacted single-line for readability.

## 3. Quick inline examples

Create
```json
{ "model": "res.partner", "method": "create", "values": { "name": "Cliente Teste", "email": "cliente@example.com" } }
```

Write (domain match then update)
```json
{ "model": "res.partner", "method": "write", "domain": [["email", "=", "cliente@example.com"]], "values": { "comment": "Atualizado via webhook" } }
```

Unlink (danger – requires Can Unlink)
```json
{ "model": "res.partner", "method": "unlink", "domain": [["email", "=", "cliente@example.com"]] }
```

Search (ids only)
```json
{ "model": "res.partner", "method": "search", "domain": [["email", "=", "cliente@example.com"]], "limit": 5 }
```

Read (returns records with selected fields)
```json
{ "model": "res.partner", "method": "read", "ids": [42], "fields": ["id", "name", "email"] }
```

Search with flat fields
```json
{ "model": "sale.order", "method": "search", "domain": [["state", "=", "sale"]], "fields": ["id", "name", "partner_id", "amount_total"], "limit": 3 }
```

Default payload template
```json
{ "model": "res.partner", "method": "default_payload" }
```

## 4. Advanced field extraction (nested relations)
Use a mixed list of strings and dict specs under `fields`:

```json
{ "model": "sale.order", "method": "search", "domain": [["id", "=", 99]], "fields": ["id", "name", { "partner_id": ["id", "name", { "country_id": ["id", "code"] }] }, { "order_line": ["id", "name", { "product_id": ["id", "default_code", "name"] }] }] }
```

Rules:
- many2one without subspec ⇒ returns `{"id": <id>}`
- many2one with subspec ⇒ object with requested subfields
- o2m/m2m ⇒ list of objects ordered by original sequence
- You can still mix dotted strings (partner_id.name) but prefer one consistent style.

## 5. Schema & Required endpoints
Schema: full metadata (required, readonly, selection, default, type) for a given model + method (create/write).
Required: returns only which fields you still must provide after evaluating defaults + provided `values`.

Example (Required, minimal):
```bash
curl -G -H "Authorization: Bearer <secret_key>" \
  --data-urlencode 'model=res.partner' \
  --data-urlencode 'values={"type":"contact"}' \
  "http://localhost:8069/bitconn/webhook/<webhook_uuid>/required"
```

## 6. Outbound webhook sending
Enable outbound inside the Webhook form: set URL + optional headers JSON.
You can drive outbound sends via:
1. Server Actions (custom Python or UI) calling a helper that assembles payload using the same advanced spec.
2. Manual Test (in form view) with a prepared Test Body and visual response log.

Manual payload spec supports:
- fields: advanced list (as above) OR simple dotted list
- static keys with placeholders: {{ field_path }} or ${field_path} resolved per record
- nested objects/arrays built from relations

## 7. n8n workflow pack
Import `docs/n8n/00-odoo-webhook-all-flows.json` to get a multi-flow template. Configure once (base_url, webhook_uuid, secret). Branch names: create_contact, update_contact, create_lead, update_lead, create_sale_order, create_invoice, post_sale_order_message, post_channel_message, update_sale_order, update_invoice.

HTTP Request nodes send `Authorization: Bearer <secret>` and JSON bodies like the examples above.

## 8. Examples directory map
`docs/examples/`
- create.json / write.json / unlink.json / read.json / search.json / default_payload.json
- search_advanced.json – nested relations sample
- outbound_send.json – base outbound test body
- manual_payload_* – templates for Server Action / outbound building (nested + placeholders)

## 9. Security & best practices
- Rotate secret via "Regenerate Credentials" button if leaked.
- Restrict Allowed Models to reduce attack surface.
- Avoid enabling Can Unlink unless absolutely necessary.
- Use HTTPS in production.

## 10. Troubleshooting quick list
401 Unauthorized: Check header name & secret.
Missing required field: Call /schema or /required endpoints.
Empty nested relation array: Verify domain actually returns records; ensure user has read rights.
Outbound 4xx: Inspect stored response body in the form (Test Result field).

## 11. Minimal curl cheatsheet
Create
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <secret_key>" \
  -d '{"model":"res.partner","method":"create","values":{"name":"Cliente X"}}' \
  http://localhost:8069/bitconn/webhook/<webhook_uuid>
```

Search advanced (pretty)
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <secret_key>" \
  -d '{"model":"sale.order","method":"search","domain":[["state","=","sale"]],"fields":["id","name",{"partner_id":["id","name"]}]}' \
  http://localhost:8069/bitconn/webhook/<webhook_uuid>
```

## 12. Roadmap (suggested next ideas)
- Optional pagination helper wrapper
- Async outbound queue with retry/backoff
- Field-level allow/deny lists per webhook

## 13. License / Contrib
Standard Odoo / repository license (see LICENSE). PRs welcome: keep examples minimal & generic.

---
Single source README: docs sub-README files were merged here for clarity. Refer to directories for raw JSON assets.

Happy integrating! 🚀

## Apoie o Projeto / Support the Project

PT-BR:
Se este módulo foi útil para você, considere fazer uma doação para apoiar o desenvolvimento contínuo ou simplesmente me pagar uma cerveja 🍺!

Chave Pix:
```
00020126810014br.gov.bcb.pix013655f22863-4cea-41e9-904c-df3ce0b241ef0219wa conn odoo module5204000053039865802BR5924Diego Ferreira Rodrigues6009Sao Paulo62290525REC68545B90764819659464106304D86E
```

Ou use o QR Code abaixo (ou na tela do módulo em Odoo).

EN:
If this module saved you time or money, consider a small donation (or buy me a beer 🍺) to keep improvements coming.

Brazil Pix Key (copy & pay):
```
00020126810014br.gov.bcb.pix013655f22863-4cea-41e9-904c-df3ce0b241ef0219wa conn odoo module5204000053039865802BR5924Diego Ferreira Rodrigues6009Sao Paulo62290525REC68545B90764819659464106304D86E
```

QR Code (place file at static/description/qr_code_donate.png):

<img src="static/description/qr_code_donate.png" alt="Donation QR Code" width="150" height="150"/>
