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

## 12. WebSocket Terminal - Integrated Module

### What changed

- **Integrated WebSocket**: server runs inside Odoo (separate thread)
- **Auto-install**: `websockets` installed automatically in `__init__.py`
- **Zero external config**: no separate service needed
- **Same base port**: WebSocket on dedicated port (8765) but managed by Odoo
- **Fully portable**: automatically detects Odoo installation path, executable, and config
- **Works everywhere**: pip install, source, Docker, any directory structure

### Environment Detection

The terminal is **100% portable** and automatically adapts to your Odoo environment:

✅ **Auto-detects Odoo root**: uses `odoo` package location, works with any installation path  
✅ **Finds executables**: searches for `odoo-bin`, `odoo`, or runs as Python module  
✅ **Uses current config**: reads the active Odoo config file (`odoo.conf`, `production.conf`, etc.)  
✅ **Smart working dir**: bash opens in Odoo root directory (where odoo-bin is located)  

**Supported installations:**
- Source installation (`/opt/odoo`, `/home/user/odoo`, custom paths)
- Pip install (`pip install odoo`)
- Docker containers
- Virtual environments (venv, virtualenv, conda)
- Any config file name or location

### Quick Start

#### 1. Reinstall module (auto-installs websockets)

```bash
# Navigate to your Odoo installation directory
cd /path/to/your/odoo
# Update the module (adjust config path as needed)
./odoo-bin -u bitconn_webhook
# or with specific config
./odoo-bin -c /path/to/odoo.conf -u bitconn_webhook
```

The `websockets` lib will be installed automatically on first import.

**Note**: No hardcoded paths! Works from any directory structure.

#### 2. Configure Secret Key (optional)

```bash
export WS_SECRET_KEY="your-secret-key-min-32-chars"
export WS_HOST="127.0.0.1"  # default
export WS_PORT="8765"        # default
```

Or add to `odoo.conf`:
```ini
[options]
# ... other configs
```

#### 3. Test

```bash
# Start Odoo (adjust path and config as needed)
./odoo-bin
# or with config file
./odoo-bin -c /path/to/your/odoo.conf
```

Open browser: http://localhost:8069 (or your configured port)
- Menu: Bitconn Webhook
- Tab: Terminal  
- Button: Open Shell

**Logs to verify:**
```
INFO bitconn_webhook.terminal: WebSocket server thread started
INFO bitconn_webhook.terminal: WebSocket terminal server started on 127.0.0.1:8765
```

### Functionality Checklist

✅ Module starts without errors  
✅ Log shows "WebSocket server thread started"  
✅ Port 8765 open: `netstat -tlnp | grep 8765`  
✅ Terminal tab opens without console errors  
✅ "Open Shell" button connects  
✅ bitconn.sh banner appears  
✅ Shell prompt visible  
✅ Real-time typing works  

### Troubleshooting

#### "websockets library not available"
```bash
pip3 install websockets
# or
python3 -m pip install websockets
```

Restart Odoo after manual installation.

#### "WebSocket connection failed"
Check if port 8765 is open:
```bash
netstat -tlnp | grep 8765
# or
ss -tlnp | grep 8765
```

#### "Authentication failed"
Different secret key between token generation and validation. Check `WS_SECRET_KEY` env var.

#### Browser doesn't connect
Check browser console (F12):
- Should show: `[bitconn_terminal] Got token, connecting to ws://127.0.0.1:8765`
- Should connect: `[bitconn_terminal] WebSocket connected`

If connection error, check firewall:
```bash
sudo ufw allow 8765/tcp
```

### Production

#### Nginx Proxy (HTTPS + WSS)

```nginx
upstream odoo {
    server 127.0.0.1:8069;
}

upstream ws_terminal {
    server 127.0.0.1:8765;
}

server {
    listen 443 ssl http2;
    server_name example.com;
    
    # Odoo
    location / {
        proxy_pass http://odoo;
        # ... standard Odoo configs
    }
    
    # Terminal WebSocket
    location /ws/terminal {
        proxy_pass http://ws_terminal;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

Configure public URL:
```bash
# In production, update in __manifest__ or via env:
export WS_HOST="0.0.0.0"  # allow external
```

Update client JS to use Nginx URL (automatic via token response).

### Comparison

| Feature | SSE (old) | **WebSocket (current)** |
|---------|-------------|----------------------|
| Installation | ✅ Stdlib | ✅ Auto (pip install) |
| Latency | ~50ms | **< 20ms** |
| Odoo Timeout | ⚠️ WARNING | **✅ OK** |
| Overhead | Base64 | **Binary** |
| Setup | Integrated | **Integrated** |
| Production | ❌ | **✅** |

### Security

- ✅ JWT tokens with HMAC-SHA256
- ✅ Configurable expiration (default 1h)
- ✅ Isolated processes (setsid)
- ✅ Automatic cleanup
- ✅ Auth via Odoo user

### Advantages of this Approach

1. **All in one module**: no external service management needed
2. **Auto-installation**: dependencies installed automatically
3. **Zero config**: works out-of-the-box
4. **Same security**: authenticates via Odoo session
5. **Centralized logs**: everything in Odoo log

## 13. Roadmap (suggested next ideas)
- Optional pagination helper wrapper
- Async outbound queue with retry/backoff
- Field-level allow/deny lists per webhook

## 14. License / Contrib
License: GPL-3 (see LICENSE file). Contributions welcome—keep examples minimal & generic.

---
Single source README: docs sub-README files were merged here for clarity. Refer to directories for raw JSON assets.

Happy integrating! 🚀

## 15. Apoie o Projeto / Support the Project

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
