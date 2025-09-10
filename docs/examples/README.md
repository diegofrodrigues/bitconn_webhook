## Examples Directory
This folder hosts raw JSON payload samples used by the Bitconn Webhook module. See the root README for full documentation; this file is a quick index.

### Basic operations
- create.json – Create record
- read.json – Read by IDs + fields
- search.json – Domain search + flat/dotted fields
- write.json – Update via domain
- unlink.json – Delete via domain (danger)
- default_payload.json – Template generation request

### Outbound
- outbound_send.json – Manual outbound POST test body

### Advanced / nested
- search_advanced.json – Advanced `fields` spec with nested relation objects

### Server Action manual payload helpers
- manual_payload_fields.json – Flat field name list response sample
- manual_payload_template.json – Template with placeholders {{ path }} / ${path}
- manual_payload_nested.json – Nested spec producing structured records
- manual_payload_nested_with_placeholders.json – Mixed placeholders + nested objects

### Advanced spec rules (summary)
- fields list can mix strings and dicts: {"relation_field": [subspec...]}
- many2one: without subspec ⇒ {"id": n}; with subspec ⇒ expanded object
- one2many/many2many: list of objects preserving order
- Mix with dotted notation only if necessary for quick flat fields

### Pattern examples
```json
["id", "name", {"order_line": ["id", "name", {"product_id": ["id", "default_code", "name"]}]}]
```
```json
{"fields": ["id", {"partner_id": ["id", "name", {"country_id": ["id", "code"]}]}, {"order_line": ["id", {"product_id": ["id", "name"]}]}]}
```

Need another scenario? Open an issue or PR.
