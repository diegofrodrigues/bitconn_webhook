## n8n Workflow Pack
Importable n8n workflows exercising the Bitconn Webhook API.

Primary file
- 00-odoo-webhook-all-flows.json – master workflow; set the variable `flow` (e.g. create_contact, update_contact, create_lead, update_lead, create_sale_order, create_invoice, post_sale_order_message, post_channel_message, update_sale_order, update_invoice).

Setup steps
1. Import JSON (top-right → Import from file) in n8n.
2. Open node "Set Config" and define:
  - base_url (e.g. http://localhost:8069)
  - webhook_uuid (from Webhook form)
  - secret (Secret Key)
3. Execute the workflow; each HTTP Request sends Authorization: Bearer <secret>.

Notes
- Methods: create, write, unlink, read, search (advanced fields supported with `fields`).
- By default search returns only ids; include `fields` to expand.
- Always respect Odoo ORM formats (many2one: id; x2many: command list on create/write if needed).

Individual examples (for quick import)
- 01-create-contact.json
- 02-update-contact.json
- 03-create-lead.json
- 04-update-lead.json
- 05-create-sale-order.json
- 06-create-invoice.json
- 07-post-sale-order-message.json
- 08-post-channel-message.json
- 09-update-sale-order.json
- 10-update-invoice.json

Refer to the root README for full API details.