# n8n example workflows for Odoo Webhook

This folder contains importable n8n workflows that call the Odoo Webhook endpoint provided by the custom module `bitconn_webhook`.

Start here
- 00-odoo-webhook-all-flows.json: a single base workflow with all flows. Set "flow" to choose which branch to run (e.g. create_contact, update_contact, create_lead, update_lead, create_sale_order, create_invoice, post_sale_order_message, post_channel_message).

How to use
- Import any JSON file into n8n (top-right menu → Import from file).
- Open the "Set Config" node and set your values:
  - base_url: your Odoo base URL (e.g., http://localhost:8069)
  - webhook_uuid: from the Webhook form in Odoo
  - secret: the Secret Key from the same Webhook
- Run the workflow. Each workflow uses HTTP Request nodes with Authorization: Bearer <secret>.

Notes
- Methods supported: create, write, unlink, read, search.
- search returns only ids by default; pass fields to get full records.
- Use proper Odoo ORM relation formats for values (many2one id, many2many/one2many command lists).
- These are minimal examples; adapt fields to your instance (company/journal/pricelist may change defaults).

Files (individual examples)
- 01-create-contact.json: Create res.partner.
- 02-update-contact.json: Update res.partner by email.
- 03-create-lead.json: Create crm.lead.
- 04-update-lead.json: Update crm.lead by id.
- 05-create-sale-order.json: Create sale.order with one line (finds partner & product first).
- 06-create-invoice.json: Create account.move (Customer Invoice) with lines (finds partner & product first).
- 07-post-sale-order-message.json: Post a comment to a sale.order chatter (find by name).
- 08-post-channel-message.json: Post a message to a mail.channel (find by name).
- 09-update-sale-order.json: Update sale.order (set note) by name.
- 10-update-invoice.json: Update account.move narration by name.