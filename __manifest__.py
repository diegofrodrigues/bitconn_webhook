# -*- coding: utf-8 -*-
{
    'name': 'Bitconn Webhook',
    'summary': 'Generic webhook to create, update and delete records in Odoo via secure endpoints',
    'description': """
Inbound & outbound webhook API for Odoo.

Inbound:
- JSON POST endpoint: create, write, unlink, search, read, default_payload
- Advanced nested field extraction (relation specs)
- Schema & Required helper endpoints

Outbound:
- HTTP callbacks (webhook send) from Server Actions / manual test
- Manual or spec-based payloads with placeholders and nested relations

Security:
- Token header (Authorization: Bearer <secret_key>)
- Regenerate credentials button

See README.md for full documentation & examples (n8n workflows, advanced specs, troubleshooting).
""",
    'version': '1.4.0',
    'category': 'Tools',
    'author': 'Bitconn Technology',
    'website': 'https://bitconn.com.br',
    'depends': ['base', 'mail'],
    'data': [
        'security/ir.model.access.csv',
        'views/webhook_views.xml',
        'views/server_action_views.xml',
    ],
    'license': 'GPL-3',
    'installable': True,
    'application': False,
    'auto_install': False,
    # 'images': ['static/description/icon.svg'],
}
