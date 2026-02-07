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
    'version': '19.0.1.4.0',
    'category': 'Tools',
    'author': 'Bitconn Technology',
    'website': 'https://bitconn.com.br',
    'depends': ['base', 'mail', 'base_automation'],
    'data': [
        'security/ir.model.access.csv',
        'views/webhook_views.xml',
        'views/server_action_views.xml',
        'views/ir_actions_server_views.xml',
    ],
    'assets': {
        'web.assets_backend': [
            'bitconn_webhook/static/src/js/xterm.js',
            'bitconn_webhook/static/src/css/xterm.css',
            'bitconn_webhook/static/src/js/addon-fit.js',
            'bitconn_webhook/static/src/js/bitconn_terminal_ws.js',
        ],
    },
    'license': 'LGPL-3',
    'installable': True,
    'application': False,
    'auto_install': False,
    # 'images': ['static/description/icon.svg'],
}
