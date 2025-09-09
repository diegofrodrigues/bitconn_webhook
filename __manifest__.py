# -*- coding: utf-8 -*-
{
    'name': 'Bitconn Webhook',
    'summary': 'Generic webhook to create, update and delete records in Odoo via secure endpoints',
    'version': '1.0.0',
    'category': 'Tools',
    'author': 'Bitconn Technology',
    'website': 'https://bitconn.com.br',
    'license': 'LGPL-3',
    'depends': ['base', 'mail'],
    'data': [
        'security/ir.model.access.csv',
        'views/webhook_views.xml',
        'views/server_action_views.xml',
    ],
    'installable': True,
    'application': False,
    # 'images': ['static/description/icon.svg'],
}
