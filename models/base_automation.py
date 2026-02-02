from odoo import fields, models


class BaseAutomationExt(models.Model):
    _inherit = 'base.automation'

    bitconn_webhook_id = fields.Many2one(
        'bitconn.webhook',
        string='Webhook',
        ondelete='cascade',
        help='Webhook configuration (Bitconn) associated with this automation rule'
    )
