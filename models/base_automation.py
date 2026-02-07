from odoo import api, fields, models


class BaseAutomationExt(models.Model):
    _inherit = 'base.automation'

    bitconn_webhook_id = fields.Many2one(
        'bitconn.webhook',
        string='Webhook',
        ondelete='cascade',
        help='Webhook configuration (Bitconn) associated with this automation rule'
    )

    @api.model_create_multi
    def create(self, vals_list):
        records = super().create(vals_list)
        records._sync_bitconn_webhook_id()
        return records

    def write(self, vals):
        res = super().write(vals)
        if 'action_server_ids' in vals or 'bitconn_webhook_id' in vals:
            self._sync_bitconn_webhook_id()
        return res

    def _sync_bitconn_webhook_id(self):
        """Sync bitconn_webhook_id from child server actions to the automation rule.
        If any server action has a bitconn_webhook_id set and the automation doesn't,
        copy it to the automation so it appears in the Outbound tab."""
        for rule in self:
            if not rule.bitconn_webhook_id:
                webhook = rule.action_server_ids.mapped('bitconn_webhook_id')[:1]
                if webhook:
                    rule.bitconn_webhook_id = webhook


