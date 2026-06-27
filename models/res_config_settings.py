from odoo import api, fields, models


class BitconnWebhookConfigSettings(models.TransientModel):
    _name = 'bitconn.webhook.config.settings'
    _description = 'Bitconn Webhook Configuration'

    execution_log_retention_days = fields.Integer(
        string='Execution Log Retention (days)',
        default=15,
        help='Number of days to keep execution logs. Older logs will be automatically purged.',
    )

    @api.model
    def default_get(self, fields_list):
        res = super().default_get(fields_list)
        ICP = self.env['ir.config_parameter'].sudo()
        res['execution_log_retention_days'] = int(ICP.get_param(
            'bitconn_webhook_execution_log_retention_days', '15'))
        return res

    def action_save(self):
        ICP = self.env['ir.config_parameter'].sudo()
        ICP.set_param(
            'bitconn_webhook_execution_log_retention_days',
            str(self.execution_log_retention_days),
        )
        return {'type': 'ir.actions.act_window_close'}
