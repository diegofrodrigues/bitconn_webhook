from odoo import api, fields, models, _
from datetime import timedelta
import json
import logging

_logger = logging.getLogger(__name__)


class BitconnWebhookExecutionLog(models.Model):
    _name = 'bitconn.webhook.execution.log'
    _description = 'Bitconn Webhook Execution Log'
    _order = 'execution_date desc, id desc'

    webhook_id = fields.Many2one('bitconn.webhook', required=True, ondelete='cascade', string='Webhook')
    server_action_id = fields.Many2one('ir.actions.server', string='Server Action', ondelete='set null')
    direction = fields.Selection([
        ('inbound', 'Inbound'),
        ('outbound', 'Outbound'),
    ], required=True, string='Direction')
    state = fields.Selection([
        ('success', 'Success'),
        ('error', 'Error'),
    ], required=True, string='Status')
    input_data = fields.Text(string='Input')
    execution_data = fields.Text(string='Execution')
    output_data = fields.Text(string='Output')
    error_message = fields.Text(string='Error Message')
    http_method = fields.Char(string='HTTP Method')
    http_status = fields.Integer(string='HTTP Status')
    model_name = fields.Char(string='Model')
    method = fields.Char(string='Method')
    execution_date = fields.Datetime(
        string='Execution Date',
        default=fields.Datetime.now,
        required=True,
    )
    duration = fields.Float(string='Duration (s)')

    @api.autovacuum
    def _gc_execution_logs(self):
        days = int(self.env['ir.config_parameter'].sudo().get_param(
            'bitconn_webhook_execution_log_retention_days', '15'))
        cutoff = fields.Datetime.now() - timedelta(days=days)
        records = self.search([('execution_date', '<', cutoff)])
        if records:
            _logger.info(
                'Purging %d execution logs older than %d days (cutoff: %s)',
                len(records), days, cutoff,
            )
            records.unlink()
