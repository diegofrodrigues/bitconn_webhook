from odoo import api, fields, models, _
from odoo.tools import get_lang
from odoo.tools.misc import get_diff
from odoo.http import request
import pytz
import babel


# -----------------------------------------------------------
# Histórico para campos de código em ir.actions.server
# (bitconn_code e bitconn_python_payload_code)
# -----------------------------------------------------------
class BitconnCodeHistory(models.Model):
    _name = 'bitconn.code.history'
    _description = 'Bitconn Code History (Server Actions)'
    _order = 'create_date desc, id desc'
    _rec_name = 'display_name'
    _max_entries_per_action = 100

    action_id = fields.Many2one('ir.actions.server', required=True, ondelete='cascade')
    code_type = fields.Selection([
        ('bitconn_code', 'Bitconn Code'),
        ('python_payload', 'Python Payload'),
    ], required=True, default='bitconn_code')
    code = fields.Text()

    def _compute_display_name(self):
        self.display_name = False
        for rec in self.filtered('create_date'):
            locale = get_lang(self.env).code
            tzinfo = pytz.timezone(self.env.user.tz) if self.env.user.tz else pytz.utc
            dt = rec.create_date.replace(microsecond=0)
            dt = pytz.utc.localize(dt, is_dst=False)
            dt = dt.astimezone(tzinfo) if tzinfo else dt
            date_label = babel.dates.format_datetime(dt, tzinfo=tzinfo, locale=locale)
            author = rec.create_uid.name
            rec.display_name = _("%(date_label)s - %(author)s", date_label=date_label, author=author)

    @api.autovacuum
    def _gc_histories(self):
        result = self._read_group(
            domain=[], groupby=["action_id"],
            aggregates=["id:recordset"],
            having=[("__count", ">", self._max_entries_per_action)],
        )
        to_clean = self
        for _action_id, history_ids in result:
            to_clean |= history_ids.sorted()[self._max_entries_per_action:]
        to_clean.unlink()


class BitconnCodeHistoryWizard(models.TransientModel):
    _name = 'bitconn.code.history.wizard'
    _description = "Bitconn Code History Wizard"

    @api.model
    def _default_revision(self):
        action_id = self.env['ir.actions.server'].browse(
            self.env.context.get('default_action_id', False)
        )
        code_type = self.env.context.get('default_code_type', 'bitconn_code')
        return self.env['bitconn.code.history'].search([
            ('action_id', '=', action_id.id),
            ('code_type', '=', code_type),
        ], limit=1)

    action_id = fields.Many2one('ir.actions.server')
    code_type = fields.Selection([
        ('bitconn_code', 'Bitconn Code'),
        ('python_payload', 'Python Payload'),
    ], default='bitconn_code')
    current_code = fields.Text(compute='_compute_current_code', readonly=True)
    revision = fields.Many2one(
        "bitconn.code.history",
        domain="[('action_id', '=', action_id), ('code_type', '=', code_type)]",
        default=_default_revision,
        required=True,
    )
    code_diff = fields.Html(compute='_compute_code_diff', sanitize_tags=False)

    @api.depends('action_id', 'code_type')
    def _compute_current_code(self):
        for rec in self:
            if rec.action_id:
                if rec.code_type == 'bitconn_code':
                    rec.current_code = rec.action_id.bitconn_code or ''
                else:
                    rec.current_code = rec.action_id.bitconn_python_payload_code or ''
            else:
                rec.current_code = ''

    @api.depends('revision')
    def _compute_code_diff(self):
        for rec in self:
            rev_code = rec.revision.code if rec.revision else ''
            actual_code = rec.current_code or ''
            has_diff = actual_code != rev_code
            if has_diff:
                rec.code_diff = get_diff(
                    (rev_code, _('Revision Code')),
                    (actual_code, _('Actual Code')),
                    dark_color_scheme=request and request.cookies.get('color_scheme') == 'dark',
                )
            else:
                rec.code_diff = False

    def restore_revision(self):
        self.ensure_one()
        if self.code_type == 'bitconn_code':
            self.action_id.bitconn_code = self.revision.code
        else:
            self.action_id.bitconn_python_payload_code = self.revision.code
        return {'type': 'ir.actions.act_window_close'}


# -----------------------------------------------------------
# Histórico para python_code em bitconn.webhook
# -----------------------------------------------------------
class BitconnWebhookCodeHistory(models.Model):
    _name = 'bitconn.webhook.code.history'
    _description = 'Bitconn Webhook Python Code History'
    _order = 'create_date desc, id desc'
    _rec_name = 'display_name'
    _max_entries_per_webhook = 100

    webhook_id = fields.Many2one('bitconn.webhook', required=True, ondelete='cascade')
    code = fields.Text()

    def _compute_display_name(self):
        self.display_name = False
        for rec in self.filtered('create_date'):
            locale = get_lang(self.env).code
            tzinfo = pytz.timezone(self.env.user.tz) if self.env.user.tz else pytz.utc
            dt = rec.create_date.replace(microsecond=0)
            dt = pytz.utc.localize(dt, is_dst=False)
            dt = dt.astimezone(tzinfo) if tzinfo else dt
            date_label = babel.dates.format_datetime(dt, tzinfo=tzinfo, locale=locale)
            author = rec.create_uid.name
            rec.display_name = _("%(date_label)s - %(author)s", date_label=date_label, author=author)

    @api.autovacuum
    def _gc_histories(self):
        result = self._read_group(
            domain=[], groupby=["webhook_id"],
            aggregates=["id:recordset"],
            having=[("__count", ">", self._max_entries_per_webhook)],
        )
        to_clean = self
        for _webhook_id, history_ids in result:
            to_clean |= history_ids.sorted()[self._max_entries_per_webhook:]
        to_clean.unlink()


class BitconnWebhookCodeHistoryWizard(models.TransientModel):
    _name = 'bitconn.webhook.code.history.wizard'
    _description = "Bitconn Webhook Code History Wizard"

    @api.model
    def _default_revision(self):
        webhook_id = self.env['bitconn.webhook'].browse(
            self.env.context.get('default_webhook_id', False)
        )
        return self.env['bitconn.webhook.code.history'].search([
            ('webhook_id', '=', webhook_id.id),
        ], limit=1)

    webhook_id = fields.Many2one('bitconn.webhook')
    current_code = fields.Text(related='webhook_id.python_code', readonly=True)
    revision = fields.Many2one(
        "bitconn.webhook.code.history",
        domain="[('webhook_id', '=', webhook_id)]",
        default=_default_revision,
        required=True,
    )
    code_diff = fields.Html(compute='_compute_code_diff', sanitize_tags=False)

    @api.depends('revision')
    def _compute_code_diff(self):
        for rec in self:
            rev_code = rec.revision.code if rec.revision else ''
            actual_code = rec.webhook_id.python_code if rec.webhook_id else ''
            has_diff = actual_code != rev_code
            if has_diff:
                rec.code_diff = get_diff(
                    (rev_code, _('Revision Code')),
                    (actual_code, _('Actual Code')),
                    dark_color_scheme=request and request.cookies.get('color_scheme') == 'dark',
                )
            else:
                rec.code_diff = False

    def restore_revision(self):
        self.ensure_one()
        self.webhook_id.python_code = self.revision.code
        return {'type': 'ir.actions.act_window_close'}
