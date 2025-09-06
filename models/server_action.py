from odoo import api, fields, models, _
import json


class IrActionsServer(models.Model):
    _inherit = 'ir.actions.server'

    state = fields.Selection(
        selection_add=[('bitconn_webhook', 'Webhook')],
        ondelete={'bitconn_webhook': 'set default'}
    )
    bitconn_webhook_id = fields.Many2one('bitconn.webhook', string='Webhook', help='Webhook configuration to use for outbound send')
    bitconn_field_ids = fields.Many2many(
        'ir.model.fields', string='Fields to Send',
        domain="[('model_id','=',model_id),('store','=',True)]",
        help='If empty, only IDs are sent. If set, selected fields are included in records.'
    )
    bitconn_extra_json = fields.Text(string='Extra JSON', help='Optional JSON object merged into payload root')
    bitconn_preview_payload = fields.Text(
        string='Preview JSON',
        help='Editable preview of the JSON body that will be sent. You can modify it manually or regenerate from selected fields.',
    )

    @api.onchange('bitconn_field_ids', 'model_id')
    def _onchange_bitconn_preview(self):
        for rec in self:
            # Only auto-fill if empty to avoid overwriting manual edits
            if not rec.bitconn_preview_payload:
                rec.bitconn_preview_payload = rec._generate_bitconn_preview()

    def action_generate_bitconn_preview(self):
        for rec in self:
            rec.bitconn_preview_payload = rec._generate_bitconn_preview()
        return True

    def _generate_bitconn_preview(self):
        self.ensure_one()
        model_name = self.model_id.model or 'res.partner'
        field_names = self.bitconn_field_ids.mapped('name') if self.bitconn_field_ids else []
        # Build a sample payload matching send_outbound behavior
        payload = {
            'model': model_name,
        }
        if field_names:
            payload['count'] = 1
            payload['records'] = [self._sample_record_for_model(model_name, field_names)]
        else:
            payload['count'] = 0
            payload['ids'] = []
        # Merge Extra JSON keys if any (just as a hint for preview)
        if self.bitconn_extra_json:
            try:
                extra = json.loads(self.bitconn_extra_json)
                if isinstance(extra, dict):
                    payload.update({k: v for k, v in extra.items() if k not in ('records', 'ids')})
            except Exception:
                pass
        try:
            return json.dumps(payload, indent=2, ensure_ascii=False)
        except Exception:
            return str(payload)

    def _sample_record_for_model(self, model_name, field_names):
        envu = self.env
        try:
            defs = envu[model_name].fields_get(field_names)
        except Exception:
            defs = {}
        def sample_for(fdef):
            ftype = (fdef or {}).get('type')
            if ftype in ('char', 'text', 'html'): return "string"
            if ftype in ('integer',): return 0
            if ftype in ('float','monetary'): return 0.0
            if ftype in ('boolean',): return True
            if ftype in ('date',): return '2025-01-01'
            if ftype in ('datetime',): return '2025-01-01T00:00:00Z'
            if ftype in ('many2one',): return 1
            if ftype in ('many2many','one2many'): return [1, 2]
            if ftype in ('selection',):
                sel = (fdef or {}).get('selection') or []
                return (sel[0][0] if sel and isinstance(sel[0], (list, tuple)) else 'value')
            return None
        rec = {}
        for name in field_names:
            rec[name] = sample_for(defs.get(name))
        return rec

    def _run_action_bitconn_webhook(self, eval_context=None):
        self.ensure_one()
        if not self.bitconn_webhook_id or not self.bitconn_webhook_id.outbound_enabled:
            return False
        model_name = self.model_id.model
        # Determine target records
        ctx = self._context or {}
        active_ids = ctx.get('active_ids') or []
        recs = self.env[model_name].browse(active_ids).exists()
        fields_list = self.bitconn_field_ids.mapped('name') if self.bitconn_field_ids else None
        extra = None
        if self.bitconn_extra_json:
            try:
                parsed = json.loads(self.bitconn_extra_json)
                if isinstance(parsed, dict):
                    extra = parsed
            except Exception:
                extra = None
        self.bitconn_webhook_id.send_outbound(model_name, ids=recs.ids, fields=fields_list, extra=extra)
        return False
