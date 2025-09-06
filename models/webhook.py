from odoo import api, fields, models, _
from odoo.exceptions import UserError
import uuid
import secrets
import json


class BitconnWebhook(models.Model):
    _name = 'bitconn.webhook'
    _description = 'Bitconn Webhook Config'
    _inherit = ['mail.thread', 'mail.activity.mixin']

    name = fields.Char(required=True, default=lambda self: _('Webhook'), tracking=True)
    user_id = fields.Many2one('res.users', string='User', required=True, help='User used to perform operations via webhook.', tracking=True)
    can_create = fields.Boolean(string='Can Create', default=True, tracking=True)
    can_write = fields.Boolean(string='Can Write', default=True, tracking=True)
    can_unlink = fields.Boolean(string='Can Unlink', default=False, help='Dangerous. Only enable if you really trust the caller.', tracking=True)
    allowed_model_ids = fields.Many2many('ir.model', string='Allowed Models', help='Restrict operations to these models. Leave empty to allow all models.', tracking=True)

    secret_key = fields.Char(string='Secret Key', readonly=True, copy=False)
    webhook_uuid = fields.Char(string='Webhook UUID', readonly=True, copy=False)
    webhook_url = fields.Char(string='Webhook URL', compute='_compute_webhook_url', compute_sudo=True)
    # Minimal outbound config (simple direct POST)
    outbound_enabled = fields.Boolean(string='Enable Outbound', default=False, tracking=True)
    outbound_url = fields.Char(string='Outbound URL', help='Destination URL to POST outbound payloads', tracking=True)
    outbound_headers = fields.Text(
        string='Outbound Headers (JSON)',
        help='Optional headers as JSON object, e.g. {"Authorization": "Bearer ..."}',
        default='{"Authorization": "Bearer YOUR_TOKEN"}'
    )
    outbound_test_body = fields.Text(
        string='Outbound Test Body (JSON)',
        help='Custom JSON body to send in a test call to the Outbound URL.',
        default=json.dumps({
            "model": "res.partner",
            "count": 1,
            "records": [
                {
                    "name": "Test Partner",
                    "email": "john.doe@example.com",
                    "phone": "+5511999999999"
                }
            ]
        }, indent=2)
    )
    outbound_test_result = fields.Text(
        string='Outbound Test Result',
        readonly=True,
        help='Stores the latest HTTP status and response body from a test send.'
    )

    def action_test_outbound(self):
        for rec in self:
            if not rec.outbound_enabled:
                raise UserError(_('Enable Outbound first.'))
            if not rec.outbound_url:
                raise UserError(_('Please set the Outbound URL.'))
            body = rec.outbound_test_body or ''
            # Prepare headers
            headers = {'Content-Type': 'application/json'}
            try:
                custom = json.loads(rec.outbound_headers or '{}')
                if isinstance(custom, dict):
                    headers.update({str(k): str(v) for k, v in custom.items()})
            except Exception:
                # keep defaults if parsing fails
                pass
            # Send request
            try:
                import requests
                resp = requests.post(rec.outbound_url, data=body, headers=headers, timeout=15)
                rec.outbound_test_result = f"Status: {resp.status_code}\nBody:\n{resp.text}"
                rec.message_post(body=_("Outbound test sent: status %s") % resp.status_code)
            except Exception as e:
                rec.outbound_test_result = f"Error: {e}"
                raise UserError(_('Outbound test failed: %s') % str(e))
        return True

    @api.model_create_multi
    def create(self, vals_list):
        recs = super().create(vals_list)
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url', 'http://localhost:8069')
        for rec in recs:
            if not rec.secret_key:
                rec.secret_key = secrets.token_urlsafe(32)
            if not rec.webhook_uuid:
                rec.webhook_uuid = str(uuid.uuid4())
            # compute field webhook_url will pick updated values
        return recs

    def action_regenerate_credentials(self):
        for rec in self:
            rec.secret_key = secrets.token_urlsafe(32)
            rec.webhook_uuid = str(uuid.uuid4())
            # Log masked credentials change
            try:
                rec.message_post(
                    body=(
                        f"Credentials regenerated:<br/>")
                        + (f"URL: …{(rec.webhook_url or '')[-4:]}<br/>" if rec.webhook_url else "")
                        + (f"Secret: ****{(rec.secret_key or '')[-4:]}" if rec.secret_key else "")
                )
            except Exception:
                pass

    def action_set_outbound_auth(self):
        """Fill outbound_headers with an Authorization: Bearer template using this webhook's secret.
        Users can edit it afterward if they prefer a different token.
        """
        for rec in self:
            token = rec.secret_key or 'YOUR_TOKEN'
            try:
                rec.outbound_headers = json.dumps({
                    'Authorization': f'Bearer {token}'
                }, indent=2, ensure_ascii=False)
            except Exception:
                rec.outbound_headers = f'{"{"}"Authorization": "Bearer {token}"{"}"}'
        return True

    @api.depends('webhook_uuid')
    def _compute_webhook_url(self):
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url', 'http://localhost:8069')
        for rec in self:
            rec.webhook_url = f"{base_url}/bitconn/webhook/{rec.webhook_uuid}" if rec.webhook_uuid else False

    # Helpers to validate incoming headers
    def _check_header(self, headers):
        self.ensure_one()
        # Prefer standard Authorization: Bearer <token>
        auth = headers.get('Authorization') or headers.get('authorization')
        incoming_token = None
        if auth and isinstance(auth, str) and auth.lower().startswith('bearer '):
            try:
                incoming_token = auth.split(' ', 1)[1].strip()
            except Exception:
                incoming_token = None
        # Fallback headers (no X- prefix required; accept X-Webhook-Key for backwards compatibility)
        if not incoming_token:
            incoming_token = headers.get('Webhook-Key') or headers.get('webhook_key') or headers.get('X-Webhook-Key')
        if not incoming_token:
            return False
        # Constant-time comparison
        try:
            from secrets import compare_digest
            return compare_digest(incoming_token, self.secret_key or '')
        except Exception:
            return incoming_token == (self.secret_key or '')

    def _can_access_model(self, model_name):
        self.ensure_one()
        if not self.allowed_model_ids:
            return True
        imodel = self.env['ir.model']
        return bool(self.allowed_model_ids.filtered(lambda m: m.model == model_name))

    # ORM execution helpers
    def _exec_create(self, model_name, values):
        self.ensure_one()
        if not self.can_create:
            return {'ok': False, 'error': 'permission_denied', 'reason': 'create_not_allowed'}
        if not self._can_access_model(model_name):
            return {'ok': False, 'error': 'permission_denied', 'reason': 'model_not_allowed'}
        # sudo as configured user
        with self.env.cr.savepoint():
            envu = self.env(user=self.user_id.id)
            rec = envu[model_name].create(values)
            return {'ok': True, 'id': rec.id}

    def _exec_write(self, model_name, domain, values):
        self.ensure_one()
        if not self.can_write:
            return {'ok': False, 'error': 'permission_denied', 'reason': 'write_not_allowed'}
        if not self._can_access_model(model_name):
            return {'ok': False, 'error': 'permission_denied', 'reason': 'model_not_allowed'}
        with self.env.cr.savepoint():
            envu = self.env(user=self.user_id.id)
            recs = envu[model_name].search(domain)
            if not recs:
                return {'ok': False, 'error': 'not_found'}
            recs.write(values)
            return {'ok': True, 'ids': recs.ids}

    def _exec_unlink(self, model_name, domain):
        self.ensure_one()
        if not self.can_unlink:
            return {'ok': False, 'error': 'permission_denied', 'reason': 'unlink_not_allowed'}
        if not self._can_access_model(model_name):
            return {'ok': False, 'error': 'permission_denied', 'reason': 'model_not_allowed'}
        with self.env.cr.savepoint():
            envu = self.env(user=self.user_id.id)
            recs = envu[model_name].search(domain)
            if not recs:
                return {'ok': False, 'error': 'not_found'}
            recs.unlink()
            return {'ok': True, 'ids': recs.ids}

    def _exec_search(self, model_name, domain, fields=None, limit=80, offset=0, order=None):
        """Search records by domain. If 'fields' provided, return records (like search_read),
        otherwise return only ids for a lean response.
        """
        self.ensure_one()
        if not self._can_access_model(model_name):
            return {'ok': False, 'error': 'permission_denied', 'reason': 'model_not_allowed'}
        with self.env.cr.savepoint():
            envu = self.env(user=self.user_id.id)
            recs = envu[model_name].search(domain or [], limit=limit or None, offset=offset or 0, order=order)
            if fields:
                data = recs.read(fields)
                return {'ok': True, 'count': len(recs), 'records': data}
            return {'ok': True, 'count': len(recs), 'ids': recs.ids}

    def _exec_read(self, model_name, ids, fields=None):
        self.ensure_one()
        if not self._can_access_model(model_name):
            return {'ok': False, 'error': 'permission_denied', 'reason': 'model_not_allowed'}
        with self.env.cr.savepoint():
            envu = self.env(user=self.user_id.id)
            recs = envu[model_name].browse(ids)
            recs = recs.exists()
            if not recs:
                return {'ok': False, 'error': 'not_found'}
            data = recs.read(fields) if fields else recs.read()
            return {'ok': True, 'records': data}

    def _get_model_schema(self, model_name, method='create'):
        """Return field metadata and required info for a model for integration scaffolding."""
        self.ensure_one()
        if not self._can_access_model(model_name):
            return {'ok': False, 'error': 'permission_denied', 'reason': 'model_not_allowed'}
        method = (method or 'create').lower()
        with self.env.cr.savepoint():
            envu = self.env(user=self.user_id.id)
            Model = envu[model_name]
            defs = Model.fields_get()
            # slim field meta
            fields_meta = {}
            for name, d in defs.items():
                fields_meta[name] = {
                    'string': d.get('string'),
                    'type': d.get('type'),
                    'required': bool(d.get('required')),
                    'readonly': bool(d.get('readonly')),
                    'selection': d.get('selection') if d.get('type') == 'selection' else None,
                    'relation': d.get('relation') if d.get('type') in ('many2one', 'one2many', 'many2many') else None,
                }
            # required fields mainly matter for create; for write, it's contextual
            if method == 'create':
                required_fields = [n for n, d in fields_meta.items() if d['required'] and not d['readonly']]
            else:
                required_fields = []
            # defaults
            try:
                defaults = Model.default_get(list(defs.keys()))
            except Exception:
                defaults = {}
            # access rights for op
            access = {
                'can_create': bool(self.can_create and Model.check_access_rights('create', raise_exception=False)),
                'can_write': bool(self.can_write and Model.check_access_rights('write', raise_exception=False)),
                'can_unlink': bool(self.can_unlink and Model.check_access_rights('unlink', raise_exception=False)),
                'can_read': bool(Model.check_access_rights('read', raise_exception=False)),
            }
            return {
                'ok': True,
                'model': model_name,
                'method': method,
                'required_fields': required_fields,
                'fields': fields_meta,
                'defaults': defaults,
                'access': access,
            }

    def _get_required_for_create(self, model_name, values=None, source='model'):
        """Return only what the caller must provide to create successfully.
        - must_provide: required fields not satisfied by defaults nor given values.
        """
        self.ensure_one()
        if not self._can_access_model(model_name):
            return {'ok': False, 'error': 'permission_denied', 'reason': 'model_not_allowed'}
        values = values or {}
        with self.env.cr.savepoint():
            envu = self.env(user=self.user_id.id)
            Model = envu[model_name]
            defs = Model.fields_get()
            source = (source or 'model').lower()
            # compute base required list
            if source == 'view':
                # Parse the primary form view and collect fields with required flags
                try:
                    view_info = Model.fields_view_get(view_type='form')
                    arch = view_info.get('arch') or ''
                    required_fields = []
                    if arch:
                        from lxml import etree as ET
                        import json as _json
                        root = ET.fromstring(arch.encode('utf-8'))
                        seen = set()
                        for node in root.xpath('.//field[@name]'):
                            fname = node.get('name')
                            if not fname or fname in seen:
                                continue
                            is_req = False
                            req_attr = node.get('required')
                            if req_attr in ('1', 'true', 'True'):
                                is_req = True
                            mods = node.get('modifiers')
                            if not is_req and mods:
                                try:
                                    mods_obj = _json.loads(mods)
                                    # modifiers.required can be a boolean or an expression; treat truthy as potentially required
                                    if bool(mods_obj.get('required')):
                                        is_req = True
                                except Exception:
                                    pass
                            if is_req:
                                seen.add(fname)
                                required_fields.append(fname)
                except Exception:
                    # fallback to model-level if view parsing fails
                    required_fields = [name for name, d in defs.items() if d.get('required') and not d.get('readonly')]
            else:
                required_fields = [name for name, d in defs.items() if d.get('required') and not d.get('readonly')]

            # Generic refinement: exclude computed/related fields since the server computes them
            if required_fields:
                required_fields = [n for n in required_fields if not defs.get(n, {}).get('compute') and not defs.get(n, {}).get('related')]

            # Exclude fields that are computed/related: caller doesn't need to provide them
            if required_fields:
                required_fields = [n for n in required_fields if not defs.get(n, {}).get('compute') and not defs.get(n, {}).get('related')]
            # defaults and merge
            try:
                defaults = Model.default_get(list(defs.keys()))
            except Exception:
                defaults = {}
            merged = dict(defaults)
            merged.update(values)

            def is_value_missing(name, val, fdef):
                ftype = fdef.get('type')
                if ftype in ('char', 'text', 'html', 'binary'):
                    return not bool(val)
                if ftype in ('integer', 'float', 'monetary'):  # 0 is acceptable
                    return val is None
                if ftype in ('boolean',):
                    # rarely required, but treat None as missing
                    return val is None
                if ftype in ('many2one',):
                    return not bool(val)
                if ftype in ('many2many', 'one2many'):
                    return not bool(val) or len(val) == 0
                if ftype in ('date', 'datetime'):  # empty/False missing
                    return not bool(val)
                return not bool(val)

            missing = []
            for name in required_fields:
                fdef = defs[name]
                dv = defaults.get(name)
                vv = merged.get(name)
                if not is_value_missing(name, vv, fdef):
                    continue
                missing.append(name)

            return {
                'ok': True,
                'model': model_name,
                'source': source,
                'must_provide': missing,
                'must_provide_detailed': [
                    {
                        'field': fname,
                        'label': defs.get(fname, {}).get('string')
                    } for fname in missing
                ],
            }

    # Outbound: direct send helper using same read/search logic to build payload
    def send_outbound(self, model_name, ids=None, domain=None, fields=None, extra=None):
        """Send an outbound POST to outbound_url with a payload built from model/ids/domain.
        - Reads with the configured user (self.user_id) respecting ACLs/rules.
        - If fields provided: includes 'records' read(fields); else includes only 'ids'.
        - 'extra' (dict) is merged into the root payload for custom additions.
        Returns a dict {ok, status, response} or {ok: False, error}.
        """
        self.ensure_one()
        if not self.outbound_enabled:
            return {'ok': False, 'error': 'outbound_disabled'}
        if not self.outbound_url:
            return {'ok': False, 'error': 'missing_outbound_url'}
        if not model_name:
            return {'ok': False, 'error': 'missing_model'}
        try:
            envu = self.env(user=self.user_id.id)
            Model = envu[model_name]
        except Exception:
            return {'ok': False, 'error': 'invalid_model'}

        with self.env.cr.savepoint():
            recs = Model.browse(ids) if ids else Model.search(domain or [])
            recs = recs.exists()
            payload = {
                'model': model_name,
                'count': len(recs),
            }
            if fields:
                payload['records'] = recs.read(fields)
            else:
                payload['ids'] = recs.ids
            if extra and isinstance(extra, dict):
                payload.update(extra)

        # prepare headers
        headers = {'Content-Type': 'application/json'}
        if self.outbound_headers:
            import json as _json
            try:
                hdrs = _json.loads(self.outbound_headers)
                if isinstance(hdrs, dict):
                    headers.update({str(k): str(v) for k, v in hdrs.items()})
            except Exception:
                pass

        # send
        import json as _json
        body = _json.dumps(payload, separators=(',', ':'))
        try:
            import requests
            resp = requests.post(self.outbound_url, data=body, headers=headers, timeout=15)
            ok = 200 <= resp.status_code < 300
            return {'ok': ok, 'status': resp.status_code, 'response': resp.text}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # Masked tracking for sensitive fields
    def write(self, vals):
        # Capture originals for fields of interest
        track_fields = {'webhook_url', 'secret_key', 'outbound_headers'}
        originals = {
            rec.id: {
                'webhook_url': rec.webhook_url,
                'secret_key': rec.secret_key,
                'outbound_headers': rec.outbound_headers,
            }
            for rec in self
        }
        res = super().write(vals)
        to_log = track_fields.intersection(vals.keys())
        if to_log:
            for rec in self:
                try:
                    orig = originals.get(rec.id, {})
                    lines = []
                    if 'webhook_url' in to_log and rec.webhook_url != orig.get('webhook_url'):
                        lines.append(f"Webhook URL: …{(rec.webhook_url or '')[-4:]}")
                    if 'secret_key' in to_log and rec.secret_key != orig.get('secret_key'):
                        lines.append(f"Secret Key: ****{(rec.secret_key or '')[-4:]}")
                    if 'outbound_headers' in to_log and rec.outbound_headers != orig.get('outbound_headers'):
                        def summarize(hdr_txt):
                            try:
                                data = json.loads(hdr_txt or '{}')
                                keys = list(data.keys())
                                auth = data.get('Authorization')
                                if isinstance(auth, str) and ' ' in auth:
                                    scheme, token = auth.split(' ', 1)
                                    masked = scheme + ' ' + ('****' + token[-4:] if token else '****')
                                elif isinstance(auth, str):
                                    masked = '****' + auth[-4:]
                                else:
                                    masked = None
                                return keys, masked
                            except Exception:
                                return [], None
                        keys, masked_auth = summarize(rec.outbound_headers)
                        desc = f"Outbound Headers: keys={keys}"
                        if masked_auth:
                            desc += f", Authorization={masked_auth}"
                        lines.append(desc)
                    if lines:
                        rec.message_post(body="<br/>".join(lines))
                except Exception:
                    continue
        return res
