from odoo import api, fields, models, _
from odoo.exceptions import UserError
import uuid
import secrets
import json
import logging
import builtins

_logger = logging.getLogger(__name__)


class BitconnWebhook(models.Model):
    _name = 'bitconn.webhook'
    _description = 'Bitconn Webhook Config'
    _inherit = ['mail.thread', 'mail.activity.mixin']

    name = fields.Char(required=True, default=lambda self: _('Webhook'), tracking=True)
    user_id = fields.Many2one('res.users', string='User', required=True, help='User used to perform operations via webhook.', tracking=True)
    can_create = fields.Boolean(string='Can Create', default=True, tracking=True)
    can_write = fields.Boolean(string='Can Write', default=True, tracking=True)
    can_unlink = fields.Boolean(string='Can Unlink', default=False, help='Dangerous. Only enable if you really trust the caller.', tracking=True)
    can_code = fields.Boolean(string='Can Execute Code', default=False, help='Allow execution of custom Python code. Only enable if you really trust the caller.', tracking=True)
    # (flag removed) Note: executed code will always run with module globals
    # so imports and normal builtins are available.
    allowed_model_ids = fields.Many2many('ir.model', string='Allowed Models', help='Restrict operations to these models. Leave empty to allow all models.', tracking=True)

    # Inbound Authentication Configuration
    inbound_auth_type = fields.Selection([
        ('none', 'None - Public Access'),
        ('header', 'Header Authentication (Bearer/API Key)')
    ], string='Inbound Authentication', default='header', required=True, 
       help='Authentication type for incoming webhooks:\n'
            '• None: Public access without authentication (use with caution!)\n'
            '• Header: Requires Bearer token or API key in request headers',
       tracking=True)

    # Sensitive fields: avoid standard tracking to prevent exposing full values; custom masked logging in write()
    secret_key = fields.Char(string='Secret Key', readonly=True, copy=False)
    webhook_uuid = fields.Char(string='Webhook UUID', readonly=True, copy=False)
    # Computed URL (not stored to avoid DB column); we log masked changes when uuid changes
    webhook_url = fields.Char(string='Webhook URL', compute='_compute_webhook_url', compute_sudo=True)
    # Minimal outbound config (simple direct POST)
    outbound_enabled = fields.Boolean(string='Enable Outbound', default=False, tracking=True)
    outbound_method = fields.Selection([
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('PATCH', 'PATCH'),
        ('DELETE', 'DELETE'),
    ], string='HTTP Method', default='POST', required=True, tracking=True,
       help='HTTP method to use for outbound requests')
    outbound_url = fields.Char(
        string='Outbound URL', 
        help='Destination URL for outbound requests.\n\n'
             'Supports dynamic variables from record fields:\n'
             '• {{field_name}} - Simple fields (e.g., {{name}}, {{id}}, {{email}})\n'
             '• {{relation.field}} - Related fields (e.g., {{partner_id.name}}, {{user_id.email}})\n\n'
             'Examples:\n'
             '• https://api.example.com/orders/{{name}}\n'
             '• https://api.example.com/partners/{{partner_id.id}}/notify\n'
             '• https://webhook.site/{{id}}?ref={{name}}',
        tracking=True
    )
    outbound_headers = fields.Text(
        string='Outbound Headers (JSON)',
        help='Optional headers as JSON object, e.g. {"Authorization": "Bearer ..."}',
        default='{"Authorization": "Bearer YOUR_TOKEN"}'
    )
    outbound_test_body = fields.Text(
        string='Outbound Test Body (JSON)',
        help='Custom JSON body to send in a test call to the Outbound URL.\n\n'
             'If your URL contains variables like {{name}}, the test will try to extract\n'
             'values from the first record in this test data.',
        default=json.dumps({
            "model": "res.partner",
            "count": 1,
            "records": [
                {
                    "id": 123,
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
    enable_test_outbound = fields.Boolean(
        string='Enable Test Outbound',
        default=False,
        help='Enable test mode to test your outbound webhook configuration'
    )
    # Server Actions linked to this webhook (allow inline management from Outbound tab)
    server_action_ids = fields.One2many(
        'ir.actions.server',
        'bitconn_webhook_id',
        string='Server Actions',
        help='Server Actions configured to send via this webhook (Action Type: Bitconn Webhook)'
    )
    # Automation Rules linked to this webhook (Automated Actions)
    automation_ids = fields.One2many(
        'base.automation',
        'bitconn_webhook_id',
        string='Automation Rules',
        help='Automation rules that will trigger using this webhook',
        context={'active_test': False}
    )
    # Help examples (JSON with common payloads)
    examples_help = fields.Text(
        string='Examples Help (JSON)',
        compute='_compute_examples_help',
        readonly=True,
        help='JSON com exemplos de payload: create, write, unlink, search_advanced.'
    )
    example_create = fields.Text(string='Create Example', compute='_compute_examples_blocks', readonly=True)
    example_write = fields.Text(string='Write Example', compute='_compute_examples_blocks', readonly=True)
    example_unlink = fields.Text(string='Unlink Example', compute='_compute_examples_blocks', readonly=True)
    example_search_advanced = fields.Text(string='Search Advanced Example', compute='_compute_examples_blocks', readonly=True)
    
    # Custom Python Code Execution
    inbound_allowed_methods = fields.Selection([
        ('POST', 'POST only'),
        ('ALL', 'All methods (GET, POST, PUT, PATCH, DELETE)'),
        ('CUSTOM', 'Custom selection')
    ], string='Allowed HTTP Methods', default='POST', 
       help='Which HTTP methods are allowed for this webhook', tracking=True)
    
    inbound_methods_get = fields.Boolean(string='GET', default=False)
    inbound_methods_post = fields.Boolean(string='POST', default=True)
    inbound_methods_put = fields.Boolean(string='PUT', default=False)
    inbound_methods_patch = fields.Boolean(string='PATCH', default=False)
    inbound_methods_delete = fields.Boolean(string='DELETE', default=False)
    
    python_code = fields.Text(
        string='Python Code',
        help='Custom Python code to execute when webhook is received. See Help tab for complete documentation.',
        default="""# ==========================================
# request - Request object
# ==========================================
# request['body'] - Raw request body as string. Use for signature validation, XML parsing, 
#                   or when you need the original text.
# request['json'] - Parsed JSON body as Python dict. Most convenient for accessing request data.
# request['headers'] - Request headers as dict. Access with request['headers'].get('Content-Type')
# request['method'] - HTTP method (GET, POST, PUT, PATCH, DELETE). Use to route different logic 
#                     based on method.
#
# Available variables: request, env, user_id, json
# Set result variable to return response
# See Help tab for complete documentation
#
# ==========================================
# Example: Create a partner from webhook data
# ==========================================
# data = request['json']
# partner = env['res.partner'].create({
#     'name': data.get('name', 'New Contact'),
#     'email': data.get('email'),
#     'phone': data.get('phone')
# })
# result = {
#     'ok': True,
#     'partner_id': partner.id,
#     'partner_name': partner.name
# }

result = {'ok': True, 'message': 'Code executed successfully'}"""
    )
    enable_test = fields.Boolean(
        string='Enable Test',
        default=False,
        help='Enable test mode to test your Python code with sample data'
    )
    pin_request = fields.Boolean(
        string='Pin Request for Testing',
        default=False,
        help='When enabled, uses the Sample Request as test input instead of Test Input field.'
    )
    test_input = fields.Text(
        string='Test Input (Request Body)',
        help='Sample request body to test the Python code. This simulates the raw request payload.',
        default='{"test": "data"}'
    )
    test_output = fields.Text(
        string='Test Output',
        readonly=True,
        help='Output from the last test code execution (value of result variable).'
    )
    sample_request_payload = fields.Text(
        string='Sample Request',
        readonly=True,
        help='Latest request payload received by this webhook. Use this to pin/save an example for testing.'
    )

    def action_create_server_action(self):
        """Open a modal to create a new `base.automation` pre-filled for this webhook.
        Uses the Bitconn primary view so that server actions created inside it
        automatically default to state='bitconn_webhook'.
        The user can still choose trigger, filters, etc.
        """
        self.ensure_one()
        view = self.env.ref(
            'bitconn_webhook.view_base_automation_form_bitconn',
            raise_if_not_found=False,
        ) or self.env.ref('base_automation.view_base_automation_form', raise_if_not_found=False)
        action = {
            'type': 'ir.actions.act_window',
            'name': 'Criar Automation Rule',
            'res_model': 'base.automation',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_bitconn_webhook_id': self.id,
            },
        }
        if view:
            action['views'] = [(view.id, 'form')]
            action['view_id'] = view.id
        return action
    
    # Real-time request monitoring
    last_request_input = fields.Text(
        string='Last Request Input',
        readonly=True,
        help='Raw input from the last webhook request received (before processing)'
    )
    last_request_date = fields.Datetime(
        string='Last Request Date',
        readonly=True,
        help='Timestamp of the last request'
    )
    last_request_output = fields.Text(
        string='Last Request Output',
        readonly=True,
        help='Output from the last request processing'
    )

    # -------- Utilities: extract fields with dot-notation --------
    def _extract_fields(self, recs, field_names):
        """Return list of dicts for recs with given field_names, supporting dot notation.
        - Simple fields are read via recs.read(simple)
        - Dotted fields (e.g., partner_id.name, order_line.product_id.name) are resolved per record
          and flattened: m2o -> single value (id unless a final scalar is requested),
          o2m/m2m -> list of values.
        """
        simple, dotted = [], []
        for f in (field_names or []):
            (dotted.append(f) if '.' in f else simple.append(f))

        base_rows = recs.read(simple) if simple else [{'id': r.id} for r in recs]

        def _path_values(start_rec, path_str):
            parts = path_str.split('.')
            current = [start_rec]

            for seg in parts:
                next_items = []
                for item in current:
                    if not item:
                        continue
                    if isinstance(item, models.BaseModel):
                        # Access field; for multi-record item, Odoo returns aggregated; iterate explicitly
                        try:
                            # iterate each record if multiple
                            items = [item] if len(item) <= 1 else [x for x in item]
                        except Exception:
                            items = [item]
                        for it in items:
                            try:
                                val = it[seg]
                            except Exception:
                                val = False
                            if isinstance(val, models.BaseModel):
                                # relation -> keep recordsets/records to traverse next
                                if len(val) <= 1:
                                    next_items.append(val)
                                else:
                                    next_items.extend([x for x in val])
                            else:
                                # scalar -> just carry value
                                next_items.append(val)
                    else:
                        # scalar encountered before end of path
                        next_items.append(False)
                current = next_items

            # Normalize final values
            results = []
            for v in current:
                if isinstance(v, models.BaseModel):
                    if len(v) == 1:
                        # if final is a record, return its id
                        results.append(v.id)
                    elif len(v) > 1:
                        results.extend([x.id for x in v])
                    else:
                        results.append(False)
                else:
                    results.append(v)
            if not results:
                return False
            return results if len(results) != 1 else results[0]

        if dotted:
            for idx, rec in enumerate(recs):
                row = base_rows[idx]
                for f in dotted:
                    row[f] = _path_values(rec, f)
        return base_rows

    def action_test_outbound(self):
        for rec in self:
            if not rec.outbound_enabled:
                raise UserError(_('Enable Outbound first.'))
            if not rec.outbound_url:
                raise UserError(_('Please set the Outbound URL.'))
            
            body = rec.outbound_test_body or ''
            
            # Try to extract model and record info from test body for URL template processing
            final_url = rec.outbound_url
            try:
                test_data = json.loads(body)
                model = test_data.get('model')
                
                # If URL has variables and we have a model in test data, try to use first record from test
                if '{{' in rec.outbound_url and model:
                    # Check if there are records in test data
                    records = test_data.get('records', [])
                    if records and isinstance(records, list) and len(records) > 0:
                        first_record = records[0]
                        # Create a temporary mock record-like object
                        class MockRecord:
                            def __init__(self, data):
                                self._data = data
                            def __getitem__(self, key):
                                return self._data.get(key, '')
                        
                        mock_rec = MockRecord(first_record)
                        # Try to process URL (will fail gracefully for complex paths)
                        try:
                            import re
                            pattern = r'\{\{([^}]+)\}\}'
                            matches = re.findall(pattern, rec.outbound_url)
                            processed_url = rec.outbound_url
                            for match in matches:
                                field_path = match.strip()
                                placeholder = f'{{{{{field_path}}}}}'
                                # Only support simple fields in test mode
                                if '.' not in field_path:
                                    value = first_record.get(field_path, '')
                                    from urllib.parse import quote
                                    value_encoded = quote(str(value), safe='')
                                    processed_url = processed_url.replace(placeholder, value_encoded)
                                else:
                                    # For nested fields in test, just use empty
                                    processed_url = processed_url.replace(placeholder, 'test')
                            final_url = processed_url
                        except Exception as e:
                            _logger.warning(f"Could not process URL template in test: {e}")
            except Exception:
                pass
            
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
                # Encode data as UTF-8 bytes to handle accents correctly
                body_bytes = body.encode('utf-8')
                
                # Use the configured HTTP method
                method = (rec.outbound_method or 'POST').upper()
                if method == 'GET':
                    resp = requests.get(final_url, headers=headers, timeout=15)
                elif method == 'PUT':
                    resp = requests.put(final_url, data=body_bytes, headers=headers, timeout=15)
                elif method == 'PATCH':
                    resp = requests.patch(final_url, data=body_bytes, headers=headers, timeout=15)
                elif method == 'DELETE':
                    resp = requests.delete(final_url, headers=headers, timeout=15)
                else:  # POST (default)
                    resp = requests.post(final_url, data=body_bytes, headers=headers, timeout=15)
                
                # Pretty print JSON when possible
                formatted = resp.text or ''
                try:
                    ctype = (resp.headers.get('Content-Type') or '').lower()
                except Exception:
                    ctype = ''
                if 'application/json' in ctype or (formatted.strip().startswith('{') or formatted.strip().startswith('[')):
                    try:
                        parsed = resp.json()
                    except Exception:
                        try:
                            parsed = json.loads(formatted)
                        except Exception:
                            parsed = None
                    if parsed is not None:
                        try:
                            formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
                        except Exception:
                            pass
                rec.outbound_test_result = f"URL: {final_url}\nStatus: {resp.status_code}\nBody:\n{formatted}"
            except Exception as e:
                rec.outbound_test_result = f"URL: {final_url}\nError: {e}"
                raise UserError(_('Outbound test failed: %s') % str(e))
        return True

    def action_clear_outbound_test_result(self):
        """Clear the outbound test result field"""
        self.ensure_one()
        self.write({'outbound_test_result': False})
        return True

    @api.model_create_multi
    def create(self, vals_list):
        recs = super().create(vals_list)
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url', 'http://localhost:8069')
        for rec in recs:
            # single write so custom masked logging captures both secret & url
            updates = {}
            if not rec.secret_key:
                updates['secret_key'] = secrets.token_urlsafe(32)
            if not rec.webhook_uuid:
                updates['webhook_uuid'] = str(uuid.uuid4())
            if updates:
                rec.write(updates)
        return recs

    def action_regenerate_credentials(self):
        # Update only; rely on field tracking to log changes (avoid duplicate custom messages)
        for rec in self:
            rec.write({
                'secret_key': secrets.token_urlsafe(32),
                'webhook_uuid': str(uuid.uuid4()),
            })
        return True

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

    @api.onchange('can_code')
    def _onchange_can_code(self):
        """When code execution is enabled, disable CRUD operations and vice versa"""
        if self.can_code:
            # If code is enabled, disable CRUD operations
            self.can_create = False
            self.can_write = False
            self.can_unlink = False

    @api.onchange('can_create', 'can_write', 'can_unlink')
    def _onchange_crud_operations(self):
        """When any CRUD operation is enabled, disable code execution"""
        if self.can_create or self.can_write or self.can_unlink:
            # If any CRUD operation is enabled, disable code execution
            self.can_code = False

    # Helpers to validate incoming headers
    def _check_header(self, headers):
        """Validate authentication based on configured inbound_auth_type.
        Returns True if authentication is valid or not required.
        """
        self.ensure_one()
        
        # If authentication is disabled (none), always allow access
        if self.inbound_auth_type == 'none':
            return True
        
        # Header authentication (original behavior)
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
    
    def _is_method_allowed(self, method):
        """Check if HTTP method is allowed for this webhook"""
        self.ensure_one()
        method = (method or 'POST').upper()
        
        if self.inbound_allowed_methods == 'POST':
            return method == 'POST'
        elif self.inbound_allowed_methods == 'ALL':
            return method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')
        elif self.inbound_allowed_methods == 'CUSTOM':
            method_fields = {
                'GET': self.inbound_methods_get,
                'POST': self.inbound_methods_post,
                'PUT': self.inbound_methods_put,
                'PATCH': self.inbound_methods_patch,
                'DELETE': self.inbound_methods_delete,
            }
            return method_fields.get(method, False)
        return False

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
                try:
                    data = self._extract_fields_advanced(recs, fields)
                except Exception:
                    # fallback para versão simples se algo falhar
                    data = self._extract_fields(recs, [f for f in fields if isinstance(f, str)])
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
            if fields:
                try:
                    data = self._extract_fields_advanced(recs, fields)
                except Exception:
                    data = self._extract_fields(recs, [f for f in fields if isinstance(f, str)])
            else:
                data = recs.read()
            return {'ok': True, 'records': data}

    # ---------------- Advanced field extraction (supports dict spec) -----------------
    def _extract_fields_advanced(self, recs, fields_spec):
        """Extração avançada com suporte a aninhamento de dicts dentro de relações.
        Agora aceita specs como:
          ["id", {"order_line": ["id", "name", {"product_id": ["id","default_code","name"]}]}]
        para incluir campos de product_id dentro de cada linha.
        Regras permanecem:
          - many2one -> objeto
          - one2many/many2many -> lista de objetos
          - ordem preservada em todos os níveis
        """
        spec = fields_spec or []

        # Helper recursivo para coletar strings dentro de uma sub-especificação (usado só quando entramos na relação)
        def collect_all_strings(sub):
            out = []
            for it in sub:
                if isinstance(it, str):
                    out.append(it)
                elif isinstance(it, dict):
                    for _k, _v in it.items():
                        if isinstance(_v, (list, tuple)):
                            out.extend(collect_all_strings(_v))
                        elif isinstance(_v, dict):
                            out.extend(collect_all_strings(_v.get('fields') or []))
            return out

        # Para o nível raiz só precisamos dos campos string diretamente especificados ali.
        base_field_strings = [f for f in spec if isinstance(f, str)]
        base_rows = self._extract_fields(recs, base_field_strings) if base_field_strings else [{'id': r.id} for r in recs]
        base_maps = [dict(r) for r in base_rows]

        def serialize_record(rec, rec_base_map, current_spec):
            data = {}
            for item in current_spec:
                if isinstance(item, str):
                    data[item] = rec_base_map.get(item)
                elif isinstance(item, dict):
                    for fname, subconf in item.items():
                        # Preparar sub-especificação
                        if isinstance(subconf, dict):
                            sub_spec = subconf.get('fields') or []
                        elif isinstance(subconf, (list, tuple)):
                            sub_spec = list(subconf)
                        else:
                            sub_spec = []
                        try:
                            val = rec[fname]
                        except Exception:
                            data[fname] = False
                            continue
                        fdef = rec._fields.get(fname)
                        ftype = getattr(fdef, 'type', None) if fdef else None
                        if ftype == 'many2one':
                            if not val:
                                data[fname] = False
                            else:
                                if sub_spec:
                                    # single record -> objeto
                                    # Para many2one: podemos coletar todos os strings (subcampos diretos) normalmente
                                    nested_strings = [s for s in sub_spec if isinstance(s, str)]
                                    # incluir nomes de relações (para acessar depois recursivamente)
                                    nested_strings += [k for d in sub_spec if isinstance(d, dict) for k in d.keys()]
                                    nested_strings = list(dict.fromkeys(nested_strings))
                                    inner_map = {'id': val.id}
                                    if nested_strings:
                                        try:
                                            inner_base = self._extract_fields(val, nested_strings)[0]
                                            inner_map.update(inner_base)
                                        except Exception:
                                            pass
                                    data[fname] = serialize_record(val, inner_map, sub_spec)
                                else:
                                    data[fname] = {'id': val.id}
                        elif ftype in ('one2many', 'many2many'):
                            if not val:
                                data[fname] = []
                            else:
                                if sub_spec:
                                    # Para o recordset relacional: apenas campos simples + nomes de relações imediatas
                                    nested_strings = [s for s in sub_spec if isinstance(s, str)]
                                    nested_strings += [k for d in sub_spec if isinstance(d, dict) for k in d.keys()]
                                    nested_strings = list(dict.fromkeys(nested_strings))
                                    inner_maps = []
                                    base_by_id = {}
                                    if nested_strings:
                                        try:
                                            inner_base_rows = self._extract_fields(val, nested_strings)
                                            base_by_id = {br.get('id'): br for br in inner_base_rows if br.get('id')}
                                        except Exception:
                                            pass
                                    for vrec in val:
                                        inner_maps.append(base_by_id.get(vrec.id, {'id': vrec.id}))
                                    data[fname] = [serialize_record(vrec, imap, sub_spec) for vrec, imap in zip(val, inner_maps)]
                                else:
                                    data[fname] = [{'id': vrec.id} for vrec in val]
                        else:
                            # Campo simples encapsulado em dict (edge case)
                            try:
                                data[fname] = rec[fname]
                            except Exception:
                                data[fname] = False
            return data

        final_rows = []
        for rec, base_map in zip(recs, base_maps):
            final_rows.append(serialize_record(rec, base_map, spec))
        return final_rows

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
                    view_info = Model.get_view(view_type='form')
                    arch = view_info.get('arch') or ''
                    required_fields = []
                    if arch:
                        from lxml import etree as ET
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
    def _process_url_template(self, url_template, record):
        """Process URL template replacing {{field_name}} with actual record values.
        Supports:
        - Simple fields: {{name}}, {{id}}, {{email}}
        - Related fields: {{partner_id.name}}, {{user_id.email}}
        - Dot notation for nested relations: {{order_id.partner_id.name}}
        
        Args:
            url_template: URL string with {{variable}} placeholders
            record: Single record (recordset with len=1) to extract values from
        
        Returns:
            Processed URL string with variables replaced
        """
        if not url_template or not record:
            return url_template
        
        import re
        
        _logger.info(f"[_process_url_template] URL template: {url_template}")
        _logger.info(f"[_process_url_template] Record: {record} (model: {record._name if record else 'None'})")
        
        # Find all {{variable}} patterns
        pattern = r'\{\{([^}]+)\}\}'
        matches = re.findall(pattern, url_template)
        
        _logger.info(f"[_process_url_template] Found {len(matches)} variables: {matches}")
        
        if not matches:
            return url_template
        
        processed_url = url_template
        
        for match in matches:
            field_path = match.strip()
            placeholder = f'{{{{{field_path}}}}}'
            
            _logger.info(f"[_process_url_template] Processing variable: {field_path}")
            
            try:
                # Split by dots for nested fields
                parts = field_path.split('.')
                value = record
                
                # Navigate through the field path
                for part in parts:
                    if not value:
                        break
                    _logger.info(f"[_process_url_template]   Accessing field: {part} on {value}")
                    value = value[part]
                    _logger.info(f"[_process_url_template]   Got value: {value} (type: {type(value).__name__})")
                
                # Convert value to string
                if isinstance(value, models.BaseModel):
                    # If it's a record, use its id or display_name
                    if len(value) == 1:
                        value = str(value.id)
                    elif len(value) > 1:
                        # Multiple records, use comma-separated ids
                        value = ','.join(str(v.id) for v in value)
                    else:
                        value = ''
                elif value is False or value is None:
                    value = ''
                else:
                    value = str(value)
                
                _logger.info(f"[_process_url_template]   Final value: '{value}'")
                
                # Replace placeholder with actual value
                # URL encode the value to handle special characters
                from urllib.parse import quote
                value_encoded = quote(str(value), safe='')
                _logger.info(f"[_process_url_template]   URL encoded: '{value_encoded}'")
                processed_url = processed_url.replace(placeholder, value_encoded)
                
            except Exception as e:
                # If field doesn't exist or error, leave placeholder or use empty
                _logger.warning(f"[_process_url_template] Failed to process variable '{field_path}': {e}")
                processed_url = processed_url.replace(placeholder, '')
        
        _logger.info(f"[_process_url_template] Final URL: {processed_url}")
        return processed_url

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
            
            # Process URL template if we have a single record
            # For multiple records, use the original URL
            final_url = self.outbound_url
            _logger.info(f"[Webhook.send_outbound] Original URL: {self.outbound_url}")
            _logger.info(f"[Webhook.send_outbound] Number of records: {len(recs)}")
            
            if len(recs) == 1:
                _logger.info(f"[Webhook.send_outbound] Processing URL template for single record: {recs}")
                final_url = self._process_url_template(self.outbound_url, recs)
                _logger.info(f"[Webhook.send_outbound] Processed URL: {final_url}")
            elif len(recs) > 1 and '{{' in self.outbound_url:
                _logger.warning(
                    f"Outbound URL contains variables but {len(recs)} records were provided. "
                    f"Variables are only replaced for single records. Using original URL."
                )
            
            payload = {
                'model': model_name,
                'count': len(recs),
            }
            if fields:
                payload['records'] = self._extract_fields(recs, fields)
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
        body = _json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
        
        _logger.info(f"[Webhook.send_outbound] Sending request:")
        _logger.info(f"[Webhook.send_outbound]   URL: {final_url}")
        _logger.info(f"[Webhook.send_outbound]   Headers: {headers}")
        _logger.info(f"[Webhook.send_outbound]   Body: {body[:500]}...")  # First 500 chars
        
        try:
            import requests
            # Encode data as UTF-8 bytes to handle accents correctly
            body_bytes = body.encode('utf-8')
            
            # Use the configured HTTP method
            method = (self.outbound_method or 'POST').upper()
            if method == 'GET':
                resp = requests.get(final_url, headers=headers, timeout=15)
            elif method == 'PUT':
                resp = requests.put(final_url, data=body_bytes, headers=headers, timeout=15)
            elif method == 'PATCH':
                resp = requests.patch(final_url, data=body_bytes, headers=headers, timeout=15)
            elif method == 'DELETE':
                resp = requests.delete(final_url, headers=headers, timeout=15)
            else:  # POST (default)
                resp = requests.post(final_url, data=body_bytes, headers=headers, timeout=15)
            
            ok = 200 <= resp.status_code < 300
            
            _logger.info(f"[Webhook.send_outbound] Response:")
            _logger.info(f"[Webhook.send_outbound]   Status: {resp.status_code}")
            _logger.info(f"[Webhook.send_outbound]   Response: {resp.text[:500]}")
            
            return {
                'ok': ok, 
                'status': resp.status_code, 
                'response': resp.text, 
                'url': final_url,
                'request_body': body,
                'request_headers': str(headers)
            }
        except Exception as e:
            return {'ok': False, 'error': str(e), 'url': final_url}

    def action_test_code(self):
        """Test custom Python code execution with test_input as request body"""
        self.ensure_one()

        if not self.can_code:
            raise UserError(_('Custom code execution is not enabled. Enable "Can Execute Code" first.'))

        if not self.python_code:
            raise UserError(_('Please provide Python code to test.'))

        # Prepare request object (pin_request or test_input)
        if self.pin_request:
            sample = self.sample_request_payload or ''
            if not sample:
                raise UserError(_('No sample request available. Please receive a webhook first or uncheck "Pin Request".'))
            try:
                sample_obj = json.loads(sample)
                if isinstance(sample_obj, dict) and 'body' in sample_obj:
                    request = sample_obj
                else:
                    request = {
                        'body': sample,
                        'headers': {},
                        'method': 'POST',
                        'json': sample_obj if isinstance(sample_obj, dict) else {}
                    }
            except Exception:
                request = {
                    'body': sample,
                    'headers': {},
                    'method': 'POST',
                    'json': {}
                }
        else:
            request_body = self.test_input or ''
            request = {
                'body': request_body,
                'headers': {},
                'method': 'POST',
            }
            try:
                request['json'] = json.loads(request_body)
            except Exception:
                request['json'] = {}

        # Execution environment: always use module globals
        exec_globals = globals().copy()
        exec_globals.update({
            'request': request,
            'env': self.env(user=self.user_id.id),
            'user_id': self.user_id.id,
            'json': json,
            '_': _,
        })

        try:
            exec(self.python_code, exec_globals)
        except Exception as e:
            import traceback
            self.test_output = f"ERROR: {str(e)}\n\n{traceback.format_exc()}"
            return True

        try:
            if 'result' in exec_globals:
                result = exec_globals['result']
                if isinstance(result, dict):
                    self.test_output = json.dumps(result, indent=2, ensure_ascii=False)
                elif isinstance(result, (list, tuple)):
                    self.test_output = json.dumps(result, indent=2, ensure_ascii=False)
                else:
                    self.test_output = str(result)
            else:
                self.test_output = 'Code executed successfully but no result variable was set.\nSet result = {...} in your code to see output here.'
            return True
        except Exception:
            import traceback
            self.test_output = f"ERROR: {traceback.format_exc()}"
            return True

    def action_save_last_request(self):
        """Manually save the last request from context (for testing purposes)"""
        self.ensure_one()
        last_request = self.env.context.get('bitconn_last_request_raw', '')
        if last_request:
            self.write({'sample_request_payload': last_request})
        return True
    
    def _save_request_monitor_async(self, request_raw, request_headers, request_method, result):
        """Save request monitoring data asynchronously to avoid serialization conflicts"""
        webhook_id = self.id
        registry = self.env.registry
        
        import threading
        import time
        
        def delayed_save():
            time.sleep(0.3)  # Short delay to let main transaction complete
            try:
                with registry.cursor() as new_cr:
                    from odoo.api import Environment
                    new_env = Environment(new_cr, 1, {})
                    webhook = new_env['bitconn.webhook'].sudo().browse(webhook_id)
                    if webhook.exists():
                        # Format request data
                        request_data = {
                            'body': request_raw[:5000] if request_raw else '',
                            'headers': dict(request_headers or {}),
                            'method': request_method,
                        }
                        
                        update_vals = {
                            'last_request_input': json.dumps(request_data, indent=2, ensure_ascii=False)[:10000],
                            'last_request_date': fields.Datetime.now(),
                            'last_request_output': json.dumps(result, indent=2, ensure_ascii=False)[:10000] if result else False,
                        }
                        webhook.write(update_vals)
                        new_cr.commit()
            except Exception as e:
                _logger.warning(f"Failed to save request monitor data async: {e}")
        
        thread = threading.Thread(target=delayed_save)
        thread.daemon = True
        thread.start()
    
    def action_refresh_monitor(self):
        """Refresh/reload the monitor fields in the UI"""
        self.ensure_one()
        return True
    
    def action_clear_request_input(self):
        """Clear the last request input and date fields"""
        self.ensure_one()
        self.write({
            'last_request_input': False,
            'last_request_date': False,
            'last_request_output': False,
        })
        return True
    
    def action_clear_test_output(self):
        """Clear the test output field"""
        self.ensure_one()
        self.write({
            'test_output': False,
        })
        return True
    
    def action_refresh_sample(self):
        """Refresh/reload the sample request field in the UI"""
        self.ensure_one()
        return True
    
    def action_clear_sample_request(self):
        """Clear the sample request payload field"""
        self.ensure_one()
        self.write({
            'sample_request_payload': False,
        })
        return True

    def _exec_code(self, request_raw, request_headers=None, request_method='POST'):
        """Execute custom Python code with request object as input"""
        self.ensure_one()
        
        if not self.can_code:
            return {'ok': False, 'error': 'permission_denied', 'reason': 'code_execution_not_allowed'}
        
        # Prepare request object with full context
        request_obj = {
            'body': request_raw,
            'headers': request_headers or {},
            'method': request_method,
        }
        
        # Try to parse body as JSON
        try:
            request_obj['json'] = json.loads(request_raw) if request_raw else {}
        except Exception:
            request_obj['json'] = {}
        
        # If pin_request is enabled and no code, just return the request for inspection
        if self.pin_request and not self.python_code:
            result = {
                'ok': True,
                'message': 'Request captured successfully',
                'data': {
                    'webhook': self.name,
                    'mode': 'pin_request',
                    'status': 'captured'
                },
                'request': request_obj,
                'contribute': {
                    'author': 'Diego Ferreira Rodrigues',
                    'email': 'diego@bitconn.com.br',
                    'website': 'https://bitconn.com.br',
                    'module': 'Bitconn Webhook',
                    'message': 'If this module helped you, consider supporting the project! 🍺',
                    'pix': '00020126810014br.gov.bcb.pix013655f22863-4cea-41e9-904c-df3ce0b241ef0219wa conn odoo module5204000053039865802BR5924Diego Ferreira Rodrigues6009Sao Paulo62290525REC68545B90764819659464106304D86E',
                    'github': 'https://github.com/diegofrodrigues'
                }
            }
            # Save monitoring data asynchronously
            self._save_request_monitor_async(request_raw, request_headers, request_method, result)
            return result
        
        # If not pinned, code is required
        if not self.python_code:
            return {'ok': False, 'error': 'invalid_configuration', 'reason': 'no_python_code_configured'}
        
        # Store request temporarily in context to save after transaction completes
        # This avoids serialization conflicts during webhook processing
        self = self.with_context(
            bitconn_last_request_raw=request_raw[:10000] if request_raw else '',
            bitconn_save_sample=True
        )

        # start from module globals so imports and builtins keep working
        exec_globals = globals().copy()

        # Ensure the method executes in the context of the webhook-configured user.
        # Rebind `self` to a recordset using that user's environment so all subsequent
        # ORM calls (including post-write hooks, message_post, etc.) execute as
        # the configured `user_id` rather than the incoming HTTP/public user.
        # NOTE: we intentionally do NOT use `su=True` here to respect ACLs.
        self = self.with_env(self.env(user=self.user_id.id))
        env_exec = self.env

        # Try to provide `model`, `record`, `records` when payload contains them
        model = None
        record = None
        records = None
        try:
            if isinstance(request_obj.get('json'), dict):
                model_name = request_obj['json'].get('_model') or request_obj['json'].get('model')
                rec_id = request_obj['json'].get('_id') or request_obj['json'].get('id')
                if model_name and model_name in env_exec:
                    model = env_exec[model_name]
                    if rec_id:
                        try:
                            rid = int(rec_id)
                            record = model.browse(rid)
                            records = model.browse([rid])
                        except Exception:
                            record = None
                            records = model
        except Exception:
            model = None

        exec_globals.update({
            'request': request_obj,
            # Use the freshly created env (for webhook.user) so the code runs
            # in the context of that user and cannot see the request's env.
            'env': env_exec,
            'user_id': int(self.user_id.id or 1),
            'json': json,
            '_': _,
            'model': model or env_exec['ir.model'],
            'record': record,
            'records': records,
            'UserError': UserError,
            'log': _logger,
            '_logger': _logger,
        })

        # Temporarily override `odoo.http.request` so any user code
        # that imports `odoo.http.request` sees an object whose `env`
        # is `env_exec` (the webhook user). This prevents accidental
        # use of the incoming HTTP/public user's env (uid=4).
        try:
            import odoo.http as _odoo_http
            _orig_request = getattr(_odoo_http, 'request', None)
        except Exception:
            _odoo_http = None
            _orig_request = None

        try:
            if _odoo_http is not None:
                # Minimal proxy preserving a few commonly-used attrs
                class _ReqProxy(object):
                    def __init__(self, orig, env):
                        self.env = env
                        self.httprequest = getattr(orig, 'httprequest', None) if orig is not None else None
                        self.params = getattr(orig, 'params', {}) if orig is not None else {}
                        self.jsonrequest = getattr(orig, 'jsonrequest', None) if orig is not None else None

                try:
                    _odoo_http.request = _ReqProxy(_orig_request, env_exec)
                except Exception:
                    # If we cannot set the proxy, continue without overriding
                    _odoo_http = None

            try:
                exec(self.python_code, exec_globals)
            finally:
                # Restore original request to avoid side-effects
                try:
                    if _odoo_http is not None:
                        _odoo_http.request = _orig_request
                except Exception:
                    pass

        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            result = {
                'ok': False,
                'error': 'code_execution_failed',
                'reason': str(e),
                'traceback': error_detail
            }
            # Save monitoring data asynchronously and return
            self._save_request_monitor_async(request_raw, request_headers, request_method, result)
            return result
        
        result = {'ok': False}

        try:
            # The code has already been executed into `exec_globals` above.
            # Inspect `exec_globals` for the `result` variable and normalize it.
            if 'result' in exec_globals:
                result = exec_globals['result']
                # Validate that result is not the request object itself
                if result is request_obj:
                    result = {
                        'ok': False,
                        'error': 'invalid_result',
                        'message': 'Result cannot be the request object. Please set result to your custom response dict.'
                    }
                elif not isinstance(result, dict):
                    result = {'ok': True, 'result': result}
                else:
                    # Ensure ok=True if not specified
                    if 'ok' not in result:
                        result['ok'] = True
            else:
                result = {
                    'ok': True,
                    'message': 'Code executed successfully (no result variable set)'
                }
            
            # Always add contribution info if pin_request is enabled
            if self.pin_request:
                result['contribute'] = {
                    'author': 'Diego Ferreira Rodrigues',
                    'email': 'diego@bitconn.com.br',
                    'website': 'https://bitconn.com.br',
                    'module': 'Bitconn Webhook',
                    'message': 'If this module helped you, consider supporting the project! 🍺',
                    'pix': '00020126810014br.gov.bcb.pix013655f22863-4cea-41e9-904c-df3ce0b241ef0219wa conn odoo module5204000053039865802BR5924Diego Ferreira Rodrigues6009Sao Paulo62290525REC68545B90764819659464106304D86E',
                    'github': 'https://github.com/diegofrodrigues'
                }
            
        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            result = {
                'ok': False,
                'error': 'code_execution_failed',
                'reason': str(e),
                'traceback': error_detail
            }
        
        # Save monitoring data asynchronously
        self._save_request_monitor_async(request_raw, request_headers, request_method, result)
        
        return result

    # Masked tracking for sensitive fields
    def write(self, vals):
        # Capture originals for fields of interest
        track_fields = {'webhook_url', 'secret_key', 'outbound_headers'}
        originals = {
            rec.id: {
                'webhook_url': rec.webhook_url,
                'secret_key': rec.secret_key,
                'outbound_headers': rec.outbound_headers,
                'outbound_enabled': rec.outbound_enabled,
            }
            for rec in self
        }
        res = super().write(vals)
        
        # Archive/Unarchive automation rules when outbound is disabled/enabled
        if 'outbound_enabled' in vals:
            for rec in self:
                original_state = originals.get(rec.id, {}).get('outbound_enabled')
                
                if not vals['outbound_enabled'] and original_state:
                    # Outbound was enabled and now is disabled, archive automation rules
                    active_automations = rec.with_context(active_test=False).automation_ids.filtered(lambda a: a.active)
                    if active_automations:
                        active_automations.write({'active': False})
                        _logger.info(
                            f"Webhook '{rec.name}' (ID: {rec.id}): Outbound disabled, "
                            f"archived {len(active_automations)} automation rule(s)"
                        )
                        rec.message_post(
                            body=_("Outbound disabled: %d automation rule(s) archived") % len(active_automations)
                        )
                
                elif vals['outbound_enabled'] and not original_state:
                    # Outbound was disabled and now is enabled, unarchive automation rules
                    archived_automations = rec.with_context(active_test=False).automation_ids.filtered(lambda a: not a.active)
                    if archived_automations:
                        archived_automations.write({'active': True})
                        _logger.info(
                            f"Webhook '{rec.name}' (ID: {rec.id}): Outbound enabled, "
                            f"unarchived {len(archived_automations)} automation rule(s)"
                        )
                        rec.message_post(
                            body=_("Outbound enabled: %d automation rule(s) unarchived") % len(archived_automations)
                        )
        
        to_log = track_fields.intersection(vals.keys())
        # If uuid changed, the computed URL changes too; force log of masked URL
        if 'webhook_uuid' in vals:
            to_log.add('webhook_url')
        if self.env.context.get('bitconn_skip_sensitive_log'):
            to_log = {f for f in to_log if f not in {'secret_key', 'webhook_url'}}
        if to_log:
            for rec in self:
                try:
                    orig = originals.get(rec.id, {})
                    changes = []
                    if 'webhook_url' in to_log and rec.webhook_url != orig.get('webhook_url'):
                        changes.append(f"Webhook URL: ****{(rec.webhook_url or '')[-4:]}")
                    if 'secret_key' in to_log and rec.secret_key != orig.get('secret_key'):
                        changes.append(f"Secret Key: ****{(rec.secret_key or '')[-4:]}")
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
                        changes.append(desc)
                    if changes:
                        rec.message_post(body=" | ".join(changes))
                except Exception:
                    continue
        return res

    # ---------------- Help examples compute -----------------
    def _compute_examples_help(self):
        # Custom compact formatting (single-line where feasible) for help aggregate
        txt = (
            '{\n'
            '  "create": { "model": "res.partner", "method": "create", "values": { "name": "Cliente Webhook", "email": "cliente@example.com", "mobile": "+5511999999999" } },\n'
            '  "write": { "model": "res.partner", "method": "write", "domain": [ [ "email", "=", "cliente@example.com" ] ], "values": { "comment": "Atualizado via webhook" } },\n'
            '  "unlink": { "model": "res.partner", "method": "unlink", "domain": [ [ "id", "in", [ 10, 11 ] ] ] },\n'
            '  "search_advanced": {\n'
            '    "model": "sale.order",\n'
            '    "method": "search",\n'
            '    "domain": [ [ "state", "=", "sale" ] ],\n'
            '    "limit": 2,\n'
            '    "fields": [\n'
            '      "id",\n'
            '      "name",\n'
            '      { "partner_id": [ "id", "name", "email" ] },\n'
            '      { "order_line": [\n'
            '          "id",\n'
            '          "name",\n'
            '          "product_uom_qty",\n'
            '          "price_unit",\n'
            '          { "product_id": [ "id", "default_code", "name" ] }\n'
            '      ] }\n'
            '    ]\n'
            '  }\n'
            '}'
        )
        for rec in self:
            rec.examples_help = txt

    def _compute_examples_blocks(self):
        # Compact / semi-compact JSON strings for each example
        c_txt = (
            '{\n'
            '  "model": "res.partner",\n'
            '  "method": "create",\n'
            '  "values": { "name": "Cliente Webhook", "email": "cliente@example.com", "mobile": "+5511999999999" }\n'
            '}'
        )
        w_txt = (
            '{\n'
            '  "model": "res.partner",\n'
            '  "method": "write",\n'
            '  "domain": [ [ "email", "=", "cliente@example.com" ] ],\n'
            '  "values": { "comment": "Atualizado via webhook" }\n'
            '}'
        )
        u_txt = (
            '{\n'
            '  "model": "res.partner",\n'
            '  "method": "unlink",\n'
            '  "domain": [ [ "id", "in", [ 10, 11 ] ] ]\n'
            '}'
        )
        s_txt = (
            '{\n'
            '  "model": "sale.order",\n'
            '  "method": "search",\n'
            '  "domain": [ [ "state", "=", "sale" ] ],\n'
            '  "limit": 2,\n'
            '  "fields": [\n'
            '    "id",\n'
            '    "name",\n'
            '    { "partner_id": [ "id", "name", "email" ] },\n'
            '    { "order_line": [\n'
            '        "id",\n'
            '        "name",\n'
            '        "product_uom_qty",\n'
            '        "price_unit",\n'
            '        { "product_id": [ "id", "default_code", "name" ] }\n'
            '    ] }\n'
            '  ]\n'
            '}'
        )
        for rec in self:
            rec.example_create = c_txt
            rec.example_write = w_txt
            rec.example_unlink = u_txt
            rec.example_search_advanced = s_txt
