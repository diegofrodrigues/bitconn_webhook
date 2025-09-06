from odoo import http
from odoo.http import request


class BitconnWebhookController(http.Controller):

    def _resolve_conf(self, uuid_str):
        return request.env['bitconn.webhook'].sudo().search([('webhook_uuid', '=', uuid_str)], limit=1)

    def _validate(self, conf):
        headers = request.httprequest.headers
        return conf._check_header(headers)

    def _default_payload(self, conf):
        return {
            'secret_key': conf.secret_key,
            'webhook_uuid': conf.webhook_uuid,
            'model': 'res.partner',
            'method': 'create',
            'domain': [],
            'values': {'name': 'Webhook Partner'},
        }

    @http.route('/bitconn/webhook/<string:uuid_str>', type='http', auth='public', methods=['POST'], csrf=False)
    def receive(self, uuid_str, **kwargs):
        conf = self._resolve_conf(uuid_str)
        if not conf:
            return request.make_json_response({'ok': False, 'error': 'conf_not_found'}, status=404)
        if not self._validate(conf):
            return request.make_json_response({'ok': False, 'error': 'forbidden', 'reason': 'invalid_token'}, status=401)

        try:
            payload = request.get_json_data() or {}
        except Exception:
            payload = {}
        model = payload.get('model')
        method = (payload.get('method') or 'create').lower()
        values = payload.get('values') or {}
        domain = payload.get('domain') or []
        fields = payload.get('fields')
        limit = payload.get('limit')
        offset = payload.get('offset') or 0
        order = payload.get('order')
        ids = payload.get('ids')

        if method == 'default_payload':
            # echo current headers to ease client config
            return request.make_json_response({
                'ok': True,
                'payload': self._default_payload(conf),
                'headers_example': {
                    'Authorization': f"Bearer {conf.secret_key}",
                    'Webhook-Key': conf.secret_key,
                }
            }, status=200)

        if not model:
            return request.make_json_response({'ok': False, 'error': 'invalid_payload', 'reason': 'missing_model'}, status=400)

        if method == 'create':
            res = conf._exec_create(model, values)
        elif method == 'write':
            res = conf._exec_write(model, domain, values)
        elif method == 'unlink':
            res = conf._exec_unlink(model, domain)
        elif method == 'read':
            res = conf._exec_read(model, ids, fields=fields)
        elif method == 'search':
            res = conf._exec_search(model, domain, fields=fields, limit=limit, offset=offset, order=order)
        else:
            res = {'ok': False, 'error': 'invalid_method'}

        status = 200 if res.get('ok') else 400
        return request.make_json_response(res, status=status)

    @http.route(['/bitconn/webhook/<string:webhook_uuid>/schema'], type='http', auth='public', methods=['GET'], csrf=False)
    def webhook_schema(self, webhook_uuid, **kw):
        # Query params: model, method=create|write
        conf = self._resolve_conf(webhook_uuid)
        if not conf:
            return request.make_json_response({'ok': False, 'error': 'invalid_webhook'}, status=404)
        if not self._validate(conf):
            return request.make_json_response({'ok': False, 'error': 'forbidden', 'reason': 'invalid_token'}, status=401)
        model = request.params.get('model')
        method = (request.params.get('method') or 'create').lower()
        if not model:
            return request.make_json_response({'ok': False, 'error': 'missing_param', 'param': 'model'}, status=400)
        res = conf._get_model_schema(model, method)
        status = 200 if res.get('ok') else 400
        return request.make_json_response(res, status=status)

    @http.route(['/bitconn/webhook/<string:webhook_uuid>/required'], type='http', auth='public', methods=['GET'], csrf=False)
    def webhook_required(self, webhook_uuid, **kw):
    # Query params: model (required), values (optional JSON string), source=model|view|auto (default:model)
        conf = self._resolve_conf(webhook_uuid)
        if not conf:
            return request.make_json_response({'ok': False, 'error': 'invalid_webhook'}, status=404)
        if not self._validate(conf):
            return request.make_json_response({'ok': False, 'error': 'forbidden', 'reason': 'invalid_token'}, status=401)
        model = request.params.get('model')
        if not model:
            return request.make_json_response({'ok': False, 'error': 'missing_param', 'param': 'model'}, status=400)
        source = (request.params.get('source') or 'auto').lower()
        values_raw = request.params.get('values')
        values = None
        if values_raw:
            try:
                values = request.jsonrequest and request.jsonrequest.get('values')  # not applicable on GET
            except Exception:
                values = None
            # fallback: try to parse querystring JSON
            if values is None:
                import json
                try:
                    values = json.loads(values_raw)
                except Exception:
                    values = None
        res = conf._get_required_for_create(model, values=values, source=source)
        if not res.get('ok'):
            return request.make_json_response({'error': res.get('error') or 'invalid'}, status=400)
        # If details=1, return field + label; else just list of fields
        details = (request.params.get('details') in ('1', 'true', 'True'))
        if details:
            return request.make_json_response(res.get('must_provide_detailed', []), status=200)
        return request.make_json_response(res.get('must_provide', []), status=200)
