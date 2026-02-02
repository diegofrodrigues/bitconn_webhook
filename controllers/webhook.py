from odoo import http
from odoo.http import request
import json
import re
import ast
import logging
import traceback


class BitconnWebhookController(http.Controller):

    def _resolve_conf(self, uuid_str):
        return request.env['bitconn.webhook'].sudo().search([('webhook_uuid', '=', uuid_str)], limit=1)

    def _validate(self, conf):
        headers = request.httprequest.headers
        return conf._check_header(headers)

    def _save_sample_async(self, webhook_id, raw_body):
        """Save sample request asynchronously after commit"""
        try:
            with request.env.registry.cursor() as new_cr:
                webhook = request.env['bitconn.webhook'].with_env(
                    request.env(cr=new_cr)
                ).sudo().browse(webhook_id)
                if webhook.exists():
                    webhook.write({'sample_request_payload': raw_body[:10000]})
                    new_cr.commit()
        except Exception:
            pass  # Silent fail

    def _default_payload(self, conf):
        return {
            'secret_key': conf.secret_key,
            'webhook_uuid': conf.webhook_uuid,
            'model': 'res.partner',
            'method': 'create',
            'domain': [],
            'values': {'name': 'Webhook Partner'},
        }

    @http.route('/bitconn/webhook/<string:uuid_str>', type='http', auth='public', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], csrf=False)
    def receive(self, uuid_str, **kwargs):
        conf = self._resolve_conf(uuid_str)
        if not conf:
            return request.make_json_response({'ok': False, 'error': 'conf_not_found'}, status=404)
        if not self._validate(conf):
            # Log masked headers for diagnostics when validation fails
            try:
                hdrs = dict(request.httprequest.headers)
                # Mask sensitive headers
                for k in list(hdrs.keys()):
                    if k.lower() in ('authorization', 'webhook-key', 'webhook_key', 'x-webhook-key'):
                        hdrs[k] = '***masked***'
                _logger = __import__('logging').getLogger(__name__)
                _logger.warning(f"[bitconn.webhook] auth failed for uuid={uuid_str}; headers={hdrs}")
            except Exception:
                pass
            return request.make_json_response({'ok': False, 'error': 'forbidden', 'reason': 'invalid_token'}, status=401)

        # Get HTTP method
        http_method = request.httprequest.method
        
        # Check if method is allowed for this webhook
        if not conf._is_method_allowed(http_method):
            allowed = []
            if conf.inbound_allowed_methods == 'POST':
                allowed = ['POST']
            elif conf.inbound_allowed_methods == 'ALL':
                allowed = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
            elif conf.inbound_allowed_methods == 'CUSTOM':
                if conf.inbound_methods_get: allowed.append('GET')
                if conf.inbound_methods_post: allowed.append('POST')
                if conf.inbound_methods_put: allowed.append('PUT')
                if conf.inbound_methods_patch: allowed.append('PATCH')
                if conf.inbound_methods_delete: allowed.append('DELETE')
            
            return request.make_json_response({
                'ok': False, 
                'error': 'method_not_allowed',
                'message': f'Method {http_method} not allowed for this webhook',
                'allowed_methods': allowed
            }, status=405)
        
        # Read raw bytes first, then decode using charset if present.
        raw_body = ''
        try:
            # Get raw bytes to attempt deterministic decoding
            raw_bytes = request.httprequest.get_data() or b''
        except Exception:
            raw_bytes = b''

        def _decode_bytes(bts):
            # Try to detect charset from Content-Type header
            try:
                ctype = request.httprequest.headers.get('Content-Type', '') or ''
                # format: 'application/json; charset=utf-8'
                charset = None
                if ';' in ctype:
                    parts = [p.strip() for p in ctype.split(';')]
                    for p in parts[1:]:
                        if p.lower().startswith('charset='):
                            charset = p.split('=', 1)[1].strip().strip('"')
                            break
                # If charset explicitly provided, try it first
                if charset:
                    try:
                        return bts.decode(charset)
                    except Exception:
                        # fallthrough to other attempts
                        pass
                else:
                    # No charset provided: assume UTF-8 (replace errors to avoid crashes)
                    try:
                        return bts.decode('utf-8')
                    except Exception:
                        try:
                            return bts.decode('utf-8', errors='replace')
                        except Exception:
                            pass
            except Exception:
                pass
            # Fallback: try latin-1 as last resort
            try:
                return bts.decode('latin-1')
            except Exception:
                return ''

        try:
            raw_body = _decode_bytes(raw_bytes) or ''
        except Exception:
            raw_body = ''

        # If we couldn't decode anything but there are bytes, save a hex/snippet for debugging
        if not raw_body and raw_bytes:
            try:
                # keep short to avoid huge logs/storage
                snippet = raw_bytes[:200]
                # attach as samples only if pin_request true later; for now keep raw_body empty
                _logger = __import__('logging').getLogger(__name__)
                _logger.debug(f"[bitconn.webhook] incoming raw bytes (len={len(raw_bytes)}): {snippet}")
            except Exception:
                pass
        
        # Don't save sample_request_payload here to avoid serialization conflicts
        # It will be saved asynchronously or manually by user

        def _lenient_parse(text):
            """Tenta fazer parsing JSON tolerante (vírgulas finais, aspas simples).
            Retorna (data, error_msg) onde error_msg é None se sucesso."""
            if not text:
                return {}, None
            # Primeiro: tentativa normal
            try:
                return json.loads(text), None
            except Exception as e_first:
                original_error = str(e_first)
            work = text
            # Remover BOM se existir
            work = work.lstrip('\ufeff')
            # Remover comentários simples // ou # (linha inteira)
            work = '\n'.join([
                ln for ln in work.splitlines()
                if not ln.strip().startswith('//') and not ln.strip().startswith('#')
            ])
            # Remover vírgulas finais em objetos/arrays
            work = re.sub(r",\s*([}\]])", r"\1", work)
            # Converter aspas simples em chaves 'campo': -> "campo":
            work = re.sub(r"'([A-Za-z0-9_\-]+)'\s*:", r'"\\1":', work)
            # Converter strings de valores e arrays com aspas simples simples 'valor'
            # Cuidado para não substituir dentro de aspas duplas já válidas
            # Estratégia simples: substituir aspas simples que delimitam tokens alfanuméricos
            work = re.sub(r":\s*'([^'\\]*)'", lambda m: ': "' + m.group(1).replace('"', '\\"') + '"', work)
            work = re.sub(r"\[\s*'([^'\\]*)'", lambda m: '[ "' + m.group(1).replace('"', '\\"') + '"', work)
            work = re.sub(r"'([^'\\]*)'\s*]", lambda m: '"' + m.group(1).replace('"', '\\"') + '"]', work)
            # Strings internas em arrays separadas por vírgula
            work = re.sub(r",\s*'([^'\\]*)'", lambda m: ', "' + m.group(1).replace('"', '\\"') + '"', work)
            try:
                return json.loads(work), None
            except Exception:
                # Último fallback: se o payload for só um dicionário python, tentar ast.literal_eval
                try:
                    data = ast.literal_eval(text)
                    if isinstance(data, (dict, list)):
                        return data, None
                except Exception:
                    pass
                return {}, f'invalid_json: {original_error}'

        payload = {}
        parse_error = None
        if raw_body:
            data, err = _lenient_parse(raw_body)
            payload = data or {}
            parse_error = err
        else:
            # fallback para método padrão (deve ser vazio se não era JSON)
            try:
                payload = request.get_json_data() or {}
            except Exception as e_json_std:
                parse_error = f'invalid_json: {e_json_std}'

        # Se houve erro de parsing e não conseguimos extrair nada significativo
        if parse_error and not payload:
            return request.make_json_response({'ok': False, 'error': 'invalid_json', 'detail': parse_error}, status=400)

        # Normalizar campo 'fields' se veio em formato de string tipo Python: "['id','name',]"
        fields = payload.get('fields')
        if isinstance(fields, str):
            try:
                f_list = ast.literal_eval(fields)
                if isinstance(f_list, (list, tuple)):
                    payload['fields'] = [str(x) for x in f_list if str(x).strip()]
            except Exception:
                # manter original, não fatal
                pass
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

        # Helper function to save sample request asynchronously
        def save_sample_async_if_pinned():
            """Save sample request if pin_request is enabled"""
            if conf.pin_request and raw_body:
                import logging
                _logger = logging.getLogger(__name__)
                
                # Capture values BEFORE creating thread to avoid "object unbound" error
                webhook_id = conf.id
                webhook_name = conf.name
                registry = request.env.registry  # Capture registry before thread
                db_name = request.env.cr.dbname  # Capture database name
                
                _logger.info(f"PIN REQUEST DETECTED - Saving sample for webhook {webhook_name} (ID: {webhook_id})")
                
                # Build complete request object to save
                request_obj = {
                    'body': raw_body,
                    'headers': dict(request.httprequest.headers),
                    'method': request.httprequest.method,
                }
                try:
                    request_obj['json'] = json.loads(raw_body)
                except:
                    request_obj['json'] = {}
                
                # Convert to JSON string
                sample_data = json.dumps(request_obj, indent=2, ensure_ascii=False)[:10000]
                
                _logger.info(f"Sample data prepared, length: {len(sample_data)}")
                
                # Schedule async save in a separate thread to avoid serialization conflicts
                import threading
                import time
                def delayed_save():
                    time.sleep(0.5)  # Wait for main transaction to complete
                    try:
                        _logger.info(f"Starting delayed save for webhook ID {webhook_id}")
                        # Use captured registry instead of request.env.registry
                        with registry.cursor() as new_cr:
                            # Create new environment with the new cursor
                            from odoo.api import Environment
                            new_env = Environment(new_cr, 1, {})  # uid=1 (admin)
                            webhook = new_env['bitconn.webhook'].sudo().browse(webhook_id)
                            if webhook.exists():
                                webhook.write({'sample_request_payload': sample_data})
                                new_cr.commit()
                                _logger.info(f"Sample request saved successfully for webhook {webhook_name}")
                            else:
                                _logger.warning(f"Webhook ID {webhook_id} not found")
                    except Exception as e:
                        _logger.error(f"Failed to save sample request: {e}", exc_info=True)
                
                thread = threading.Thread(target=delayed_save)
                thread.daemon = True
                thread.start()
                _logger.info("Async save thread started")
            elif conf.pin_request:
                import logging
                _logger = logging.getLogger(__name__)
                # Capture webhook_name before using it
                webhook_name = conf.name
                _logger.warning(f"PIN REQUEST enabled but no raw_body for webhook {webhook_name}")
        
        # Derive an execution-bound conf that uses the webhook's configured user
        # (avoid using the HTTP/request environment user). Do not use sudo here.
        try:
            conf_exec = conf.with_env(conf.env(user=conf.user_id.id)) if conf and conf.user_id else conf
        except Exception:
            conf_exec = conf

        # Debug: log env uids to diagnose intermittent ACL issues
        try:
            _logger = logging.getLogger(__name__)
            req_uid = getattr(request.env, 'uid', None)
            conf_uid = getattr(conf.env, 'uid', None) if conf else None
            conf_exec_uid = getattr(conf_exec.env, 'uid', None) if conf_exec else None
            _logger.info(f"[bitconn.webhook.receive] request.env.uid={req_uid} conf.env.uid={conf_uid} conf_exec.env.uid={conf_exec_uid} method={method} model={model}")
        except Exception:
            pass

        # Temporarily override global odoo.http.request so any code called below
        # that reads `odoo.http.request.env` sees `conf_exec.env` (the webhook user).
        try:
            import odoo.http as _odoo_http
            _orig_http_request = getattr(_odoo_http, 'request', None)
        except Exception:
            _odoo_http = None
            _orig_http_request = None

        # Also capture the local request.env so we can temporarily override it
        _orig_local_request_env = getattr(request, 'env', None)

        # Proxy class that exposes env and basic attributes used by other code
        class _ReqGlobalProxy(object):
            def __init__(self, orig, env):
                self._orig = orig
                self.env = env
                # keep httprequest if present for code that accesses it
                self.httprequest = getattr(orig, 'httprequest', None) if orig is not None else None
                self.params = getattr(orig, 'params', {}) if orig is not None else {}
                self.jsonrequest = getattr(orig, 'jsonrequest', None) if orig is not None else None

        try:
            # Override local request.env so any code using the `request` object directly
            # will see the webhook user's env; restore in finally.
            try:
                request.env = conf_exec.env
            except Exception:
                pass

            if _odoo_http is not None:
                try:
                    _odoo_http.request = _ReqGlobalProxy(_orig_http_request, conf_exec.env)
                except Exception:
                    _odoo_http = None

            # Check if custom code execution is enabled (doesn't require model)
            # If can_code is enabled and method is 'code', OR if no model provided and can_code is enabled
            if conf_exec.can_code and (method == 'code' or (not model and conf_exec.pin_request) or (not model and conf_exec.python_code)):
                try:
                    res = conf_exec._exec_code(
                        raw_body,
                        request_headers=dict(request.httprequest.headers),
                        request_method=request.httprequest.method
                    )
                except Exception:
                    # Log full traceback and return it in JSON for debugging
                    _logger = logging.getLogger(__name__)
                    tb = traceback.format_exc()
                    try:
                        _logger.error(f"[bitconn.webhook] _exec_code exception for webhook id={conf.id} user_id={getattr(conf, 'user_id', None)}:\n{tb}")
                    except Exception:
                        _logger.error("[bitconn.webhook] _exec_code exception but failed to log details")
                    return request.make_json_response({'ok': False, 'error': 'internal_error', 'traceback': tb}, status=500)
                status = 200 if res.get('ok') else 400

                # Save sample request if pinned
                save_sample_async_if_pinned()

                return request.make_json_response(res, status=status)

            # For other methods, model is required
            if not model:
                return request.make_json_response({'ok': False, 'error': 'invalid_payload', 'reason': 'missing_model'}, status=400)

            if method == 'create':
                res = conf_exec._exec_create(model, values)
            elif method == 'write':
                res = conf_exec._exec_write(model, domain, values)
            elif method == 'unlink':
                res = conf_exec._exec_unlink(model, domain)
            elif method == 'read':
                res = conf_exec._exec_read(model, ids, fields=fields)
            elif method == 'search':
                res = conf_exec._exec_search(model, domain, fields=fields, limit=limit, offset=offset, order=order)
            else:
                res = {'ok': False, 'error': 'invalid_method'}

            status = 200 if res.get('ok') else 400
            if parse_error and res.get('ok'):
                # Anexar aviso de parsing tolerante, sem quebrar sucesso principal
                res['warning'] = parse_error

            # Save sample request if pinned (for all operations)
            save_sample_async_if_pinned()

            return request.make_json_response(res, status=status)

        finally:
            # restore original global request to avoid side-effects
            try:
                if _odoo_http is not None:
                    _odoo_http.request = _orig_http_request
            except Exception:
                pass

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
