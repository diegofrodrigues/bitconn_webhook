from odoo import api, fields, models, _
import json


class IrActionsServer(models.Model):
    bitconn_preview_record_id = fields.Integer(
        string='ID para Preview',
        help='ID do registro a ser usado como exemplo no preview do Python Payload. Se vazio, busca o primeiro registro disponível.'
    )
    bitconn_python_payload = fields.Boolean(
        string='Usar Python Payload',
        help='Se ativo, executa o código Python abaixo para gerar o payload do webhook.'
    )
    bitconn_python_payload_code = fields.Text(
        string='Código Python Payload',
        help='Bloco de código Python que recebe "record" (ou "records") e deve definir a variável "result" com o payload final.'
    )
    _inherit = 'ir.actions.server'

    state = fields.Selection(
        selection_add=[('bitconn_webhook', 'Bitconn Webhook')],
        ondelete={'bitconn_webhook': 'set default'}
    )
    bitconn_webhook_id = fields.Many2one('bitconn.webhook', string='Webhook', help='Webhook configuration to use for outbound send')
    bitconn_field_ids = fields.Many2many(
        'ir.model.fields', string='Fields to Send',
        domain="[('model_id','=',model_id),('store','=',True)]",
        help='If empty, only IDs are sent. If set, selected fields are included in records.'
    )
    bitconn_preview_payload = fields.Text(
        string='Preview JSON',
    help='Editable preview of the JSON body that will be sent. You can modify it manually or regenerate from selected fields.',
    )
    bitconn_manual_payload = fields.Boolean(
        string='Manual Payload',
    help='Enable to write the payload manually below and send it as-is.'
    )
    bitconn_manual_payload_text = fields.Text(
        string='Manual Payload (JSON)',
    help='If Manual Payload is enabled, this JSON body will be sent as-is. Must be a JSON object.'
    )
    bitconn_last_result = fields.Text(
        string='Last Result',
        readonly=True,
        help='Latest HTTP status and response body from running this Server Action.'
    )
    # Relational fields via dot-notation are no longer supported in Server Actions.

    @api.onchange('bitconn_field_ids', 'model_id', 'bitconn_manual_payload', 'bitconn_manual_payload_text')
    def _onchange_bitconn_preview(self):
        for rec in self:
            # If manual mode is enabled and no body yet, prefill with a minimal template
            if rec.bitconn_manual_payload and not rec.bitconn_manual_payload_text:
                try:
                    rec.bitconn_manual_payload_text = json.dumps({'fields': []}, indent=2, ensure_ascii=False)
                except Exception:
                    rec.bitconn_manual_payload_text = '{"fields": []}'
            # Only auto-fill if empty to avoid overwriting manual edits
            if not rec.bitconn_preview_payload:
                rec.bitconn_preview_payload = rec._generate_bitconn_preview()

    def action_generate_bitconn_preview(self):
        for rec in self:
            rec.bitconn_preview_payload = rec._generate_bitconn_preview()
        return True

    def _generate_bitconn_preview(self):
        self.ensure_one()
        # Preview para Python Payload customizado
        if self.bitconn_python_payload and self.bitconn_python_payload_code:
            from odoo.tools.safe_eval import safe_eval
            model_name = self.model_id.model or 'res.partner'
            # Tenta pegar um registro de exemplo
            # Se o usuário definiu um ID para preview, tenta buscar esse registro
            preview_id = getattr(self, 'bitconn_preview_record_id', None)
            rec = None
            log_info = {}
            if preview_id:
                recs = self.env[model_name].browse(preview_id)
                rec = recs[0] if recs and recs.exists() else None
                log_info['preview_id'] = int(preview_id) if preview_id else None
                log_info['record_exists'] = bool(recs.exists()) if recs else False
                if not rec:
                    recs = self.env[model_name].search([], limit=1)
                    rec = recs[0] if recs else None
                    log_info['fallback_first_id'] = int(rec.id) if rec else None
            else:
                recs = self.env[model_name].search([], limit=1)
                rec = recs[0] if recs else None
                log_info['fallback_first_id'] = int(rec.id) if rec else None
            # Se não houver registro, cria um mock sintético
            if not rec:
                # Remove objetos Odoo do log_info
                for k, v in list(log_info.items()):
                    if hasattr(v, 'ids'):
                        log_info[k] = list(v.ids)
                    elif hasattr(v, 'id'):
                        log_info[k] = int(v.id)
                return json.dumps({
                    'error': 'Nenhum registro encontrado para preview.',
                    'debug': log_info
                }, indent=2, ensure_ascii=False)
            else:
                local_ctx = {
                    'record': rec,
                    'records': recs if recs else [rec],
                    'env': self.env,
                    'getattr': getattr,
                    'dir': dir,
                    'repr': repr,
                }
                try:
                    exec(self.bitconn_python_payload_code, {}, local_ctx)
                    result = local_ctx.get('result')
                    if result is None:
                        # Remove objetos Odoo do log_info
                        for k, v in list(log_info.items()):
                            if hasattr(v, 'ids'):
                                log_info[k] = list(v.ids)
                            elif hasattr(v, 'id'):
                                log_info[k] = int(v.id)
                        return json.dumps({'error': 'O código Python não definiu a variável result ou retornou None.', 'debug': log_info}, indent=2, ensure_ascii=False)
                    return json.dumps(result, indent=2, ensure_ascii=False)
                except Exception as e:
                    # Remove objetos Odoo do log_info
                    for k, v in list(log_info.items()):
                        if hasattr(v, 'ids'):
                            log_info[k] = list(v.ids)
                        elif hasattr(v, 'id'):
                            log_info[k] = int(v.id)
                    return json.dumps({'error': f'Erro ao executar Python Payload: {e}', 'debug': log_info}, indent=2, ensure_ascii=False)

        # If manual payload enabled and present, show it
        if self.bitconn_manual_payload and self.bitconn_manual_payload_text:
            try:
                base = json.loads(self.bitconn_manual_payload_text) or {}
                if not isinstance(base, dict):
                    base = {'_manual_payload': self.bitconn_manual_payload_text}
            except Exception:
                base = {'_manual_payload': self.bitconn_manual_payload_text}
            return json.dumps(base, indent=2, ensure_ascii=False)

        model_name = self.model_id.model or 'res.partner'
        field_names = self.bitconn_field_ids.mapped('name') if self.bitconn_field_ids else []
        combined_fields = list(dict.fromkeys(field_names))
        # Build a sample payload matching send_outbound behavior
        payload = {
            'model': model_name,
        }
        if combined_fields:
            payload['count'] = 1
            payload['records'] = [self._sample_record_for_model(model_name, combined_fields)]
        else:
            payload['count'] = 0
            payload['ids'] = []
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
        # Se usar Python Payload customizado
        if self.bitconn_python_payload and self.bitconn_python_payload_code:
            code = self.bitconn_python_payload_code
            # Sempre processa como singleton igual ao preview
            if recs:
                rec = recs[0]
                local_ctx = {
                    'record': rec,
                    'records': recs,
                    'env': self.env,
                    'getattr': getattr,
                    'dir': dir,
                    'repr': repr,
                }
                exec(code, {}, local_ctx)
                body = local_ctx.get('result')
                if body is None:
                    body = {'error': 'O código Python não definiu a variável result ou retornou None.'}
            else:
                body = {'error': 'Nenhum registro selecionado para execução.'}
            # direct send using webhook config
            try:
                import requests, json as _json
                headers = {'Content-Type': 'application/json'}
                # merge configured headers
                if self.bitconn_webhook_id.outbound_headers:
                    try:
                        hdrs = json.loads(self.bitconn_webhook_id.outbound_headers)
                        if isinstance(hdrs, dict):
                            headers.update({str(k): str(v) for k, v in hdrs.items()})
                    except Exception:
                        pass
                url = self.bitconn_webhook_id.outbound_url
                data = _json.dumps(body, ensure_ascii=False)
                resp = requests.post(url, data=data, headers=headers, timeout=15)
                # Format result: Status + pretty body when JSON
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
                self.sudo().write({'bitconn_last_result': f"Status: {resp.status_code}\nBody:\n{formatted}"})
            except Exception as e:
                self.sudo().write({'bitconn_last_result': f"Error: {e}"})
            return False
        # If manual payload: send body as-is (mantém lógica anterior)
        if self.bitconn_manual_payload and self.bitconn_manual_payload_text:
            body = {}
            try:
                body = json.loads(self.bitconn_manual_payload_text) or {}
            except Exception:
                # send raw text as string payload
                body = {'_payload': self.bitconn_manual_payload_text}
            # Resolve placeholders from active records when using {{ path }} or ${path}
            try:
                # If 'fields' provided: use advanced extraction (supports dict spec like [{"partner_id": ["id","name"]}])
                if isinstance(body, dict) and isinstance(body.get('fields'), list):
                    spec = [f for f in body.get('fields') if isinstance(f, (str, dict))]
                    payload = dict(body)
                    payload['model'] = model_name
                    payload['count'] = len(recs)
                    if spec:
                        try:
                            payload['records'] = self.bitconn_webhook_id._extract_fields_advanced(recs, spec)
                        except Exception as e:
                            # Registrar erro para diagnóstico e fazer fallback estendido
                            try:
                                self.sudo().write({'bitconn_last_result': f"Advanced extraction error: {e}"})
                            except Exception:
                                pass
                            # Campos simples originais
                            simple = [f for f in spec if isinstance(f, str)]
                            # Adiciona também os nomes relacionais (keys dos dicts) para ao menos retornar seus IDs/listas
                            rel_names = []
                            for f in spec:
                                if isinstance(f, dict):
                                    rel_names.extend(list(f.keys()))
                            simple_extended = list(dict.fromkeys(simple + rel_names))
                            payload['records'] = self.bitconn_webhook_id._extract_fields(recs, simple_extended)
                    else:
                        payload['ids'] = recs.ids
                    payload.pop('fields', None)
                    body = payload
                else:
                    import re
                    placeholder_re = re.compile(r"^(?:\$\{\s*([A-Za-z0-9_\.]+)\s*\}|\{\{\s*([A-Za-z0-9_\.]+)\s*\}\})$")

                def get_path_value(rec, path):
                    try:
                        rows = self.bitconn_webhook_id._extract_fields(rec, [path])
                        if rows and isinstance(rows, list):
                            return rows[0].get(path)
                    except Exception:
                        return None
                    return None

                def resolve_node(node, rec):
                    if isinstance(node, dict):
                        return {k: resolve_node(v, rec) for k, v in node.items()}
                    if isinstance(node, list):
                        return [resolve_node(v, rec) for v in node]
                    if isinstance(node, str):
                        m = placeholder_re.match(node.strip())
                        if m:
                            path = m.group(1) or m.group(2)
                            return get_path_value(rec, path)
                        return node
                    return node

                if isinstance(body, dict) and recs and 'fields' not in body:
                    # If records is a single-template list, expand per active record
                    if isinstance(body.get('records'), list) and len(body['records']) == 1:
                        template = body['records'][0]
                        body['records'] = [resolve_node(template, r) for r in recs]
                        body['count'] = len(recs)
                        if 'model' not in body and model_name:
                            body['model'] = model_name
                    elif isinstance(body.get('records'), list) and len(body['records']) >= 1:
                        # Resolve each record item against matching rec; extra items use last rec
                        resolved = []
                        for idx, item in enumerate(body['records']):
                            rec_match = recs[idx] if idx < len(recs) else recs[-1]
                            resolved.append(resolve_node(item, rec_match))
                        body['records'] = resolved
                        body['count'] = len(body['records'])
                        if 'model' not in body and model_name:
                            body['model'] = model_name
                    else:
                        # Resolve placeholders in the whole body using the first record
                        first = recs[0]
                        body = resolve_node(body, first)
                        if 'model' not in body and model_name:
                            body['model'] = model_name
            except Exception:
                # On any resolution error, keep original body
                pass
            # direct send using webhook config
            try:
                import requests, json as _json
                headers = {'Content-Type': 'application/json'}
                # merge configured headers
                if self.bitconn_webhook_id.outbound_headers:
                    try:
                        hdrs = json.loads(self.bitconn_webhook_id.outbound_headers)
                        if isinstance(hdrs, dict):
                            headers.update({str(k): str(v) for k, v in hdrs.items()})
                    except Exception:
                        pass
                url = self.bitconn_webhook_id.outbound_url
                data = _json.dumps(body, ensure_ascii=False)
                resp = requests.post(url, data=data, headers=headers, timeout=15)
                # Format result: Status + pretty body when JSON
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
                self.sudo().write({'bitconn_last_result': f"Status: {resp.status_code}\nBody:\n{formatted}"})
            except Exception as e:
                self.sudo().write({'bitconn_last_result': f"Error: {e}"})
            return False

        # Otherwise: build fields list and use helper
        base_fields = self.bitconn_field_ids.mapped('name') if self.bitconn_field_ids else []
        fields_list = list(dict.fromkeys(base_fields)) or None
        result = self.bitconn_webhook_id.send_outbound(model_name, ids=recs.ids, fields=fields_list, extra=None)
        # Format and store result on the action for visibility
        try:
            if result and result.get('error'):
                self.sudo().write({'bitconn_last_result': f"Error: {result.get('error')}"})
            else:
                status = result.get('status') if isinstance(result, dict) else None
                text = result.get('response') if isinstance(result, dict) else ''
                formatted = text or ''
                if formatted:
                    try:
                        if formatted.strip().startswith('{') or formatted.strip().startswith('['):
                            parsed = json.loads(formatted)
                            formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
                    except Exception:
                        pass
                self.sudo().write({'bitconn_last_result': f"Status: {status}\nBody:\n{formatted}"})
        except Exception:
            # best-effort only
            pass
        return False

    # capture json feature removed intentionally
