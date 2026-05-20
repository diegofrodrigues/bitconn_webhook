
def normalize(payload):
    payload = payload or {}

    contact_obj = payload.get('contact_inbox') or {}
    meta_obj = payload.get('meta') or {}
    custom_attrs = payload.get('custom_attributes') or {}

    team = meta_obj.get('team') or {}
    assignee = meta_obj.get('assignee') or {}
    sender = meta_obj.get('sender') or {}

    return {
        'cw_conversation_id': payload.get('id'),
        'cw_team_id': team.get('id'),
        'cw_agent_id': assignee.get('id'),
        'cw_inbox_id': contact_obj.get('id'),
        'cw_contact_id': contact_obj.get('contact_id'),

        'cw_sender_name': sender.get('name', ''),
        'cw_sender_phone': sender.get('phone_number', ''),
        'cw_sender_email': sender.get('email', ''),

        # lead custom attrs
        'cw_lead_id': custom_attrs.get('crm_id', ''),
        'cw_lead_name': custom_attrs.get('assunto_crm', ''),
        'cw_lead_stage': custom_attrs.get('negcio_crm', ''),
        'cw_lead_link': custom_attrs.get('link_crm', ''),
        
        # ticket custom attrs
        'cw_ticket_id': custom_attrs.get('ticket_id', ''),
        'cw_ticket_name': custom_attrs.get('assunto_ticket', ''),
        'cw_ticket_stage': custom_attrs.get('estagio_ticket', ''),
        'cw_ticket_link': custom_attrs.get('link_ticket', ''),
    }


def lead_search(data):
    Lead = env['crm.lead']

    lead_id = data.get('cw_lead_id')
    cw_id = data.get('cw_conversation_id')

    if lead_id:
        try:
            return Lead.browse(int(lead_id))
        except Exception:
            pass
    if cw_id:
        return Lead.search([('chatwoot_conversation_id', '=', cw_id)], limit=1)
    return None


def _ensure_partner_from_data(data):
    Partner = env['res.partner']
    name = data.get('cw_sender_name') or 'Cliente'
    phone = data.get('cw_sender_phone') or False
    email = data.get('cw_sender_email') or False
    phone_clean = phone.lstrip('+') if phone else False

    partner = False
    cw_contact_id = data.get('cw_contact_id')
    if cw_contact_id:
        partner = Partner.search([('chatwoot_contact_id', '=', cw_contact_id)], limit=1)
        if partner:
            return partner

    if phone_clean:
        # try exact match first
        partner = Partner.search([('phone', '=', phone_clean)], limit=1)
        if partner:
            return partner

        # fallback: search by last 4 digits using ORM candidates and normalize stored phone/mobile
        try:
            import re
            digits = re.sub(r"\D", "", phone_clean)
            last4 = digits[-4:]
            last8 = digits[-8:]
            if last4:
                # find candidates that contain the last4 sequence, collect normalized nums
                domain = ['|', ('phone', 'ilike', last4), ('mobile', 'ilike', last4)]
                candidates = Partner.search(domain, limit=50)
                normalized = []  # list of tuples (partner, normalized_number)
                for p in candidates:
                    for num in (p.phone or '', p.mobile or ''):
                        num_digits = re.sub(r"\D", "", num)
                        if num_digits:
                            normalized.append((p, num_digits))

                # prefer strict match on last 8 digits from the normalized list
                if last8:
                    for p, nd in normalized:
                        if nd.endswith(last8):
                            return p

                # as a fallback, if nothing matched by 8, return first candidate that endswith last4
                for p, nd in normalized:
                    if nd.endswith(last4):
                        return p
        except Exception:
            # don't block processing on regex/search issues; fallback to creating partner
            pass

    vals = {'name': name}
    if phone_clean:
        vals['phone'] = phone_clean
    if email:
        vals['email'] = email
    if cw_contact_id:
        vals['chatwoot_contact_id'] = cw_contact_id

    return Partner.create(vals)


def lead_create(data):
    Lead = env['crm.lead']
    Users = env['res.users']

    partner = None
    try:
        partner = _ensure_partner_from_data(data)
    except Exception:
        partner = None

    agent = None
    if data.get('cw_agent_id'):
        try:
            aid = int(data.get('cw_agent_id'))
        except Exception:
            aid = data.get('cw_agent_id')
        try:
            agent = Users.search([('chatwoot_agent_id', '=', aid)], limit=1)
        except Exception:
            agent = None

    vals = {
        'name': data.get('cw_lead_name') or f"Lead de {getattr(partner, 'name', 'cliente')}",
        'partner_id': partner.id if partner else False,
        'chatwoot_conversation_id': data.get('cw_conversation_id'),
    }
    if agent and agent.exists():
        vals['user_id'] = agent.id

    # extra fields could be added here as needed
    return Lead.create(vals)


def lead_update(data):
    Lead = env['crm.lead']
    Users = env['res.users']

    cw_id = data.get('cw_conversation_id')
    lead = Lead.search([('chatwoot_conversation_id', '=', cw_id)], limit=1)
    if not lead:
        return None

    agent = None
    if data.get('cw_agent_id'):
        try:
            aid = int(data.get('cw_agent_id'))
        except Exception:
            aid = data.get('cw_agent_id')
        try:
            agent = Users.search([('chatwoot_agent_id', '=', aid)], limit=1)
        except Exception:
            agent = None

    # map incoming keys to model fields
    FIELD_MAP = {
        'cw_lead_name': 'name',
        'cw_lead_stage': 'stage_id',
        'cw_lead_link': 'link',
        'cw_agent_id': 'user_id',
        'cw_conversation_id': 'chatwoot_conversation_id',
    }

    current_vals = {
        'name': lead.name,
        'user_id': lead.user_id.id if lead.user_id else False,
        'stage_id': lead.stage_id.id if lead.stage_id else False,
        'chatwoot_conversation_id': lead.chatwoot_conversation_id,
    }

    vals = {}
    for data_key, model_field in FIELD_MAP.items():
        if data_key not in data:
            continue
        new = data[data_key]
        try:
            # if payload gives dict with id
            if isinstance(new, dict) and 'id' in new:
                new = new['id']
        except Exception:
            pass
        if new in (None, ''):
            continue
        # use browsed records for relational fields
        if model_field == 'user_id':
            new = agent.id if agent and agent.exists() else False
        # normalize numeric strings
        try:
            if isinstance(new, str) and new.isdigit():
                new = int(new)
        except Exception:
            pass
        if current_vals.get(model_field) != new:
            vals[model_field] = new

    if vals:
        lead.write(vals)
    return lead


def process_payload(data):
    # data must be normalized before calling this
    lead = lead_search(data)
    if lead and lead.exists():
        return lead_update(data) or lead
    return lead_create(data)


payload = request.get('json') if isinstance(request, dict) else request['json']
data = normalize(payload)

if data:
    lead = process_payload(data)
    if lead:
        result = {
            'ok': True,
            'lead_id': lead.id,
            'lead_name': lead.name,
        }
    else:
        result = {
            'ok': False,
            'message': 'Não foi possível criar/atualizar o lead',
        }
else:
    result = {
        'ok': False,
        'message': 'Payload inválido',
    }

