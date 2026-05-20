
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

        # ticket custom attrs
        'cw_ticket_id': custom_attrs.get('ticket_id', ''),
        'cw_ticket_name': custom_attrs.get('assunto_ticket', ''),
        'cw_ticket_stage': custom_attrs.get('estagio_ticket', ''),
        'cw_ticket_link': custom_attrs.get('link_ticket', ''),
    }


def ticket_search(data):
    Ticket = env['helpdesk.ticket']

    ticket_id = data.get('cw_ticket_id')
    cw_id = data.get('cw_conversation_id')

    if ticket_id:
        try:
            return Ticket.browse(int(ticket_id))
        except Exception:
            pass
    if cw_id:
        return Ticket.search([('chatwoot_conversation_id', '=', cw_id)], limit=1)
    return None


def _ensure_partner_from_data(data):
    Partner = env['res.partner']
    name = data.get('cw_sender_name') or 'Cliente'
    phone = data.get('cw_sender_phone') or False
    email = data.get('cw_sender_email') or False
    phone_clean = phone.lstrip('+') if phone else False
    cw_contact_id = data.get('cw_contact_id')

    # prefer partner linked by chatwoot_contact_id
    if cw_contact_id:
        partner = Partner.search([('chatwoot_contact_id', '=', cw_contact_id)], limit=1)
        if partner:
            return partner

    if phone_clean:
        partner = Partner.search([('phone', '=', phone_clean)], limit=1)
        if partner:
            return partner

    vals = {'name': name}
    if phone_clean:
        vals['phone'] = phone_clean
    if email:
        vals['email'] = email
    if cw_contact_id:
        vals['chatwoot_contact_id'] = cw_contact_id

    return Partner.create(vals)


def ticket_create(data):
    Team = env['helpdesk.team']
    Partner = env['res.partner']
    Users = env['res.users']

    team = Team.browse(data.get('cw_team_id') or False)
    partner = None
    try:
        partner = _ensure_partner_from_data(data)
    except Exception:
        partner = Partner.browse(data.get('cw_contact_id') or False)
    agent = Users.browse(data.get('cw_agent_id') or False) if data.get('cw_agent_id') else None

    vals = {
        'name': data.get('cw_ticket_name') or f"ticket de {getattr(partner, 'name', 'cliente')}",
        'partner_id': partner.id or False,
        'partner_phone': data.get('cw_sender_phone') or getattr(partner, 'phone', False),
        'team_id': team.id or False,
        'chatwoot_conversation_id': data.get('cw_conversation_id'),
    }
    if agent and agent.exists():
        vals['user_id'] = agent.id
    # vals.update({}) to extra fields
    return env['helpdesk.ticket'].create(vals)


def ticket_update(data):
    Ticket = env['helpdesk.ticket']
    Team = env['helpdesk.team']
    Users = env['res.users']

    cw_id = data.get('cw_conversation_id')
    ticket = Ticket.search([('chatwoot_conversation_id', '=', cw_id)], limit=1)
    if not ticket:
        return None

    # browse related records first (don't use raw ids)
    team = Team.browse(data.get('cw_team_id') or False)
    agent = Users.browse(data.get('cw_agent_id') or False) if data.get('cw_agent_id') else None

    ticket_vals = {
        'id': ticket.id,
        'name': ticket.name,
        'user_id': ticket.user_id.id if ticket.user_id else False,
        'team_id': ticket.team_id.id if ticket.team_id else False,
        'chatwoot_conversation_id': ticket.chatwoot_conversation_id,
    }

    FIELD_MAP = {
        'cw_ticket_name': 'name',
        'cw_ticket_stage': 'stage_id',
        'cw_ticket_link': 'link',
        'cw_agent_id': 'user_id',
        'cw_team_id': 'team_id',
        'cw_conversation_id': 'chatwoot_conversation_id',
    }

    vals = {}
    for data_key, model_field in FIELD_MAP.items():
        if data_key not in data:
            continue
        new = data[data_key]
        try:
            # handle dict with id
            if isinstance(new, dict) and 'id' in new:
                new = new['id']
        except Exception:
            pass
        if new in (None, ''):
            continue
        # use browsed records for relational fields
        if model_field == 'team_id':
            new = team.id or False
        elif model_field == 'user_id':
            new = agent.id or False
        # normalize numeric strings
        try:
            if isinstance(new, str) and new.isdigit():
                new = int(new)
        except Exception:
            pass
        if ticket_vals.get(model_field) != new:
            vals[model_field] = new

    if vals:
        ticket.write(vals)
    return ticket


def process_payload(data):
    # receives normalized data
    ticket = ticket_search(data)
    if ticket and ticket.exists():
        return ticket_update(data)
    return ticket_create(data)


payload = request.get('json') if isinstance(request, dict) else request['json']
data = normalize(payload)

if data:
    ticket = process_payload(data)
    if ticket:
        result = {
            'ok': True,
            'ticket_id': ticket.id,
            'ticket_name': ticket.name,
        }
    else:
        result = {
            'ok': False,
            'message': 'Não foi possível criar/atualizar o ticket',
        }
else:
    result = {
        'ok': False,
        'message': 'Payload inválido',
    }

