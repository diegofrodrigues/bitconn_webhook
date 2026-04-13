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
    }

def assign_lead(lead_id, team_id=None, agent_id=None):
    """
    Atribui time e/ou agente a um lead no Odoo baseado nos IDs do Chatwoot

    Args:
        lead_id: ID do lead no Odoo
        team_id: ID do time no Chatwoot (opcional)
        agent_id: ID do agente no Chatwoot (opcional)

    Returns:
        Lead objeto se encontrado e atualizado, None se não encontrado
    """
    Lead = env['crm.lead'].sudo()

    # Verifica se o lead existe
    lead = Lead.browse(lead_id)
    if not lead.exists():
        return None

    vals = {}

    # Atribui time se fornecido
    if team_id is not None:
        Team = env['crm.team'].sudo()
        team = Team.search([('chatwoot_team_id', '=', team_id)], limit=1)
        if team and team.id != (lead.team_id.id if lead.team_id else False):
            vals['team_id'] = team.id

    # Atribui agente se fornecido
    if agent_id is not None:
        User = env['res.users'].sudo()
        user = None
        # Primeiro, tenta encontrar pelo campo chatwoot_agent_id
        try:
            # se agent_id for numérico, tente como int primeiro
            try:
                agent_key = int(agent_id)
            except Exception:
                agent_key = agent_id
            user = User.search([('chatwoot_agent_id', '=', agent_key)], limit=1)
        except Exception:
            user = None
        # Se não encontrou, tenta interpretar agent_id como ID do usuário Odoo
        if not user:
            try:
                uid = int(agent_id)
                u = User.browse(uid)
                if u and u.exists():
                    user = u
            except Exception:
                user = None
        if user and user.id != (lead.user_id.id if lead.user_id else False):
            vals['user_id'] = user.id

    # Aplica as atualizações se houver algo para atualizar
    if vals:
        lead.write(vals)

    return lead

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

def process_payload(data):
    # data must be normalized before calling this
    lead = lead_search(data)
    if not lead or not lead.exists():
        return None

    team_id = data.get('cw_team_id')
    agent_id = data.get('cw_agent_id')
    try:
        team_id_int = int(team_id) if team_id else None
    except Exception:
        team_id_int = None
    try:
        agent_id_int = int(agent_id) if agent_id else None
    except Exception:
        agent_id_int = None

    return assign_lead(lead.id, team_id=team_id_int, agent_id=agent_id_int)


# Processamento principal
payload = request.get('json') if isinstance(request, dict) else request['json']
data = normalize(payload)

if data:
    found_lead = process_payload(data)
    if found_lead:
        result = {
            'ok': True,
            'lead_id': found_lead.id,
            'lead_name': found_lead.name,
            'team_id': found_lead.team_id.id if found_lead.team_id else None,
            'team_name': found_lead.team_id.name if found_lead.team_id else None,
            'agent_id': found_lead.user_id.id if found_lead.user_id else None,
            'agent_name': found_lead.user_id.name if found_lead.user_id else None,
        }
    else:
        result = {
            'ok': False,
            'message': 'Lead not found or not assigned',
        }
else:
    result = {
        'ok': False,
        'message': 'Payload inválido',
    }
