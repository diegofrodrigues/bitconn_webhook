Bitconn Webhook
================

Generic webhook to create, update and delete records in Odoo via secure HTTP JSON endpoints.

Overview
--------
- Plain HTTP JSON (no JSON-RPC).
- Auth by header token.
- Minimal search, and create/write/unlink/read helpers.
- Optional outbound sender + Server Action integration.

Endpoints
---------
- POST JSON: ``/bitconn/webhook/<webhook_uuid>``
- GET schema: ``/bitconn/webhook/<webhook_uuid>/schema?model=<model>&method=create|write``
- GET required: ``/bitconn/webhook/<webhook_uuid>/required?model=<model>&values=<json>``

Headers
-------
- Prefer: ``Authorization: Bearer <secret_key>``
- Fallback: ``Webhook-Key: <secret_key>``  (``X-Webhook-Key`` legacy also accepted)

Methods
-------
- ``create``: create a record with ``model`` and ``values``.
- ``write``: update records by ``ids`` or ``domain`` with ``values``.
- ``unlink``: delete by ``ids`` or ``domain`` (requires permission enabled).
- ``search``: return ids (or records if ``fields`` provided) with optional limit/offset.
- ``read``: read fields for given ``ids``.

Examples
--------

Create (curl)
^^^^^^^^^^^^^

.. code-block:: bash

   curl -X POST \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <secret_key>" \
     -d '{
           "method": "create",
           "model": "res.partner",
           "values": {"name": "John Doe", "email": "john@example.com"}
         }' \
     http://localhost:8069/bitconn/webhook/<webhook_uuid>

Search ids (curl)
^^^^^^^^^^^^^^^^^

.. code-block:: bash

   curl -X POST \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <secret_key>" \
     -d '{
           "method": "search",
           "model": "res.partner",
           "domain": [["email","=","cliente@example.com"]],
           "limit": 5
         }' \
     http://localhost:8069/bitconn/webhook/<webhook_uuid>

Schema (curl)
^^^^^^^^^^^^^

.. code-block:: bash

   curl -X GET \
     -H "Authorization: Bearer <secret_key>" \
     "http://localhost:8069/bitconn/webhook/<webhook_uuid>/schema?model=res.partner&method=create"

Required (curl)
^^^^^^^^^^^^^^^

.. code-block:: bash

   curl -G \
     -H "Authorization: Bearer <secret_key>" \
     --data-urlencode 'model=res.partner' \
     --data-urlencode 'values={"type":"contact"}' \
     "http://localhost:8069/bitconn/webhook/<webhook_uuid>/required"
