from odoo import http
from odoo.http import request
from odoo.tools import config as odoo_config
import os
import pty
import subprocess
import threading
import queue
import uuid
import time
import traceback
import logging
import sys
import json
import base64
import hmac
import hashlib
import asyncio
import struct
import fcntl
import termios
import signal
import shutil

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    _logger = logging.getLogger('bitconn_webhook.terminal')
    _logger.warning('websockets library not available, WebSocket terminal disabled')

_logger = logging.getLogger('bitconn_webhook.terminal')

SESSIONS = {}
WS_SESSIONS = {}  # WebSocket sessions
SESSION_TTL_DEFAULT = 60 * 60  # 1 hour
_CLEANER_STARTED = False
_WS_SERVER = None
_WS_SERVER_TASK = None
WS_SECRET_KEY = os.getenv('WS_SECRET_KEY', 'change-this-secret-key-in-production')
WS_HOST = os.getenv('WS_HOST', '127.0.0.1')
WS_PORT = int(os.getenv('WS_PORT', '8765'))


def _get_odoo_root():
    """Get Odoo root directory dynamically."""
    # Try to get from odoo module location
    try:
        import odoo
        odoo_path = os.path.dirname(odoo.__file__)
        return os.path.dirname(odoo_path)  # Parent of odoo package
    except:
        # Fallback to current working directory
        return os.getcwd()


def _get_odoo_bin():
    """Find odoo-bin or odoo executable."""
    # Check common locations
    odoo_root = _get_odoo_root()
    
    # Try odoo-bin in root
    odoo_bin = os.path.join(odoo_root, 'odoo-bin')
    if os.path.isfile(odoo_bin) and os.access(odoo_bin, os.X_OK):
        return odoo_bin
    
    # Try odoo-bin in PATH
    odoo_bin_path = shutil.which('odoo-bin')
    if odoo_bin_path:
        return odoo_bin_path
    
    # Try odoo in PATH
    odoo_path = shutil.which('odoo')
    if odoo_path:
        return odoo_path
    
    # Fallback: try to run as module
    return None


def _get_odoo_config():
    """Get current Odoo config file path."""
    # Get from running Odoo instance
    try:
        config_file = odoo_config.rcfile
        if config_file and os.path.isfile(config_file):
            return config_file
    except:
        pass
    
    # Fallback to common names
    for name in ['odoo.conf', 'openerp-server.conf']:
        if os.path.isfile(name):
            return name
    
    return None


def _get_working_dir():
    """Get appropriate working directory for shell."""
    # Use Odoo root directory (where odoo-bin is located)
    return _get_odoo_root()


def _verify_token(token):
    """Verify JWT-like token signed by Odoo."""
    try:
        parts = token.split('.')
        if len(parts) != 2:
            return None
        
        payload_b64, signature = parts
        expected_sig = hmac.new(
            WS_SECRET_KEY.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_sig):
            return None
        
        payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
        payload = json.loads(payload_json)
        
        if payload.get('exp', 0) < time.time():
            return None
        
        return payload
    except Exception as e:
        _logger.error(f"Token verification failed: {e}")
        return None


async def _read_pty_async(master_fd, websocket, session_id):
    """Read from PTY and send to WebSocket."""
    loop = asyncio.get_event_loop()
    try:
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, master_fd, 4096)
                if not data:
                    break
                await websocket.send(data)
            except OSError:
                break
    except (websockets.exceptions.ConnectionClosed, asyncio.CancelledError):
        pass
    finally:
        _logger.info(f"[{session_id}] PTY reader stopped")


async def _handle_websocket(websocket, path=None):
    """Handle WebSocket connection for terminal."""
    session_id = None
    master_fd = None
    proc = None
    reader_task = None
    
    try:
        # Parse token from query string (from websocket.request.path or legacy path arg)
        ws_path = path if path else (websocket.request.path if hasattr(websocket, 'request') else websocket.path)
        query = dict(param.split('=') for param in ws_path.split('?')[1].split('&') if '=' in param) if '?' in ws_path else {}
        token = query.get('token', '')
        
        payload = _verify_token(token)
        if not payload:
            await websocket.send(json.dumps({'error': 'invalid_token'}))
            await websocket.close(1008, 'Invalid token')
            return
        
        user_id = payload.get('user_id')
        shell_mode = payload.get('shell_mode', 'bash')
        session_id = f"ws_{user_id}_{int(time.time() * 1000)}"
        
        _logger.info(f"[{session_id}] New WebSocket connection from user {user_id}, shell_mode={shell_mode}")
        
        # Create PTY
        master_fd, slave_fd = pty.openpty()
        
        # Get initial size
        try:
            first_msg = await asyncio.wait_for(websocket.recv(), timeout=2.0)
            if isinstance(first_msg, str):
                msg = json.loads(first_msg)
                if msg.get('type') == 'resize':
                    rows = int(msg.get('rows', 24))
                    cols = int(msg.get('cols', 80))
                    winsize = struct.pack('HHHH', rows, cols, 0, 0)
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
        except asyncio.TimeoutError:
            pass
        
        # Start subprocess
        python_exe = sys.executable
        working_dir = _get_working_dir()
        
        if shell_mode == 'odoo':
            # Odoo shell
            odoo_bin = _get_odoo_bin()
            if odoo_bin:
                cmd = [python_exe, odoo_bin, 'shell', '--no-http']
                config_file = _get_odoo_config()
                if config_file:
                    cmd.extend(['-c', config_file])
            else:
                # Fallback: try to run odoo as module
                cmd = [python_exe, '-m', 'odoo', 'shell', '--no-http']
                config_file = _get_odoo_config()
                if config_file:
                    cmd.extend(['-c', config_file])
        else:
            # Bash shell
            cmd = ['/bin/bash', '-l']
        
        env = os.environ.copy()
        env['TERM'] = 'xterm-256color'
        env.setdefault('COLORTERM', 'truecolor')
        
        proc = subprocess.Popen(
            cmd, cwd=working_dir, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True, env=env, preexec_fn=os.setsid
        )
        os.close(slave_fd)
        
        WS_SESSIONS[session_id] = {
            'proc': proc,
            'master_fd': master_fd,
            'user_id': user_id,
            'created': time.time()
        }
        
        _logger.info(f"[{session_id}] Started shell PID={proc.pid}")
        
        reader_task = asyncio.create_task(_read_pty_async(master_fd, websocket, session_id))
        
        async for message in websocket:
            if isinstance(message, bytes):
                try:
                    os.write(master_fd, message)
                except OSError as e:
                    _logger.error(f"[{session_id}] Write failed: {e}")
                    break
            elif isinstance(message, str):
                try:
                    msg = json.loads(message)
                    if msg.get('type') == 'resize':
                        rows = int(msg.get('rows', 24))
                        cols = int(msg.get('cols', 80))
                        winsize = struct.pack('HHHH', rows, cols, 0, 0)
                        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
                except (json.JSONDecodeError, ValueError) as e:
                    _logger.error(f"[{session_id}] Invalid control message: {e}")
    
    except websockets.exceptions.ConnectionClosed:
        _logger.info(f"[{session_id}] Connection closed")
    except Exception as e:
        _logger.exception(f"[{session_id}] Error: {e}")
    finally:
        if reader_task:
            reader_task.cancel()
            try:
                await reader_task
            except asyncio.CancelledError:
                pass
        
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=2)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
        
        if master_fd is not None:
            try:
                os.close(master_fd)
            except Exception:
                pass
        
        if session_id in WS_SESSIONS:
            del WS_SESSIONS[session_id]
            _logger.info(f"[{session_id}] Cleaned up")


def _start_websocket_server():
    """Start WebSocket server in background thread."""
    if not WEBSOCKETS_AVAILABLE:
        _logger.warning('WebSocket server not started: websockets library not available')
        return
    
    global _WS_SERVER, _WS_SERVER_TASK
    
    def run_server():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def serve():
            global _WS_SERVER
            _WS_SERVER = await websockets.serve(
                _handle_websocket,
                WS_HOST,
                WS_PORT,
                ping_interval=20,
                ping_timeout=10
            )
            _logger.info(f"WebSocket terminal server started on {WS_HOST}:{WS_PORT}")
            await asyncio.Future()
        
        try:
            loop.run_until_complete(serve())
        except Exception as e:
            _logger.exception(f"WebSocket server error: {e}")
    
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    _logger.info('WebSocket server thread started')


def _reader_thread(master_fd, out_q, session_id):
    try:
        while True:
            try:
                data = os.read(master_fd, 1024)
            except OSError:
                break
            if not data:
                break
            out_q.put(data)
    finally:
        out_q.put(None)


def _session_cleaner():
    """Background thread that terminates and cleans sessions past their expiry."""
    while True:
        try:
            now = time.time()
            expired = []
            for sid, sess in list(SESSIONS.items()):
                exp = sess.get('expires_at')
                if exp and now > exp:
                    expired.append(sid)
            for sid in expired:
                try:
                    s = SESSIONS.pop(sid, None)
                    if not s:
                        continue
                    _logger.info('session expired cleanup session=%s', sid)
                    try:
                        proc = s.get('proc')
                        if proc and proc.poll() is None:
                            proc.terminate()
                    except Exception:
                        pass
                    try:
                        os.close(s.get('master'))
                    except Exception:
                        pass
                    try:
                        q = s.get('queue')
                        if q:
                            q.put(None)
                    except Exception:
                        pass
                except Exception:
                    _logger.exception('error while cleaning session %s', sid)
        except Exception:
            _logger.exception('session cleaner error')
        time.sleep(5)


class BitconnTerminal(http.Controller):
    def __init__(self):
        super().__init__()
        # Start WebSocket server once on first import
        global _WS_SERVER_TASK
        if _WS_SERVER_TASK is None and WEBSOCKETS_AVAILABLE:
            _WS_SERVER_TASK = True  # Mark as started
            _start_websocket_server()
    
    @http.route('/bitconn_webhook/terminal/get_ws_token', type='json', auth='user', methods=['POST'], csrf=False)
    def get_ws_token(self, shell_mode='bash', **kw):
        """Generate WebSocket token for terminal connection."""
        if not WEBSOCKETS_AVAILABLE:
            return {'error': 'WebSocket not available. Install websockets: pip install websockets'}
        
        try:
            user_id = request.env.uid
            ttl = int(kw.get('ttl', SESSION_TTL_DEFAULT))
            exp = int(time.time()) + ttl
            
            payload = {
                'user_id': user_id,
                'exp': exp,
                'shell_mode': shell_mode  # 'bash' or 'odoo'
            }
            payload_json = json.dumps(payload)
            payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
            
            signature = hmac.new(
                WS_SECRET_KEY.encode(),
                payload_b64.encode(),
                hashlib.sha256
            ).hexdigest()
            
            token = f"{payload_b64}.{signature}"
            ws_url = f"ws://{WS_HOST}:{WS_PORT}"
            
            return {
                'ok': True,
                'token': token,
                'ws_url': ws_url,
                'expires_at': exp
            }
        except Exception as e:
            _logger.exception('Failed to generate WS token')
            return {'error': str(e)}
    
    @http.route('/bitconn_webhook/terminal/start', type='http', auth='user', methods=['POST'], csrf=False)
    def start(self, **kw):
        # Return JSON response; requires authenticated user so SSE stream can reuse same session
        try:
            session_id = str(uuid.uuid4())
            master, slave = pty.openpty()
            # Build command dynamically
            odoo_bin = _get_odoo_bin()
            if odoo_bin:
                cmd = [sys.executable, odoo_bin, 'shell', '--no-http']
                config_file = _get_odoo_config()
                if config_file:
                    cmd.extend(['-c', config_file])
            else:
                # Fallback: try to run odoo as module
                cmd = [sys.executable, '-m', 'odoo', 'shell', '--no-http']
                config_file = _get_odoo_config()
                if config_file:
                    cmd.extend(['-c', config_file])
            
            env = os.environ.copy()
            env['TERM'] = env.get('TERM', 'xterm-256color')
            env.setdefault('COLORTERM', 'truecolor')
            # set initial window size if provided by client
            try:
                import fcntl, struct, termios
                rows = int(kw.get('rows') or 20)
                cols = int(kw.get('cols') or 80)
                winsize = struct.pack('HHHH', rows, cols, 0, 0)
                try:
                    fcntl.ioctl(master, termios.TIOCSWINSZ, winsize)
                except Exception:
                    try:
                        fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize)
                    except Exception:
                        pass
            except Exception:
                pass
            working_dir = _get_working_dir()
            proc = subprocess.Popen(cmd, cwd=working_dir, stdin=slave, stdout=slave, stderr=slave, close_fds=True, env=env)
            os.close(slave)
            out_q = queue.Queue()
            th = threading.Thread(target=_reader_thread, args=(master, out_q, session_id), daemon=True)
            th.start()
            ttl = int(kw.get('ttl') or SESSION_TTL_DEFAULT)
            SESSIONS[session_id] = {
                'proc': proc,
                'master': master,
                'thread': th,
                'queue': out_q,
                'created': time.time(),
                'expires_at': time.time() + ttl,
                'pid': getattr(proc, 'pid', None),
            }
            _logger.info('terminal started session=%s pid=%s', session_id, SESSIONS[session_id].get('pid'))
            # start cleaner thread once
            global _CLEANER_STARTED
            if not _CLEANER_STARTED:
                try:
                    t = threading.Thread(target=_session_cleaner, daemon=True)
                    t.start()
                    _CLEANER_STARTED = True
                except Exception:
                    _logger.exception('failed to start session cleaner')
            import json
            return request.make_response(json.dumps({'session_id': session_id}), headers=[('Content-Type', 'application/json')])
        except Exception as e:
            # return full traceback to aid debugging
            tb = traceback.format_exc()
            try:
                import logging
                logging.getLogger('bitconn_webhook.terminal').error('Failed to start terminal session: %s', tb)
            except Exception:
                pass
            import json
            return request.make_response(json.dumps({'error': 'Failed to start terminal', 'traceback': tb}), headers=[('Content-Type', 'application/json')], status=500)

    @http.route('/bitconn_webhook/terminal/stream/<string:session_id>', type='http', auth='user')
    def stream(self, session_id, **kw):
        _logger.debug('stream request for session=%s; sessions=%s', session_id, list(SESSIONS.keys()))
        sess = SESSIONS.get(session_id)
        if not sess:
            _logger.warning('stream: session not found %s', session_id)
            return request.make_response('Session not found', headers=[('Content-Type', 'text/plain')], status=404)

        # if session expired, inform client and cleanup
        exp = sess.get('expires_at')
        if exp and time.time() > exp:
            _logger.info('stream: session expired %s', session_id)
            def expired_stream():
                yield 'data: [EXPIRED]\n\n'
                yield 'data: [EOF]\n\n'
            # attempt cleanup
            try:
                s = SESSIONS.pop(session_id, None)
                if s:
                    try:
                        proc = s.get('proc')
                        if proc and proc.poll() is None:
                            proc.terminate()
                    except Exception:
                        pass
                    try:
                        os.close(s.get('master'))
                    except Exception:
                        pass
                    try:
                        q = s.get('queue')
                        if q:
                            q.put(None)
                    except Exception:
                        pass
            except Exception:
                _logger.exception('error cleaning expired session')
            return request.make_response(expired_stream(), headers=[('Content-Type', 'text/event-stream')])

        def event_stream():
            q = sess['queue']
            while True:
                item = q.get()
                if item is None:
                    yield 'data: [EOF]\n\n'
                    break
                # SSE requires text. Base64-encode raw bytes and prefix with a marker so
                # the client can decode binary-safe payloads (preserves ESC/control bytes).
                try:
                    import base64
                    b64 = base64.b64encode(item).decode('ascii')
                    yield 'data: b64:%s\n\n' % b64
                except Exception:
                    # fallback: send a safe replacement string
                    try:
                        txt = item.decode(errors='replace')
                        for chunk in txt.split('\n'):
                            yield 'data: %s\n' % chunk
                        yield '\n'
                    except Exception:
                        yield 'data: [UNAVAILABLE]\n\n'
            # cleanup after EOF
            try:
                proc = sess.get('proc')
                if proc and proc.poll() is None:
                    proc.terminate()
            except Exception:
                pass

        return request.make_response(event_stream(), headers=[('Content-Type', 'text/event-stream')])

    @http.route('/bitconn_webhook/terminal/sessions', type='json', auth='user')
    def list_sessions(self, **kw):
        # debug endpoint: list active session ids
        try:
            return {'sessions': list(SESSIONS.keys())}
        except Exception as e:
            _logger.exception('failed listing sessions')
            return {'error': str(e)}

    @http.route('/bitconn_webhook/terminal/resize/<string:session_id>', type='json', auth='user', methods=['POST'], csrf=False)
    def resize(self, session_id, **kw):
        sess = SESSIONS.get(session_id)
        if not sess:
            return {'error': 'session_not_found'}
        # check expiry
        exp = sess.get('expires_at')
        if exp and time.time() > exp:
            return {'error': 'session_expired'}
        master = sess.get('master')
        if master is None:
            return {'error': 'no_master_fd'}
        try:
            import fcntl, struct, termios
            rows = int(kw.get('rows') or 24)
            cols = int(kw.get('cols') or 80)
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            try:
                fcntl.ioctl(master, termios.TIOCSWINSZ, winsize)
            except Exception:
                # best-effort on slave as fallback
                pass
            return {'ok': True}
        except Exception as e:
            return {'error': str(e)}

    @http.route('/bitconn_webhook/terminal/input/<string:session_id>', type='http', auth='user', methods=['POST'], csrf=False)
    def input(self, session_id, data=None, **kw):
        """Accept input for the PTY. Accepts JSON body {"data": "..."} or form-encoded.
        Using type='http' to be tolerant with fetch() requests from the frontend.
        """
        sess = SESSIONS.get(session_id)
        if not sess:
            return request.make_response('{"error":"session_not_found"}', headers=[('Content-Type', 'application/json')], status=404)
        # check expiry
        exp = sess.get('expires_at')
        if exp and time.time() > exp:
            # cleanup same as cleaner
            try:
                s = SESSIONS.pop(session_id, None)
                if s:
                    try:
                        proc = s.get('proc')
                        if proc and proc.poll() is None:
                            proc.terminate()
                    except Exception:
                        pass
                    try:
                        os.close(s.get('master'))
                    except Exception:
                        pass
                    try:
                        q = s.get('queue')
                        if q:
                            q.put(None)
                    except Exception:
                        pass
            except Exception:
                _logger.exception('error cleaning expired session on input')
            return request.make_response('{"error":"session_expired"}', headers=[('Content-Type', 'application/json')], status=410)
        try:
            payload = data
            # attempt to parse raw JSON body if `data` param not provided
            if payload is None:
                try:
                    raw = request.httprequest.get_data(as_text=True)
                    if raw:
                        import json as _json
                        try:
                            j = _json.loads(raw)
                            payload = j.get('data') if isinstance(j, dict) else None
                        except Exception:
                            # handle form-encoded like data={...}
                            try:
                                from urllib.parse import parse_qs
                                q = parse_qs(raw)
                                if 'data' in q:
                                    payload = q['data'][0]
                            except Exception:
                                payload = None
                except Exception:
                    payload = None

            try:
                _logger.debug('terminal input session=%s payload=%r', session_id, (payload[:200] + '...') if isinstance(payload, str) and len(payload) > 200 else payload)
            except Exception:
                _logger.debug('terminal input session=%s (failed to repr payload)', session_id)

            # ignore empty payloads
            if payload is None:
                _logger.debug('terminal input: empty payload for session=%s; ignoring', session_id)
                return request.make_response('{"ok": true}', headers=[('Content-Type', 'application/json')])

            # robust write: accept str or bytes
            if isinstance(payload, bytes):
                os.write(sess['master'], payload)
            elif isinstance(payload, str):
                os.write(sess['master'], payload.encode())
            else:
                os.write(sess['master'], str(payload).encode())
            return request.make_response('{"ok": true}', headers=[('Content-Type', 'application/json')])
        except Exception as e:
            _logger.exception('failed writing to terminal master for session=%s', session_id)
            import json as _json
            return request.make_response(_json.dumps({'error': str(e)}), headers=[('Content-Type', 'application/json')], status=500)

    @http.route('/bitconn_webhook/terminal/stop', type='json', auth='user')
    def stop(self, session_id=None, **kw):
        sess = SESSIONS.pop(session_id, None)
        if not sess:
            return {'error': 'session_not_found'}
        try:
            proc = sess.get('proc')
            if proc and proc.poll() is None:
                proc.terminate()
        except Exception:
            pass
        try:
            os.close(sess.get('master'))
        except Exception:
            pass
        return {'ok': True}
