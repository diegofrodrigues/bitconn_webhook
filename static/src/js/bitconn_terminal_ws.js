/* WebSocket-based xterm integration for Bitconn Webhook
   - Connects to dedicated WebSocket terminal service
   - Binary frames for PTY I/O (efficient, no base64)
   - JWT token authentication from Odoo
   - Best practices: proper cleanup, resize handling, keepalive
 */
(function () {
    'use strict';

    function initOnce(container) {
        if (!container || container._bitconn_init) {
            return;
        }
        container._bitconn_init = true;

        var termEl = container.querySelector('#bitconn_terminal');
        if (!termEl) {
            termEl = document.getElementById('bitconn_terminal');
        }
        if (!termEl) { return; }

        var Terminal = window.Terminal || window.XTerm || null;
        if (!Terminal) {
            console.warn('[bitconn_terminal] xterm not available');
            termEl.innerText = 'xterm.js not loaded';
            return;
        }
        var term = new Terminal({cursorBlink: true});
        
        term.open(termEl);
        
        // Load FitAddon if available
        var fitAddon = null;
        try {
            var Fit = window.FitAddon || (window.FitAddon && window.FitAddon.FitAddon) || window.fit;
            if (Fit) {
                try {
                    fitAddon = (typeof Fit === 'function') ? new Fit() : new Fit.FitAddon();
                } catch (e) {
                    try { fitAddon = new Fit.FitAddon(); } catch (ee) {}
                }
                if (fitAddon && term.loadAddon) {
                    try { term.loadAddon(fitAddon); fitAddon.fit(); } catch (e) {}
                }
            }
        } catch (e) {}
        
        // Ensure fit runs after layout settles, then show welcome
        var _welcomeShown = false;
        function fitAndWelcome() {
            try { if (fitAddon && fitAddon.fit) { fitAddon.fit(); } } catch(e) {}
            if (!_welcomeShown) {
                _welcomeShown = true;
                showWelcome();
            }
        }
        try {
            setTimeout(fitAndWelcome, 80);
        } catch(e) {
            showWelcome();
            _welcomeShown = true;
        }
        
        // Configure xterm element
        var xtermEl = term.element || (term._core && term._core.element) || termEl;
        try {
            xtermEl.tabIndex = 0;
            xtermEl.style.outline = 'none';
        } catch (e) {}
        
        try { term.focus(); } catch (e) {}
        xtermEl.addEventListener('click', function () { try { term.focus(); } catch (e) {} });
        
        // State
        var ws = null;
        var wsToken = null;
        var wsUrl = null;
        var bannerEl = container.querySelector('#bitconn_terminal_banner');
        var _onDataDisposable = null; // track onData handler for cleanup

        function showBanner(msg) {
            try {
                if (!bannerEl) { return; }
                bannerEl.style.display = '';
                bannerEl.textContent = msg || 'Session expired. Click Open Shell to start a new session.';
            } catch (e) {}
        }

        function hideBanner() {
            try { if (bannerEl) { bannerEl.style.display = 'none'; } } catch (e) {}
        }

        function setButtonsState(running) {
            var connectBtn = container.querySelector('.o_bitconn_terminal_connect');
            var shellBtn = container.querySelector('.o_bitconn_terminal_shell');
            var disconnectBtn = container.querySelector('.o_bitconn_terminal_disconnect');
            
            if (connectBtn) {
                connectBtn.style.display = running ? 'none' : '';
            }
            if (shellBtn) {
                shellBtn.style.display = running ? 'none' : '';
            }
            if (disconnectBtn) {
                disconnectBtn.style.display = running ? '' : 'none';
            }
        }

        function showWelcome() {
            try {
                var banner = '';
                // ASCII art logo em azul
                banner += '\x1b[1;34m'
                banner += '┓ •                        \r\n';
                banner += '┣┓┓╋┏┏┓┏┓┏┓  ╋┏┓┏┓┏┳┓┓┏┓┏┓┃\r\n';
                banner += '┗┛┗┗┗┗┛┛┗┛┗  ┗┗ ┛ ┛┗┗┗┛┗┗┻┗\r\n';
                banner += '\x1b[0m\r\n';
                
                banner += 'Welcome to the terminal\r\n\r\n';
                banner += 'Use the \x1b[1;34mConnect\x1b[0m button to connect to bash terminal\r\n';
                banner += 'Use the \x1b[1;34mShell\x1b[0m button to connect to Odoo shell\r\n\r\n';
                
                try { term.writeln(''); } catch (e) {}
                term.write(banner);
                try { term.focus(); } catch (e) {}
            } catch (e) {
                try { term.writeln('Welcome to Bitconn Terminal (WebSocket)'); } catch (e) {}
            }
        }

        // showWelcome is called after fitAddon runs (see setTimeout above)

        function startSession(shellMode) {
            if (ws) { return; }
            shellMode = shellMode || 'bash';
            
            fetch('/bitconn_webhook/terminal/get_ws_token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    method: 'call',
                    params: {shell_mode: shellMode},
                    id: Math.random()
                })
            })
            .then(function(r) { 
                if (!r.ok) {
                    throw new Error('HTTP ' + r.status);
                }
                return r.json(); 
            })
            .then(function(response) {
                var data = response.result || response;
                
                if (data.error) {
                    term.writeln('\r\n[ERROR] ' + data.error);
                    console.error('[bitconn_terminal] Server error:', data.error);
                    return;
                }
                
                wsToken = data.token;
                wsUrl = data.ws_url;
                
                if (!wsToken || !wsUrl) {
                    console.error('[bitconn_terminal] Invalid response - missing token or ws_url');
                    term.writeln('\r\n[ERROR] Invalid server response');
                    return;
                }
                
                // Connect WebSocket
                connectWebSocket();
            })
            .catch(function(err) {
                console.error('[bitconn_terminal] Fetch error:', err);
                term.writeln('\r\n[ERROR] Failed to get token: ' + String(err));
            });
        }

        function connectWebSocket() {
            if (!wsUrl || !wsToken) { 
                console.error('[bitconn_terminal] Missing wsUrl or wsToken');
                return; 
            }
            
            var fullUrl = wsUrl + '?token=' + encodeURIComponent(wsToken);
            
            try {
                ws = new WebSocket(fullUrl);
                ws.binaryType = 'arraybuffer';
                
                ws.onopen = function() {
                    hideBanner();
                    setButtonsState(true);
                    
                    // Register input handlers AFTER connection is open
                    registerInputHandlers();
                    
                    // Send initial resize
                    sendResize();
                    
                    // Focus terminal
                    try { term.focus(); } catch(e) {}
                    try { if (fitAddon && fitAddon.fit) { fitAddon.fit(); sendResize(); } } catch(e) {}
                };
                
                ws.onmessage = function(event) {
                    // Binary data from PTY
                    if (event.data instanceof ArrayBuffer) {
                        var bytes = new Uint8Array(event.data);
                        var text = new TextDecoder().decode(bytes);
                        try { term.write(text); } catch(e) {}
                        try { term.focus(); } catch(e) {}
                    }
                };
                
                ws.onerror = function(error) {
                    console.error('[bitconn_terminal] WebSocket error', error);
                };
                
                ws.onclose = function(event) {
                    
                    // Reset terminal to initial state
                    resetTerminal();
                    
                    // Show appropriate message for errors only
                    if (event.code === 1008) {
                        showBanner('Authentication failed. Click Connect to retry.');
                    } else if (event.code !== 1000 && event.code !== 1001) {
                        showBanner('Connection closed unexpectedly. Click Connect to reconnect.');
                    }
                };
                
            } catch(e) {
                term.writeln('\r\n[ERROR] Failed to connect WebSocket: ' + String(e));
            }
        }

        function sendInput(data) {
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                return;
            }
            try {
                var bytes = new TextEncoder().encode(data);
                ws.send(bytes);
            } catch(e) {
                console.error('[bitconn_terminal] Failed to send input', e);
            }
        }

        function sendResize() {
            if (!ws || ws.readyState !== WebSocket.OPEN) { return; }
            try {
                var rows = term.rows || 24;
                var cols = term.cols || 80;
                ws.send(JSON.stringify({
                    type: 'resize',
                    rows: rows,
                    cols: cols
                }));
            } catch(e) {}
        }

        function closeSession() {
            // Dispose input handler to prevent ghost writes
            if (_onDataDisposable && typeof _onDataDisposable.dispose === 'function') {
                _onDataDisposable.dispose();
                _onDataDisposable = null;
            }
            if (ws) {
                try { ws.close(); } catch(e) {}
                ws = null;
            }
            wsToken = null;
            wsUrl = null;
            setButtonsState(false);
        }
        
        function resetTerminal() {
            closeSession();
            term.clear();
            showWelcome();
            hideBanner();
        }

        // Function to register input handlers (called after WebSocket connects)
        function registerInputHandlers() {
            
            // Dispose previous handler to avoid duplicates on reconnect
            if (_onDataDisposable && typeof _onDataDisposable.dispose === 'function') {
                _onDataDisposable.dispose();
                _onDataDisposable = null;
            }
            
            // Attach xterm input handler
            if (typeof term.onData === 'function') {
                _onDataDisposable = term.onData(function(data) {
                    sendInput(data);
                });
            } else if (typeof term.onKey === 'function') {
                _onDataDisposable = term.onKey(function(ev) {
                    var dom = ev.domEvent || {};
                    var seq = '';
                    if (dom.key === 'Enter') { seq = '\r'; }
                    else if (dom.key === 'Backspace') { seq = '\x7f'; }
                    else if (dom.key === 'ArrowUp') { seq = '\x1b[A'; }
                    else if (dom.key === 'ArrowDown') { seq = '\x1b[B'; }
                    else if (dom.key === 'ArrowLeft') { seq = '\x1b[D'; }
                    else if (dom.key === 'ArrowRight') { seq = '\x1b[C'; }
                    else if (ev.key && ev.key.length === 1) { seq = ev.key; }
                    if (seq) { sendInput(seq); }
                });
            }
        }

        // Paste support
        xtermEl.addEventListener('paste', function(ev) {
            try {
                var text = (ev.clipboardData || window.clipboardData).getData('text');
                if (text) { sendInput(text); }
                ev.preventDefault();
            } catch(e) {}
        });

        // Buttons
        var connectBtn = container.querySelector('.o_bitconn_terminal_connect');
        if (connectBtn) {
            connectBtn.addEventListener('click', function(ev) {
                ev.preventDefault();
                term.clear();
                startSession('bash');
                try { term.focus(); } catch(e) {}
            });
        }
        
        var shellBtn = container.querySelector('.o_bitconn_terminal_shell');
        if (shellBtn) {
            shellBtn.addEventListener('click', function(ev) {
                ev.preventDefault();
                term.clear();
                startSession('odoo');
                try { term.focus(); } catch(e) {}
            });
        }
        
        var disconnectBtn = container.querySelector('.o_bitconn_terminal_disconnect');
        if (disconnectBtn) {
            disconnectBtn.addEventListener('click', function(ev) {
                ev.preventDefault();
                resetTerminal();
            });
        }
        
        var clearBtn = container.querySelector('.o_bitconn_terminal_clear');
        if (clearBtn) {
            clearBtn.addEventListener('click', function(ev) {
                ev.preventDefault();
                if (!ws) {
                    term.clear();
                    showWelcome();
                } else {
                    term.clear();
                }
            });
        }

        // Fullscreen toggle
        var fullscreenBtn = container.querySelector('.o_bitconn_terminal_fullscreen');
        var _isFullscreen = false;
        var _initialRows = term.rows || 24;
        var _initialCols = term.cols || 80;
        var _savedContainerHeight = container.offsetHeight;
        function toggleFullscreen() {
            _isFullscreen = !_isFullscreen;
            if (_isFullscreen) {
                _savedContainerHeight = container.offsetHeight;
                container.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:10000;background:#000;padding:12px;box-sizing:border-box;display:flex;flex-direction:column;';
                termEl.style.cssText = 'flex:1;overflow:hidden;';
                if (fullscreenBtn) {
                    fullscreenBtn.querySelector('i').className = 'fa fa-compress me-1';
                    fullscreenBtn.childNodes[1].textContent = 'Exit';
                }
            } else {
                container.style.cssText = '';
                termEl.style.cssText = '';
                // Force terminal back to initial size
                try { term.resize(_initialCols, _initialRows); } catch(e) {}
                if (fullscreenBtn) {
                    fullscreenBtn.querySelector('i').className = 'fa fa-expand me-1';
                    fullscreenBtn.childNodes[1].textContent = 'Fullscreen';
                }
            }
            setTimeout(function() {
                if (_isFullscreen) {
                    try { if (fitAddon && fitAddon.fit) { fitAddon.fit(); } } catch(e) {}
                } else {
                    try { term.resize(_initialCols, _initialRows); } catch(e) {}
                }
                sendResize();
                try { term.focus(); } catch(e) {}
            }, 100);
        }
        if (fullscreenBtn) {
            fullscreenBtn.addEventListener('click', function(ev) {
                ev.preventDefault();
                toggleFullscreen();
            });
        }
        // Exit fullscreen with Escape
        document.addEventListener('keydown', function(ev) {
            if (ev.key === 'Escape' && _isFullscreen) {
                toggleFullscreen();
            }
        });

        // Resize handling
        window.addEventListener('resize', function() {
            try {
                if (fitAddon && fitAddon.fit) { fitAddon.fit(); }
                sendResize();
            } catch(e) {}
        });

        // MutationObserver for container visibility (tab switch)
        var mo = new MutationObserver(function() {
            try {
                if (container.offsetParent !== null) {
                    if (fitAddon && fitAddon.fit) { fitAddon.fit(); }
                    sendResize();
                    if (!_welcomeShown) {
                        _welcomeShown = true;
                        showWelcome();
                    }
                    try { term.focus(); } catch(e) {}
                }
            } catch(e) {}
        });
        mo.observe(container, {attributes: true, childList: true, subtree: false});

        // Cleanup on unload
        window.addEventListener('beforeunload', function() { closeSession(); });
    }

    // Poll for terminal container — re-check periodically to handle SPA re-renders
    function waitForContainer() {
        var selector = '.o_bitconn_terminal_container';
        var found = document.querySelectorAll(selector);
        if (found && found.length) {
            found.forEach(function(c) {
                // Re-init if DOM node was replaced by Odoo (detached from document)
                if (c._bitconn_init && !document.body.contains(c._bitconn_ref || c)) {
                    c._bitconn_init = false;
                }
                initOnce(c);
                c._bitconn_ref = c;
            });
        }
        setTimeout(waitForContainer, 1000);
    }

    // Start
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        waitForContainer();
    } else {
        document.addEventListener('DOMContentLoaded', waitForContainer);
    }
})();
