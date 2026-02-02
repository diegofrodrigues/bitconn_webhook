/* Simplified xterm integration for Bitconn Webhook
   - Uses xterm.js from CDN (Terminal global)
   - Starts session via POST to /bitconn_webhook/terminal/start
   - Connects to SSE /bitconn_webhook/terminal/stream/<session_id>
   - Sends input via /bitconn_webhook/terminal/input/<session_id>
 */
(function () {
    'use strict';

    function base64ToString(b64) {
        try {
            return atob(b64);
        } catch (e) {
            return '';
        }
    }

    function initOnce(container) {
        if (!container || container._bitconn_init) {
            return;
        }
        container._bitconn_init = true;

        var termEl = container.querySelector('#bitconn_terminal');
        if (!termEl) {
            // fallback: find by id anywhere inside
            termEl = document.getElementById('bitconn_terminal');
        }
        if (!termEl) { return; }

        var Terminal = window.Terminal || window.XTerm || null;
        if (!Terminal) {
            console.warn('xterm not available');
            termEl.innerText = 'xterm.js not loaded';
            return;
        }

        console.debug('[bitconn_terminal] initOnce for container', container);
        var term = new Terminal({cursorBlink: true});
        // apply sensible visual defaults in case xterm.css not loaded yet
        try {
            term.setOption && term.setOption('fontFamily', 'Menlo, Monaco, "Courier New", monospace');
            term.setOption && term.setOption('fontSize', 10);
            // term.setOption && term.setOption('theme', {background: '#000000', foreground: '#ffffff', cursor: '#ffffff'});
        } catch (e) {}
        term.open(termEl);
        // sizing and visuals are handled via CSS (bitconn_terminal.css)
        // try to load FitAddon if available to auto-fit terminal to container
        var fitAddon = null;
        try {
            var Fit = window.FitAddon || window.FitAddon && window.FitAddon.FitAddon || window.FitAddon;
            if (!Fit && window.fit) { Fit = window.fit; }
            if (Fit) {
                try { fitAddon = (typeof Fit === 'function') ? new Fit() : new Fit.FitAddon(); } catch (e) { try { fitAddon = new Fit.FitAddon(); } catch (ee) {} }
                if (fitAddon && term.loadAddon) { try { term.loadAddon(fitAddon); fitAddon.fit(); } catch (e) {} }
            }
        } catch (e) {}
        // ensure fit runs after a short delay to let layout settle
        try { setTimeout(function(){ if (fitAddon && fitAddon.fit) { try{ fitAddon.fit(); resizeSession(); }catch(e){} } }, 80); } catch(e){}
        // try to find the real xterm element created by xterm.js
        var xtermEl = term.element || (term._core && term._core.element) || termEl;
        // allow focus and keyboard events on the actual xterm element
        try {
            xtermEl.tabIndex = 0;
            xtermEl.style.outline = 'none';
        } catch (e) {}
        // focus terminal so key events are captured
        try { term.focus(); console.debug('[bitconn_terminal] term.focus() called'); } catch (e) {}
        xtermEl.addEventListener('click', function () { try { term.focus(); } catch (e) {} });
        // support paste (send pasted text to backend)
        xtermEl.addEventListener('paste', function (ev) {
            try {
                var text = (ev.clipboardData || window.clipboardData).getData('text');
                if (text) { sendInput(text); }
                ev.preventDefault();
            } catch (e) {}
        });

        var sessionId = null;
        var evtSource = null;
        var pendingInitialInput = null;
        var inputBuffer = '';
        var bannerEl = container.querySelector('#bitconn_terminal_banner');

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
            var openBtn = container.querySelector('.o_bitconn_terminal_open');
            if (openBtn) {
                openBtn.textContent = running ? 'Connected' : 'Open Shell';
                openBtn.classList.toggle('disabled', running);
                openBtn.style.pointerEvents = running ? 'none' : '';
            }
        }

        function showWelcome() {
            try {
                // ANSI colored banner similar to Odoo.sh welcome
                var banner = '';
                banner += '\x1b[1;35mWelcome to bitconn.sh\x1b[0m\r\n\r\n';
                banner += 'You are connected to your instance via web terminal.\r\n';
                // banner += 'Overview of useful commands:\r\n\r\n';
                // banner += '  $ \x1b[1;33modoo-bin shell\x1b[0m\t Open an Odoo shell\r\n';
                // banner += '  $ \x1b[1;33modoo-update\x1b[0m\t Update modules in the database\r\n';
                // banner += '  $ \x1b[1;33modoosh-restart\x1b[0m\t Restart Odoo services\r\n\r\n';
                banner += '\x1b[31mbitconn\x1b[0m:$ ';
                // write banner and ensure focus
                try { term.writeln(''); } catch (e) {}
                term.write(banner);
                try { term.focus(); } catch (e) {}
                try { if (fitAddon && fitAddon.fit) { fitAddon.fit(); } } catch (e) {}
                console.debug('[bitconn_terminal] showWelcome written');
            } catch (e) {
                try { term.writeln('Welcome to Odoo (terminal)'); } catch (e) {}
            }
        }

        // show banner immediately and wait for explicit user command to start shell
        try { showWelcome(); } catch (e) {}

        function startSession(initialInput) {
            if (sessionId) { return; }
            if (initialInput) { pendingInitialInput = initialInput; }
            console.debug('[bitconn_terminal] startSession invoked');
            var rows = 24, cols = 80;
            try { rows = Math.max(10, Math.floor(term.rows || 24)); cols = Math.max(10, Math.floor(term.cols || 80)); } catch(e){}
            fetch('/bitconn_webhook/terminal/start', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'rows='+rows+'&cols='+cols})
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.session_id) {
                        sessionId = data.session_id;
                        console.log('[bitconn_terminal] session started', sessionId);
                        setButtonsState(true);
                        try { /* don't rewrite banner; session started */ } catch (e) {}
                        connectStream();
                    } else if (data.error) {
                        term.writeln('\r\n[ERROR] ' + (data.error || 'failed to start'));
                    }
                })
                .catch(function (err) { term.writeln('\r\n[ERROR] ' + String(err)); });
        }

        function connectStream() {
            if (!sessionId) { return; }
            try {
                evtSource = new EventSource('/bitconn_webhook/terminal/stream/' + encodeURIComponent(sessionId));
            } catch (e) {
                term.writeln('\r\n[ERROR] failed to open stream');
                return;
            }
            evtSource.onopen = function () { console.debug('[bitconn_terminal] EventSource opened for', sessionId); try { term.focus(); } catch(e){} };
            evtSource.onmessage = function (e) {
                console.debug('[bitconn_terminal] SSE message', e.data && (e.data.length>200? e.data.slice(0,200)+'...': e.data));
                // handle server-side expiration signal
                if (e.data === '[EXPIRED]') {
                    try { showBanner('Session expired. Click Open Shell to start a new session.'); } catch (e) {}
                    closeSession();
                    return;
                }
                
                var d = e.data || '';
                if (d === '[EOF]') {
                    term.writeln('\r\n[EOF] session closed');
                    closeSession();
                    return;
                }
                if (d.indexOf('b64:') === 0) {
                    var b64 = d.substring(4);
                    var txt = base64ToString(b64);
                    try { term.write(txt); } catch (e) { term.writeln('\r\n[DECODE ERROR]'); }
                    // mark ready when we receive first data from server
                    // ensure terminal receives focus when some output arrives
                    try { term.focus(); } catch (e) {}
                } else {
                    term.writeln(d);
                }
            };
            // when stream opens, if there is a pending initial input, send it
            evtSource.addEventListener('open', function () {
                hideBanner();
                if (pendingInitialInput) {
                    try { sendInput(pendingInitialInput + '\r'); } catch (e) {}
                    pendingInitialInput = null;
                }
                try { if (fitAddon && fitAddon.fit) { fitAddon.fit(); resizeSession(); } } catch (e) {}
                
            });
            evtSource.onerror = function (ev) {
                // leave a small notice
                //console.debug('SSE error', ev);
            };
            // ensure focus after stream opens
            try { setTimeout(function () { term.focus(); }, 50); } catch (e) {}
        }

        function sendInput(data) {
            if (!sessionId) { return; }
            // ensure we always send a string (avoid sending null/undefined)
            try { if (data === null || data === undefined) { data = ''; } } catch (e) { data = ''; }
            var payload = (typeof data === 'string') ? data : String(data);
            console.debug('[bitconn_terminal] sendInput ->', payload && (payload.length>200? payload.slice(0,200)+'...': payload));
            
            fetch('/bitconn_webhook/terminal/input/' + encodeURIComponent(sessionId), {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({data: payload})})
                .then(function (r) {
                    return r.json().then(function (j) { return {status: r.status, json: j}; }).catch(function () { return {status: r.status, json: null}; });
                })
                .then(function (res) {
                    var st = res && res.status; var j = res && res.json;
                    if (st === 410 || (j && j.error === 'session_expired')) {
                        showBanner('Session expired. Click Open Shell to start a new session.');
                        closeSession();
                        return;
                    }
                    if (j && j.error) { term.writeln('\r\n[ERROR] '+j.error); }
                    else { console.debug('[bitconn_terminal] sendInput ok'); }
                })
                .catch(function (e) { term.writeln('\r\n[ERROR] '+String(e)); });
        }

        function resizeSession() {
            if (!sessionId) { return; }
            var rows = term.rows || 24;
            var cols = term.cols || 80;
            fetch('/bitconn_webhook/terminal/resize/' + encodeURIComponent(sessionId), {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({rows: rows, cols: cols})}).catch(function(){});
        }

        function closeSession() {
            if (evtSource) { try { evtSource.close(); } catch (e){} evtSource = null; }
            if (sessionId) {
                fetch('/bitconn_webhook/terminal/stop', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({session_id: sessionId})}).catch(function(){});
                sessionId = null;
            }
            setButtonsState(false);
        }

        // attach xterm input handler (support multiple xterm versions)
        if (typeof term.onData === 'function') {
            // preferred: xterm v3+/v4+ onData provides correct control sequences
            term.onData(function (data) {
                try {
                    if (sessionId) { sendInput(data); return; }
                    // no session: emulate local typing, buffer until Enter
                    if (data === '\x7f') { // backspace
                        if (inputBuffer.length > 0) { inputBuffer = inputBuffer.slice(0, -1); try { term.write('\b \b'); } catch(e){} }
                        return;
                    }
                    // echo typed data
                    try { term.write(data); } catch (e) {}
                    inputBuffer += data;
                    if (data === '\r' || data === '\n') {
                        var line = inputBuffer.replace(/\r|\n/g, '').trim();
                        inputBuffer = '';
                        // trigger: user typed "odoo-bin shell" (or './odoo-bin shell')
                        if (line.indexOf('odoo-bin shell') !== -1 || line === 'shell') {
                            // start session and send the original command
                            startSession(line);
                        }
                    }
                } catch (e) {}
            });
        } else if (typeof term.onKey === 'function') {
            // fallback: map common keys to control sequences
            term.onKey(function (ev) {
                try {
                    var dom = ev.domEvent || {};
                    var k = ev.key || dom.key || '';
                    var seq = '';
                    if (dom.key === 'Enter') { seq = '\r'; }
                    else if (dom.key === 'Backspace') { seq = '\x7f'; }
                    else if (dom.key === 'ArrowUp') { seq = '\x1b[A'; }
                    else if (dom.key === 'ArrowDown') { seq = '\x1b[B'; }
                    else if (dom.key === 'ArrowLeft') { seq = '\x1b[D'; }
                    else if (dom.key === 'ArrowRight') { seq = '\x1b[C'; }
                    else if (k && k.length === 1) { seq = k; }
                    if (seq) {
                        if (sessionId) { sendInput(seq); }
                        else {
                            // echo locally and buffer
                            if (seq === '\x7f') { if (inputBuffer.length>0) { inputBuffer = inputBuffer.slice(0,-1); try{ term.write('\b \b'); }catch(e){} } }
                            else { try{ term.write(seq); }catch(e){} inputBuffer += seq; }
                            if (seq === '\r') {
                                var line = inputBuffer.replace(/\r|\n/g, '').trim();
                                inputBuffer = '';
                                if (line.indexOf('odoo-bin shell') !== -1 || line === 'shell') { startSession(line); }
                            }
                        }
                    }
                } catch (e) {}
            });
        } else {
            // as a last resort, forward keydown events when terminal is focused
            xtermEl.addEventListener('keydown', function (ev) {
                try {
                    var k = ev.key;
                    if (sessionId) {
                        if (k === 'Enter') { sendInput('\r'); }
                        else if (k === 'Backspace') { sendInput('\x7f'); }
                        else if (k.length === 1) { sendInput(k); }
                    } else {
                        // local echo/buffer when session not started
                        if (k === 'Enter') { try{ term.write('\r\n'); }catch(e){} var line = inputBuffer.trim(); inputBuffer = ''; if (line.indexOf('odoo-bin shell') !== -1 || line === 'shell') { startSession(line); } }
                        else if (k === 'Backspace') { if (inputBuffer.length>0) { inputBuffer = inputBuffer.slice(0,-1); try{ term.write('\b \b'); }catch(e){} } }
                        else if (k.length === 1) { inputBuffer += k; try{ term.write(k); }catch(e){} }
                    }
                } catch (e) {}
            });
        }

        // bind buttons
        var openBtn = container.querySelector('.o_bitconn_terminal_open');
        if (openBtn) {
            openBtn.addEventListener('click', function (ev) { ev.preventDefault(); startSession(); try { term.focus(); } catch(e){} });
        }
        var clearBtn = container.querySelector('.o_bitconn_terminal_clear');
        if (clearBtn) {
            clearBtn.addEventListener('click', function (ev) { ev.preventDefault(); term.clear(); });
        }

        // try auto-start when opening the tab
        // observe container visibility to auto-start when shown
        var mo = new MutationObserver(function () {
            try {
                // when container becomes visible, refit terminal
                if (container.offsetParent !== null) {
                    try { if (fitAddon && fitAddon.fit) { fitAddon.fit(); } } catch(e){}
                    try { term.focus(); } catch(e){}
                }
            } catch(e){}
        });
        mo.observe(container, {attributes: true, childList: true, subtree: false});

        // basic resize handling
        window.addEventListener('resize', function () { resizeSession(); });

        // cleanup on unload
        window.addEventListener('beforeunload', function () { closeSession(); });
    }

    // poll for terminal container within dynamic Odoo form
    function waitForContainer() {
        var selector = '.o_bitconn_terminal_container';
        var found = document.querySelectorAll(selector);
        if (found && found.length) {
            found.forEach(function (c) { initOnce(c); });
            return;
        }
        setTimeout(waitForContainer, 500);
    }

    // start
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        waitForContainer();
    } else {
        document.addEventListener('DOMContentLoaded', waitForContainer);
    }
})();
