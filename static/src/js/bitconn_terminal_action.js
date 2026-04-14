/** @odoo-module **/

import { registry } from "@web/core/registry";
import { Component, onMounted, onWillUnmount, useRef } from "@odoo/owl";

class BitconnTerminalAction extends Component {
    static template = "bitconn_webhook.TerminalAction";
    static props = ["*"];

    setup() {
        this.containerRef = useRef("terminalContainer");
        this._pollTimer = null;

        onMounted(() => {
            // The vanilla JS (bitconn_terminal_ws.js) polls for .o_bitconn_terminal_container
            // and calls initOnce(). We just need to make sure our container is in the DOM.
            // Trigger immediate check instead of waiting for the 1s poll cycle.
            this._pollTimer = setTimeout(() => {
                const el = this.containerRef.el;
                if (el && !el._bitconn_init && window.document.body.contains(el)) {
                    // The polling in bitconn_terminal_ws.js will pick it up on next tick.
                    // Force a slightly faster detection:
                    const evt = new Event('resize');
                    window.dispatchEvent(evt);
                }
            }, 150);
        });

        onWillUnmount(() => {
            if (this._pollTimer) {
                clearTimeout(this._pollTimer);
            }
        });
    }
}

registry.category("actions").add("bitconn_terminal", BitconnTerminalAction);
