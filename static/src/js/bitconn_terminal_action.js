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
            this._pollTimer = setTimeout(() => {
                const el = this.containerRef.el;
                if (el && !el._bitconn_init && window.document.body.contains(el)) {
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
