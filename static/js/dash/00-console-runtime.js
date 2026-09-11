/* Shared presentation state; never pauses backend collection or response. */
(function () {
  const SOCRealtime = {
    paused: false, pending: 0, omitted: 0, limit: 500, buffer: [], listeners: [], snapshots: new Map(),
    snapshotEvents: new Set(['packet_update','sysmon_update','alert_stats','siem_status','soar_status','ml_update','decision_update']),
    attach(client) {
      const original = client.on.bind(client), handlers = new Map();
      client.on = (event, fn) => {
        if (['connect', 'disconnect', 'connect_error', 'chat_response'].includes(event)) {
          original(event, fn); return client;
        }
        if (!handlers.has(event)) {
          handlers.set(event, []);
          original(event, data => {
            const deliver = payload => handlers.get(event).forEach(handler => handler(payload));
            if (this.paused) {
              this.pending++;
              const previous = this.snapshots.get(event);
              if (previous) previous.data = data;
              else {
                const record = {event, data, deliver};
                this.buffer.push(record);
                if (this.snapshotEvents.has(event)) this.snapshots.set(event, record);
              }
              if (this.buffer.length > this.limit) {
                const removed = this.buffer.shift(); this.omitted++;
                if (this.snapshots.get(removed.event) === removed) this.snapshots.delete(removed.event);
              }
              this.changed();
            } else deliver(data);
          });
        }
        handlers.get(event).push(fn);
        return client;
      };
    },
    subscribe(fn) { this.listeners.push(fn); },
    changed() { this.listeners.forEach(fn => fn(this)); },
    setPaused(value) {
      if (this.paused === value) return;
      this.paused = value;
      if (!value) {
        // Existing handlers batch their charts. A single drain preserves event order.
        const events = this.buffer.splice(0);
        this.pending = 0;
        this.snapshots.clear();
        events.forEach(record => record.deliver(record.data));
        document.dispatchEvent(new CustomEvent('soc:resume', {detail: {omitted: this.omitted}}));
        this.omitted = 0;
      }
      this.changed();
    },
  };

  const SOCUI = {
    hours: 24, currentPanel: 'overview',
    number(value) { return value == null ? '—' : Number(value).toLocaleString(); },
    confidence(alert) {
      const value = alert.confidence ?? alert.details?.confidence;
      return typeof value === 'number' && value >= 0 && value <= 1 ? Math.round(value * 100) + '%' : '—';
    },
    provenance(record) {
      const p = record?.provenance;
      const state = p?.state || (record?.details?.demo || record?.origin === 'demo' ? 'DEMO' : 'UNAVAILABLE');
      const safe = ['REAL', 'DEMO', 'SYNTHETIC', 'SIMULATED', 'EXPERIMENTAL', 'UNAVAILABLE', 'MIXED'].includes(state) ? state : 'UNAVAILABLE';
      return `<span class="provenance provenance-${safe.toLowerCase()}" title="${escapeHtml(p?.reason || '출처 미기록')}">${safe}</span>`;
    },
    entity(value) {
      if (value == null || value === '') return '<span class="text-muted">—</span>';
      return `<button class="entity-link" ${act('consoleSearchEntity', [String(value)])} data-stop>${escapeHtml(String(value))}</button>`;
    },
    async request(url, options) {
      const response = await fetch(url, options);
      const data = await response.json();
      if (!response.ok || data.success === false) throw new Error(data.error || '요청을 완료하지 못했습니다.');
      return data;
    },
    notify(text) {
      const box = document.getElementById('console-notice');
      if (box) { box.textContent = text; box.hidden = false; }
      if (typeof announce === 'function') announce(text);
    },
    navigate(panel) {
      showPanel(panel);
      if (location.hash !== '#' + panel) history.pushState(null, '', '#' + panel);
    },
  };
  Object.assign(window, { SOCRealtime, SOCUI });
})();
