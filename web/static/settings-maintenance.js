(() => {
  // Maintenance windows: times are shown and entered in the browser's time zone and sent to the
  // server as UTC instants (RFC 3339) in the hidden starts_at / ends_at fields.
  window.addEventListener('DOMContentLoaded', () => {
    const page = document.getElementById('maintenance-page');
    if (!(page instanceof HTMLElement)) {
      return;
    }

    const pad = (n) => String(n).padStart(2, '0');
    const toLocalInput = (date) => `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;

    try {
      const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
      const label = document.getElementById('maintenance-tz');
      if (label && zone) {
        label.textContent = zone;
      }
    } catch (_) {
    }

    page.querySelectorAll('time.maint-time[datetime]').forEach((element) => {
      const date = new Date(element.getAttribute('datetime') || '');
      if (!Number.isNaN(date.getTime())) {
        element.textContent = date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
      }
    });

    const form = document.getElementById('maintenance-form');
    if (!(form instanceof HTMLFormElement)) {
      return;
    }

    // Prefill the local inputs from the stored UTC instants (edit mode).
    form.querySelectorAll('input[type="datetime-local"][data-utc]').forEach((input) => {
      const raw = input.getAttribute('data-utc');
      if (!raw) {
        return;
      }
      const date = new Date(raw);
      if (!Number.isNaN(date.getTime())) {
        input.value = toLocalInput(date);
      }
    });

    const syncUTC = (localName, utcName) => {
      const local = form.elements.namedItem(localName);
      const utc = form.elements.namedItem(utcName);
      if (!(local instanceof HTMLInputElement) || !(utc instanceof HTMLInputElement)) {
        return;
      }
      // "YYYY-MM-DDTHH:mm" without an offset is parsed as local time, DST rules included.
      const date = new Date(local.value);
      utc.value = local.value && !Number.isNaN(date.getTime()) ? date.toISOString() : '';
    };
    form.addEventListener('submit', () => {
      syncUTC('starts_local', 'starts_at');
      syncUTC('ends_local', 'ends_at');
    });

    const scope = document.getElementById('maintenance-scope');
    const applyScope = () => {
      const value = scope instanceof HTMLSelectElement ? scope.value : 'all';
      form.querySelectorAll('[data-scope-section]').forEach((section) => {
        section.hidden = section.getAttribute('data-scope-section') !== value;
      });
    };
    if (scope) {
      scope.addEventListener('change', applyScope);
    }
    applyScope();
  });
})();
