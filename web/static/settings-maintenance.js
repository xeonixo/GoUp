(() => {
  // Maintenance windows: times are wall-clock values in the selected IANA timezone.
  // The server interprets starts_local/ends_local in that zone; hidden starts_at/ends_at
  // stay empty so the timezone is authoritative.
  window.addEventListener('DOMContentLoaded', () => {
    const page = document.getElementById('maintenance-page');
    if (!(page instanceof HTMLElement)) {
      return;
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

    form.querySelectorAll('input[type="datetime-local"][data-local]').forEach((input) => {
      const local = input.getAttribute('data-local');
      if (local && !input.value) {
        input.value = local;
      }
    });

    form.addEventListener('submit', () => {
      const startsAt = form.elements.namedItem('starts_at');
      const endsAt = form.elements.namedItem('ends_at');
      if (startsAt instanceof HTMLInputElement) {
        startsAt.value = '';
      }
      if (endsAt instanceof HTMLInputElement) {
        endsAt.value = '';
      }
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
