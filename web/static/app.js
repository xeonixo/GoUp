(() => {
  const scrollKey = `goup:scroll:${window.location.pathname}`;

  window.addEventListener('beforeunload', () => {
    try {
      sessionStorage.setItem(scrollKey, String(window.scrollY || 0));
    } catch (_) {
    }
  });

  window.addEventListener('DOMContentLoaded', () => {
    try {
      const currentURL = new URL(window.location.href);
      let changed = false;
      if (currentURL.searchParams.has('error')) {
        currentURL.searchParams.delete('error');
        changed = true;
      }
      if (currentURL.searchParams.has('notice')) {
        currentURL.searchParams.delete('notice');
        changed = true;
      }
      if (changed) {
        let next = currentURL.pathname;
        const qs = currentURL.searchParams.toString();
        if (qs) {
          next += `?${qs}`;
        }
        if (currentURL.hash) {
          next += currentURL.hash;
        }
        history.replaceState({}, '', next);
      }
    } catch (_) {
    }

    try {
      if (!window.location.hash) {
        const y = Number.parseInt(sessionStorage.getItem(scrollKey) || '0', 10);
        if (!Number.isNaN(y) && y > 0) {
          window.scrollTo({ top: y, behavior: 'auto' });
        }
      }
    } catch (_) {
    }

    document.querySelectorAll('.js-local-datetime[data-utc]').forEach((element) => {
      const raw = element.getAttribute('data-utc');
      if (!raw) {
        return;
      }
      const date = new Date(raw);
      if (Number.isNaN(date.getTime())) {
        return;
      }
      element.textContent = date.toLocaleString();
      element.setAttribute('title', raw);
    });

    document.addEventListener('submit', (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }
      const message = form.dataset.confirm;
      if (!message) {
        return;
      }
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });

    // Mobile hamburger menu
    const hamburger = document.getElementById('topbar-hamburger');
    const collapsible = document.getElementById('topbar-collapsible');
    if (hamburger && collapsible) {
      const openMenu = () => {
        collapsible.classList.add('is-open');
        hamburger.setAttribute('aria-expanded', 'true');
        hamburger.setAttribute('aria-label', 'Menü schließen');
      };
      const closeMenu = () => {
        collapsible.classList.remove('is-open');
        hamburger.setAttribute('aria-expanded', 'false');
        hamburger.setAttribute('aria-label', 'Menü öffnen');
      };
      hamburger.addEventListener('click', (e) => {
        e.stopPropagation();
        if (collapsible.classList.contains('is-open')) {
          closeMenu();
        } else {
          openMenu();
        }
      });
      document.addEventListener('click', (e) => {
        if (collapsible.classList.contains('is-open') &&
            !collapsible.contains(e.target) &&
            !hamburger.contains(e.target)) {
          closeMenu();
        }
      });
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && collapsible.classList.contains('is-open')) {
          closeMenu();
          hamburger.focus();
        }
      });
    }
  });
})();
