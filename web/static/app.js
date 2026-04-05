(() => {
  const scrollKey = `goup:scroll:${window.location.pathname}`;

  window.addEventListener('beforeunload', () => {
    try {
      sessionStorage.setItem(scrollKey, String(window.scrollY || 0));
    } catch (_) {
    }
  });

  window.addEventListener('DOMContentLoaded', () => {
    const languageTag = ((document.documentElement && document.documentElement.lang) || (navigator.languages && navigator.languages[0]) || navigator.language || 'en').toLowerCase();
    const durationUnits = (() => {
      if (languageTag.startsWith('de')) {
        return { day: 'T', hour: 'Std.', minute: 'Min.', second: 'Sek.' };
      }
      if (languageTag.startsWith('fr')) {
        return { day: 'j', hour: 'h', minute: 'min', second: 's' };
      }
      if (languageTag.startsWith('es')) {
        return { day: 'd', hour: 'h', minute: 'min', second: 's' };
      }
      return { day: 'd', hour: 'h', minute: 'min.', second: 'sec.' };
    })();

    const formatDurationCompact = (totalSeconds) => {
      const safeSeconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
      if (safeSeconds < 60) {
        return `${safeSeconds} ${durationUnits.second}`;
      }

      const minutes = Math.floor(safeSeconds / 60);
      const seconds = safeSeconds % 60;
      if (safeSeconds < 3600) {
        if (seconds > 0) {
          return `${minutes} ${durationUnits.minute} ${seconds} ${durationUnits.second}`;
        }
        return `${minutes} ${durationUnits.minute}`;
      }

      const hours = Math.floor(minutes / 60);
      const remMinutes = minutes % 60;
      if (safeSeconds < 86400) {
        if (remMinutes > 0) {
          return `${hours} ${durationUnits.hour} ${remMinutes} ${durationUnits.minute}`;
        }
        return `${hours} ${durationUnits.hour}`;
      }

      const days = Math.floor(hours / 24);
      const remHours = hours % 24;
      if (remMinutes > 0) {
        return `${days} ${durationUnits.day} ${remHours} ${durationUnits.hour} ${remMinutes} ${durationUnits.minute}`;
      }
      if (remHours > 0) {
        return `${days} ${durationUnits.day} ${remHours} ${durationUnits.hour}`;
      }
      return `${days} ${durationUnits.day}`;
    };

    const updateRelativeAgeLabels = () => {
      document.querySelectorAll('.js-relative-age[data-utc]').forEach((element) => {
        const raw = element.getAttribute('data-utc');
        if (!raw) {
          return;
        }
        const date = new Date(raw);
        if (Number.isNaN(date.getTime())) {
          return;
        }
        const elapsedSeconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
        element.textContent = formatDurationCompact(elapsedSeconds);
        element.setAttribute('title', date.toLocaleString());
      });
    };

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

    updateRelativeAgeLabels();
    window.setInterval(updateRelativeAgeLabels, 30000);

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
      const menuOpenLabel = String(hamburger.getAttribute('data-menu-open-label') || hamburger.getAttribute('aria-label') || 'Open menu');
      const menuCloseLabel = String(hamburger.getAttribute('data-menu-close-label') || 'Close menu');
      const openMenu = () => {
        collapsible.classList.add('is-open');
        hamburger.setAttribute('aria-expanded', 'true');
        hamburger.setAttribute('aria-label', menuCloseLabel);
      };
      const closeMenu = () => {
        collapsible.classList.remove('is-open');
        hamburger.setAttribute('aria-expanded', 'false');
        hamburger.setAttribute('aria-label', menuOpenLabel);
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
