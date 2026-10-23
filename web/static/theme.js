// Applies the stored theme preference (auto | light | dark) before first paint.
// Loaded synchronously in <head>; no inline script is allowed by the CSP.
(function () {
  var KEY = 'goup-theme';
  var root = document.documentElement;
  // Keep the browser/PWA chrome (status bar) in sync with a forced theme.
  var THEME_COLORS = { dark: '#0b1020', light: '#f4f6fb' };
  function syncThemeColor(value) {
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < metas.length; i++) {
      var media = metas[i].getAttribute('data-media') || metas[i].getAttribute('media') || '';
      if (!metas[i].hasAttribute('data-media')) {
        metas[i].setAttribute('data-media', media);
      }
      if (value === 'light' || value === 'dark') {
        // A forced theme wins over the OS preference: drop the media query.
        metas[i].removeAttribute('media');
        metas[i].setAttribute('content', THEME_COLORS[value]);
      } else {
        if (media) {
          metas[i].setAttribute('media', media);
        }
        metas[i].setAttribute('content', media.indexOf('light') !== -1 ? THEME_COLORS.light : THEME_COLORS.dark);
      }
    }
  }
  function apply(value) {
    if (value === 'light' || value === 'dark') {
      root.setAttribute('data-theme', value);
    } else {
      root.removeAttribute('data-theme');
    }
    syncThemeColor(value);
  }
  var stored = null;
  try {
    stored = window.localStorage.getItem(KEY);
  } catch (_) {
    stored = null;
  }
  apply(stored);
  // theme.js runs in <head>; re-sync once the meta tags are guaranteed to exist.
  document.addEventListener('DOMContentLoaded', function () {
    syncThemeColor(stored);
  });
  window.GoUpTheme = {
    key: KEY,
    get: function () {
      return stored === 'light' || stored === 'dark' ? stored : 'auto';
    },
    set: function (value) {
      stored = value === 'light' || value === 'dark' ? value : 'auto';
      try {
        if (stored === 'auto') {
          window.localStorage.removeItem(KEY);
        } else {
          window.localStorage.setItem(KEY, stored);
        }
      } catch (_) {
        // storage unavailable: theme applies for this page view only
      }
      apply(stored);
    }
  };
})();
