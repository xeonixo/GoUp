// Applies the stored theme preference (auto | light | dark) before first paint.
// Loaded synchronously in <head>; no inline script is allowed by the CSP.
(function () {
  var KEY = 'goup-theme';
  var root = document.documentElement;
  function apply(value) {
    if (value === 'light' || value === 'dark') {
      root.setAttribute('data-theme', value);
    } else {
      root.removeAttribute('data-theme');
    }
  }
  var stored = null;
  try {
    stored = window.localStorage.getItem(KEY);
  } catch (_) {
    stored = null;
  }
  apply(stored);
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
