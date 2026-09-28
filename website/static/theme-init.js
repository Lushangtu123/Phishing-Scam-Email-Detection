// Resolve the colour theme before first paint to avoid a flash.
// Loaded synchronously in <head> so the page CSP needs no 'unsafe-inline'.
(function () {
  var stored = null;
  try { stored = localStorage.getItem('phishguard-theme'); } catch (e) {}
  var system = window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  document.documentElement.dataset.theme = (stored === 'light' || stored === 'dark') ? stored : system;
  document.documentElement.dataset.themeMode = stored || 'auto';
})();
