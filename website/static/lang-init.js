// Resolve the page language before first paint, like theme-init.js does for
// the theme. i18n.js translates the page and clears the pending flag; it runs
// before DOMContentLoaded on both pages (a classic script at the end of the
// homepage <body>, a deferred script on cases.html), so clearing the flag
// there too reveals the page even if i18n.js failed to load. The stylesheets
// also reveal it after a delay.
(function () {
  var stored = null;
  try { stored = localStorage.getItem('phishguard-lang'); } catch (e) {}
  var nav = (navigator.languages && navigator.languages[0]) || navigator.language || '';
  var lang = stored === 'en' || stored === 'zh' ? stored : (/^zh\b/i.test(nav) ? 'zh' : 'en');
  var root = document.documentElement;
  root.lang = lang === 'zh' ? 'zh-CN' : 'en';
  if (lang === 'en') return;
  root.setAttribute('data-i18n-pending', '');
  if (typeof document.addEventListener === 'function') {
    document.addEventListener('DOMContentLoaded', function () { root.removeAttribute('data-i18n-pending'); });
  }
})();
