// Resolve the page language before first paint, like theme-init.js does for
// the theme. For Chinese it hides the page (data-i18n-pending) and starts
// fetching the Chinese strings (i18n-zh.js, an external script, so the CSP
// needs no inline code) while the rest of the page downloads. i18n.js, which
// runs before DOMContentLoaded on both pages (a classic script at the end of
// the homepage <body>, a deferred script on cases.html), translates the page
// once those strings are here, and clears the flag. DOMContentLoaded clears it
// too, once the Chinese file has finished loading or failed, so the page is
// shown even if i18n.js failed to load. The stylesheets also reveal it after
// a delay. An English page requests nothing extra.
(function () {
  var stored = null;
  try { stored = localStorage.getItem('phishguard-lang'); } catch (e) {}
  var nav = (navigator.languages && navigator.languages[0]) || navigator.language || '';
  var lang = stored === 'en' || stored === 'zh' ? stored : (/^zh\b/i.test(nav) ? 'zh' : 'en');
  var root = document.documentElement;
  root.lang = lang === 'zh' ? 'zh-CN' : 'en';
  if (lang === 'en') return;
  root.setAttribute('data-i18n-pending', '');
  var reveal = function () { root.removeAttribute('data-i18n-pending'); };
  var script = null;
  try {
    script = document.createElement('script');
    script.src = '/static/i18n-zh.js?v=34';
    script.setAttribute('data-i18n-dictionary', 'zh');
    // It gates the first paint of a Chinese page, so fetch it early.
    script.fetchPriority = 'high';
    // data-state tells i18n.js a finished request, whose events it missed.
    script.addEventListener('load', function () { script.setAttribute('data-state', 'loaded'); });
    script.addEventListener('error', function () { script.setAttribute('data-state', 'error'); });
    (document.head || root).appendChild(script);
  } catch (e) { script = null; }
  if (typeof document.addEventListener === 'function') {
    document.addEventListener('DOMContentLoaded', function () {
      if (!script || script.getAttribute('data-state')) { reveal(); return; }
      script.addEventListener('load', reveal);
      script.addEventListener('error', reveal);
    });
  }
})();
