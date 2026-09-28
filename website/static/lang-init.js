// Resolve the homepage language before first paint, like theme-init.js does
// for the theme. i18n.js (end of <body>) translates the page and clears the
// pending flag; style.css reveals the page after a delay if it never loads.
(function () {
  var stored = null;
  try { stored = localStorage.getItem('phishguard-lang'); } catch (e) {}
  var nav = (navigator.languages && navigator.languages[0]) || navigator.language || '';
  var lang = stored === 'en' || stored === 'zh' ? stored : (/^zh\b/i.test(nav) ? 'zh' : 'en');
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  if (lang !== 'en') document.documentElement.setAttribute('data-i18n-pending', '');
})();
