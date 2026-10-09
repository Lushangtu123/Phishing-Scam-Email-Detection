/* ──────────────────────────────────────────────────────────────────────────
   compat.js – small polyfills for older phone browsers
   iOS Safari before 15.4, older Android WebViews and in-app browsers lack a
   few newer APIs the page scripts call during setup; one missing API there
   stopped the setup before the configuration showed the Text Message tab.
   Loaded first, and written in ES5 so it parses wherever the page loads.
   ────────────────────────────────────────────────────────────────────────── */
(function () {
  // Object.hasOwn: Safari 15.4, Chrome 93.
  if (typeof Object.hasOwn !== 'function') {
    Object.defineProperty(Object, 'hasOwn', {
      value: function (object, key) { return Object.prototype.hasOwnProperty.call(object, key); },
      configurable: true,
      writable: true,
    });
  }
  // MediaQueryList.addEventListener: Safari 14; older Safari has addListener only.
  var queries = typeof MediaQueryList !== 'undefined' ? MediaQueryList.prototype : null;
  if (queries && typeof queries.addEventListener !== 'function' && typeof queries.addListener === 'function') {
    queries.addEventListener = function (type, listener) { if (type === 'change') this.addListener(listener); };
    queries.removeEventListener = function (type, listener) { if (type === 'change') this.removeListener(listener); };
  }
  // crypto.randomUUID: Safari 15.4, Chrome 92. getRandomValues is far older.
  var random = typeof crypto !== 'undefined' ? crypto : null;
  if (random && typeof random.randomUUID !== 'function' && typeof random.getRandomValues === 'function') {
    random.randomUUID = function () {
      var bytes = random.getRandomValues(new Uint8Array(16));
      bytes[6] = (bytes[6] & 0x0f) | 0x40;
      bytes[8] = (bytes[8] & 0x3f) | 0x80;
      var hex = Array.prototype.map.call(bytes, function (byte) { return (byte + 0x100).toString(16).slice(1); }).join('');
      return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
    };
  }
})();
