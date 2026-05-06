/* sealed-env · language auto-detect (no deps)
 *
 * URL resolution comes from the <link rel="alternate" hreflang="..."> tags
 * already present in the page <head>. This means the script works correctly
 * regardless of where the site is hosted (root domain, /sealed-env/ project
 * path, or a future custom domain) — there is no hardcoded base path.
 *
 * Behaviour:
 *   1. ?lang=xx in the URL — manual override; persisted to localStorage
 *      and never overridden by auto-detect afterwards.
 *   2. localStorage already has a choice — don't auto-detect.
 *   3. First-time visitor — sniff navigator.language and redirect if a
 *      matching hreflang exists.
 */
(function () {
  var STORE_KEY = 'sealed-env:lang';
  var current = (document.documentElement.lang || 'en').slice(0, 2).toLowerCase();

  function urlFor(lang) {
    var link = document.querySelector(
      'link[rel="alternate"][hreflang="' + lang + '"]'
    );
    return link ? link.href : null;
  }

  // 1. Manual override via ?lang=xx
  var qs = new URLSearchParams(location.search);
  var picked = qs.get('lang');
  if (picked) {
    try { localStorage.setItem(STORE_KEY, picked); } catch (e) { /* noop */ }
    if (picked !== current) {
      var override = urlFor(picked);
      if (override) { location.replace(override); return; }
    }
    return; // language already matches — stay
  }

  // 2. Already chose? Skip auto-detect.
  try { if (localStorage.getItem(STORE_KEY)) return; } catch (e) { return; }

  // 3. First visit — sniff browser language.
  var pref = (navigator.language || 'en').slice(0, 2).toLowerCase();
  if (pref === current) return;
  var target = urlFor(pref);
  if (target) location.replace(target);
})();
