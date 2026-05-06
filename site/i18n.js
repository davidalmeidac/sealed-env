/* sealed-env · language auto-detect (29 lines, no deps)
 *
 * Behaviour:
 *   1. If the user has manually chosen a language (saved in localStorage),
 *      respect it forever — never auto-redirect.
 *   2. Otherwise, on first visit only, if the browser's primary language
 *      matches a translation we ship, redirect to it.
 *   3. Each language version of the page has the same script — the user's
 *      manual click on a flag persists their choice via the `?lang=`
 *      param read here.
 */
(function () {
  var STORE_KEY = 'sealed-env:lang';
  var SUPPORTED = ['en', 'es']; // add 'pt', 'zh', 'ja' as translations land
  var current = document.documentElement.lang || 'en';

  // 1. Manual override via ?lang=xx (used when clicking a flag)
  var qs = new URLSearchParams(location.search);
  var picked = qs.get('lang');
  if (picked && SUPPORTED.indexOf(picked) !== -1) {
    try { localStorage.setItem(STORE_KEY, picked); } catch (e) { /* noop */ }
    if (picked !== current) {
      location.replace(picked === 'en' ? '/' : '/' + picked + '/');
      return;
    }
  }

  // 2. Already chose? Don't auto-detect.
  try { if (localStorage.getItem(STORE_KEY)) return; } catch (e) { return; }

  // 3. First-time visitor — sniff browser language.
  var pref = (navigator.language || 'en').slice(0, 2).toLowerCase();
  if (pref === current) return;
  if (SUPPORTED.indexOf(pref) === -1) return;
  location.replace(pref === 'en' ? '/' : '/' + pref + '/');
})();
