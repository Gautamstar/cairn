/**
 * The Cairn tracker.
 *
 * Installed as one tag, with no build step and no configuration:
 *
 *   <script defer src="https://<dist>.cloudfront.net/cairn.js"
 *           data-site="example.com"></script>
 *
 * This is the only Cairn code that runs on someone else's page, which sets the
 * constraints. It must not block rendering, must not throw into a host page's
 * error handler, and must stay small enough that installing it is never a
 * performance decision. It currently costs 1.2 kB minified and 647 bytes
 * gzipped, which is the number that actually crosses the wire.
 *
 * It writes no cookies and touches no storage. There is nothing to consent to
 * because nothing is persisted on the visitor's device, which is what lets a
 * site install this without a cookie banner.
 *
 * Optional attributes:
 *   data-api               override the endpoint (defaults to /e next to this script)
 *   data-track-localhost   report from localhost too, for testing the pipeline
 */
(function () {
  'use strict';

  var script = document.currentScript;
  if (!script) return;

  var site = script.getAttribute('data-site');
  if (!site) return;

  // Default the endpoint to `/e` alongside wherever this script was served
  // from, so a standard install has one attribute rather than two.
  var endpoint = script.getAttribute('data-api') || script.src.replace(/[^/]*$/, 'e');

  var loc = window.location;

  // Honour Do Not Track. It is deprecated and most browsers no longer send it,
  // but a visitor who went out of their way to set it has stated a preference,
  // and ignoring it would sit badly next to the rest of this project.
  if (navigator.doNotTrack === '1' || window.doNotTrack === '1') return;

  // Never report from a developer's own machine. Without this, every local
  // `npm run dev` session quietly pollutes production numbers, which is the
  // most common way self-hosted analytics data goes bad.
  var local = loc.protocol === 'file:' ||
    /^(localhost|127\.0\.0\.1|\[::1\])$/.test(loc.hostname) ||
    /\.local$/.test(loc.hostname);
  if (local && !script.hasAttribute('data-track-localhost')) return;

  // Last path reported, so repeated pageviews for the same route collapse.
  // Frameworks call replaceState freely for things that are not navigations
  // (syncing query state, restoring scroll), and each one would otherwise
  // register as a fresh view.
  var lastPath = null;

  function send(name) {
    if (name === 'pageview') {
      if (loc.pathname === lastPath) return;
      lastPath = loc.pathname;
    }

    var payload = JSON.stringify({
      site: site,
      name: name,
      url: loc.href,
      // JSON.stringify drops undefined keys, so a direct visit sends no
      // referrer field at all rather than an empty string.
      referrer: document.referrer || undefined,
      // Only ever used to break device-classification ties server-side.
      width: window.innerWidth
    });

    // `text/plain` is deliberate. It keeps this a CORS-simple request, which
    // means no preflight OPTIONS round trip before the beacon goes out. An
    // application/json body would double the request count on every pageview.
    if (navigator.sendBeacon) {
      navigator.sendBeacon(endpoint, new Blob([payload], { type: 'text/plain' }));
      return;
    }

    // Fallback for browsers without sendBeacon. `keepalive` is what lets the
    // request survive the page being unloaded, which is the whole reason
    // sendBeacon exists.
    try {
      fetch(endpoint, {
        method: 'POST',
        body: payload,
        keepalive: true,
        mode: 'no-cors',
        headers: { 'Content-Type': 'text/plain' }
      });
    } catch (e) {
      // A failed pageview is not worth breaking a host page over.
    }
  }

  // Wrap the History API so client-side route changes register. Without this a
  // single-page app reports exactly one pageview per full page load, no matter
  // how many routes the visitor moves through.
  function wrap(method) {
    var original = history[method];
    history[method] = function () {
      var result = original.apply(this, arguments);
      send('pageview');
      return result;
    };
  }

  wrap('pushState');
  wrap('replaceState');
  window.addEventListener('popstate', function () { send('pageview'); });

  // Custom events, for anything a site wants to count beyond pageviews:
  //   cairn('signup')
  window.cairn = send;

  // A prerendered page has not been seen by anyone yet, so counting it now
  // would inflate views with pages that may never be shown.
  if (document.visibilityState === 'prerender') {
    document.addEventListener('visibilitychange', function onVisible() {
      if (document.visibilityState !== 'prerender') {
        document.removeEventListener('visibilitychange', onVisible);
        send('pageview');
      }
    });
  } else {
    send('pageview');
  }
})();
