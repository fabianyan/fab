const puppeteer = require('puppeteer-core');

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const NAV_TIMEOUT_MS = 25000;

// Sites can serve different markup to phones, not just different CSS, so the
// capture itself has to be made as the requested device rather than only
// being displayed narrow afterwards.
const DEVICES = {
  desktop: {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    isMobile: false,
    hasTouch: false,
  },
  mobile: {
    width: 390,
    height: 844,
    deviceScaleFactor: 2,
    isMobile: true,
    hasTouch: true,
    userAgent:
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) ' +
      'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  },
};

// @sparticuz/chromium bundles a Linux binary built for AWS Lambda, which is
// where deployed Netlify functions run. `netlify dev` runs the function on
// the developer's own OS (Windows/macOS/local Linux), where that binary
// can't execute - so local dev instead uses full `puppeteer`, which manages
// its own Chromium build for the host OS.
async function launchBrowser() {
  if (process.env.NETLIFY_DEV) {
    const puppeteerFull = require('puppeteer');
    return puppeteerFull.launch({ headless: true, args: ['--no-sandbox'] });
  }

  const chromium = require('@sparticuz/chromium');
  return puppeteer.launch({
    args: chromium.args,
    defaultViewport: chromium.defaultViewport,
    executablePath: await chromium.executablePath(),
    headless: chromium.headless,
  });
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS_HEADERS, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return respond(405, { error: 'Method not allowed' });
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    return respond(400, { error: 'Invalid JSON body' });
  }

  const { url, user, pass } = payload;
  if (!url || typeof url !== 'string') {
    return respond(400, { error: 'Missing "url"' });
  }

  const deviceName = DEVICES[payload.device] ? payload.device : 'desktop';
  const device = DEVICES[deviceName];

  let targetUrl;
  try {
    targetUrl = new URL(normalizeUrl(url));
  } catch (err) {
    return respond(400, { error: 'Invalid URL: ' + url });
  }
  if (!/^https?:$/.test(targetUrl.protocol)) {
    return respond(400, { error: 'URL must be http or https' });
  }

  let browser;
  try {
    browser = await launchBrowser();

    const page = await browser.newPage();

    await page.setViewport({
      width: device.width,
      height: device.height,
      deviceScaleFactor: device.deviceScaleFactor,
      isMobile: device.isMobile,
      hasTouch: device.hasTouch,
    });
    if (device.userAgent) await page.setUserAgent(device.userAgent);

    if (user) {
      await page.authenticate({ username: user, password: pass || '' });
    }

    await page.goto(targetUrl.toString(), {
      waitUntil: 'networkidle2',
      timeout: NAV_TIMEOUT_MS,
    });

    // The request may have redirected (casino.com -> casino.com/zh/), so
    // everything downstream must describe where the browser actually landed,
    // not what was asked for. Otherwise relative links resolve against the
    // wrong base and "recapture this page" re-requests the pre-redirect URL.
    let landedUrl = targetUrl;
    try {
      landedUrl = new URL(page.url());
    } catch (err) {
      // keep the requested URL if page.url() is unparseable (about:blank etc)
    }

    const { root, authored, schemeNames, pageFont, pageFontSize } = await page.evaluate(() => {
      // Custom properties cannot be discovered by iterating a computed style:
      // getComputedStyle()'s indexed list contains only standard properties,
      // so `for (const p of computed)` never yields a --scheme-* name even
      // when getPropertyValue() resolves it fine. Names have to be gathered
      // from where they are written, then read back individually.
      const names = new Set();

      // Resolved values alone are not enough. A component token is usually
      // written as `--scheme-widgets-cta-default: var(--scheme-colors-color-primary)`,
      // and resolving it stores the literal colour instead, breaking the link:
      // editing the general colour then changes nothing downstream. So the
      // authored text of each declaration is captured alongside the resolved
      // value, and the preview is built from that.
      //
      // Every custom property that reaches :root is captured, not only the
      // --scheme-* ones. A scheme leans on the page's own tokens: the family
      // lives in `--font-base`, and `--scheme-typography-h1-fontWeight-m` is
      // written as `var(--font-weight-bold)`. Restricting the capture to the
      // scheme namespace cost two things - the family could not be edited at
      // all because nothing represented it, and since :root blocks are
      // stripped from the CSS returned below, the preview lost the declaration
      // too and rendered every specimen in a fallback face.
      const authored = {};
      const declRe = /(--[A-Za-z0-9_-]+)\s*:\s*([^;}]+)/g;

      const collectAuthored = (rules) => {
        for (const rule of rules) {
          // Recurse but never skip: since CSS nesting shipped, an ordinary
          // style rule also exposes a (usually empty) cssRules list, so
          // treating a truthy cssRules as "this is only a container" skips
          // every real rule and finds nothing at all.
          if (rule.cssRules) collectAuthored(rule.cssRules);
          if (!rule.selectorText || !rule.cssText) continue;
          // Only declarations that actually reach :root matter here.
          let applies = false;
          try {
            applies = document.documentElement.matches(rule.selectorText);
          } catch (err) {
            continue;
          }
          if (!applies) continue;

          const open = rule.cssText.indexOf('{');
          const close = rule.cssText.lastIndexOf('}');
          if (open === -1 || close === -1) continue;

          const body = rule.cssText.slice(open + 1, close);
          let match;
          declRe.lastIndex = 0;
          // Later declarations win, approximating the cascade.
          while ((match = declRe.exec(body))) authored[match[1]] = match[2].trim();
        }
      };

      for (const sheet of document.styleSheets) {
        try {
          if (sheet.cssRules) collectAuthored(sheet.cssRules);
        } catch (err) {
          // cross-origin sheet
        }
      }

      // Anything Vulcan set on :root at runtime outranks the stylesheets.
      const inlineStyle = document.documentElement.style;
      for (let i = 0; i < inlineStyle.length; i++) {
        const prop = inlineStyle[i];
        if (prop.indexOf('--') === 0) {
          authored[prop] = inlineStyle.getPropertyValue(prop).trim();
        }
      }

      Object.keys(authored).forEach((name) => names.add(name));

      // Vulcan can also inject a scheme value with no declaration anywhere to
      // find, so --scheme-* names referenced in the CSS are collected as well.
      // Anything that does not resolve to a value is dropped below, so a
      // reference to an undefined variable cannot invent an entry.
      const collectFrom = (rules) => {
        for (const rule of rules) {
          if (rule.cssRules) collectFrom(rule.cssRules);
          const found = rule.cssText && rule.cssText.match(/--scheme-[A-Za-z0-9_-]+/g);
          if (found) found.forEach((name) => names.add(name));
        }
      };

      for (const sheet of document.styleSheets) {
        try {
          if (sheet.cssRules) collectFrom(sheet.cssRules);
        } catch (err) {
          // cross-origin stylesheet, unreadable by design
        }
      }

      const computed = getComputedStyle(document.documentElement);
      // Kept in case an engine does enumerate custom properties.
      for (const prop of computed) {
        if (prop.indexOf('--') === 0) names.add(prop);
      }

      const vars = {};
      names.forEach((name) => {
        const value = computed.getPropertyValue(name).trim();
        if (value) vars[name] = value;
      });

      const schemes = Array.from(
        new Set(
          Array.from(document.querySelectorAll('[data-color-scheme]')).map((el) =>
            el.getAttribute('data-color-scheme')
          )
        )
      ).filter(Boolean);

      // An authored value is only safe to ship if every variable it references
      // was captured too: :root blocks are stripped from the CSS we return, so
      // a reference to anything else would resolve to nothing in the preview.
      // Those fall back to the resolved value.
      const safeAuthored = {};
      Object.keys(vars).forEach((name) => {
        const value = authored[name];
        const refs = value
          ? (value.match(/var\(\s*(--[A-Za-z0-9_-]+)/g) || []).map(function (ref) {
              return ref.replace(/var\(\s*/, '');
            })
          : [];
        var resolvable = refs.every(function (ref) {
          return Object.prototype.hasOwnProperty.call(vars, ref);
        });
        safeAuthored[name] = value && resolvable ? value : vars[name];
      });

      // Most typography variable sets carry size, weight and line height but
      // no family, so the spec sheet needs the page's own face to fall back to
      // rather than showing specimens in a system font.
      const bodyStyle = getComputedStyle(document.body);

      return {
        root: vars,
        authored: safeAuthored,
        schemeNames: schemes,
        pageFont: bodyStyle.fontFamily || '',
        pageFontSize: bodyStyle.fontSize || '',
      };
    });

    const body = await page.evaluate(() => {
      const clone = document.body.cloneNode(true);
      clone.querySelectorAll('script').forEach((el) => el.remove());
      return clone.outerHTML;
    });

    const stylesheetUrls = await page.evaluate(() =>
      Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
        .map((el) => el.href)
        .filter(Boolean)
    );

    await browser.close();
    browser = null;

    const cssParts = await Promise.all(
      stylesheetUrls.map(async (href) => {
        try {
          const res = await fetch(href);
          if (!res.ok) return '';
          const text = await res.text();
          return stripRootBlocks(text);
        } catch (err) {
          return '';
        }
      })
    );

    return respond(200, {
      root,
      authored,
      css: cssParts.join('\n\n'),
      body,
      base: `${landedUrl.protocol}//${landedUrl.host}`,
      // The full post-redirect URL, so the preview can resolve relative links
      // and assets against the actual page rather than just the origin.
      pageUrl: landedUrl.toString(),
      device: deviceName,
      schemeNames,
      pageFont,
      pageFontSize,
      varCount: Object.keys(root).length,
      // Reported separately so the status line can say how much of the capture
      // is the scheme itself and how much is the page's own tokens.
      schemeCount: Object.keys(root).filter((name) => name.indexOf('--scheme-') === 0).length,
    });
  } catch (err) {
    return respond(500, { error: err && err.message ? err.message : 'Capture failed' });
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch (_) {
        // already closed
      }
    }
  }
};

// Accepts what people actually paste: "casino.com", "www.casino.com/zh/".
// A bare host has no scheme for `new URL` to parse, so default it to https.
// Anything that already carries a scheme is left alone, so a non-http one
// still fails the protocol check below rather than being silently rewritten.
function normalizeUrl(raw) {
  const trimmed = String(raw).trim();
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) return trimmed;
  return 'https://' + trimmed.replace(/^\/+/, '');
}

function stripRootBlocks(css) {
  return css.replace(/:root\s*\{[^}]*\}/g, '');
}

function respond(statusCode, data) {
  return {
    statusCode,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  };
}
