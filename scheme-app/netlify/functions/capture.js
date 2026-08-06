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

    const { root, schemeNames, pageFont, pageFontSize } = await page.evaluate(() => {
      // Custom properties cannot be discovered by iterating a computed style:
      // getComputedStyle()'s indexed list contains only standard properties,
      // so `for (const p of computed)` never yields a --scheme-* name even
      // when getPropertyValue() resolves it fine. Names have to be gathered
      // from where they are written, then read back individually.
      const names = new Set();

      const collectFrom = (rules) => {
        for (const rule of rules) {
          if (rule.cssRules) collectFrom(rule.cssRules);
          // Matches declarations and var() references alike; anything that
          // does not resolve to a value is dropped below, so a reference to
          // an undefined variable cannot invent an entry.
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

      // Values Vulcan sets on :root at runtime rather than in a stylesheet.
      const inline = document.documentElement.style;
      for (let i = 0; i < inline.length; i++) {
        if (inline[i].indexOf('--scheme-') === 0) names.add(inline[i]);
      }

      const computed = getComputedStyle(document.documentElement);
      // Kept in case an engine does enumerate custom properties.
      for (const prop of computed) {
        if (prop.indexOf('--scheme-') === 0) names.add(prop);
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

      // Most typography variable sets carry size, weight and line height but
      // no family, so the spec sheet needs the page's own face to fall back to
      // rather than showing specimens in a system font.
      const bodyStyle = getComputedStyle(document.body);

      return {
        root: vars,
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
