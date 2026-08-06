const puppeteer = require('puppeteer-core');

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const NAV_TIMEOUT_MS = 25000;

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

    const { root, schemeNames } = await page.evaluate(() => {
      const computed = getComputedStyle(document.documentElement);
      const vars = {};
      for (const prop of computed) {
        if (prop.startsWith('--scheme-')) {
          vars[prop] = computed.getPropertyValue(prop).trim();
        }
      }
      const names = Array.from(
        new Set(
          Array.from(document.querySelectorAll('[data-color-scheme]')).map((el) =>
            el.getAttribute('data-color-scheme')
          )
        )
      ).filter(Boolean);
      return { root: vars, schemeNames: names };
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
      schemeNames,
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
