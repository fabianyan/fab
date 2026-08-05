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
    targetUrl = new URL(url);
  } catch (err) {
    return respond(400, { error: 'Invalid URL' });
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
      base: `${targetUrl.protocol}//${targetUrl.host}`,
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
