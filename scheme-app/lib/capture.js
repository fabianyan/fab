const puppeteer = require('puppeteer-core');

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
  // `vercel dev` runs on the developer's own OS too, so it needs the same
  // treatment as `netlify dev` rather than the Lambda binary.
  if (process.env.NETLIFY_DEV || process.env.VERCEL_ENV === 'development') {
    const puppeteerFull = require('puppeteer');
    return puppeteerFull.launch({ headless: true, args: ['--no-sandbox'] });
  }

  // @sparticuz/chromium ships Chromium's shared libraries (libnss3 and
  // friends) as a separate archive, and only unpacks them - and points
  // LD_LIBRARY_PATH at them - when it believes it is inside a Lambda
  // container. It decides that from AWS_EXECUTION_ENV or AWS_LAMBDA_JS_RUNTIME.
  // Vercel's functions do run on Lambda but expose neither, so the archive was
  // never unpacked: the binary itself extracted fine and then died with
  // "libnss3.so: cannot open shared object file".
  //
  // Both the unpacking and the LD_LIBRARY_PATH assignment happen when the
  // module is first required, so this has to be set before that require, not
  // after. Which archive is right follows the OS behind the runtime, and the
  // Node version is what identifies it: 20 and later run on Amazon Linux 2023,
  // earlier ones on Amazon Linux 2. A host that already sets either variable
  // knows better than we do and is left alone.
  if (!process.env.AWS_EXECUTION_ENV && !process.env.AWS_LAMBDA_JS_RUNTIME) {
    const major = parseInt(process.versions.node, 10);
    process.env.AWS_LAMBDA_JS_RUNTIME = major >= 20 ? 'nodejs20.x' : 'nodejs18.x';
  }

  const chromium = require('@sparticuz/chromium');
  return puppeteer.launch({
    args: chromium.args,
    defaultViewport: chromium.defaultViewport,
    executablePath: await chromium.executablePath(),
    headless: chromium.headless,
  });
}

// Runs one capture. Platform-neutral on purpose: Netlify and Vercel hand a
// request over in different shapes, and the browser work has nothing to do
// with either of them. Returns { status, data } for an adapter to send.
async function runCapture(payload) {
  const { url } = payload || {};
  let { user, pass } = payload || {};
  if (!url || typeof url !== 'string') {
    return result(400, { error: 'Missing "url"' });
  }

  const deviceName = DEVICES[payload.device] ? payload.device : 'desktop';
  const device = DEVICES[deviceName];

  let targetUrl;
  try {
    targetUrl = new URL(normalizeUrl(url));
  } catch (err) {
    return result(400, { error: 'Invalid URL: ' + url });
  }
  if (!/^https?:$/.test(targetUrl.protocol)) {
    return result(400, { error: 'URL must be http or https' });
  }

  // Credentials pasted into the URL - https://user:pass@host - are how people
  // actually share a protected dev site, and they were being thrown away: the
  // fields were the only source, so page.authenticate never ran. A browser
  // sends URL credentials on the first navigation and nothing after it, so the
  // page loaded while nine of its ten stylesheets came back 401, leaving a
  // preview with no styling. They are lifted out here and stripped from the
  // URL, so every later request is authenticated the same way.
  if (targetUrl.username && !user) {
    user = decodeURIComponent(targetUrl.username);
    pass = decodeURIComponent(targetUrl.password || '');
  }
  targetUrl.username = '';
  targetUrl.password = '';

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

    // The <html> element carries a site's theme hooks - a theme class, a
    // data-theme, a dir, and the generated class a font loader hangs its
    // --font-* variables off. Rendering the preview with a bare <html> made
    // every rule keyed to one of those miss, so a fully captured page still
    // came out looking unstyled. `style` is deliberately left out: the custom
    // properties it holds are already in `authored`, and re-applying it as an
    // inline style would outrank the editor's own :root block.
    const htmlAttrs = await page.evaluate(() => {
      const out = {};
      Array.from(document.documentElement.attributes).forEach((attr) => {
        if (attr.name.toLowerCase() !== 'style') out[attr.name] = attr.value;
      });
      return out;
    });

    // Every stylesheet the document actually has, in document order - not just
    // the <link> ones. A framework-built site keeps most of its CSS in <style>
    // blocks the server rendered or the bundler injected, and collecting only
    // links meant fetching a handful of vendor files and none of the styling:
    // the capture reported no missing stylesheets while the preview rendered
    // as bare text.
    //
    // Where the rules are readable they are serialised straight from CSSOM,
    // which also picks up anything JavaScript added after load. A cross-origin
    // sheet throws on .cssRules and is left to be fetched by URL below.
    const sheets = await page.evaluate(() => {
      const read = (sheet) => {
        const node = sheet.ownerNode;
        let text = '';
        let rules = -1;
        if (node && node.tagName === 'STYLE') {
          text = node.textContent || '';
        }
        try {
          if (sheet.cssRules) {
            rules = sheet.cssRules.length;
            if (!text) text = Array.from(sheet.cssRules).map((rule) => rule.cssText).join('\n');
          }
        } catch (err) {
          // cross-origin: unreadable here, fetched below
        }
        return {
          href: sheet.href || '',
          text: text,
          // A sheet limited to print, or to a width the preview is not at,
          // must stay limited. Concatenating it unconditionally applied a
          // print skin - no backgrounds, no nav - over the whole page.
          media: (sheet.media && sheet.media.mediaText) || '',
          // Alternate themes ship as disabled sheets and stay in
          // document.styleSheets. Taking them applied every theme at once.
          disabled: !!sheet.disabled,
          kind: node ? (node.tagName || '').toLowerCase() : 'adopted',
          rules: rules,
        };
      };

      const all = Array.from(document.styleSheets).map(read);
      // Constructed sheets are not in document.styleSheets at all, so a site
      // that adopts them had that CSS missing with nothing reported.
      Array.from(document.adoptedStyleSheets || []).forEach((sheet) => all.push(read(sheet)));
      return all;
    });

    const stylesheetUrls = sheets.map((sheet) => sheet.href);

    // Fetch the stylesheets from inside the page, not from here. The browser
    // is already authenticated - page.authenticate answers the basic-auth
    // challenge for every request it makes, and it holds the session cookies
    // too. A fetch from Node has neither, so on a protected site every
    // stylesheet came back 401 and was silently dropped: the variables still
    // loaded (they are read from the live page) while the preview rendered
    // with no CSS at all, which looks exactly like a broken site.
    const fetched = await page.evaluate(async (list) => {
      const out = [];
      for (const sheet of list) {
        // A disabled sheet is not styling the page; fetching it would only
        // let a theme the site has switched off into the preview.
        if (sheet.disabled) {
          out.push('');
          continue;
        }
        // Already have the rules - no request needed at all.
        if (sheet.text) {
          out.push(sheet.text);
          continue;
        }
        if (!sheet.href) {
          out.push('');
          continue;
        }
        try {
          const res = await fetch(sheet.href, { credentials: 'include' });
          out.push(res.ok ? await res.text() : '');
        } catch (err) {
          // Cross-origin without CORS headers - retried from Node below,
          // where the same-origin policy does not apply.
          out.push('');
        }
      }
      return out;
    }, sheets);

    await browser.close();
    browser = null;

    // Whatever the page could not fetch itself, try from here - carrying the
    // credentials this time, so a protected asset host still works.
    const authHeader = user
      ? { Authorization: 'Basic ' + Buffer.from(`${user}:${pass || ''}`).toString('base64') }
      : undefined;

    const cssParts = await Promise.all(
      sheets.map(async (sheet, i) => {
        let text = fetched[i];
        if (!text && sheet.href && !sheet.disabled) {
          try {
            const res = await fetch(sheet.href, authHeader ? { headers: authHeader } : undefined);
            text = res.ok ? await res.text() : '';
          } catch (err) {
            text = '';
          }
        }
        if (!text) return '';
        // An inline <style> has no URL of its own; its relative urls resolve
        // against the page, which is what the preview's <base> already points at.
        text = absolutizeUrls(stripRootVars(text), sheet.href || landedUrl.toString());
        // The media attribute lives on the element, not in the file. Every
        // sheet lands in one <style>, so the restriction has to be written
        // back in or a print-only sheet paints the screen.
        return wrapMedia(text, sheet.media);
      })
    );

    // A disabled sheet is deliberately not contributing, so it is not a
    // failure to report.
    const cssMissing = cssParts.filter((part, i) => !part && !sheets[i].disabled).length;

    const sheetReport = sheets.map((sheet, i) => ({
      href: sheet.href,
      kind: sheet.kind,
      media: sheet.media,
      disabled: sheet.disabled,
      rules: sheet.rules,
      bytes: cssParts[i].length,
    }));

    return result(200, {
      root,
      authored,
      css: hoistImports(cssParts.join('\n\n')),
      // The same CSS kept one sheet per entry. The preview gives each its own
      // <style>, so a sheet this pipeline mangles can only cost its own rules
      // instead of taking the other nine down with it - a single unbalanced
      // comment in one bundle parsed the whole 800KB concatenation to zero
      // rules and the page rendered with nothing applied at all.
      cssList: cssParts,
      body,
      htmlAttrs,
      base: `${landedUrl.protocol}//${landedUrl.host}`,
      // The full post-redirect URL, so the preview can resolve relative links
      // and assets against the actual page rather than just the origin.
      pageUrl: landedUrl.toString(),
      device: deviceName,
      schemeNames,
      pageFont,
      pageFontSize,
      varCount: Object.keys(root).length,
      // A stylesheet that could not be read is why a preview renders naked.
      // Reporting it turns a mystery into a message.
      cssCount: stylesheetUrls.length,
      cssMissing: cssMissing,
      // What each sheet actually contributed, so a preview that still looks
      // wrong can be diagnosed from the app instead of guessed at.
      sheetReport,
      // Reported separately so the status line can say how much of the capture
      // is the scheme itself and how much is the page's own tokens.
      schemeCount: Object.keys(root).filter((name) => name.indexOf('--scheme-') === 0).length,
    });
  } catch (err) {
    return result(500, { error: err && err.message ? err.message : 'Capture failed' });
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch (_) {
        // already closed
      }
    }
  }
}

// Accepts what people actually paste: "casino.com", "www.casino.com/zh/".
// A bare host has no scheme for `new URL` to parse, so default it to https.
// Anything that already carries a scheme is left alone, so a non-http one
// still fails the protocol check below rather than being silently rewritten.
function normalizeUrl(raw) {
  const trimmed = String(raw).trim();
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) return trimmed;
  return 'https://' + trimmed.replace(/^\/+/, '');
}

// The editor owns the page's custom properties, so the authored ones are
// taken out and re-emitted from its own :root block. Only the custom
// properties, though: throwing the whole block away also threw away things
// like `:root { font-size: 62.5% }`, and every rem on the page then measured
// against 16px instead of 10px - a page that captured perfectly and rendered
// at the wrong size everywhere.
function stripRootVars(css) {
  return css.replace(/(^|[\s,{}])(:root\b[^{}]*)\{([^{}]*)\}/g, (whole, lead, selector, body) => {
    // Only a plain :root selector - `:root .card` styles descendants and its
    // declarations are not ours to touch.
    if (!/^:root(\s*:[A-Za-z-]+(\([^)]*\))?)*\s*$/.test(selector)) return whole;
    const kept = body
      .split(';')
      .filter((decl) => decl.trim() && !/^\s*--/.test(decl))
      .join(';');
    return kept.trim() ? `${lead}${selector}{${kept};}` : lead;
  });
}

// A sheet's media restriction lives on the <link>/<style> element, not in the
// file. Concatenating every sheet into one <style> drops it, so it is written
// back as an @media wrapper.
function wrapMedia(css, media) {
  const query = String(media || '').trim();
  if (!query || query.toLowerCase() === 'all') return css;
  return `@media ${query} {\n${css}\n}`;
}

// A stylesheet's relative URLs resolve against the stylesheet, not the page.
// The preview puts every sheet in one <style> under a <base> pointing at the
// page, so `url(../fonts/lato.woff2)` in /assets/css/site.css would be looked
// for in the wrong directory and the web font would never arrive - leaving the
// preview, and the specimens beside it, in a fallback face.
function absolutizeUrls(css, sheetHref) {
  return css
    .replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/g, (whole, quote, ref) => {
      if (/^(data:|https?:|\/\/|#)/i.test(ref)) return whole;
      try {
        return 'url("' + new URL(ref, sheetHref).toString() + '")';
      } catch (err) {
        return whole;
      }
    })
    .replace(/@import\s+(['"])([^'"]+)\1/g, (whole, quote, ref) => {
      if (/^(data:|https?:|\/\/)/i.test(ref)) return whole;
      try {
        return '@import "' + new URL(ref, sheetHref).toString() + '"';
      } catch (err) {
        return whole;
      }
    });
}

// @import is only honoured at the very start of a stylesheet. Every sheet is
// concatenated into one <style>, so any import belonging to the second sheet
// onwards would be silently dropped - and a site that loads its typeface that
// way (`@import url(...Lato...)`) would render in a fallback face with no
// error anywhere. Lifting them to the front, in order, keeps them valid.
function hoistImports(css) {
  const imports = [];
  const rest = css.replace(/@import\s+[^;]+;/g, (whole) => {
    imports.push(whole.trim());
    return '';
  });
  return imports.length ? imports.join('\n') + '\n' + rest : rest;
}

function result(status, data) {
  return { status, data };
}

module.exports = { runCapture };
