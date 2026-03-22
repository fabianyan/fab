const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const BOT_UA = 'python-requests/2.31';
const REQUEST_TIMEOUT = 8000;

function normalizeUrl(url) {
  url = url.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }
  return url;
}

function countLinks(html) {
  const matches = html.match(/<a[\s>]/gi);
  return matches ? matches.length : 0;
}

async function fetchWithConfig(url, userAgent, followRedirects = true) {
  const start = Date.now();
  let redirectCount = 0;
  let finalUrl = url;

  const instance = axios.create({
    timeout: REQUEST_TIMEOUT,
    maxRedirects: followRedirects ? 10 : 0,
    validateStatus: () => true,
    headers: {
      'User-Agent': userAgent,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  });

  // Track redirects
  instance.interceptors.response.use((response) => {
    if (response.request && response.request.res) {
      finalUrl = response.request.res.responseUrl || url;
    }
    return response;
  });

  const response = await instance.get(url);
  const elapsed = Date.now() - start;

  // Count redirects from history if available
  if (response.request && response.request._redirectable) {
    redirectCount = response.request._redirectable._redirectCount || 0;
  }

  // Try to get final URL
  if (response.request && response.request.res && response.request.res.responseUrl) {
    finalUrl = response.request.res.responseUrl;
    try {
      const origHost = new URL(url).hostname;
      const finalHost = new URL(finalUrl).hostname;
      if (origHost !== finalHost) redirectCount = Math.max(redirectCount, 1);
    } catch {}
  }

  return {
    status: response.status,
    headers: response.headers,
    data: response.data || '',
    elapsed,
    finalUrl,
    redirectCount,
  };
}

function analyzeHeaders(headers) {
  const findings = {
    cloudflare: false,
    cloudfront: false,
    waf: false,
    reasons: [],
    signals: {},
  };

  const h = {};
  for (const [k, v] of Object.entries(headers)) {
    h[k.toLowerCase()] = String(v).toLowerCase();
  }

  // Cloudflare detection
  if (h['server'] && h['server'].includes('cloudflare')) {
    findings.cloudflare = true;
    findings.reasons.push('Header "server: cloudflare" detected');
    findings.signals.server = headers['server'];
  }
  if (h['cf-ray']) {
    findings.cloudflare = true;
    findings.reasons.push('Cloudflare "cf-ray" header detected');
    findings.signals['cf-ray'] = headers['cf-ray'];
  }
  if (h['cf-cache-status']) {
    findings.cloudflare = true;
    findings.reasons.push('Cloudflare "cf-cache-status" header detected');
    findings.signals['cf-cache-status'] = headers['cf-cache-status'];
  }
  if (h['cf-mitigated']) {
    findings.cloudflare = true;
    findings.reasons.push('Cloudflare "cf-mitigated" header detected');
    findings.signals['cf-mitigated'] = headers['cf-mitigated'];
  }

  // CloudFront detection
  if (h['x-amz-cf-id']) {
    findings.cloudfront = true;
    findings.waf = true;
    findings.reasons.push('AWS CloudFront "x-amz-cf-id" header detected');
    findings.signals['x-amz-cf-id'] = headers['x-amz-cf-id'];
  }
  if (h['x-amz-cf-pop']) {
    findings.cloudfront = true;
    findings.waf = true;
    findings.reasons.push('AWS CloudFront "x-amz-cf-pop" header detected');
    findings.signals['x-amz-cf-pop'] = headers['x-amz-cf-pop'];
  }

  // Generic WAF detection
  if (h['x-sucuri-id']) {
    findings.waf = true;
    findings.reasons.push('Sucuri WAF "x-sucuri-id" header detected');
    findings.signals['x-sucuri-id'] = headers['x-sucuri-id'];
  }
  if (h['x-firewall']) {
    findings.waf = true;
    findings.reasons.push('"x-firewall" header detected');
    findings.signals['x-firewall'] = headers['x-firewall'];
  }
  if (h['x-waf-event-info']) {
    findings.waf = true;
    findings.reasons.push('"x-waf-event-info" header detected');
    findings.signals['x-waf-event-info'] = headers['x-waf-event-info'];
  }
  if (h['x-cdn'] && (h['x-cdn'].includes('incapsula') || h['x-cdn'].includes('imperva'))) {
    findings.waf = true;
    findings.reasons.push('Imperva/Incapsula WAF "x-cdn" header detected');
    findings.signals['x-cdn'] = headers['x-cdn'];
  }
  if (h['x-iinfo']) {
    findings.waf = true;
    findings.reasons.push('Incapsula WAF "x-iinfo" header detected');
    findings.signals['x-iinfo'] = headers['x-iinfo'];
  }
  if (h['server'] && (h['server'].includes('akamai') || h['server'].includes('ghost'))) {
    findings.waf = true;
    findings.reasons.push(`Akamai WAF server header detected: ${headers['server']}`);
    findings.signals['server-akamai'] = headers['server'];
  }

  return findings;
}

function analyzeHtml(html) {
  const length = html.length;
  const linkCount = countLinks(html);
  const findings = { reasons: [], signals: { html_length: length, link_count: linkCount } };

  if (length < 5000) {
    findings.suspicious = true;
    findings.reasons.push(`HTML length is ${length} bytes (< 5000) — response may be a challenge page`);
  }
  if (linkCount === 0) {
    findings.blocked = true;
    findings.reasons.push('No <a> links found in HTML — likely a block/challenge page');
  }

  // Check for known challenge page patterns
  if (/cf-browser-verification|challenge-running|jschl_vc|cf_chl_/i.test(html)) {
    findings.cloudflareChallenge = true;
    findings.reasons.push('Cloudflare browser challenge/CAPTCHA page detected in HTML');
  }
  if (/sucuri_cloudproxy|sucuri website firewall/i.test(html)) {
    findings.sucuri = true;
    findings.reasons.push('Sucuri WAF block page detected in HTML');
  }
  if (/Access Denied|Request blocked|Forbidden|403 Forbidden/i.test(html) && length < 10000) {
    findings.blocked = true;
    findings.reasons.push('Access denied / blocked content detected in small HTML response');
  }

  return findings;
}

function compareUaResponses(browserResult, botResult) {
  const findings = { botDetection: false, reasons: [], signals: {} };

  const lenDiff = Math.abs(browserResult.html_length - botResult.html_length);
  const linkDiff = Math.abs(browserResult.link_count - botResult.link_count);
  const lenRatio = browserResult.html_length > 0
    ? lenDiff / browserResult.html_length
    : 0;

  findings.signals = {
    browser_html_length: browserResult.html_length,
    bot_html_length: botResult.html_length,
    length_difference: lenDiff,
    browser_link_count: browserResult.link_count,
    bot_link_count: botResult.link_count,
    link_difference: linkDiff,
    length_ratio: Math.round(lenRatio * 100) / 100,
  };

  if (lenRatio > 0.2 && lenDiff > 500) {
    findings.botDetection = true;
    findings.reasons.push(
      `HTML length differs significantly between browser UA (${browserResult.html_length}B) and bot UA (${botResult.html_length}B) — ${Math.round(lenRatio * 100)}% difference`
    );
  }
  if (linkDiff >= 3 && botResult.link_count < browserResult.link_count) {
    findings.botDetection = true;
    findings.reasons.push(
      `Link count differs: browser UA got ${browserResult.link_count} links, bot UA got ${botResult.link_count} links`
    );
  }
  if (botResult.status !== browserResult.status) {
    findings.botDetection = true;
    findings.reasons.push(
      `Different HTTP status codes: browser UA got ${browserResult.status}, bot UA got ${botResult.status}`
    );
  }

  return findings;
}

app.post('/analyze', async (req, res) => {
  let { url } = req.body;

  if (!url || typeof url !== 'string' || url.trim() === '') {
    return res.status(400).json({ error: 'URL is required' });
  }

  url = normalizeUrl(url);

  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const result = {
    cloudflare: false,
    cloudfront: false,
    waf: false,
    bot_detection: false,
    geo_filtering: 'unknown',
    confidence_score: 0,
    reasons: [],
    raw_signals: {},
    meta: { url, analyzed_at: new Date().toISOString() },
  };

  let score = 0;

  // --- 1. Browser UA request (primary) ---
  let browserRes;
  try {
    browserRes = await fetchWithConfig(url, BROWSER_UA, true);
    result.raw_signals.browser_request = {
      status: browserRes.status,
      elapsed_ms: browserRes.elapsed,
      final_url: browserRes.finalUrl,
      redirect_count: browserRes.redirectCount,
      html_length: browserRes.data.length,
      link_count: countLinks(browserRes.data),
    };

    // --- 2. Header analysis ---
    const headerFindings = analyzeHeaders(browserRes.headers);
    if (headerFindings.cloudflare) {
      result.cloudflare = true;
      score += 40;
    }
    if (headerFindings.cloudfront) {
      result.cloudfront = true;
    }
    if (headerFindings.waf || headerFindings.cloudfront) {
      result.waf = true;
      score += 30;
    }
    result.reasons.push(...headerFindings.reasons);
    result.raw_signals.headers_detected = headerFindings.signals;

    // --- 3. HTML content analysis ---
    const htmlFindings = analyzeHtml(browserRes.data);
    result.reasons.push(...htmlFindings.reasons);
    result.raw_signals.html_analysis = htmlFindings.signals;
    if (htmlFindings.suspicious || htmlFindings.blocked) {
      score += 20;
    }
    if (htmlFindings.cloudflareChallenge) {
      result.cloudflare = true;
      score += 20;
    }

    // --- 4. Redirect tracking ---
    result.raw_signals.redirects = {
      count: browserRes.redirectCount,
      final_url: browserRes.finalUrl,
    };
    if (browserRes.redirectCount > 3) {
      result.reasons.push(`Excessive redirects detected (${browserRes.redirectCount} hops)`);
      score += 10;
    }

    // --- 5. Timing analysis ---
    result.raw_signals.timing = { elapsed_ms: browserRes.elapsed };
    if (browserRes.elapsed > 3000) {
      result.reasons.push(`Slow response time (${browserRes.elapsed}ms) — possible WAF challenge or rate limiting`);
      score += 10;
    }

  } catch (err) {
    const msg = err.code === 'ECONNABORTED' ? 'Request timed out (8s)' : err.message;
    result.reasons.push(`Browser UA request failed: ${msg}`);
    result.raw_signals.browser_request_error = msg;

    if (err.code === 'ECONNABORTED') {
      score += 15;
      result.reasons.push('Timeout may indicate WAF challenge or heavy rate limiting');
    }
  }

  // --- 6. Bot UA request (for comparison) ---
  let botRes;
  try {
    botRes = await fetchWithConfig(url, BOT_UA, true);
    result.raw_signals.bot_request = {
      status: botRes.status,
      elapsed_ms: botRes.elapsed,
      html_length: botRes.data.length,
      link_count: countLinks(botRes.data),
    };

    // UA comparison (only if browser request also succeeded)
    if (browserRes) {
      const uaFindings = compareUaResponses(
        result.raw_signals.browser_request,
        result.raw_signals.bot_request
      );
      if (uaFindings.botDetection) {
        result.bot_detection = true;
        score += 30;
      }
      result.reasons.push(...uaFindings.reasons);
      result.raw_signals.ua_comparison = uaFindings.signals;
    }

    // Geo filtering heuristic: if bot UA gets 403/503 but browser doesn't
    if (botRes.status === 403 || botRes.status === 503) {
      if (browserRes && browserRes.status === 200) {
        result.geo_filtering = 'suspected';
        result.bot_detection = true;
        result.reasons.push(`Bot UA received HTTP ${botRes.status} while browser UA received ${browserRes.status} — likely bot/geo filtering`);
        score += 20;
      }
    }

  } catch (err) {
    const msg = err.code === 'ECONNABORTED' ? 'Request timed out (8s)' : err.message;
    result.raw_signals.bot_request_error = msg;

    // If browser succeeded but bot timed out/failed → strong bot detection signal
    if (browserRes) {
      result.bot_detection = true;
      score += 30;
      result.reasons.push(`Bot UA request failed (${msg}) while browser UA succeeded — strong bot detection signal`);
    }
  }

  result.confidence_score = Math.min(score, 100);

  if (result.reasons.length === 0) {
    result.reasons.push('No protection signals detected');
  }

  // Collect notable response headers for display
  if (browserRes) {
    const interestingHeaders = [
      'server', 'x-powered-by', 'cf-ray', 'cf-cache-status', 'cf-mitigated',
      'x-amz-cf-id', 'x-amz-cf-pop', 'x-sucuri-id', 'x-firewall',
      'x-cache', 'x-cdn', 'via', 'x-frame-options', 'strict-transport-security',
    ];
    const collected = {};
    for (const h of interestingHeaders) {
      if (browserRes.headers[h]) collected[h] = browserRes.headers[h];
    }
    result.raw_signals.notable_headers = collected;
  }

  res.json(result);
});

app.listen(PORT, () => {
  console.log(`WAF Detector running at http://localhost:${PORT}`);
});
