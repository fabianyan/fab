(function () {
  const urlInput   = document.getElementById('urlInput');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const statusEl   = document.getElementById('status');
  const resultsEl  = document.getElementById('results');

  // Allow Enter key to trigger analysis
  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') analyzeBtn.click();
  });

  analyzeBtn.addEventListener('click', async () => {
    const raw = urlInput.value.trim();
    if (!raw) {
      setStatus('Please enter a URL.', 'warn');
      return;
    }

    setLoading(true);
    setStatus('<span class="spinner"></span> Analyzing — making browser & bot requests…');
    resultsEl.style.display = 'none';
    resultsEl.innerHTML = '';

    try {
      const res = await fetch('/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: raw }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || `Server error ${res.status}`);
      }

      setStatus('');
      renderResults(data);
    } catch (err) {
      setStatus('');
      resultsEl.style.display = 'block';
      resultsEl.innerHTML = `<div class="error-box">Error: ${escHtml(err.message)}</div>`;
    } finally {
      setLoading(false);
    }
  });

  /* ── Rendering ─────────────────────────────────────────── */

  function renderResults(d) {
    const score = d.confidence_score || 0;
    const level = score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';

    const verdictText = level === 'high'
      ? 'Very likely protected'
      : level === 'medium'
        ? 'Possibly protected'
        : 'No strong protection detected';

    const verdictIcon = level === 'high' ? '🔴' : level === 'medium' ? '🟡' : '🟢';
    const verdictSub  = `Confidence score: ${score}/100`;

    // Detection items
    const detItems = [
      {
        icon: '☁️',
        name: 'Cloudflare',
        value: d.cloudflare ? 'Detected' : 'Not detected',
        cls: d.cloudflare ? 'yes' : 'no',
      },
      {
        icon: '🛡️',
        name: 'WAF / CDN',
        value: d.waf ? 'Detected' : 'Not detected',
        cls: d.waf ? 'yes' : 'no',
      },
      {
        icon: '🤖',
        name: 'Bot Detection',
        value: d.bot_detection ? 'Detected' : 'Not detected',
        cls: d.bot_detection ? 'yes' : 'no',
      },
      {
        icon: '🌍',
        name: 'Geo Filtering',
        value: capitalize(d.geo_filtering || 'unknown'),
        cls: d.geo_filtering === 'suspected' ? 'suspected' : 'unknown',
      },
    ];

    const detHTML = detItems.map((item) => `
      <div class="det-item">
        <span class="det-icon">${item.icon}</span>
        <div class="det-info">
          <div class="det-name">${item.name}</div>
          <div class="det-value ${item.cls}">${item.value}</div>
        </div>
      </div>
    `).join('');

    const reasons = Array.isArray(d.reasons) && d.reasons.length
      ? d.reasons.map((r) => `<li>${escHtml(r)}</li>`).join('')
      : '<li>No signals recorded.</li>';

    const rawJson = JSON.stringify(d.raw_signals || {}, null, 2);

    const metaUrl      = d.meta?.url || '';
    const metaFinalUrl = d.raw_signals?.redirects?.final_url || '';
    const metaTime     = d.raw_signals?.timing?.elapsed_ms != null
      ? `${d.raw_signals.timing.elapsed_ms}ms` : '—';
    const metaRedirects = d.raw_signals?.redirects?.count != null
      ? d.raw_signals.redirects.count : '—';

    resultsEl.innerHTML = `
      <div class="verdict ${level}">
        <span class="verdict-icon">${verdictIcon}</span>
        <div class="verdict-text">
          <h2>${verdictText}</h2>
          <p>${verdictSub}</p>
        </div>
      </div>

      <div class="score-bar-wrap">
        <div class="score-label">
          <span>Protection confidence</span>
          <span>${score}%</span>
        </div>
        <div class="score-bar-bg">
          <div class="score-bar-fill ${level}" style="width: ${score}%"></div>
        </div>
      </div>

      <div class="detections">${detHTML}</div>

      <p class="section-title">Evidence</p>
      <ul class="reasons-list">${reasons}</ul>

      <details>
        <summary>Raw signals</summary>
        <pre>${escHtml(rawJson)}</pre>
      </details>

      <div class="meta">
        <span>URL: <strong>${escHtml(metaUrl)}</strong></span>
        ${metaFinalUrl && metaFinalUrl !== metaUrl ? `<span>Final URL: <strong>${escHtml(metaFinalUrl)}</strong></span>` : ''}
        <span>Response time: <strong>${metaTime}</strong></span>
        <span>Redirects: <strong>${metaRedirects}</strong></span>
      </div>
    `;

    resultsEl.style.display = 'block';
    // Animate score bar
    requestAnimationFrame(() => {
      const fill = resultsEl.querySelector('.score-bar-fill');
      if (fill) fill.style.width = score + '%';
    });
  }

  /* ── Helpers ────────────────────────────────────────────── */

  function setLoading(on) {
    analyzeBtn.disabled = on;
    analyzeBtn.textContent = on ? 'Analyzing…' : 'Analyze';
  }

  function setStatus(html) {
    statusEl.innerHTML = html;
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function capitalize(s) {
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
})();
