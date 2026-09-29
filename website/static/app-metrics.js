/* ──────────────────────────────────────────────────────────────────────────
   app-metrics.js – benchmark metrics table and chart
   The table renders as soon as /api/metrics answers. Chart.js is fetched only
   when the benchmark section comes near the viewport; the chart is drawn once
   both the metrics and the library are here, in whichever order they arrive.
   ────────────────────────────────────────────────────────────────────────── */

let metricsChart = null;
// The last loaded metrics, or null (loading) / false (failed), for re-rendering
// the table and chart labels after a language switch.
let _lastMetrics = null;
const METRIC_KEYS = ['Accuracy', 'Precision', 'Recall', 'F1', 'ROC_AUC'];
const metricLabel = key => t(`metric.${key}`);

function renderMetricsUnavailable() {
  document.getElementById('metrics-tbody').innerHTML =
    `<tr><td colspan="6" class="loading-cell">${escapeHtml(t('perf.unavailable'))}</td></tr>`;
}

// ── Metrics Table ─────────────────────────────────────────────────────────────
async function loadMetrics() {
  let metrics;
  try {
    metrics = await getRequest('/api/metrics', undefined, async res => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.json())?.metrics;
    });
    if (!metrics || typeof metrics !== 'object' || !Object.keys(metrics).length) {
      throw new Error('Response has no metrics');
    }
    renderMetricsTable(metrics);
    _lastMetrics = metrics;
  } catch (e) {
    console.error('Failed to load metrics:', e);
    _lastMetrics = false;
    renderMetricsUnavailable();
    return;
  }
  drawMetricsChart();
}

// Draws (or redraws) the chart from the last metrics once Chart.js is here.
// A chart failure must not replace the table that already rendered.
function drawMetricsChart() {
  if (!_lastMetrics || typeof Chart !== 'function') return;
  try {
    renderMetricsChart(_lastMetrics);
  } catch (e) {
    console.error('Failed to render metrics chart:', e);
  }
}

// ── Chart.js, on demand ──────────────────────────────────────────────────────
// The vendored file and its SRI pin; the request is same-origin, so the
// integrity check needs no crossorigin attribute.
const CHART_SRC = '/static/vendor/chart/chart.umd.min.js?v=4.4.0';
const CHART_INTEGRITY = 'sha384-e6nUZLBkQ86NJ6TVVKAeSaK8jWa3NhkYWZFomE39AvDbQWeie9PlQqM3pmYW5d1g';
// 'idle' until requested, then 'loading', 'ready' or 'failed'.
let _chartLibrary = 'idle';

function loadChartLibrary() {
  if (_chartLibrary !== 'idle') return;
  if (typeof Chart === 'function') { _chartLibrary = 'ready'; drawMetricsChart(); return; }
  _chartLibrary = 'loading';
  const failed = error => {
    _chartLibrary = 'failed';
    console.warn('Benchmark chart unavailable; the table shows the same results.', error || '');
  };
  try {
    const script = document.createElement('script');
    script.src = CHART_SRC;
    script.integrity = CHART_INTEGRITY;
    script.addEventListener('load', () => {
      if (typeof Chart !== 'function') { failed(); return; }
      _chartLibrary = 'ready';
      if (!metricsChart) drawMetricsChart();
    });
    // A network or integrity failure: the table stays, nothing is drawn.
    script.addEventListener('error', () => failed());
    (document.head || document.body).appendChild(script);
  } catch (error) {
    failed(error);
  }
}

// Requests Chart.js when #performance is within 600px of the viewport (at
// once if it already is, or without IntersectionObserver).
function setupMetricsChartLoader() {
  const section = document.getElementById('performance');
  if (typeof IntersectionObserver === 'undefined' || !section) { loadChartLibrary(); return; }
  const observer = new IntersectionObserver(entries => {
    if (!entries.some(entry => entry.isIntersecting)) return;
    observer.disconnect();
    loadChartLibrary();
  }, { rootMargin: '600px 0px' });
  observer.observe(section);
}

function renderMetricsTable(metrics) {
  const tbody = document.getElementById('metrics-tbody');
  const classifiers = Object.keys(metrics);
  const cols = METRIC_KEYS;
  const best = {};
  cols.forEach(col => { best[col] = Math.max(...classifiers.map(c => metrics[c][col])); });
  // The overall "Best" row is the highest F1; a tie goes to the higher ROC_AUC.
  const bestClf = classifiers.reduce((top, clf) =>
    (metrics[clf].F1 - metrics[top].F1 || metrics[clf].ROC_AUC - metrics[top].ROC_AUC) > 0 ? clf : top,
  classifiers[0]);

  tbody.innerHTML = classifiers.map(clf => {
    const m = metrics[clf];
    const isBest = clf === bestClf;
    return `
      <tr class="${isBest ? 'row-best' : ''}">
        <td class="clf-name">${escapeHtml(clf)}${isBest ? ` <span class="best-badge">${icon('award')} ${escapeHtml(t('perf.best'))}</span>` : ''}</td>
        ${cols.map(col => `<td class="${m[col] === best[col] ? 'cell-best' : ''}" data-label="${escapeHtml(metricLabel(col))}">${m[col].toFixed(4)}</td>`).join('')}
      </tr>
    `;
  }).join('');
}

const CHART_PALETTES = {
  dark:  ['79,209,255', '63,213,143', '240,192,90', '180,140,255'],
  light: ['10,127,214', '21,154,99', '183,134,11', '124,77,219'],
};

// Chart.js draws on a canvas, so CSS variables do not reach it; read the
// current theme's tokens and pass them in explicitly.
function chartTheme() {
  const root = document.documentElement;
  const css = root && typeof getComputedStyle === 'function' ? getComputedStyle(root) : null;
  const token = (name, fallback) => (css && css.getPropertyValue(name).trim()) || fallback;
  const light = Boolean(root && root.dataset && root.dataset.theme === 'light');
  return {
    palette: CHART_PALETTES[light ? 'light' : 'dark'],
    text: token('--text-muted', '#9aa3b2'),
    title: token('--text', '#f3f5f9'),
    grid: token('--line', 'rgba(255,255,255,0.08)'),
    tooltipBg: token('--bg-card2', '#121826'),
    tooltipBorder: token('--border-hi', 'rgba(255,255,255,0.16)'),
  };
}

// Accepts either a Chart instance or its constructor config (same data/options shape).
function applyChartTheme(chart) {
  const theme = chartTheme();
  chart.data.datasets.forEach((dataset, i) => {
    const rgb = theme.palette[i % theme.palette.length];
    dataset.backgroundColor = `rgba(${rgb},0.80)`;
    dataset.borderColor = `rgba(${rgb},1)`;
  });
  const { plugins, scales } = chart.options;
  plugins.legend.labels.color = theme.text;
  Object.assign(plugins.tooltip, {
    backgroundColor: theme.tooltipBg, borderColor: theme.tooltipBorder,
    titleColor: theme.title, bodyColor: theme.text,
  });
  scales.y.ticks.color = theme.text;
  scales.y.grid.color = theme.grid;
  scales.x.ticks.color = theme.text;
}

function restyleMetricsChart() {
  if (!metricsChart) return;
  applyChartTheme(metricsChart);
  metricsChart.update('none');
}

// Re-renders the benchmark table and chart axis labels in the current language.
// Classifier names are model names from the API and stay as sent.
function relabelMetrics() {
  if (_lastMetrics === false) renderMetricsUnavailable();
  if (!_lastMetrics) return;
  renderMetricsTable(_lastMetrics);
  if (!metricsChart) return;
  metricsChart.data.labels = METRIC_KEYS.map(metricLabel);
  metricsChart.update('none');
}

function renderMetricsChart(metrics) {
  const ctx = document.getElementById('metricsChart').getContext('2d');
  const classifiers = Object.keys(metrics);
  const labels = METRIC_KEYS.map(metricLabel);
  const datasets = classifiers.map(clf => ({
    label: clf,
    data: METRIC_KEYS.map(k => metrics[clf][k]),
    borderWidth: 1.5,
    borderRadius: 4,
  }));
  if (metricsChart) metricsChart.destroy();
  const config = {
    type: 'bar',
    data: { labels, datasets },
    options: {
      responsive: true,
      // Drawn as the section scrolls into view, so its entry animation can be seen.
      ...(prefersReducedMotion() ? { animation: false } : {}),
      plugins: {
        legend: { position: 'bottom', labels: { font: { size: 11 }, boxWidth: 12, boxHeight: 12 } },
        tooltip: {
          borderWidth: 1,
          callbacks: { label: c => `${c.dataset.label}: ${c.parsed.y.toFixed(4)}` },
        },
      },
      scales: {
        y: { min: 0.88, max: 1.0, ticks: {}, grid: {} },
        x: { ticks: {}, grid: { display: false } },
      },
    },
  };
  applyChartTheme(config);
  metricsChart = new Chart(ctx, config);
}
