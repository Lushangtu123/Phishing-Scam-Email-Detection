/* ──────────────────────────────────────────────────────────────────────────
   app-metrics.js – benchmark metrics table and chart
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
    const res = await fetch('/api/metrics');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    metrics = (await res.json())?.metrics;
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
  // A chart failure must not replace the table that already rendered.
  try {
    renderMetricsChart(metrics);
  } catch (e) {
    console.error('Failed to render metrics chart:', e);
  }
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
