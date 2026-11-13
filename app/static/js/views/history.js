import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { api } from '../core/api.js';
import { active } from '../core/poller.js';
import { scanPath } from '../core/router.js';
import { timestamp, elapsed, short } from '../core/format.js';
import { pageHeading, button, link, panel, table, tr, stateBadge, severity, kv, empty, errorBox, htmlReportLink, copyButton } from '../components/ui.js';

export function mount(root, ctx) {
  let state, selected = null, selectedKey = null, loading = false, failure = null;
  let clearing = false, disposed = false, generation = 0, previous = null;
  async function load(id) {
    const current = ++generation;
    selected = null; failure = null; loading = !!id;
    if (!id) { render(); return; }
    render();
    const result = await api.scan(id);
    if (disposed || current !== generation) return;
    loading = false;
    if (result.ok) selected = result.data;
    else failure = result.error;
    render();
  }
  function running() { return active(state?.activeScan?.state) || active(state?.scan?.state); }
  async function clear() {
    if (clearing || running() || !window.confirm(t('historyClearConfirm'))) return;
    clearing = true; failure = null; render();
    const result = await api.clearHistory();
    if (disposed) return;
    clearing = false;
    if (result.ok) {
      generation++; selected = null; selectedKey = null;
      ctx.go('/history'); ctx.historyCleared();
    } else failure = result.error;
    render();
  }
  function detail() {
    if (loading) return empty(t('loading'));
    if (!selected) return empty(t(failure ? 'scanGone' : 'historyChoose'));
    const scan = selected, report = scan.report?.report;
    const tools = Object.values(scan.tools);
    return h('div', { dataset: test('history-detail') },
      kv([
        [t('historyScanID'), scan.scan_id], [t('target'), scan.target.url],
        [t('state'), stateBadge(scan.state)], [t('started'), timestamp(scan.created_at, state.prefs.tz)],
        [t('totalDuration'), elapsed(scan)],
        [t('historyReportRevision'), scan.report ? `r${scan.report.revision}` : '—'],
        [t('providers'), scan.report ? `${scan.report.provider_id} · ${scan.report.model}` : scan.provider_id],
      ]),
      h('div', { class: 'c-actions' },
        link(t('historyOpenWorkspace'), scanPath(scan.scan_id), 'history-open-workspace'),
        htmlReportLink(t('historyOpenHTML'), scan, 'history-open-html')),
      scan.report_url ? h('div', { class: 'v-history-report-url' },
        h('strong', {}, t('historyReportURL')),
        h('code', { dataset: test('history-report-url') }, scan.report_url),
        copyButton(new URL(scan.report_url, location.origin).href, 'history-copy-report-url')) : null,
      report ? h('section', {}, h('h3', {}, t('historyReportSummary')),
        severity(report.overall_risk), h('p', { class: 'v-history-copy' }, report.summary),
        ...report.findings.map((finding) => h('article', { class: 'v-history-finding' },
          h('h4', {}, finding.title), severity(finding.severity), h('small', {}, finding.scope),
          h('p', { class: 'v-history-copy' }, finding.description),
          h('p', { class: 'v-history-copy' }, finding.recommendation))),
        h('details', {}, h('summary', {}, t('historyLimitations')),
          h('ul', {}, ...report.limitations.map((item) => h('li', {}, item)))))
        : empty(t('historyNoReport')),
      h('h3', {}, t('coverage')),
      table([t('tools'), t('state'), 'Evidence'], tools.map((tool) => tr([
        tool.tool_id, stateBadge(tool.state), tool.evidence.length,
      ]))),
    );
  }
  function render() {
    if (!state || disposed) return;
    const rows = state.recent;
    replace(root, pageHeading(t('nav.history'), t('historyDescription')),
      h('div', { class: 'c-actions' },
        button(t('historyRefresh'), () => { ctx.historyPage(state.historyOffset || 0); load(ctx.route.params.selected); }, 'history-refresh', { disabled: clearing }),
        button(t('historyClear'), clear, 'history-clear', { disabled: clearing || running() || !rows.length })),
      failure ? errorBox(failure) : null,
      panel(t('historySavedScans'), 'history-list', rows.length ? h('div', {},
        table([t('historyScanID'), t('target'), t('started'), t('state'), t('risk'), 'HTML'],
          rows.map((scan) => tr([
            h('a', { href: `#/history/${encodeURIComponent(scan.scan_id)}`, dataset: test(`history-select-${scan.scan_id}`),
              ...(ctx.route.params.selected === scan.scan_id ? { 'aria-current': 'page' } : {}) }, short(scan.scan_id)),
            scan.target_url || '—', timestamp(scan.created_at, state.prefs.tz),
            stateBadge(scan.state), severity(scan.overall_risk || 'unknown'),
            htmlReportLink(t('historyOpenHTML'), scan, `history-html-${scan.scan_id}`) || '—',
          ], `history-item-${scan.scan_id}`))),
        h('div', { class: 'c-actions' },
          button(t('previous'), () => ctx.historyPage(Math.max(0, state.historyOffset - 10)), 'archive-previous', { disabled: state.historyBusy || !state.historyOffset }),
          h('span', {}, t('historyPage', { page: Math.floor((state.historyOffset || 0) / 10) + 1, total: state.historyTotal })),
          button(t('next'), () => ctx.historyPage((state.historyOffset || 0) + 10), 'archive-next', { disabled: state.historyBusy || !state.historyHasMore })))
        : h('div', { dataset: test('history-empty') }, empty(t('recentEmpty'), t('historyEmptyHelp')))),
      ctx.route.params.selected ? panel(t('historySelectedScan'), 'history-selected', detail())
        : rows.length ? empty(t('historyChoose')) : null);
  }
  return {
    update(next) {
      state = next;
      const key = ctx.route.params.selected || '';
      if (key !== selectedKey) { selectedKey = key; load(key); }
      const input = [state.recent, state.historyOffset, state.historyBusy, state.historyTotal, state.activeScan, state.scan, state.prefs, key];
      if (!previous || !input.every((value, index) => value === previous[index])) { previous = input; render(); }
    },
    destroy() { disposed = true; generation++; selected = null; },
  };
}
