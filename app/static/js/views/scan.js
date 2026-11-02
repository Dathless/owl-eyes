import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { api } from '../core/api.js';
import { active } from '../core/poller.js';
import { duration, collectionElapsed, short, timestamp, providerLabel } from '../core/format.js';
import { scanPath } from '../core/router.js';
import { scanTabs, scanActions } from '../registry/scan-tabs.js';
import { scanSteps, parseLabels } from '../registry/enums.js';
import { CveResults } from '../components/cve-results.js';
import {
  button,
  link,
  copyButton,
  banner,
  errorBox,
  empty,
  stateBadge,
  provider,
  kv,
  tabs,
  choices,
} from '../components/ui.js';
export function mount(root, ctx) {
  let exportingPDF = false, exportError = null, disposed = false;
  let lookingUpCves = false, cveError = null;
  let state,
    retryOpen = false,
    retryProvider = null,
    raw = null,
    rawKey = '',
    lastContent = '',
    contentNode = null;
  const pages = {},
    filters = {},
    scrolls = new Map();
  let lastTab = null,
    defaultTab = null;
  const rawCache = new Map();
  let previousUpdate = null;
  async function lookupCves() {
    const scan = state.scan;
    if (lookingUpCves || !scan || active(scan.state)) return;
    lookingUpCves = true; cveError = null; render();
    const result = await api.cves(scan.scan_id);
    if (disposed) return;
    lookingUpCves = false;
    if (result.ok) {
      const current = ctx.store.get().scan;
      if (current?.scan_id === scan.scan_id)
        ctx.store.set({ scan: { ...current, cve_lookup: result.data.cve_lookup } });
    } else cveError = result.error;
    render();
  }
  async function exportPDF() {
    const scan = state.scan;
    if (exportingPDF || !scan?.report) return;
    exportingPDF = true; exportError = null; render();
    const result = await api.reportPDF(scan.scan_id);
    if (disposed) return;
    exportingPDF = false;
    if (result.ok) {
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement('a');
      anchor.href = url; anchor.download = result.filename;
      document.body.append(anchor); anchor.click(); anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } else exportError = result.error;
    render();
  }
  function changeTab(id) {
    scrolls.set(lastTab, window.scrollY);
    ctx.go(scanPath(state.scan.scan_id, id, Object.fromEntries(ctx.route.query)));
    requestAnimationFrame(() => window.scrollTo(0, scrolls.get(id) ?? 0));
  }
  function render() {
    const scan = state.scan;
    const id = ctx.route.params.id || state.pointer?.scan_id;
    if (state.scanErr?.status === 404) {
      replace(root, h('h1', {}, 'Scan'), empty(t('scanGone')), link(t('home'), '/'));
      return;
    }
    if (!scan || scan.scan_id !== id) {
      replace(
        root,
        h('h1', {}, 'Scan'),
        errorBox(state.scanErr?.error),
        empty(id ? t('loading') : t('noScan')),
        link(t('home'), '/'),
      );
      return;
    }
    defaultTab ??= scan.state === 'completed' || scan.report ? 'report' : 'raw';
    const selectedTab = ctx.route.params.tab || defaultTab;
    const tab = scanTabs.find((t) => t.id === selectedTab);
    if (!tab) {
      replace(root, empty(t('notFound')), link(t('home'), '/'));
      return;
    }
    const selectedTool = ctx.route.query.get('tool');
    const tool = scan.tools[selectedTool];
    const p = state.caps.providers.find((p) => p.provider_id === scan.provider_id);
    const canRetry =
      ['completed', 'analysis_failed'].includes(scan.state) &&
      Object.values(scan.tools).some((x) => x.evidence.length);
    const busy = state.busy;
    retryProvider ??= state.caps.providers.find((p) => p.enabled)?.provider_id;
    const chosen = state.caps.providers.find((p) => p.provider_id === retryProvider);
    const header = h(
      'header',
      { class: 'v-scan-header' },
      h('h1', {}, 'Scan'),
      h('span', { title: scan.scan_id, dataset: test('scan-id') }, short(scan.scan_id)),
      copyButton(scan.scan_id),
      h('span', { dataset: test('scan-state') }, stateBadge(scan.state)),
      t('scanDuration') + ': ',
      h(
        'span',
        { dataset: { ...test('scan-elapsed'), elapsed: scan.scan_id } },
        collectionElapsed(scan),
      ),
      scan.partial ? banner('partial', 'warn') : null,
      provider(p),
    );
    const actionBar = h(
      'div',
      { class: 'c-actions' },
      active(scan.state)
        ? button(
            t(scan.state === 'cancelling' || busy === 'cancel'
              ? 'cancelling'
              : scan.state === 'analyzing' ? 'cancelAnalysis' : 'cancel'),
            () => ctx.cancel(scan.scan_id),
            'cancel-btn',
            { disabled: scan.state === 'cancelling' || !!busy },
          )
        : null,
      button(
        t('retryAnalysis'),
        () => {
          retryOpen = !retryOpen;
          render();
        },
        'retry-btn',
        {
          disabled: !canRetry || !!busy,
          'aria-describedby': !canRetry ? 'retry-reason' : null,
          'aria-expanded': String(retryOpen),
        },
      ),
      !canRetry ? h('small', { id: 'retry-reason' }, t('retryDisabled')) : null,
      button(t(exportingPDF ? 'exportingPDF' : 'exportPDF'), exportPDF, 'export-pdf', {
        disabled: exportingPDF || !scan.report,
        title: !scan.report ? t('exportPDFDisabled') : t('exportPDF'),
      }),
      exportError ? h('div', { dataset: test('export-pdf-error') }, errorBox(exportError)) : null,
      state.caps.features?.cve_lookup ? button(
        t(lookingUpCves ? 'cveLookingUp' : 'cveLookup'), lookupCves, 'cve-lookup',
        { disabled: lookingUpCves || active(scan.state), title: t('cveLookupNote') },
      ) : null,
      copyButton(location.href, 'scan-copy-link'),
      ...scanActions
        .filter((a) => !a.when || a.when(state.caps, scan))
        .map((a) => button(t(a.label), () => a.run(ctx, scan))),
    );
    const retryPanel =
      retryOpen && canRetry
        ? h(
            'section',
            { class: 'c-panel c-panel-body', dataset: test('retry-panel') },
            h('h2', {}, t('retryAnalysis')),
            h('p', {}, t('retryNote')),
            choices(
              state.caps.providers.map((p) => ({
                id: p.provider_id,
                label: `${providerLabel(p)} · ${p.kind}`,
                disabled: !p.enabled,
                reason: p.reason,
              })),
              retryProvider,
              (v) => {
                retryProvider = v;
                render();
              },
              'retry-provider',
              t('providers'),
            ),
            chosen?.kind === 'external'
              ? banner(t('external', { host: chosen.host ?? t('unknownField') }), 'warn')
              : null,
            button(
              t('runAnalysis'),
              () => {
                retryOpen = false;
                ctx.retry(scan.scan_id, retryProvider);
              },
              'retry-confirm',
              { disabled: !!busy || !chosen?.enabled },
            ),
          )
        : null;
    const steps = ['queued', 'collecting', 'analyzing', 'result'];
    const stepIndex = {
      queued: 0,
      collecting: 1,
      analyzing: 2,
      completed: 3,
      analysis_failed: 2,
      collection_failed: 1,
      cancelled: 3,
      cancelling: 3,
    }[scan.state];
    const progress = scanSteps(scan);
    const stepper = h(
      'div',
      { class: 'c-stepper', dataset: test('stepper'), 'aria-label': t('state') },
      ...steps.map((s, i) =>
        h(
          'span',
          { dataset: test(`step-${s}`), 'aria-current': i === stepIndex ? 'step' : null },
          progress[i] + ' ',
          s === 'result' ? scan.state : t(s) === s ? s : t(s),
        ),
      ),
    );
    const strip = h(
      'div',
      { class: 'c-tool-strip' },
      ...Object.values(scan.tools).map((tool) =>
        button(
          h(
            'span',
            {},
            tool.tool_id,
            ' ',
            stateBadge(tool.state),
            h(
              'small',
              {},
              h(
                'span',
                {
                  dataset:
                    tool.state === 'running' && tool.started_at
                      ? { toolStarted: tool.started_at }
                      : {},
                },
                duration(
                  tool.state === 'running' && tool.started_at
                    ? Date.now() - new Date(tool.started_at)
                    : tool.duration_ms,
                ),
              ),
              ' ',
              parseLabels[tool.parse_status] ?? tool.parse_status,
              ` !${tool.warnings.length}`,
            ),
          ),
          () => {
            if (selectedTab === 'report') {
              document
                .querySelector(`[data-testid="coverage-row-${CSS.escape(tool.tool_id)}"]`)
                ?.closest('details')
                ?.setAttribute('open', '');
              document
                .querySelector(`[data-testid="coverage-row-${CSS.escape(tool.tool_id)}"]`)
                ?.scrollIntoView({ block: 'center' });
            }
            ctx.selectTool(tool.tool_id);
          },
          `tool-cell-${tool.tool_id}`,
          { 'aria-pressed': String(tool.tool_id === selectedTool) },
        ),
      ),
    );
    const detail = tool
      ? h(
          'div',
          { dataset: test('tool-detail') },
          kv([
            ['state', tool.state],
            ['parse_status', tool.parse_status],
            ['started_at', timestamp(tool.started_at, state.prefs.tz)],
            ['finished_at', timestamp(tool.finished_at, state.prefs.tz)],
            ['duration', duration(tool.duration_ms)],
            ['observations', tool.observations.length],
            ['evidence', tool.evidence.length],
          ]),
          errorBox(tool.error),
          ...tool.warnings.map((w) => banner(w, 'warn')),
        )
      : null;
    const key = `${scan.scan_id}/${selectedTab}/${ctx.route.query.get('tool') ?? ''}/${ctx.route.query.get('stream') ?? ''}/${ctx.route.query.get('hl') ?? ''}`;
    if (selectedTab === 'raw') {
      if (rawKey !== key) {
        raw = rawCache.get(key);
        if (!raw) {
          raw = tab.render(scan, ctx);
          rawCache.set(key, raw);
        }
        rawKey = key;
      }
      raw.update(scan);
      contentNode = raw.node;
      lastContent = '';
    } else {
      raw = null;
      rawKey = '';
      const sig = JSON.stringify([
        scan,
        selectedTab,
        ctx.route.query.toString(),
        state.prefs,
        pages,
        filters,
      ]);
      if (sig !== lastContent) {
        contentNode = tab.render(scan, ctx, selectedTab === 'report' ? pages : filters);
        lastContent = sig;
      }
    }
    lastTab = selectedTab;
    replace(
      root,
      header,
      p?.kind === 'external'
        ? banner(t('external', { host: p.host ?? t('unknownField') }), 'warn')
        : null,
      errorBox(state.actionError),
      actionBar,
      cveError ? h('div', { dataset: test('cve-error') }, errorBox(cveError)) : null,
      state.caps.features?.cve_lookup ? h('p', {}, t('cveLookupNote')) : null,
      CveResults(scan.cve_lookup, ctx),
      retryPanel,
      stepper,
      scan.state === 'analyzing'
        ? h(
            'section',
            {
              class: 'c-panel c-panel-body',
              role: 'status',
              'aria-live': 'polite',
              dataset: test('analysis-running-notice'),
            },
            h('h2', {}, t('buildingReport')),
            h('progress', {
              class: 'c-analysis-progress', 'aria-label': t('buildingReport'),
            }),
            h('p', {}, t('analysisProgress')),
          )
        : null,
      strip,
      detail,
      tabs(scanTabs, selectedTab, changeTab),
      h(
        'div',
        {
          id: `tabpanel-${selectedTab}`,
          role: 'tabpanel',
          'aria-labelledby': `tab-${selectedTab}`,
          dataset: test(`tabpanel-${selectedTab}`),
        },
        contentNode,
      ),
    );
  }
  const closePopover = () => {
    retryOpen = false;
    render();
  };
  ctx.closePopover = closePopover;
  return {
    update(s, revision) {
      state = s;
      const selected = [
        s.scan,
        s.scanErr,
        s.caps,
        s.busy,
        s.actionError,
        s.prefs,
        location.hash,
        revision,
      ];
      if (
        previousUpdate &&
        selected.every((value, index) => value === previousUpdate[index])
      )
        return;
      previousUpdate = selected;
      render();
    },
    destroy() {
      disposed = true;
      if (ctx.closePopover === closePopover) delete ctx.closePopover;
      for (const entry of rawCache.values()) entry.destroy();
    },
  };
}
