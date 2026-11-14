import { h, replace, test } from '../core/dom.js';
import { t, hasText } from '../core/i18n.js';
import {
  duration, elapsed, collectionElapsed, timestamp, short, providerLabel,
} from '../core/format.js';
import { active } from '../core/poller.js';
import { scanPath } from '../core/router.js';
import { panels } from '../registry/panels.js';
import {
  button,
  link,
  badge,
  stateBadge,
  severity,
  provider,
  panel,
  kv,
  banner,
  errorBox,
  empty,
  table,
  tr,
  choices,
  pageHeading,
  Icon,
} from '../components/ui.js';
const selectable = (tool) => tool.enabled;
export function mount(root, ctx) {
  let previousUpdate = null;
  let catalogOpen = false;
  const historyOpen = new Set(), versionsOpen = new Set();
  const rememberOpen = (set, key, event) => {
    if (!event.target.isConnected) return;
    event.target.open ? set.add(key) : set.delete(key);
  };
  let selected = null,
    selectedTarget = null,
    selectedProvider = null,
    state;
  const currentTarget = () => (state.caps.targets ?? [state.caps.target])
    .find((item) => item.target_id === (selectedTarget ?? state.caps.target.target_id)) || state.caps.target;
  const form = () => {
    const caps = state.caps;
    const targets = caps.targets?.length ? caps.targets : [caps.target];
    selectedTarget ??= caps.target.target_id;
    const target = targets.find((item) => item.target_id === selectedTarget);
    const applicable = (tool) => !!target && (tool.applicable_to ?? ['dvwa']).includes(target.kind ?? 'dvwa')
      && (!tool.requires_https || target.scheme === 'https');
    const recommended = (tool) => !!target && (tool.recommended_for ?? []).includes(target.kind);
    const primary = (tool) => target?.kind === 'public_domain' ? recommended(tool) : tool.default_selected !== false;
    selected ??= new Set(
      caps.tools.filter((x) => x.enabled && x.default_selected !== false).map((x) => x.tool_id),
    );
    const enabled = new Set(
      caps.tools.filter((tool) => selectable(tool) && applicable(tool)).map((tool) => tool.tool_id),
    );
    selected = new Set([...selected].filter((id) => enabled.has(id)));
    selectedProvider ??= caps.providers.find((x) => x.enabled)?.provider_id;
    const p = caps.providers.find((x) => x.provider_id === selectedProvider);
    const busy = state.busy === 'start';
    const running = active((state.activeScan ?? state.scan)?.state);
    const why = running
      ? t('busy', { id: short((state.activeScan ?? state.scan).scan_id) })
      : !target ? t('selectTarget') : !selected.size || !p?.enabled
        ? t('selectTools')
        : '';
    const toolChoice = (tool) => {
      const id = tool.tool_id;
      const note = hasText(`tool.${id}.note`) ? t(`tool.${id}.note`) : null;
      return h(
        'div',
        { class: 'c-tool-choice' },
        h(
          'label',
          { class: 'c-choice' },
          h('input', {
            type: 'checkbox',
            checked: selected.has(id),
            disabled: !selectable(tool) || !applicable(tool),
            dataset: test(`tool-check-${id}`),
            'aria-describedby': `tool-reason-${id}`,
            onChange: (e) => {
              e.target.checked ? selected.add(id) : selected.delete(id);
              render();
            },
          }),
          h('strong', {}, id),
          recommended(tool) ? h('span', { class: 'c-badge tone-accent', dataset: test(`tool-recommend-${id}`) }, t('recommended')) : null,
          badge(
            !tool.enabled
                ? (tool.reason ?? t('disabled'))
                : t('ready'),
            !selectable(tool) ? 'err' : 'neutral',
          ),
        ),
        h(
          'small',
          { id: `tool-reason-${id}` },
          !applicable(tool) ? t(tool.requires_https && target?.scheme !== 'https' ? 'httpsRequired' : 'toolTargetUnsupported') : tool.reason ?? '',
          ' ',
          tool.preset_summary ?? '',
          tool.timeout_seconds ? ` (${tool.timeout_seconds}s)` : '',
        ),
        h('details', {
          class: 'c-tool-version', open: versionsOpen.has(id),
          onToggle: (e) => rememberOpen(versionsOpen, id, e),
        },
          h('summary', {}, t('toolVersion')),
          h('code', {}, tool.version ?? t('versionUnknown')),
        ),
        note && selected.has(id) ? banner(note) : null,
      );
    };
    return h(
      'form',
      {
        onSubmit: (e) => {
          e.preventDefault();
          if (!why && !busy)
            ctx.start({
              target_id: selectedTarget,
              tools: [...selected],
              provider_id: selectedProvider,
            });
        },
      },
      h('div', { class: 'c-target-summary', dataset: test('setup-target') },
        h('label', { class: 'c-step-label', for: 'scan-target' }, t('setupTarget')),
        h('select', { id: 'scan-target', value: selectedTarget, dataset: test('target-choice'), disabled: busy || running,
          onChange: (event) => { selectedTarget = event.target.value; render(); } },
          !target ? h('option', { value: '' }, t('selectTarget')) : null,
          ...targets.map((item) => h('option', { value: item.target_id, selected: item.target_id === selectedTarget },
            `${item.name || item.target_id} · ${item.url}`))),
        h('div', { class: 'c-target-address' }, Icon('i-shield'),
          h('div', {}, h('strong', {}, target?.name || target?.target_id || t('selectTarget')),
            h('code', {}, target?.url || '')),
          link(t('manageTargets'), '/settings/target')),
        target?.kind === 'public_domain' ? h('p', { class: 'meta' }, t('publicTargetHelp')) : null,
      ),
      h('fieldset', { class: 'c-setup-tools' }, h('legend', {}, t('setupTools')),
        h('div', { class: 'c-tool-grid' },
        ...caps.tools.filter(primary).map(toolChoice),
        ),
        h('details', {
          class: 'c-tool-catalog', open: catalogOpen,
          dataset: test('tool-catalog'),
          onToggle: (e) => { catalogOpen = e.target.open; },
        },
        h('summary', {}, t('addTools')),
        h('p', {}, t('toolCatalogHelp')),
        h('div', { class: 'c-tool-grid' },
          ...caps.tools.filter((x) => !primary(x)).map(toolChoice))),
      ),
      choices(
        caps.providers.map((x) => ({
          id: x.provider_id,
          label: `${providerLabel(x)} · ${x.kind}`,
          disabled: !x.enabled,
          reason: x.reason,
        })),
        selectedProvider,
        (value) => {
          selectedProvider = value;
          render();
        },
        'provider-choice',
        t('setupProvider'),
      ),
      p?.kind === 'external'
        ? banner(t('external', { host: p.host ?? t('unknownField') }), 'warn')
        : null,
      errorBox(state.actionError),
      why ? h('p', { id: 'start-reason' }, why) : null,
      h(
        'div',
        { class: 'c-actions' },
        h(
          'button',
          {
            type: 'submit',
            class: 'primary',
            disabled: !!why || busy,
            'aria-busy': String(busy),
            'aria-describedby': why ? 'start-reason' : null,
            dataset: test('start-btn'),
          },
          Icon('i-play'), t(busy ? 'sending' : 'start'),
        ),
        h('span', { class: 'c-selection-summary' }, t('toolSelection', { count: selected.size })),
      ),
    );
  };
  const renderers = {
    preflight: () =>
      kv([
        [
          t('target'),
          link(
            `${currentTarget().name || currentTarget().target_id} ${currentTarget().url}`,
            '/settings/target',
          ),
          'preflight-row-target',
        ],
        [
          'auth',
          h(
            'div',
            {},
            badge(currentTarget().kind === 'public_domain' ? t('publicDomain') : currentTarget().auth_mode, 'warn'),
            h('p', {}, t(currentTarget().kind === 'public_domain' ? 'publicAuthNote' : 'authNote')),
          ),
          'preflight-row-auth',
        ],
        [
          t('tools'),
          state.caps.tools.map((x) =>
            h(
              'span',
              { class: 'c-preflight-tool' },
              badge(t(x.enabled ? 'ready' : 'disabled'), x.enabled ? 'neutral' : 'err'),
              x.tool_id,
            ),
          ),
          'preflight-row-tools',
        ],
        [
          t('providers'),
          state.caps.providers.map((x) =>
            h('div', {}, provider(x), ' ', x.enabled ? t('ready') : x.reason),
          ),
          'preflight-row-providers',
        ],
        [
          'runtime',
          `${short(state.caps.server_instance_id)}  concurrency=${state.caps.limits?.max_concurrent_tools ?? t('unknownField')}. ${t(state.caps.features?.persistent_state ? 'persistentHistory' : 'ram')}`,
          'preflight-row-runtime',
        ],
      ]),
    new: form,
    active: () => {
      const scan = state.activeScan ?? state.scan;
      if (!scan) return empty(t('activityEmpty'), t('activityEmptyDescription'));
      return h(
        'div',
        { dataset: test('active-scan-card') },
        link(short(scan.scan_id), scanPath(scan.scan_id)),
        stateBadge(scan.state),
        t('scanDuration') + ': ',
        h('span', { dataset: { elapsed: scan.scan_id } }, collectionElapsed(scan)),
        scan.state === 'analyzing' ? banner(t('buildingReport'), 'info') : null,
        ...Object.values(scan.tools).map((tool) =>
          h(
            'p',
            {},
            tool.tool_id,
            ' ',
            stateBadge(tool.state),
            ' ',
            duration(tool.duration_ms),
          ),
        ),
        provider(state.caps.providers.find((p) => p.provider_id === scan.provider_id)),
        h(
          'div',
          { class: 'c-actions' },
          link(t('openScan'), scanPath(scan.scan_id)),
          active(scan.state)
            ? button(
                t(scan.state === 'cancelling'
                  ? 'cancelling'
                  : scan.state === 'analyzing' ? 'cancelAnalysis' : 'cancel'),
                () => ctx.cancel(scan.scan_id),
                'active-cancel',
                { disabled: scan.state === 'cancelling' || state.busy === 'cancel' },
              )
            : null,
        ),
      );
    },
    recent: () => {
      const rows = state.recent.length ? state.recent : !state.historyOffset && state.scan ? [state.scan] : [];
      if (!rows.length) return empty(t('recentEmpty'), t('recentEmptyDescription'), 'i-server');
      return h('div', {}, table(
        [
          'ID',
          t('state'),
          t('started'),
          t('totalDuration'),
          t('tools'),
          t('providers'),
          t('risk'),
          t('notes'),
        ],
        rows
          .slice(0, 10)
          .map((s) =>
            tr(
              [
                h('a', { href: `#${scanPath(s.scan_id)}`, class: 'c-history-id' }, short(s.scan_id)),
                stateBadge(s.state),
                timestamp(s.created_at, state.prefs.tz),
                elapsed(s),
                h('details', {
                  class: 'c-history-tools', dataset: test(`recent-tools-${s.scan_id}`),
                  open: historyOpen.has(s.scan_id),
                  onToggle: (e) => rememberOpen(historyOpen, s.scan_id, e),
                },
                  h('summary', {}, t('toolCount', { count: Object.keys(s.tools).length })),
                  h('div', { class: 'c-history-tool-list' },
                    ...Object.entries(s.tools).map(([id, v]) =>
                      h('span', { class: 'c-inline' },
                        id, ' ', stateBadge(typeof v === 'string' ? v : v.state),
                      ),
                    ),
                  ),
                ),
                h('span', { title: s.provider_id },
                  state.caps.providers.find((p) => p.provider_id === s.provider_id)?.display_name ?? s.provider_id),
                severity(s.overall_risk ?? s.report?.report.overall_risk ?? 'unknown'),
                s.partial ? 'partial' : '—',
              ],
              `recent-row-${s.scan_id}`,
            ),
          ),
      ), h('div', { class: 'c-actions' },
        link(t('historySavedScans'), '/history', 'open-history'),
        button(t('previous'), () => ctx.historyPage(Math.max(0, state.historyOffset - 10)),
          'history-previous', { disabled: state.historyBusy || !state.historyOffset }),
        h('span', {}, t('historyPage', { page: Math.floor((state.historyOffset ?? 0) / 10) + 1,
          total: state.historyTotal ?? rows.length })),
        button(t('next'), () => ctx.historyPage((state.historyOffset ?? 0) + 10),
          'history-next', { disabled: state.historyBusy || !state.historyHasMore }),
      ));
    },
  };
  function render() {
    const focused = root.contains(document.activeElement)
      ? document.activeElement.dataset.testid : null;
    const metric = (label, value, id, icon, note) => h('div', { class: 'c-metric' },
      h('dt', {}, h('span', {}, label), Icon(icon)),
      h('dd', { dataset: test(`overview-${id}`) }, value),
      h('dd', { class: 'c-metric-note' }, t(note)),
    );
    const nodes = panels
      .filter((p) => !p.when || p.when(state.caps))
      .sort((a, b) => a.order - b.order)
      .map((p) => {
        let content;
        try {
          content = (p.render ?? renderers[p.id])(state, ctx);
        } catch {
          content = banner(t('viewError'), 'err');
        }
        const node = panel(t(p.label), p.id, content);
        const heading = node.querySelector('.c-panel-heading');
        heading.prepend(h('span', { class: 'c-panel-icon' }, Icon(p.icon ?? 'i-grid')));
        const description = p.id === 'new' ? 'setupDescription'
          : `panel${p.id[0].toUpperCase()}${p.id.slice(1)}Description`;
        if (hasText(description)) heading.append(h('p', {}, t(description)));
        return { node, region: p.region ?? 'main' };
      });
    replace(
      root,
      pageHeading(t('nav.dashboard'), t('dashboardDescription')),
      h('dl', { class: 'v-overview', 'aria-label': t('preflight') },
        metric(t('overviewTools'), `${state.caps.tools.filter((x) => x.enabled).length} / ${state.caps.tools.length}`, 'tools', 'i-terminal', 'metricToolsNote'),
        metric(t('overviewProviders'), `${state.caps.providers.filter((x) => x.enabled).length} / ${state.caps.providers.length}`, 'providers', 'i-cloud', 'metricProvidersNote'),
        metric(t(state.caps.features?.persistent_state ? 'overviewHistory' : 'overviewSession'), String(state.historyTotal ?? 0), 'history', 'i-server', 'metricHistoryNote'),
      ),
      h(
        'div',
        { class: 'v-dashboard' },
        ...nodes.filter((p) => p.region === 'main').map((p) => p.node),
        h('div', { class: 'v-dashboard-side' },
          ...nodes.filter((p) => p.region === 'side').map((p) => p.node)),
        ...nodes.filter((p) => p.region === 'full').map((p) => p.node),
      ),
    );
    if (focused)
      root.querySelector(`[data-testid="${CSS.escape(focused)}"]`)?.focus({ preventScroll: true });
  }
  return {
    update(s, revision) {
      state = s;
      const selected = [
        s.caps,
        s.scan,
        s.activeScan,
        s.recent,
        s.prefs,
        s.busy,
        s.actionError,
        s.historyOffset, s.historyTotal, s.historyHasMore, s.historyBusy,
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
    destroy() {},
  };
}
