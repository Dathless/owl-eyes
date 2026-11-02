import { h, replace, test } from './core/dom.js';
import { enterView } from './core/motion.js';
import { t } from './core/i18n.js';
import { api, onApiError } from './core/api.js';
import { Poller, active } from './core/poller.js';
import { createStore } from './core/store.js';
import { read, write, pointer, preferences } from './core/pointer.js';
import { route, go, query, scanPath } from './core/router.js';
import { short, collectionElapsed, duration } from './core/format.js';
import { nav } from './registry/nav.js';
import { shortcuts } from './registry/shortcuts.js';
import { button, link, banner, stateBadge, errorBox, Icon } from './components/ui.js';
import { renderDrawer } from './components/drawer.js';
const root = document.getElementById('view');
const store = createStore({
  caps: null,
  scan: null,
  activeScan: null,
  scanErr: null,
  conn: 'ok',
  failures: 0,
  pointer: pointer(),
  prefs: preferences(read('kda.prefs')),
  recent: [],
  historyOffset: 0,
  historyTotal: 0,
  historyHasMore: false,
  historyBusy: false,
  busy: null,
  actionError: null,
  reset: false,
  drawer: null,
});
onApiError((result) => {
  if (result.status === 401) store.set({ conn: 'expired' });
});
const unavailable = new Set();
let view = null,
  viewKey = '',
  routing = 0,
  subscribed = null,
  refreshToken = 0,
  drawerOpener = null,
  lastHash = '',
  loadFailed = null,
  topInputs = [],
  railInputs = [],
  motionKey = '';
const ctx = {
  store,
  route: route(),
  go,
  setQuery: query,
  refreshView: () => {
    refreshToken++;
    render();
  },
  setPrefs(patch, reset = false) {
    const prefs = preferences({ ...store.get().prefs, ...patch });
    write('kda.prefs', reset ? null : prefs);
    applyPrefs(prefs);
    store.set({ prefs, prefSaved: true });
  },
  openEvidence(id) {
    if (!document.getElementById('drawer').contains(document.activeElement))
      drawerOpener = document.activeElement;
    query({ ev: id });
  },
  closeDrawer() {
    const previous = drawerOpener;
    const tid = previous?.dataset.testid;
    store.set({ drawer: null });
    if (ctx.route.query.has('ev')) query({ ev: null });
    requestAnimationFrame(() => {
      if (previous?.isConnected) previous.focus();
      else if (tid) document.querySelector(`[data-testid="${CSS.escape(tid)}"]`)?.focus();
    });
  },
  openShortcuts() {
    drawerOpener = document.activeElement;
    query({ ev: null });
    store.set({ drawer: 'shortcuts' });
  },
  selectTool(id) {
    query({ tool: id, hl: null });
  },
  evidenceRaw(id) {
    const scan = store.get().scan;
    const ev = Object.values(scan?.tools ?? {})
      .flatMap((t) => t.evidence)
      .find((e) => e.id === id);
    if (ev)
      go(
        scanPath(scan.scan_id, 'raw', { tool: ev.tool_id, stream: ev.source, hl: ev.id }),
      );
  },
  reference(tab, key, id) {
    go(scanPath(store.get().scan.scan_id, tab, { [key]: id }));
  },
  start: (body) => operation('start', () => api.start(body)),
  cancel: (id) => operation('cancel', () => api.cancel(id)),
  retry: (id, provider) => operation('retry', () => api.retry(id, provider)),
  historyPage: (offset) => recent(offset),
};
function applyPrefs(p) {
  const doc = document.documentElement;
  doc.dataset.pref = p.theme;
  doc.dataset.theme =
    p.theme === 'system'
      ? matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
      : p.theme;
  doc.dataset.density = p.density;
}
applyPrefs(store.get().prefs);
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () =>
  applyPrefs(store.get().prefs),
);
matchMedia('(min-width:1280px)').addEventListener('change', () =>
  renderDrawer(document.getElementById('drawer'), store.get(), ctx),
);
function toast(text, action) {
  const box = banner(text, 'info', null, action);
  box.dataset.testid = 'toast';
  const host = document.getElementById('toasts');
  while (host.children.length >= 3) host.firstChild.remove();
  host.append(box);
  setTimeout(() => box.remove(), 4000);
}
function clearState() {
  if (subscribed) unavailable.add(subscribed);
  poller.stop();
  subscribed = null;
  write('kda.pointer', null);
  store.set({
    pointer: null,
    scan: null,
    activeScan: null,
    recent: [],
    reset: true,
    scanErr: { status: 404, error: { code: 'scan_not_found', message: t('scanGone') } },
  });
}
function accept(scan) {
  const before = store.get();
  if (scan.server_instance_id !== before.caps.server_instance_id) {
    if (!before.caps.features?.persistent_state) clearState();
    else { poller.stop(); subscribed = null; }
    boot();
    return;
  }
  const current = route();
  const displayed =
    current.id === 'scan'
      ? current.params.id || before.pointer?.scan_id
      : before.pointer?.scan_id;
  const running =
    before.activeScan?.scan_id ?? before.recent.find((s) => active(s.state))?.scan_id;
  const p = { scan_id: scan.scan_id, server_instance_id: scan.server_instance_id };
  const next = { conn: 'ok', failures: 0, reset: false };
  if (!displayed || scan.scan_id === displayed) {
    next.scanErr = null;
    if (JSON.stringify(scan) !== JSON.stringify(before.scan)) next.scan = scan;
  }
  if (active(scan.state) || !running || running === scan.scan_id) {
    write('kda.pointer', p);
    next.pointer = p;
  }
  next.activeScan = active(scan.state)
    ? scan
    : before.activeScan?.scan_id === scan.scan_id
      ? null
      : before.activeScan;
  if (JSON.stringify(next.activeScan) === JSON.stringify(before.activeScan))
    next.activeScan = before.activeScan;
  const summary = {
    scan_id: scan.scan_id,
    state: scan.state,
    provider_id: scan.provider_id,
    partial: scan.partial,
    created_at: scan.created_at,
    finished_at: scan.finished_at,
    tools: Object.fromEntries(
      Object.entries(scan.tools).map(([id, tool]) => [id, tool.state]),
    ),
    overall_risk: scan.report?.report.overall_risk ?? null,
  };
  next.recent = before.historyOffset
    ? before.recent.map((s) => s.scan_id === scan.scan_id ? summary : s)
    : [summary, ...before.recent.filter((s) => s.scan_id !== scan.scan_id)]
        .sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 10);
  if (JSON.stringify(next.recent) === JSON.stringify(before.recent))
    next.recent = before.recent;
  if (
    before.scan?.scan_id === scan.scan_id &&
    before.scan.state === 'analyzing' &&
    scan.state === 'completed'
  )
    toast(
      t('viewReport'),
      button(t('viewReport'), () => go(scanPath(scan.scan_id, 'report'))),
    );
  if (before.scan?.state !== scan.state)
    document.getElementById('announcements').textContent = `Scan ${scan.state}`;
  store.set(next);
}
const pendingViews = new Set();
function readView(id) {
  if (pendingViews.has(id) || unavailable.has(id)) return;
  pendingViews.add(id);
  poller
    .read(id)
    .then((result) => {
      const current = route();
      if (
        current.id !== 'scan' ||
        (current.params.id || store.get().pointer?.scan_id) !== id
      )
        return;
      if (result.ok) accept(result.data);
      else if (result.status === 404) {
        unavailable.add(id);
        if (store.get().pointer?.scan_id === id) {
          write('kda.pointer', null);
          store.set({ pointer: null });
        }
        store.set({ scanErr: result, reset: true });
      } else
        store.set({
          scanErr: result,
          conn: result.status === 401 ? 'expired' : 'retrying',
        });
    })
    .finally(() => pendingViews.delete(id));
}
const poller = new Poller(
  (id) => api.scan(id),
  (result, id, failures) => {
    if (result.ok) accept(result.data);
    else if (result.status === 404) clearState();
    else
      store.set({
        scanErr: { ...result },
        conn: result.status === 401 ? 'expired' : failures >= 3 ? 'lost' : 'retrying',
        failures,
      });
  },
);
function subscribe(id) {
  if (id && id !== subscribed && !unavailable.has(id)) {
    subscribed = id;
    poller.subscribe(id);
  }
}
async function recent(offset = store.get().historyOffset ?? 0) {
  if (!store.get().caps?.features?.recent_scans) return;
  store.set({ historyBusy: true });
  const result = await api.recent(offset);
  if (result.ok) {
    store.set({ recent: result.data.scans, historyOffset: offset,
      historyTotal: result.data.total ?? result.data.scans.length,
      historyHasMore: !!result.data.has_more, historyBusy: false });
    const running = result.data.scans.find((s) => active(s.state));
    if (result.data.active_scan_id) subscribe(result.data.active_scan_id);
    else if (running && !store.get().pointer) subscribe(running.scan_id);
  } else if (result.status === 401) store.set({ conn: 'expired' });
  if (!result.ok) store.set({ historyBusy: false, actionError: result.error });
}
async function operation(kind, call) {
  if (store.get().busy) return;
  store.set({ busy: kind, actionError: null });
  const result = await call();
  if (result.ok) {
    if (kind === 'start') go(scanPath(result.data.scan_id));
    accept(result.data);
    subscribed = null;
    subscribe(result.data.scan_id);
  } else {
    store.set({
      actionError: result.error,
      ...(result.status === 401 ? { conn: 'expired' } : {}),
    });
    if (result.status === 409 && result.error.scan_id) {
      subscribed = null;
      subscribe(result.error.scan_id);
      toast(result.error.message);
    } else if (result.status === 409) {
      subscribed = null;
      subscribe(store.get().scan?.scan_id);
    }
    if (result.status === 422) {
      const caps = await api.capabilities();
      if (caps.ok) store.set({ caps: caps.data });
    }
    if (!result.status) {
      toast(t('postUncertain'));
      await recent();
    }
  }
  store.set({ busy: null });
  recent();
}
function renderTopbar(state) {
  const scan = state.activeScan;
  const themeValues = ['system', 'light', 'dark'];
  const themes = h(
    'div',
    {
      class: 'c-segmented', role: 'radiogroup', 'aria-label': t('theme'),
      onKeydown: (event) => {
        const index = themeValues.indexOf(state.prefs.theme);
        const next = {
          ArrowRight: (index + 1) % 3, ArrowDown: (index + 1) % 3,
          ArrowLeft: (index + 2) % 3, ArrowUp: (index + 2) % 3,
          Home: 0, End: 2,
        }[event.key];
        if (next == null) return;
        event.preventDefault();
        const value = themeValues[next];
        ctx.setPrefs({ theme: value });
        document.querySelector(`[data-testid="theme-${value}"]`)?.focus();
      },
    },
    ...themeValues.map((value) =>
      button(
        Icon({ system: 'i-monitor', light: 'i-sun', dark: 'i-moon' }[value]),
        () => ctx.setPrefs({ theme: value }),
        `theme-${value}`,
        {
          role: 'radio',
          tabIndex: state.prefs.theme === value ? 0 : -1,
          'aria-checked': String(state.prefs.theme === value),
          'aria-label': t(value),
          title: t(value),
        },
      ),
    ),
  );
  const brand = link([
    h('span', { class: 'brand-mark' }, Icon('i-shield')),
    h('span', {}, 'PenChecker'),
    h('span', { class: 'brand-tag' }, 'LAB'),
  ], '/', 'brand-home');
  brand.setAttribute('aria-label', 'PenChecker');
  replace(
    document.getElementById('topbar'),
    brand,
    state.caps
      ? link(
          [Icon('i-server'), h('span', {}, state.caps.target.target_id),
            h('span', { class: 'target-ip' }, state.caps.target.ip)],
          '/settings/target',
        )
      : null,
    scan
      ? h(
          'a',
          { href: `#${scanPath(scan.scan_id)}`, dataset: test('active-chip') },
          stateBadge(scan.state),
          ' ',
          h('span', { class: 'top-elapsed-label' }, t('scanDuration') + ': '),
          h('span', { dataset: { elapsed: scan.scan_id } }, collectionElapsed(scan)),
        )
      : null,
    h(
      'div',
      { class: 'top-actions' },
      state.caps
        ? h(
            'span',
            { class: 'top-server', title: state.caps.server_instance_id },
            `srv ${short(state.caps.server_instance_id)}`,
          )
        : null,
      themes,
      button('?', () => ctx.openShortcuts(), 'shortcuts-btn', {
        'aria-label': t('shortcuts'),
      }),
    ),
  );
  document.querySelector('#topbar a')?.classList.add('brand');
  document.querySelectorAll('#topbar a')[1]?.classList.add('target');
}
function renderRail(state) {
  const current = ctx.route.id;
  replace(
    document.getElementById('rail'),
    h('div', { class: 'rail-workspace' }, Icon('i-shield'),
      h('div', {}, h('strong', {}, t('workspaceLabel')), h('small', {}, t('labEnvironment')))),
    h('p', { class: 'rail-label' }, t('workspace')),
    ...nav
      .filter((n) => !n.when || n.when(state.caps))
      .map((n) =>
        h(
          'a',
          {
            href: `#${n.to}`,
            dataset: test(`nav-${n.id}`),
            'aria-label': t(n.label),
            'aria-current': current === n.id ? 'page' : 'false',
            title: t(n.label),
          },
          Icon(n.icon),
          h('span', { class: 'nav-label' }, t(n.label)),
        ),
      ),
    h(
      'div',
      { class: 'rail-footer', title: t(state.caps?.features?.persistent_state ? 'persistentHistory' : 'ram') },
      Icon('i-server'),
      h('p', {}, t(state.conn === 'ok' ? 'connectionReady' : 'connectionWaiting')),
      h('small', {}, t('scanWorkspace')),
      h('small', { class: 'c-technical' }, `contract ${state.caps?.schema_version ?? '—'}`),
    ),
  );
}
function shell(state) {
  const scan = state.activeScan;
  const top = [state.caps, state.prefs.theme, scan?.scan_id, scan?.state];
  if (top.some((value, i) => value !== topInputs[i])) {
    topInputs = top;
    renderTopbar(state);
  }
  const rail = [ctx.route.id, state.conn, state.caps];
  if (rail.some((value, i) => value !== railInputs[i])) {
    railInputs = rail;
    renderRail(state);
  }
  const banners = [];
  if (state.conn === 'expired')
    banners.push(
      banner(
        t('sessionExpired'),
        'err',
        'session_expired',
        button(t('reload'), () => location.reload()),
      ),
    );
  if (state.conn === 'lost')
    banners.push(
      banner(
        t('connectionLost'),
        'err',
        'conn_lost',
        button(t('retry'), () => {
          subscribed = null;
          subscribe(state.pointer?.scan_id);
        }),
      ),
    );
  if (state.reset)
    banners.push(
      banner(
        t('stateReset'),
        'warn',
        'state_reset',
        link(t('start'), '/'),
        button(t('close'), () => store.set({ reset: false })),
      ),
    );
  if (state.conn === 'retrying')
    banners.push(
      banner(t('connectionRetry', { n: state.failures }), 'warn', 'conn_retrying'),
    );
  if (state.caps?.schema_version && state.caps.schema_version.split('.')[0] !== '1')
    banners.push(
      banner(
        t('schemaMismatch', { version: state.caps.schema_version }),
        'warn',
        'schema_mismatch',
      ),
    );
  replace(document.getElementById('banners'), ...banners.slice(0, 2));
  renderDrawer(document.getElementById('drawer'), state, ctx);
}
function render() {
  const state = store.get();
  ctx.route = route();
  shell(state);
  if (!state.caps) {
    replace(
      root,
      h('h1', {}, t(loadFailed ? 'backendError' : 'loading')),
      loadFailed ? errorBox(loadFailed) : null,
      loadFailed ? button(t('retry'), boot) : null,
    );
    return;
  }
  const id = ctx.route.params.id || state.pointer?.scan_id;
  const running =
    state.activeScan?.scan_id ?? state.recent.find((s) => active(s.state))?.scan_id;
  subscribe(running ?? id);
  if (
    ctx.route.id === 'scan' &&
    id &&
    running &&
    id !== running &&
    state.scan?.scan_id !== id
  )
    readView(id);
  const key = `${ctx.route.id}/${ctx.route.params.id ?? ''}/${ctx.route.params.group ?? ''}`;
  if (key !== viewKey) {
    viewKey = key;
    view?.destroy();
    view = null;
    const generation = ++routing;
    ctx.route
      .view()
      .then((module) => {
        if (generation !== routing) return;
        view = module.mount(root, ctx);
        render();
      })
      .catch((e) => {
        console.error(e);
        if (generation === routing) replace(root, banner(t('viewError'), 'err'));
      });
    return;
  }
  try {
    view?.update(state, refreshToken);
    const nextMotion = `${viewKey}/${ctx.route.params.tab ?? ''}`;
    if (view && motionKey !== nextMotion) {
      motionKey = nextMotion;
      enterView(root);
    }
  } catch (e) {
    console.error(e);
    replace(
      root,
      banner(t('viewError'), 'err'),
      button(t('reload'), () => location.reload()),
    );
  }
}
store.subscribe(render);
window.addEventListener('hashchange', () => {
  ctx.route = route();
  if (lastHash !== location.hash) {
    lastHash = location.hash;
    store.set({ actionError: null, scanErr: null });
    if (ctx.route.id === 'dashboard') recent();
  } else render();
});
let sequence = 0;
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    ctx.closePopover?.();
    ctx.closeDrawer();
    return;
  }
  if (
    e.ctrlKey ||
    e.metaKey ||
    e.altKey ||
    e.target.closest('input,textarea,select,[contenteditable]')
  )
    return;
  if (e.key === 'g') {
    sequence = performance.now();
    return;
  }
  if (
    sequence &&
    performance.now() - sequence < 1000 &&
    { d: '/', s: '/scan', c: '/settings' }[e.key]
  ) {
    go({ d: '/', s: '/scan', c: '/settings' }[e.key]);
    sequence = 0;
    return;
  }
  if (['[', ']'].includes(e.key)) {
    const tabs = [...document.querySelectorAll('[role="tab"]')];
    const i = tabs.findIndex((x) => x.getAttribute('aria-selected') === 'true');
    tabs[(i + (e.key === ']' ? 1 : tabs.length - 1)) % tabs.length]?.click();
    return;
  }
  const shortcut = shortcuts.find((s) => s.keys === e.key && s.run);
  if (shortcut) {
    e.preventDefault();
    shortcut.run(ctx);
  }
});
document.querySelector('.skip-link').addEventListener('click', (e) => {
  e.preventDefault();
  root.focus();
});
setInterval(() => {
  const state = store.get();
  for (const el of document.querySelectorAll('[data-tool-started]'))
    el.textContent = duration(Date.now() - new Date(el.dataset.toolStarted));
  for (const el of document.querySelectorAll('[data-elapsed]')) {
    const scan = [state.scan, state.activeScan].find(
      (s) => s?.scan_id === el.dataset.elapsed,
    );
    if (scan) el.textContent = collectionElapsed(scan);
  }
}, 1000);
async function boot() {
  const result = await api.capabilities();
  if (!result.ok) {
    loadFailed = result.error;
    render();
    return;
  }
  loadFailed = null;
  const old = store.get().pointer;
  if (old && old.server_instance_id !== result.data.server_instance_id) {
    if (result.data.features?.persistent_state) {
      const restored = { ...old, server_instance_id: result.data.server_instance_id };
      write('kda.pointer', restored);
      store.set({ pointer: restored, reset: false });
    } else {
      write('kda.pointer', null);
      store.set({ pointer: null, reset: true });
    }
  }
  store.set({ caps: result.data });
  await recent();
}
render();
boot();
