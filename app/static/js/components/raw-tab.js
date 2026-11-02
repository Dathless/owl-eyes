import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { api } from '../core/api.js';
import { button, code, banner, empty, errorBox, checkbox, copyButton } from './ui.js';
export function RawTab(initial, ctx) {
  let scan = initial,
    text = '',
    offset = 0,
    more = true,
    loading = false,
    all = false,
    pages = 0,
    destroyed = false,
    error = null,
    search = '',
    matchIndex = 0;
  const prefs = ctx.store.get().prefs;
  const toolId = ctx.route.query.get('tool') ?? Object.keys(scan.tools)[0];
  const stream = ctx.route.query.get('stream') ?? 'stdout';
  const highlight = ctx.route.query.get('hl');
  const evidence = Object.values(scan.tools)
    .flatMap((t) => t.evidence)
    .find((e) => e.id === highlight);
  const controller = new AbortController();
  const viewer = h('div', {
    class: 'v-raw-viewer',
    tabIndex: 0,
    dataset: {
      ...test('raw-viewer'),
      wrap: String(prefs.rawWrap),
      lines: String(prefs.lineNumbers),
      font: String(prefs.rawFont),
    },
    'aria-label': t('raw'),
  });
  const notice = h('div', { dataset: test('raw-notice') });
  const count = h('span', { 'aria-live': 'polite' });
  const searchBox = h('input', {
    type: 'search',
    placeholder: t('searchLoaded'),
    'aria-label': t('searchLoaded'),
    dataset: test('raw-search'),
    onInput: (e) => {
      search = e.target.value;
      matchIndex = 0;
      renderText();
    },
    onKeydown: (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        jump(e.shiftKey ? -1 : 1);
      }
    },
  });
  const next = button(t('loadMore'), () => load(false), 'raw-load-more');
  const loadAll = button(
    t('loadAll'),
    () => {
      if (all) {
        all = false;
        updateControls();
      } else load(true);
    },
    'raw-load-all',
  );
  const node = h(
    'section',
    {},
    h(
      'div',
      { class: 'c-actions', 'aria-label': t('tools') },
      ...Object.keys(scan.tools).map((id) =>
        button(id, () => ctx.selectTool(id), `raw-tool-${id}`, {
          'aria-pressed': String(id === toolId),
        }),
      ),
    ),
    h(
      'div',
      { class: 'c-actions', 'aria-label': 'Stream' },
      ...['stdout', 'stderr', 'artifact'].map((s) =>
        button(s, () => ctx.setQuery({ stream: s, hl: null }), `raw-stream-${s}`, {
          'aria-pressed': String(s === stream),
        }),
      ),
    ),
    h(
      'div',
      { class: 'v-raw-controls' },
      searchBox,
      count,
      button('‹', () => jump(-1), null, { 'aria-label': t('previous') }),
      button('›', () => jump(1), null, { 'aria-label': t('next') }),
      checkbox(
        t('wrap'),
        prefs.rawWrap,
        (v) => {
          viewer.dataset.wrap = String(v);
          ctx.setPrefs({ rawWrap: v });
        },
        'raw-wrap',
      ),
      checkbox(
        t('lineNumbers'),
        prefs.lineNumbers,
        (v) => {
          viewer.dataset.lines = String(v);
          ctx.setPrefs({ lineNumbers: v });
        },
        'raw-lines',
      ),
      h(
        'label',
        {},
        t('rawFont'),
        h(
          'select',
          {
            'aria-label': t('rawFont'),
            onChange: (e) => {
              viewer.dataset.font = e.target.value;
              ctx.setPrefs({ rawFont: Number(e.target.value) });
            },
          },
          ...[12, 13, 14, 15, 16].map((n) =>
            h('option', { value: n, selected: n === prefs.rawFont }, n),
          ),
        ),
      ),
      copyButton(() => text, 'raw-copy'),
      next,
      loadAll,
    ),
    notice,
    viewer,
  );
  function jump(delta) {
    const marks = viewer.querySelectorAll('mark:not(.ev)');
    if (!marks.length) return;
    matchIndex = (matchIndex + delta + marks.length) % marks.length;
    marks[matchIndex].scrollIntoView({ block: 'center' });
  }
  function renderText() {
    const fragments = [];
    let chunk,
      position = 0,
      hits = 0;
    const evStart = evidence?.excerpt ? text.indexOf(evidence.excerpt) : -1;
    const evEnd = evStart + (evidence?.excerpt.length ?? 0);
    for (const [i, line] of text.split('\n').entries()) {
      if (i % 200 === 0) {
        chunk = h('div', { class: 'chunk' });
        fragments.push(chunk);
      }
      const ln = h('span', { class: 'ln', dataset: { n: String(i + 1) } });
      let cursor = 0;
      const ranges = [];
      if (evStart >= 0 && position < evEnd && position + line.length > evStart)
        ranges.push([
          Math.max(0, evStart - position),
          Math.min(line.length, evEnd - position),
          'ev',
        ]);
      if (search) {
        let found = line.indexOf(search);
        while (found >= 0 && hits < 500) {
          ranges.push([found, found + search.length, '']);
          hits++;
          found = line.indexOf(search, found + Math.max(1, search.length));
        }
      }
      ranges.sort((a, b) => a[0] - b[0]);
      for (const [start, end, cls] of ranges) {
        if (start < cursor) continue;
        ln.append(
          document.createTextNode(line.slice(cursor, start)),
          h('mark', { class: cls }, line.slice(start, end)),
        );
        cursor = end;
      }
      ln.append(document.createTextNode(line.slice(cursor)));
      chunk.append(ln);
      position += line.length + 1;
    }
    replace(viewer, ...fragments);
    count.textContent = `${hits}${hits === 500 ? '+' : ''}`;
    if (highlight && evStart >= 0)
      viewer.querySelector('mark.ev')?.scrollIntoView({ block: 'center' });
  }
  function toolReady() {
    return (
      scan.tools[toolId] && !['queued', 'running'].includes(scan.tools[toolId].state)
    );
  }
  function updateControls() {
    next.disabled = loading || !more || !toolReady() || pages >= 40;
    loadAll.disabled = (!all && loading) || !more || !toolReady() || pages >= 40;
    loadAll.textContent = t(all ? 'stopLoad' : 'loadAll');
    const tool = scan.tools[toolId];
    const streams = ctx.store.get().caps.tools.find((t) => t.tool_id === toolId)?.streams;
    const unavailable = streams && !streams.includes(stream);
    const notices = [];
    if (!tool) notices.push(empty(t('unknownField')));
    else if (unavailable) {
      notices.push(empty(t('noStream', { stream })));
      next.disabled = true;
      loadAll.disabled = true;
    } else if (!toolReady()) notices.push(empty(t('rawWaiting')));
    else if (tool.state === 'skipped')
      notices.push(empty(`${t('rawSkipped')} ${tool.warnings.join('; ')}`));
    if (tool && ['timed_out', 'output_limited', 'cancelled'].includes(tool.state))
      notices.push(banner(t('rawLimited'), 'warn'));
    if (error)
      notices.push(
        errorBox(error),
        button(t('retry'), () => load(false), 'raw-retry'),
      );
    if (pages >= 40 && more) notices.push(banner(t('pageLimit'), 'warn'));
    if (highlight && evidence && !more && !text.includes(evidence.excerpt))
      notices.push(banner(t('rawNotFound', { locator: evidence.locator })));
    notices.push(
      h('small', {}, `${toolId ?? '—'} ${stream} · ${offset} ${t('rawScrub')}`),
    );
    if (pages && !text && !loading) notices.push(empty(t('rawEmpty')));
    replace(notice, ...notices);
  }
  async function load(everything) {
    if (loading || destroyed || !toolReady()) return;
    const streams = ctx.store.get().caps.tools.find((t) => t.tool_id === toolId)?.streams;
    if (streams && !streams.includes(stream)) return;
    all = everything;
    loading = true;
    error = null;
    updateControls();
    do {
      const result = await api.output(
        scan.scan_id,
        toolId,
        stream,
        offset,
        controller.signal,
      );
      if (destroyed) return;
      if (!result.ok) {
        if (result.error.code !== 'output_not_ready') error = result.error;
        break;
      }
      if (result.data.has_more && result.data.next_offset <= offset) {
        error = { code: 'bad_response', message: 'Invalid output offset' };
        break;
      }
      text += result.data.text;
      offset = result.data.next_offset;
      more = result.data.has_more;
      pages++;
      const locating = !!evidence?.excerpt && !text.includes(evidence.excerpt);
      if (!all && !locating) break;
    } while (more && pages < 40 && (all || !!evidence));
    all = false;
    loading = false;
    renderText();
    updateControls();
  }
  updateControls();
  load(false);
  return {
    node,
    update(s) {
      scan = s;
      updateControls();
      if (!pages && !loading) load(false);
    },
    destroy() {
      destroyed = true;
      all = false;
      controller.abort();
    },
  };
}
