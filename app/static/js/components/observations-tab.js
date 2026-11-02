import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { scope, evidenceChip, table, tr, code, pager, empty } from './ui.js';
export function ObservationsTab(scan, ctx, filters = {}) {
  filters.page ??= 0;
  const node = h('section');
  let rows = Object.values(scan.tools).flatMap((x) => x.observations);
  const tool = ctx.route.query.get('tool') ?? filters.tool ?? '';
  const select = (label, key, options, value) =>
    h(
      'label',
      { class: 'c-field' },
      label,
      h(
        'select',
        {
          'aria-label': label,
          value,
          onChange: (e) => {
            filters[key] = e.target.value;
            filters.page = 0;
            render();
          },
        },
        h('option', { value: '' }, t('all')),
        ...options.map((v) => h('option', { value: v, selected: value === v }, v)),
      ),
    );
  const controls = h(
    'div',
    { class: 'c-actions' },
    select(t('tools'), 'tool', Object.keys(scan.tools), tool),
    select(t('kind'), 'kind', [...new Set(rows.map((x) => x.kind))], filters.kind ?? ''),
    select(
      t('scope'),
      'scope',
      [...new Set(rows.map((x) => x.scope))],
      filters.scope ?? '',
    ),
    h(
      'label',
      { class: 'c-field' },
      t('subject'),
      h('input', {
        type: 'search',
        value: filters.search ?? '',
        dataset: test('observations-search'),
        'aria-label': t('subject'),
        onInput: (e) => {
          filters.search = e.target.value;
          filters.page = 0;
          renderRows();
        },
      }),
    ),
  );
  const body = h('div');
  node.append(controls, body, h('small', {}, t('signalNote')));
  function renderRows() {
    const filtered = rows.filter(
      (o) =>
        (!(filters.tool ?? tool) || o.tool_id === (filters.tool ?? tool)) &&
        (!filters.kind || o.kind === filters.kind) &&
        (!filters.scope || o.scope === filters.scope) &&
        (!filters.search ||
          o.subject.toLocaleLowerCase().includes(filters.search.toLocaleLowerCase())),
    );
    const page = filters.page;
    replace(
      body,
      filtered.length
        ? table(
            [t('tools'), t('kind'), t('scope'), t('subject'), t('value'), 'Evidence'],
            filtered
              .slice(page * 100, page * 100 + 100)
              .map((o) =>
                tr(
                  [
                    o.tool_id,
                    o.kind,
                    scope(o.scope),
                    o.subject,
                    h(
                      'details',
                      { open: ctx.route.query.get('observation') === o.id },
                      h('summary', {}, JSON.stringify(o.value).slice(0, 80)),
                      code(JSON.stringify(o.value, null, 2)),
                    ),
                    o.evidence_ids.map((id) => evidenceChip(id, ctx)),
                  ],
                  `observation-row-${o.id}`,
                ),
              ),
          )
        : empty(t('unknownField')),
      filtered.length > 100
        ? pager(page, Math.ceil(filtered.length / 100), (p) => {
            filters.page = p;
            renderRows();
          })
        : null,
    );
  }
  function render() {
    ctx.refreshView();
  }
  renderRows();
  return node;
}
