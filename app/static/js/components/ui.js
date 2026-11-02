import { h, test } from '../core/dom.js';
import { t, hasText } from '../core/i18n.js';
import { providerLabel } from '../core/format.js';
import { enumGlyph, tones, severities, scopes } from '../registry/enums.js';
export const button = (label, onClick, id, props = {}) =>
  h('button', { type: 'button', onClick, dataset: id ? test(id) : {}, ...props }, label);
export const link = (label, to, id) =>
  h('a', { href: `#${to}`, dataset: id ? test(id) : {} }, label);
export const badge = (value, tone = 'neutral') =>
  h('span', { class: `c-badge tone-${tone}` }, value);
export const stateBadge = (value) =>
  badge(`${enumGlyph(value)} ${value}`, tones[value] ?? 'neutral');
export const severity = (value) =>
  h(
    'span',
    { class: `c-badge severity-${severities.includes(value) ? value : 'unknown'}` },
    `${enumGlyph(value)} ${value}`,
  );
export const scope = (value) =>
  badge(scopes[value] ?? value, value === 'other_path' ? 'warn' : 'neutral');
export const provider = (p) =>
  badge(
    `${providerLabel(p)}  ${p?.kind ?? ''}`,
    p?.kind === 'external' ? 'warn' : 'neutral',
  );
export const banner = (text, tone = 'info', id, ...actions) =>
  h(
    'div',
    {
      class: `c-banner tone-${tone}`,
      role: tone === 'err' ? 'alert' : 'status',
      dataset: id ? test(`banner-${id}`) : {},
    },
    h('span', {}, text),
    ...actions,
  );
export const errorBox = (error) =>
  error
    ? banner(
        `${hasText(`error.${error.code}`) ? t(`error.${error.code}`) + ' ' : ''}${error.code}: ${error.message}`,
        'err',
        error.code,
      )
    : null;
export const empty = (text, description, icon = 'i-terminal') =>
  description
    ? h('div', { class: 'c-empty c-empty-illustrated' },
        h('span', { class: 'c-empty-icon' }, Icon(icon)),
        h('strong', {}, text), h('p', {}, description))
    : h('p', { class: 'c-empty' }, text);
export const pageHeading = (title, description) =>
  h('header', { class: 'c-page-heading' },
    h('p', { class: 'c-eyebrow' }, t('workspace')),
    h('h1', {}, title),
    h('p', { class: 'c-page-description' }, description),
  );
export const panel = (title, id, ...body) =>
  h(
    'section',
    { class: 'c-panel', dataset: test(`panel-${id}`), id: `panel-${id}` },
    h('header', { class: 'c-panel-heading' }, h('h2', {}, title)),
    h('div', { class: 'c-panel-body' }, ...body),
  );
export const code = (text, id) =>
  h('pre', { class: 'c-code', tabIndex: 0, dataset: id ? test(id) : {} }, text);
export const kv = (rows) =>
  h(
    'dl',
    { class: 'c-kv' },
    ...rows.flatMap(([k, v, id]) => [
      h('dt', {}, k),
      h('dd', { dataset: id ? test(id) : {} }, v ?? '—'),
    ]),
  );
export function table(headers, rows, label) {
  return h(
    'div',
    { class: 'c-table-scroll', tabIndex: 0, 'aria-label': label ?? headers.join(' / ') },
    h(
      'table',
      {},
      h('thead', {}, h('tr', {}, ...headers.map((x) => h('th', { scope: 'col' }, x)))),
      h('tbody', {}, ...rows),
    ),
  );
}
export const tr = (values, id) =>
  h('tr', { dataset: id ? test(id) : {} }, ...values.map((v) => h('td', {}, v)));
export async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* HTTP origins may need the selection fallback. */
  }
  const previous = document.activeElement;
  const area = h('textarea', {
    class: 'c-copy-buffer',
    'aria-label': t('copy'),
    value: text,
  });
  document.body.append(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    /* Manual copy remains available. */
  }
  area.remove();
  previous?.focus({ preventScroll: true });
  return ok;
}
export function copyButton(text, id) {
  const btn = button(
    t('copy'),
    async () => {
      const ok = await copyText(typeof text === 'function' ? text() : text);
      btn.textContent = t(ok ? 'copied' : 'copyFailed');
      if (ok)
        setTimeout(() => {
          btn.textContent = t('copy');
        }, 1500);
    },
    id,
    { 'aria-live': 'polite' },
  );
  return btn;
}
export function evidenceChip(id, ctx) {
  return button(
    `ev:${id.slice(0, 8)}`,
    () => ctx.openEvidence(id),
    `evidence-chip-${id}`,
    { class: 'c-evidence', 'aria-label': `Evidence ${id}` },
  );
}
export function choices(options, value, onChange, prefix, label) {
  if (options.length > 4) {
    const select = h(
      'select',
      {
        'aria-label': label,
        dataset: test(`${prefix}-select`),
        onChange: (e) => onChange(e.target.value),
      },
      ...options.map((o) =>
        h(
          'option',
          { value: o.id, selected: o.id === value, disabled: o.disabled },
          o.label,
        ),
      ),
    );
    return h('label', { class: 'c-field c-select-choice' }, label, select);
  }
  return h(
    'fieldset',
    { class: 'c-choices' },
    h('legend', {}, label),
    ...options.map((o) =>
      h(
        'label',
        { class: 'c-choice' },
        h('input', {
          type: 'radio',
          name: prefix,
          value: o.id,
          checked: o.id === value,
          disabled: o.disabled,
          dataset: test(`${prefix}-${o.id}`),
          onChange: () => onChange(o.id),
          'aria-describedby': `${prefix}-reason-${o.id}`,
        }),
        h(
          'span',
          {},
          o.label,
          h('small', { id: `${prefix}-reason-${o.id}` }, o.reason ?? ''),
        ),
      ),
    ),
  );
}
export function tabs(items, current, onChange) {
  const list = h('div', { role: 'tablist', class: 'c-tabs', 'aria-label': t('report') });
  const buttons = items.map((item) =>
    button(t(item.label), () => onChange(item.id), `tab-${item.id}`, {
      id: `tab-${item.id}`,
      role: 'tab',
      'aria-selected': String(item.id === current),
      'aria-controls': `tabpanel-${item.id}`,
      tabIndex: item.id === current ? 0 : -1,
    }),
  );
  list.append(...buttons);
  list.addEventListener('keydown', (e) => {
    const i = buttons.indexOf(document.activeElement);
    const next =
      e.key === 'Home'
        ? 0
        : e.key === 'End'
          ? buttons.length - 1
          : e.key === 'ArrowRight'
            ? (i + 1) % buttons.length
            : e.key === 'ArrowLeft'
              ? (i + buttons.length - 1) % buttons.length
              : -1;
    if (next < 0) return;
    e.preventDefault();
    onChange(items[next].id);
    requestAnimationFrame(() =>
      document.getElementById(`tab-${items[next].id}`)?.focus(),
    );
  });
  return list;
}
export const checkbox = (label, value, onChange, id) =>
  h(
    'label',
    { class: 'c-choice' },
    h('input', {
      type: 'checkbox',
      checked: value,
      onChange: (e) => onChange(e.target.checked),
      dataset: test(id),
    }),
    label,
  );
export function pager(page, total, change) {
  return h(
    'div',
    { class: 'c-actions' },
    button(t('previous'), () => change(page - 1), null, { disabled: page <= 0 }),
    h('span', {}, t('page', { page: page + 1, total: Math.max(1, total) })),
    button(t('next'), () => change(page + 1), null, { disabled: page + 1 >= total }),
  );
}

export const Icon = (name) =>
  h(
    'svg',
    { class: 'c-icon', viewBox: '0 0 24 24', 'aria-hidden': 'true' },
    h('use', { href: `/static/icons.svg#${name}` }),
  );
