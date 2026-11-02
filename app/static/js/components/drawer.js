import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { short } from '../core/format.js';
import { shortcuts } from '../registry/shortcuts.js';
import { button, code, copyButton, empty, kv } from './ui.js';
export const drawerKinds = {
  shortcuts: (state, ctx) =>
    h(
      'div',
      {},
      h('h2', { id: 'drawer-title', tabIndex: -1 }, t('shortcuts')),
      ...shortcuts.map((s) => h('p', {}, h('kbd', {}, s.keys), ' ', t(s.label))),
    ),
  evidence: (state, ctx, id) => {
    const all = Object.values(state.scan?.tools ?? {}).flatMap((tool) => tool.evidence);
    const ev = all.find((e) => e.id === id);
    const title = h(
      'h2',
      { id: 'drawer-title', tabIndex: -1 },
      `Evidence ev:${short(id)}`,
    );
    if (!ev) return h('div', {}, title, empty(t('evidenceMissing')));
    const findings = (state.scan.report?.report.findings ?? []).filter((f) =>
      f.evidence_ids.includes(id),
    );
    const observations = Object.values(state.scan.tools)
      .flatMap((t) => t.observations)
      .filter((o) => o.evidence_ids.includes(id));
    const siblings = findings[0]?.evidence_ids ?? [];
    const index = siblings.indexOf(id);
    return h(
      'div',
      {},
      title,
      siblings.length > 1
        ? h(
            'div',
            { class: 'c-actions' },
            button(
              '‹',
              () =>
                ctx.openEvidence(
                  siblings[(index + siblings.length - 1) % siblings.length],
                ),
              null,
              { 'aria-label': t('previous') },
            ),
            button(
              '›',
              () => ctx.openEvidence(siblings[(index + 1) % siblings.length]),
              null,
              { 'aria-label': t('next') },
            ),
          )
        : null,
      kv([
        ['tool', ev.tool_id, 'ev-tool'],
        ['source', ev.source, 'ev-source'],
        ['locator', h('span', {}, ev.locator, copyButton(ev.locator)), 'ev-locator'],
        ['id', h('span', {}, ev.id, copyButton(ev.id))],
      ]),
      h('h3', {}, 'Excerpt'),
      code(ev.excerpt, 'ev-excerpt'),
      h('h3', {}, t('references')),
      h(
        'div',
        { dataset: test('ev-refs') },
        ...findings.map((f) =>
          button(f.title, () => ctx.reference('report', 'finding', f.id)),
        ),
        ...observations.map((o) =>
          button(`${o.kind} ${o.scope} ${o.subject}`, () =>
            ctx.reference('observations', 'observation', o.id),
          ),
        ),
      ),
      button(t('viewRaw'), () => ctx.evidenceRaw(id), 'ev-open-raw'),
    );
  },
};
export function renderDrawer(root, state, ctx) {
  const id = ctx.route.query.get('ev');
  const kind = id ? 'evidence' : state.drawer;
  const wasOpen = !root.hidden;
  const key = `${kind}/${id ?? ''}`;
  if (!kind) {
    root.hidden = true;
    document.body.dataset.drawer = 'closed';
    return;
  }
  root.hidden = false;
  document.body.dataset.drawer = 'open';
  const docked = matchMedia('(min-width:1280px)').matches;
  root.setAttribute('role', docked ? 'complementary' : 'dialog');
  root.setAttribute('aria-modal', 'false');
  root.setAttribute('aria-labelledby', 'drawer-title');
  const signature = JSON.stringify([
    key,
    Object.values(state.scan?.tools ?? {}).map((tool) => [
      tool.evidence,
      tool.observations,
    ]),
    state.scan?.report?.report.findings,
  ]);
  if (wasOpen && root.dataset.signature === signature) return;
  root.dataset.signature = signature;
  replace(
    root,
    button(t('close'), () => ctx.closeDrawer(), 'drawer-close'),
    drawerKinds[kind]?.(state, ctx, id),
  );
  if (!wasOpen || root.dataset.key !== key) root.querySelector('#drawer-title')?.focus();
  root.dataset.key = key;
}
