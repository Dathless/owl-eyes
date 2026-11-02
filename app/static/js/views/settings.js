import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { defaults, storageBlocked } from '../core/pointer.js';
import { settingValue } from '../core/format.js';
import { settingsGroups } from '../registry/settings-groups.js';
import { AISettingsEditor } from '../components/ai-settings.js';
import {
  badge,
  provider,
  panel,
  banner,
  table,
  tr,
  copyButton,
  choices,
  checkbox,
  button,
  pageHeading,
} from '../components/ui.js';
export function mount(root, ctx) {
  let observer,
    previousUpdate = null;
  let aiEditor = null;
  function row(setting) {
    return h(
      'div',
      {
        class: 'v-setting',
        dataset: { ...test(`setting-${setting.key}`), serverSetting: 'true' },
      },
      h(
        'div',
        {},
        setting.label ?? setting.key,
        setting.description ? h('small', {}, setting.description) : null,
      ),
      h('div', {}, settingValue(setting)),
      h(
        'div',
        { class: 'meta' },
        setting.key,
        ' ',
        badge(setting.source ?? 'derived'),
        badge(setting.status ?? 'ok'),
        copyButton(setting.key),
      ),
    );
  }
  function appearance(state) {
    const p = state.prefs;
    const options = (key, values) =>
      choices(
        values.map((id) => ({ id, label: t(id.toLowerCase()) })),
        p[key],
        (v) => ctx.setPrefs({ [key]: v }),
        `pref-${key}`,
        t(key === 'tz' ? 'timezone' : key),
      );
    return h(
      'div',
      {},
      options('theme', ['system', 'light', 'dark']),
      options('density', ['comfortable', 'compact']),
      h(
        'label',
        { class: 'c-field' },
        t('rawFont'),
        h('input', {
          type: 'number',
          min: 12,
          max: 16,
          step: 1,
          value: p.rawFont,
          dataset: test('pref-rawFont'),
          onChange: (e) => ctx.setPrefs({ rawFont: Number(e.target.value) }),
        }),
      ),
      checkbox(t('wrap'), p.rawWrap, (v) => ctx.setPrefs({ rawWrap: v }), 'pref-rawWrap'),
      checkbox(
        t('lineNumbers'),
        p.lineNumbers,
        (v) => ctx.setPrefs({ lineNumbers: v }),
        'pref-lines',
      ),
      options('tz', ['local', 'UTC']),
      button(t('reset'), () => ctx.setPrefs(defaults, true), 'pref-reset'),
      h('span', { 'aria-live': 'polite' }, state.prefSaved ? t('saved') : ''),
    );
  }
  function render(state) {
    const caps = state.caps;
    const extra = [...new Set((caps.settings ?? []).map((s) => s.group))]
      .filter((id) => !settingsGroups.some((g) => g.id === id))
      .map((id, i) => ({ id, label: id, order: 100 + i }));
    const groups = [...settingsGroups, ...extra].sort((a, b) => a.order - b.order);
    const sections = groups.map((group) => {
      let content;
      const rows = (caps.settings ?? []).filter((s) => s.group === group.id);
      if (group.render) content = group.render(state, ctx);
      else if (group.id === 'appearance') content = appearance(state);
      else if (group.id === 'providers')
        content = h(
          'div',
          {},
          caps.features?.ai_settings
            ? (aiEditor ??= AISettingsEditor(ctx)).node
            : h('p', {}, t('readonly')),
          h(caps.features?.ai_settings ? 'details' : 'div', {},
            caps.features?.ai_settings ? h('summary', {}, t('providerTechnicalSummary')) : null,
          table(
            [t('providers'), 'Model', 'Mode', 'Host', 'Key', t('state')],
            caps.providers.map((p) =>
              tr([
                provider(p),
                p.model ?? t('unset'),
                p.output_mode ?? t('unknownField'),
                p.host ?? '—',
                t(p.key_configured ? 'set' : 'unset'),
                p.enabled ? t('ready') : (p.reason ?? t('disabled')),
              ]),
            ),
          ),
          ...rows.map(row)),
        );
      else if (group.id === 'tools')
        content = h(
          'div',
          {},
          table(
            [t('tools'), t('state'), 'Version', 'Preset', t('duration'), t('notes')],
            caps.tools.map((tool) =>
              tr([
                tool.tool_id,
                tool.enabled ? t('ready') : (tool.reason ?? t('disabled')),
                tool.version ?? t('versionUnknown'),
                tool.preset_summary ?? t('unknownField'),
                tool.timeout_seconds ?? '—',
                tool.applicability_note ?? '—',
              ]),
            ),
          ),
          h('p', {}, t('presetNote')),
          ...rows.map(row),
        );
      else
        content = h(
          'div',
          {},
          h('p', {}, t('readonly')),
          group.id === 'target' ? h('p', {}, t('authNote')) : null,
          ...(rows.length ? rows : (group.fromCaps?.(caps) ?? [])).map(row),
          group.id === 'target'
            ? Object.entries(caps.target)
                .filter(([key]) => !rows.some((r) => r.key.toLowerCase().endsWith(key)))
                .map(([key, value]) => row({ key, label: key, value, source: 'derived' }))
            : null,
          group.id === 'server' && rows.length ? group.fromCaps(caps).map(row) : null,
          !rows.length && (!group.fromCaps || !group.fromCaps(caps).length)
            ? h('p', {}, t('unknownField'))
            : null,
        );
      const section = panel(t(group.label), group.id, content);
      section.id = `settings-${group.id}`;
      return section;
    });
    const diag = {
      app_version: caps.app_version ?? null,
      schema_version: caps.schema_version ?? null,
      server_instance_id: caps.server_instance_id,
      target: caps.target,
      tools: caps.tools.map((x) => ({
        tool_id: x.tool_id,
        enabled: x.enabled,
        version: x.version,
      })),
      providers: caps.providers.map((x) => ({
        provider_id: x.provider_id,
        kind: x.kind,
        enabled: x.enabled,
        model: x.model,
        host: x.host,
      })),
      limits: caps.limits ?? {},
    };
    const diagButton = copyButton(JSON.stringify(diag, null, 2), 'diag-copy');
    diagButton.textContent = t('diagCopy');
    replace(
      root,
      pageHeading(t('nav.settings'), t('settingsDescription')),
      storageBlocked ? banner(t('storage'), 'warn', 'storage') : null,
      h(
        'div',
        { class: 'v-settings' },
        h(
          'nav',
          { class: 'v-settings-toc', 'aria-label': t('nav.settings') },
          ...groups.map((g) =>
            h(
              'a',
              {
                href: `#/settings/${encodeURIComponent(g.id)}`,
                dataset: test(`settings-toc-${g.id}`),
              },
              t(g.label),
            ),
          ),
        ),
        h('div', { class: 'v-settings-body' }, ...sections, diagButton),
      ),
    );
    observer?.disconnect();
    observer = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            for (const a of root.querySelectorAll('.v-settings-toc a')) {
              a.setAttribute(
                'aria-current',
                a.hash.endsWith(e.target.id.slice(9)) ? 'location' : 'false',
              );
            }
            break;
          }
        }
      },
      { rootMargin: '-10% 0px -65% 0px' },
    );
    sections.forEach((s) => observer.observe(s));
    if (ctx.route.params.group)
      document
        .getElementById(`settings-${ctx.route.params.group}`)
        ?.scrollIntoView({ block: 'start' });
  }
  return {
    update(state) {
      aiEditor?.update(state);
      const selected = [state.caps, state.prefs, state.prefSaved, ctx.route.params.group];
      if (
        previousUpdate &&
        selected.every((value, index) => value === previousUpdate[index])
      )
        return;
      previousUpdate = selected;
      render(state);
      aiEditor?.update(state);
    },
    destroy() {
      observer?.disconnect();
      aiEditor?.destroy();
    },
  };
}
