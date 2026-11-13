import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { defaults, storageBlocked } from '../core/pointer.js';
import { settingsGroups } from '../registry/settings-groups.js';
import { AISettingsEditor } from '../components/ai-settings.js';
import { ProjectSettingsEditor } from '../components/project-settings.js';
import { panel, banner, choices, checkbox, button, pageHeading } from '../components/ui.js';

const aliases = { appearance: 'general', server: 'host', tools: 'system', limits: 'system' };
export function mount(root, ctx) {
  let previousUpdate = null, aiEditor = null, project = null, displayOpen = false;
  function appearance(state) {
    const p = state.prefs;
    const options = (key, values) => choices(
      values.map((id) => ({ id, label: t(id.toLowerCase()) })), p[key],
      (value) => ctx.setPrefs({ [key]: value }), `pref-${key}`,
      t(key === 'tz' ? 'timezone' : key),
    );
    return h('div', { class: 'v-settings-preferences' },
      h('h3', {}, t('appearance')), h('p', { class: 'meta' }, t('appearanceLocalHelp')),
      options('theme', ['system', 'light', 'dark']),
      options('density', ['comfortable', 'compact']),
      h('details', { open: displayOpen, onToggle: (event) => { displayOpen = event.target.open; } }, h('summary', {}, t('reportDisplay')),
        h('label', { class: 'c-field' }, t('rawFont'), h('input', {
          type: 'number', min: 12, max: 16, step: 1, value: p.rawFont,
          dataset: test('pref-rawFont'), onChange: (event) => ctx.setPrefs({ rawFont: Number(event.target.value) }),
        })),
        checkbox(t('wrap'), p.rawWrap, (value) => ctx.setPrefs({ rawWrap: value }), 'pref-rawWrap'),
        checkbox(t('lineNumbers'), p.lineNumbers, (value) => ctx.setPrefs({ lineNumbers: value }), 'pref-lines'),
        options('tz', ['local', 'UTC'])),
      button(t('reset'), () => ctx.setPrefs(defaults, true), 'pref-reset'),
      h('span', { 'aria-live': 'polite' }, state.prefSaved ? t('saved') : ''),
    );
  }
  function render(state) {
    const requested = ctx.route.params.group || 'general';
    const selected = aliases[requested] || requested;
    const group = settingsGroups.find((item) => item.id === selected) || settingsGroups[0];
    let content;
    if (group.id === 'providers') content = state.caps.features?.ai_settings
      ? (aiEditor ??= AISettingsEditor(ctx)).node
      : h('div', {}, h('p', {}, t('projectReadonly')),
        ...state.caps.providers.map((item) => h('article', { class: 'c-provider-card' },
          h('strong', {}, item.display_name || item.provider_id),
          h('span', {}, item.model_display_name || item.model || t('unset')),
          h('small', {}, t(item.enabled ? 'ready' : 'disabled')))));
    else {
      project ??= ProjectSettingsEditor(ctx);
      content = group.id === 'general'
        ? [project.nodes.general, appearance(state)] : project.nodes[group.id];
    }
    const section = panel(t(group.label), group.id, content);
    section.id = `settings-${group.id}`;
    replace(root, pageHeading(t('nav.settings'), t('settingsDescription')),
      storageBlocked ? banner(t('storage'), 'warn', 'storage') : null,
      h('div', { class: 'v-settings' },
        h('nav', { class: 'v-settings-toc', 'aria-label': t('nav.settings') },
          ...settingsGroups.map((item) => h('a', {
            href: `#/settings/${item.id}`, dataset: test(`settings-toc-${item.id}`),
            ...(item.id === group.id ? { 'aria-current': 'location' } : {}),
          }, t(item.label)))),
        h('div', { class: 'v-settings-body' }, section)));
    const nav = root.querySelector('.v-settings-toc');
    const current = nav.querySelector('[aria-current="location"]');
    if (nav.scrollWidth > nav.clientWidth && current) {
      nav.scrollLeft += current.getBoundingClientRect().left - nav.getBoundingClientRect().left
        - (nav.clientWidth - current.offsetWidth) / 2;
    }
  }
  return {
    update(state) {
      const selected = [state.caps, state.prefs, state.prefSaved, ctx.route.params.group];
      if (!previousUpdate || !selected.every((value, index) => value === previousUpdate[index])) {
        previousUpdate = selected; render(state);
      }
      aiEditor?.update(state); project?.update(state);
    },
    destroy() { aiEditor?.destroy(); project?.destroy(); },
  };
}
