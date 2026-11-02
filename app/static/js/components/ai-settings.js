import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { api } from '../core/api.js';
import { active } from '../core/poller.js';
import { ProviderProfilesEditor } from './provider-profiles.js';
import { button, errorBox } from './ui.js';

export function AISettingsEditor(ctx) {
  const node = h('div', { dataset: test('ai-settings-editor') });
  const profiles = ProviderProfilesEditor(ctx);
  const dirty = new Set();
  let globalOpen = false;
  let state, view = null, failure = null, saving = false, saved = false;
  let disposed = false;
  const draft = {};
  let saveButton, message;
  function busy() {
    return active(state?.activeScan?.state) || active(state?.scan?.state);
  }
  function feedback() {
    if (saveButton) saveButton.disabled = saving || busy() || !dirty.size;
    if (message) message.textContent = busy() ? t('aiSettingsBusy')
      : saving ? t('sending') : saved ? t('aiSettingsSaved') : '';
  }
  async function save(event) {
    event.preventDefault();
    if (saving || busy() || !view) return;
    saving = true; saved = false; failure = null; feedback();
    const body = {};
    for (const field of view.fields) {
      if (!dirty.has(field.key) || field.key.startsWith('openai_')) continue;
      const value = draft[field.key];
      if (field.secret) {
        if (value) body[field.key] = value;
      } else body[field.key] = field.kind === 'number' ? Number(value)
        : value === '' ? null : value;
    }
    const result = await api.saveAISettings(body);
    if (disposed) return;
    saving = false;
    if (result.ok) {
      view = result.data;
      saved = true; dirty.clear();
      for (const field of view.fields)
        draft[field.key] = field.secret ? '' : view.values[field.key] ?? '';
      const caps = await api.capabilities();
      if (caps.ok) ctx.store.set({ caps: caps.data });
    } else failure = result.error;
    render();
  }
  function render() {
    if (disposed) return;
    if (!view) {
      replace(node, profiles.node, failure ? errorBox(failure) : h('p', {}, t('aiSettingsLoading')));
      return;
    }
    const fields = view.fields.filter((field) => !field.key.startsWith('openai_')).map((field) => {
      const props = {
        id: `ai-${field.key}`, dataset: test(`ai-field-${field.key}`),
        value: draft[field.key], autocomplete: 'off',
        onInput: (event) => { draft[field.key] = event.target.value; dirty.add(field.key); saved = false; feedback(); },
      };
      const control = field.kind === 'select'
        ? h('select', props, ...field.options.map((value) => h('option', { value }, value)))
        : h('input', { ...props, type: field.kind === 'password' ? 'password'
          : field.kind === 'number' ? 'number' : 'text',
          ...(field.kind === 'number' ? { step: 'any', min: 1 } : {}),
          ...(field.secret ? { placeholder: t('aiKeyKeep') } : {}),
        });
      control.value = draft[field.key];
      return h('label', { class: 'c-ai-field', for: `ai-${field.key}` },
        h('span', {}, field.label), control,
        field.secret ? h('small', {}, `${t(view.openai_key_configured ? 'set' : 'unset')}. ${t('aiKeyKeep')}`) : null);
    });
    saveButton = button(t('aiSettingsSave'), null, 'ai-settings-save', { type: 'submit' });
    message = h('p', { role: 'status', dataset: test('ai-settings-message') });
    replace(node, profiles.node, h('details', {
      open: globalOpen, dataset: test('ai-global-settings'),
      onToggle: (e) => { globalOpen = e.target.open; },
    }, h('summary', {}, t('providerGlobalSettings')), h('p', {}, t('aiEditorNote')),
      errorBox(failure), h('form', { onSubmit: save },
        h('div', { class: 'c-ai-fields' }, ...fields), saveButton, message)));
    feedback();
  }
  api.aiSettings().then((result) => {
    if (disposed) return;
    if (result.ok) {
      view = result.data;
      for (const field of view.fields)
        draft[field.key] = field.secret ? '' : view.values[field.key] ?? '';
    } else failure = result.error;
    render();
  });
  return {
    node,
    update(next) { state = next; profiles.update(next); feedback(); },
    destroy() { disposed = true; profiles.destroy(); for (const key of Object.keys(draft)) delete draft[key]; },
  };
}
