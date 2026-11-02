import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { api } from '../core/api.js';
import { active } from '../core/poller.js';
import { button, checkbox, errorBox } from './ui.js';

const basics = [
  ['name', 'providerTitle'], ['base_url', 'providerURL'],
  ['api_key', 'providerKey'], ['model_id', 'providerModelID'],
  ['model_display_name', 'providerModelName'],
];
export function ProviderProfilesEditor(ctx) {
  const node = h('section', { dataset: test('provider-profiles') });
  let state, profiles = null, editing = null, draft = {}, failure = null;
  let saving = false, saved = false, disposed = false, clearKey = false, advancedOpen = false;
  let saveButton, status, deleted = false;
  const dirty = new Set();
  function busy() { return active(state?.activeScan?.state) || active(state?.scan?.state); }
  function reset(profile = null) {
    editing = profile?.provider_id ?? null;
    draft = { name: '', base_url: '', model_id: '', model_display_name: '',
      output_mode: 'json_schema', token_limit_field: 'max_tokens', ...profile, api_key: '' };
    dirty.clear(); clearKey = false; failure = null; saved = false; deleted = false; advancedOpen = false;
  }
  reset();
  function feedback() {
    if (saveButton) saveButton.disabled = saving || busy();
    node.querySelectorAll('[data-testid^="provider-delete-"]').forEach((button) => { button.disabled = saving || busy(); });
    if (status) status.textContent = busy() ? t('aiSettingsBusy')
      : saving ? t('sending') : deleted ? t('providerDeleted') : saved ? t('providerSaved') : '';
  }
  async function save(event) {
    event.preventDefault();
    if (saving || busy()) return;
    const body = {};
    for (const key of ['name', 'base_url', 'api_key', 'model_id', 'model_display_name', 'output_mode', 'token_limit_field']) {
      if (editing && !dirty.has(key)) continue;
      const value = String(draft[key] ?? '').trim();
      if (key === 'api_key') { if (value) body[key] = value; }
      else if (key === 'model_display_name') body[key] = value || null;
      else if (!editing && ['output_mode', 'token_limit_field'].includes(key) && !dirty.has(key)) continue;
      else body[key] = value;
    }
    if (clearKey) body.clear_api_key = true;
    saving = true; saved = false; failure = null; feedback();
    const result = await api.saveProvider(editing, body);
    if (disposed) return;
    saving = false;
    if (result.ok) {
      profiles = [...profiles.filter((p) => p.provider_id !== result.data.provider_id), result.data];
      reset(result.data); saved = true;
      const caps = await api.capabilities();
      if (disposed) return;
      if (caps.ok) ctx.store.set({ caps: caps.data });
    } else failure = result.error;
    render();
  }
  async function remove(profile) {
    if (saving || busy() || !window.confirm(t('providerDeleteConfirm', { name: profile.name }))) return;
    saving = true; saved = false; deleted = false; failure = null; render();
    const result = await api.deleteProvider(profile.provider_id);
    if (disposed) return;
    if (result.ok) {
      profiles = result.data.providers;
      if (editing === profile.provider_id) reset();
      deleted = true;
      const caps = await api.capabilities();
      if (disposed) return;
      if (caps.ok) ctx.store.set({ caps: caps.data });
    } else failure = result.error;
    saving = false; render();
  }
  function input(key, label, options = null) {
    const props = { dataset: test(`provider-field-${key}`), id: `provider-${key}`,
      autocomplete: 'off', value: draft[key] ?? '',
      onInput: (e) => { draft[key] = e.target.value; dirty.add(key); saved = false; feedback(); },
    };
    const control = options
      ? h('select', props, ...options.map((v) => h('option', { value: v }, v)))
      : h('input', { ...props, type: key === 'api_key' ? 'password' : 'text',
        ...(key === 'api_key' && editing ? { placeholder: t('aiKeyKeep') } : {}) });
    control.value = draft[key] ?? '';
    return h('label', { class: 'c-ai-field', for: `provider-${key}` },
      h('span', {}, t(label)), control,
      key === 'base_url' ? h('small', {}, t('providerURLHint')) : null,
      key === 'model_display_name' ? h('small', {}, t('providerModelNameHint')) : null,
      key === 'api_key' && editing ? h('small', {}, t(draft.key_configured ? 'set' : 'unset'), '. ', t('aiKeyKeep')) : null);
  }
  function render() {
    if (disposed) return;
    if (!profiles) { replace(node, failure ? errorBox(failure) : h('p', {}, t('aiSettingsLoading'))); return; }
    const visible = profiles.filter((p) => p.base_url || p.model_id || p.key_configured);
    saveButton = button(t(editing ? 'providerSaveEdit' : 'providerAdd'), null, 'provider-save', { type: 'submit' });
    status = h('p', { role: 'status', dataset: test('provider-message') });
    replace(node, h('h3', {}, t('providerListTitle')), h('p', {}, t('providerSimpleNote')),
      h('div', { class: 'c-provider-list' },
        ...visible.map((p) => h('article', { class: 'c-provider-card', dataset: test(`provider-card-${p.provider_id}`) },
          h('strong', {}, p.name), h('span', {}, p.model_display_name || p.model_id),
          h('small', {}, p.base_url),
          h('small', {}, t(p.enabled ? 'ready' : 'providerIncomplete')),
          h('div', { class: 'c-actions c-provider-card-actions' },
            button(t('providerEdit'), () => { reset(p); render(); }, `provider-edit-${p.provider_id}`, { disabled: saving }),
            button(t('providerDelete'), () => remove(p), `provider-delete-${p.provider_id}`, { disabled: saving || busy() })))),
        !visible.length ? h('p', {}, t('providerNone')) : null),
      button(t('providerAddNew'), () => { reset(); render(); }, 'provider-new', { disabled: saving }),
      h('form', { onSubmit: save, class: 'c-provider-form' },
        h('h3', {}, t(editing ? 'providerEditing' : 'providerAdding')),
        errorBox(failure),
        h('div', { class: 'c-ai-fields' }, ...basics.map(([key, label]) => input(key, label))),
        h('details', { open: advancedOpen, dataset: test('provider-advanced'), onToggle: (e) => { advancedOpen = e.target.open; } },
          h('summary', {}, t('providerAdvanced')), h('p', {}, t('providerAdvancedNote')),
          h('div', { class: 'c-ai-fields' },
            input('output_mode', 'providerOutputMode', ['json_schema', 'json_object', 'prompt_json']),
            input('token_limit_field', 'providerTokenField', ['max_tokens', 'max_completion_tokens'])),
          editing ? checkbox(t('aiKeyClear'), clearKey, (value) => { clearKey = value; }, 'provider-clear-key') : null),
        saveButton, status));
    feedback();
  }
  api.providers().then((result) => {
    if (disposed) return;
    if (result.ok) profiles = result.data.providers;
    else failure = result.error;
    render();
  });
  return { node, update(next) { state = next; feedback(); }, destroy() { disposed = true; draft = {}; dirty.clear(); } };
}
