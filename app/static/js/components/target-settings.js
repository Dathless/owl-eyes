import { h, replace, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { api } from '../core/api.js';
import { active } from '../core/poller.js';
import { button, errorBox } from './ui.js';

export function TargetSettingsEditor(ctx) {
  const node = h('div', { class: 'v-target-profiles', dataset: test('target-profiles') });
  let view = null, state, disposed = false, saving = false, failure = null;
  let editing = null, confirming = null, dirty = false;
  let draft = { name: '', kind: 'public_domain', url: '', ip: '' };
  const busy = () => saving || active(state?.activeScan?.state) || active(state?.scan?.state) || !view?.editable;
  async function refresh(result) {
    if (disposed) return;
    saving = false;
    if (!result.ok) { failure = result.error; render(); return; }
    const loaded = await api.targetProfiles();
    if (disposed) return;
    if (loaded.ok) view = loaded.data; else failure = loaded.error;
    const caps = await api.capabilities();
    if (disposed) return;
    if (caps.ok) ctx.store.set({ caps: caps.data });
    editing = null; confirming = null; dirty = false;
    draft = { name: '', kind: 'public_domain', url: '', ip: '' };
    render();
  }
  function edit(target) {
    editing = target?.target_id || null;
    draft = { name: target?.name || '', kind: target?.kind || 'public_domain', url: target?.url || '', ip: target?.ip || '' };
    dirty = false; failure = null; confirming = null; render();
    node.querySelector('[data-testid="target-profile-name"]')?.focus();
  }
  function field(key, label) {
    return h('label', { class: 'c-ai-field', for: `target-profile-${key}` },
      h('span', {}, t(label)), h('input', { id: `target-profile-${key}`, value: draft[key], type: 'text', autocomplete: 'off',
        dataset: test(`target-profile-${key}`), disabled: busy(),
        onInput: (event) => { draft[key] = event.target.value; dirty = true; } }));
  }
  function render() {
    if (disposed) return;
    if (!view) { replace(node, failure ? errorBox(failure) : h('p', {}, t('projectLoading'))); return; }
    replace(node, h('h3', {}, t('savedTargets')), h('p', { class: 'meta' }, t('savedTargetsHelp')),
      failure ? errorBox(failure) : null,
      h('div', { class: 'c-provider-list' }, ...view.targets.map((target) => h('article', { class: 'c-provider-card' },
        h('strong', {}, target.name || target.target_id), h('code', {}, target.url),
        h('small', {}, t(target.kind === 'public_domain' ? 'publicDomain' : 'dvwaTarget')),
        target.target_id === 'dvwa' ? h('small', {}, t('builtinTargetHelp')) : h('div', { class: 'c-actions' },
          button(t('edit'), () => edit(target), `target-edit-${target.target_id}`, { disabled: busy() }),
          button(t('deleteTarget'), () => { confirming = target.target_id; render(); }, `target-delete-${target.target_id}`, { disabled: busy() })),
        confirming === target.target_id ? h('div', {}, h('p', {}, t('deleteTargetConfirm', { name: target.name || target.target_id })),
          button(t('confirm'), async () => { if (busy()) return; saving = true; failure = null; render(); await refresh(await api.deleteTarget(target.target_id)); }, `target-delete-confirm-${target.target_id}`, { disabled: busy() }),
          button(t('cancel'), () => { confirming = null; render(); }, `target-delete-cancel-${target.target_id}`, { disabled: saving })) : null))),
      h('h3', {}, t(editing ? 'editTarget' : 'addTarget')),
      h('form', { class: 'v-settings-form', onSubmit: async (event) => {
        event.preventDefault(); if (busy()) return;
        const body = { name: draft.name, kind: draft.kind, url: draft.url, ip: draft.kind === 'dvwa' ? draft.ip : null };
        saving = true; failure = null; render();
        await refresh(await api.saveTarget(editing, body));
      } }, h('div', { class: 'c-ai-fields' }, field('name', 'targetName'),
        h('label', { class: 'c-ai-field', for: 'target-profile-kind' }, h('span', {}, t('targetType')),
          h('select', { id: 'target-profile-kind', dataset: test('target-profile-kind'), disabled: busy(), value: draft.kind,
            onChange: (event) => { draft.kind = event.target.value; dirty = true; render(); } },
            ...['public_domain', 'dvwa'].map((kind) => h('option', { value: kind, selected: draft.kind === kind }, t(kind === 'public_domain' ? 'publicDomain' : 'dvwaTarget'))))),
        field('url', draft.kind === 'public_domain' ? 'publicTargetURL' : 'targetURL'), draft.kind === 'dvwa' ? field('ip', 'targetIP') : null),
        h('p', { class: 'meta' }, t(draft.kind === 'public_domain' ? 'publicTargetHelp' : 'sharedLabCredentials')),
        h('div', { class: 'c-actions' }, button(t(saving ? 'sending' : 'projectSave'), null, 'target-profile-save', { type: 'submit', disabled: busy() }),
          editing ? button(t('addTarget'), () => edit(null), 'target-profile-add', { disabled: busy() }) : null)));
  }
  api.targetProfiles().then((result) => { if (disposed) return; if (result.ok) view = result.data; else failure = result.error; render(); });
  return { node, update(next) {
    const targetsChanged = view && Array.isArray(next.caps.targets) && state?.caps !== next.caps;
    const was = busy(); state = next;
    if (targetsChanged) view = { ...view, targets: next.caps.targets };
    if (targetsChanged || was !== busy() || (!dirty && !view)) render();
    node.querySelectorAll('input,select,button').forEach((control) => { control.disabled = busy(); });
  }, destroy() { disposed = true; } };
}
