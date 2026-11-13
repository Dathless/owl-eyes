import { h, replace, test } from '../core/dom.js';
import { api } from '../core/api.js';
import { t } from '../core/i18n.js';
import { active } from '../core/poller.js';
import { button, errorBox, checkbox } from './ui.js';

const targetFields = [
  ['lab_target_ip', 'targetIP', 'text'],
  ['lab_target_url', 'targetURL', 'text'],
  ['dvwa_username', 'targetUsername', 'text'],
  ['dvwa_password', 'targetPassword', 'password'],
];
const generalFields = [
  ['ai_agent_max_loops', 'agentRounds', 'number', 1, 20],
  ['ai_total_timeout_seconds', 'analysisDeadline', 'number', 1, 3600],
];
export function ProjectSettingsEditor(ctx) {
  const nodes = Object.fromEntries(['target', 'general', 'host', 'system'].map((id) =>
    [id, h('div', { dataset: test(`project-${id}`) })]));
  const draft = {};
  const dirty = new Set();
  let view = null, state, saving = null, saved = null, failure = null, disposed = false;
  function busy() { return active(state?.activeScan?.state) || active(state?.scan?.state); }
  function feedback() {
    for (const group of ['target', 'general']) {
      nodes[group].querySelectorAll('input,button').forEach((control) => {
        control.disabled = !!saving || busy() || !view?.editable;
        if (control.type === 'submit') control.disabled ||= !keys(group).some((key) => dirty.has(key));
      });
      const message = nodes[group].querySelector('[role="status"]');
      if (message) message.textContent = busy() ? t('projectBusy') : saving === group
        ? t('sending') : saved === group ? t('projectSaved') : '';
    }
  }
  function keys(group) { return group === 'target' ? targetFields.map(([key]) => key)
    : ['ai_agent_enabled', ...generalFields.map(([key]) => key)]; }
  function fill() {
    const values = {
      lab_target_ip: view.target.ip, lab_target_url: view.target.url,
      dvwa_username: view.target.username, dvwa_password: '', ...view.general,
    };
    for (const [key, value] of Object.entries(values)) if (!dirty.has(key)) draft[key] = value;
  }
  async function save(group, event) {
    event.preventDefault();
    if (saving || busy() || !view?.editable) return;
    const body = {};
    for (const key of keys(group)) {
      if (!dirty.has(key)) continue;
      if (key === 'dvwa_password' && !draft[key]) continue;
      body[key] = key === 'ai_agent_enabled' ? !!draft[key]
        : generalFields.some(([name]) => name === key) ? Number(draft[key]) : draft[key];
    }
    saving = group; saved = null; failure = null; feedback();
    const result = await api.saveProjectSettings(body);
    if (disposed) return;
    saving = null;
    if (result.ok) {
      view = result.data; saved = group;
      keys(group).forEach((key) => dirty.delete(key));
      fill();
      const caps = await api.capabilities();
      if (disposed) return;
      if (caps.ok) ctx.store.set({ caps: caps.data });
    } else failure = { group, error: result.error };
    render();
  }
  function field([key, label, type, min, max]) {
    return h('label', { class: 'c-ai-field', for: `project-${key}` },
      h('span', {}, t(label)), h('input', {
        id: `project-${key}`, dataset: test(`project-${key}`), type, value: draft[key] ?? '',
        autocomplete: type === 'password' ? 'new-password' : 'off',
        ...(type === 'number' ? { min, max, step: 1 } : {}),
        ...(type === 'password' ? { placeholder: t('targetPasswordKeep') } : {}),
        onInput: (event) => { draft[key] = event.target.value; dirty.add(key); saved = null; feedback(); },
      }), type === 'password' ? h('small', {}, t('targetPasswordKeep')) : null);
  }
  function facts(entries) {
    return h('dl', { class: 'v-settings-facts' }, ...entries.map(([label, value]) =>
      h('div', {}, h('dt', {}, t(label)), h('dd', {}, value ?? '—'))));
  }
  function render() {
    if (disposed) return;
    if (!view) {
      for (const node of Object.values(nodes)) replace(node,
        failure ? errorBox(failure.error) : h('p', {}, t('projectLoading')));
      return;
    }
    for (const group of ['target', 'general']) {
      const fields = group === 'target' ? targetFields : generalFields;
      replace(nodes[group], h('p', { class: 'meta' }, t(group === 'target' ? 'targetEditHelp' : 'generalEditHelp')),
        group === 'target' && view.system.lab_network ? h('p', { class: 'meta' }, `${t('labNetwork')}: ${view.system.lab_network}`) : null,
        !view.editable ? h('p', {}, t('projectReadonly')) : null,
        failure?.group === group ? errorBox(failure.error) : null,
        h('form', { onSubmit: (event) => save(group, event), class: 'v-settings-form' },
          group === 'general' ? checkbox(t('agentEnabled'), draft.ai_agent_enabled,
            (value) => { draft.ai_agent_enabled = value; dirty.add('ai_agent_enabled'); saved = null; feedback(); },
            'project-ai_agent_enabled') : null,
          h('div', { class: 'c-ai-fields' }, ...fields.map(field)),
          button(t('projectSave'), null, `project-save-${group}`, { type: 'submit' }),
          h('p', { role: 'status', dataset: test(`project-message-${group}`) })));
    }
    const host = view.host;
    replace(nodes.host, h('p', { class: 'meta' }, t('hostHelp')), facts([
      ['hostName', host.name], ['hostSystem', host.system], ['hostAddress', host.address],
      ['hostPort', host.port], ['hostOrigin', host.origin], ['hostPython', host.python],
    ]));
    const system = view.system;
    replace(nodes.system, h('p', { class: 'meta' }, t('systemHelp')), facts([
      ['projectVersion', state?.caps?.app_version ?? '—'],
      ['parallelTools', system.max_concurrent_tools],
      ['outputLimit', `${Math.round(system.tool_capture_limit_bytes / 1024)} KB`],
      ['historyStorage', system.history_storage === 'SQLite' ? t('historyPersistent') : t('historySession')],
    ]), h('div', { class: 'v-settings-tool-summary' },
      h('h3', {}, t('scannerAvailability')),
      ...(state?.caps?.tools ?? []).map((tool) => h('div', { class: 'v-settings-tool' },
        h('strong', {}, tool.tool_id), h('span', {}, t(tool.enabled ? 'ready' : 'disabled')),
        h('small', {}, tool.version || t('versionUnknown'))))),
      h('p', { class: 'meta' }, t('presetNote')));
    feedback();
  }
  api.projectSettings().then((result) => {
    if (disposed) return;
    if (result.ok) { view = result.data; fill(); }
    else failure = { error: result.error };
    render();
  });
  render();
  return {
    nodes,
    update(next) { state = next; feedback(); },
    destroy() { disposed = true; draft.dvwa_password = ''; dirty.clear(); },
  };
}
