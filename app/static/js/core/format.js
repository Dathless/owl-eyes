import { t } from './i18n.js';
export const short = (id) => String(id ?? '—').slice(0, 8);
export const duration = (ms) => `${Math.max(0, (ms ?? 0) / 1000).toFixed(1)}s`;
export function timestamp(value, tz = 'local') {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(+date)
    ? String(value)
    : date.toLocaleString('vi-VN', tz === 'UTC' ? { timeZone: 'UTC' } : {});
}
export const elapsed = (scan) =>
  duration(new Date(scan.finished_at ?? Date.now()) - new Date(scan.created_at));
export function collectionElapsed(scan) {
  const tools = Object.values(scan.tools ?? {});
  const terminal = [
    'succeeded', 'failed', 'timed_out', 'output_limited', 'skipped', 'cancelled',
  ];
  if (tools.length && tools.every((tool) => terminal.includes(tool.state))) {
    if (tools.some((tool) => !tool.finished_at)) return '—';
    const end = Math.max(...tools.map((tool) => +new Date(tool.finished_at)));
    return Number.isFinite(end) ? duration(end - new Date(scan.created_at)) : '—';
  }
  return elapsed(scan);
}
export const settingValue = (row) => {
  if (row.secret || row.kind === 'secret_state')
    return t(row.status === 'unset' ? 'unset' : 'set');
  if (row.value == null && row.display_value == null) return t('unknownField');
  const value = row.display_value ?? row.value;
  if (row.kind === 'url' && row.group === 'providers') {
    try {
      return new URL(String(value)).host;
    } catch {
      return t('unknownField');
    }
  }
  if (row.kind === 'bytes' && typeof value === 'number')
    return `${(value / 1024).toFixed(1)} KiB (${value})`;
  if (row.kind === 'duration') return `${value} s`;
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
};

export const providerLabel = (p) => p
  ? `${p.display_name || p.provider_id} · ${p.model_display_name || p.model || t('unset')}`
  : '—';
