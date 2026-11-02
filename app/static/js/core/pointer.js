export let storageBlocked = false;
export function read(key) {
  try {
    return JSON.parse(localStorage.getItem(key));
  } catch {
    storageBlocked = true;
    return null;
  }
}
export function write(key, value) {
  try {
    if (value == null) localStorage.removeItem(key);
    else localStorage.setItem(key, JSON.stringify(value));
  } catch {
    storageBlocked = true;
  }
}
export const defaults = {
  theme: 'system',
  density: 'comfortable',
  rawFont: 13,
  rawWrap: false,
  lineNumbers: true,
  tz: 'local',
};
export function preferences(value) {
  const p = value ?? {};
  return {
    theme: ['system', 'light', 'dark'].includes(p.theme) ? p.theme : defaults.theme,
    density: ['comfortable', 'compact'].includes(p.density)
      ? p.density
      : defaults.density,
    rawFont: [12, 13, 14, 15, 16].includes(p.rawFont) ? p.rawFont : defaults.rawFont,
    rawWrap: typeof p.rawWrap === 'boolean' ? p.rawWrap : false,
    lineNumbers: p.lineNumbers !== false,
    tz: p.tz === 'UTC' ? 'UTC' : 'local',
  };
}
export function pointer() {
  const p = read('kda.pointer');
  return p && typeof p.scan_id === 'string' && typeof p.server_instance_id === 'string'
    ? { scan_id: p.scan_id, server_instance_id: p.server_instance_id }
    : null;
}
