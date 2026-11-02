import { vi } from '../i18n/vi.js';
export const t = (key, vars = {}) =>
  (vi[key] ?? key).replace(/\{(\w+)\}/g, (_, k) => String(vars[k] ?? ''));
export const hasText = (key) => Object.hasOwn(vi, key);
