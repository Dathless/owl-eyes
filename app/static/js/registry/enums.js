export const severities = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
export const glyphs = {
  queued: '○',
  collecting: '◐',
  analyzing: '◐',
  cancelling: '■',
  completed: '✓',
  analysis_failed: '✕',
  collection_failed: '✕',
  cancelled: '■',
  running: '◐',
  succeeded: '●',
  failed: '✕',
  timed_out: '▲',
  output_limited: '▲',
  skipped: '–',
  critical: '◆◆',
  high: '▲',
  medium: '■',
  low: '●',
  info: '○',
  unknown: '?',
};
export const tones = {
  collecting: 'accent',
  analyzing: 'accent',
  running: 'accent',
  succeeded: 'ok',
  failed: 'err',
  analysis_failed: 'err',
  collection_failed: 'err',
  timed_out: 'warn',
  output_limited: 'warn',
  cancelling: 'warn',
};
export const scopes = {
  dvwa_path: '/dvwa',
  http_origin: 'origin',
  host_service: 'host',
  other_path: 'ngoài /dvwa',
  unknown: 'chưa rõ',
};
const warned = new Set();
export function enumGlyph(value) {
  if (!Object.hasOwn(glyphs, value) && !warned.has(value)) {
    warned.add(value);
    console.warn('Unknown enum:', value);
  }
  return glyphs[value] ?? '–';
}
export function scanSteps(scan) {
  const index = { queued: 0, collecting: 1, analyzing: 2 }[scan.state];
  if (index !== undefined)
    return Array.from({ length: 4 }, (_, i) =>
      i < index ? '✓' : i === index ? '◐' : '○',
    );
  const terminal = {
    completed: ['✓', '✓', '✓', '✓'],
    analysis_failed: ['✓', '✓', '✕', '✕'],
    collection_failed: ['✓', '✕', '–', '✕'],
  };
  if (terminal[scan.state]) return terminal[scan.state];
  if (['cancelling', 'cancelled'].includes(scan.state)) {
    const stage = scan.attempts.length
      ? 2
      : Object.values(scan.tools).some((t) => t.started_at)
        ? 1
        : 0;
    return Array.from({ length: 4 }, (_, i) =>
      i === 3
        ? '■'
        : i < stage
          ? '✓'
          : i === stage
            ? scan.state === 'cancelling'
              ? '◐'
              : '✕'
            : '–',
    );
  }
  return ['–', '–', '–', '–'];
}
export const parseLabels = {
  pending: 'chờ',
  succeeded: 'parse ok',
  failed: 'parse lỗi',
  not_applicable: 'n/a',
};
