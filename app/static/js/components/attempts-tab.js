import { h } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { duration, timestamp } from '../core/format.js';
import { table, tr, stateBadge, errorBox, banner, empty } from './ui.js';
export function AttemptsTab(scan, ctx) {
  return h(
    'section',
    {},
    ...scan.warnings.map((x) => banner(x, 'warn')),
    scan.attempts.length
      ? table(
          [
            '#',
            t('providers'),
            'Model',
            t('state'),
            t('started'),
            t('duration'),
            t('notes'),
          ],
          scan.attempts.map((a) =>
            tr([
              a.attempt_no,
              a.provider_id,
              a.model,
              stateBadge(a.state),
              timestamp(a.started_at, ctx.store.get().prefs.tz),
              duration(a.duration_ms),
              errorBox(a.error),
            ]),
          ),
        )
      : empty(t('reportPending')),
  );
}
