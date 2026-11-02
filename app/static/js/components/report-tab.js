import { h, test } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { timestamp, duration, collectionElapsed } from '../core/format.js';
import { severities } from '../registry/enums.js';
import { defaultToolRenderer, toolRenderers } from '../registry/tool-renderers.js';
import {
  banner,
  empty,
  errorBox,
  stateBadge,
  severity,
  scope,
  evidenceChip,
  table,
  tr,
  pager,
  button,
  kv,
} from './ui.js';
export function ReportTab(scan, ctx, pages = {}) {
  const heading = (n, label) => h('h2', { class: 'v-report-section-title' },
    h('span', { class: 'v-report-section-number' }, String(n).padStart(2, '0')), label);
  const tools = Object.values(scan.tools);
  const allEvidence = new Map(tools.flatMap((tool) => tool.evidence).map((e) => [e.id, e]));
  const envelope = scan.report;
  const report = envelope?.report;
  const latestError = [...scan.attempts].reverse().find((x) => x.error)?.error;
  const warnings = [
    ...scan.warnings,
    ...Object.values(scan.tools).flatMap((x) => x.warnings),
  ];
  const limited =
    scan.partial ||
    warnings.length ||
    Object.values(scan.tools).some(
      (x) =>
        ['failed', 'timed_out', 'output_limited', 'cancelled'].includes(x.state) ||
        x.parse_status === 'failed',
    ) ||
    scan.target.auth_mode === 'public_only_login_required';
  const top = [];
  if (scan.state === 'analysis_failed')
    top.push(
      banner(t('analysisFailed'), 'err', 'analysis-failed'),
      errorBox(latestError),
    );
  if (scan.state === 'collection_failed')
    top.push(empty(t('collectionFailed')), errorBox(scan.failure));
  if (scan.state === 'cancelled') top.push(empty(t('cancelled')));
  if (!report)
    return h(
      'div',
      { class: 'v-report' },
      ...top,
      !['cancelled', 'collection_failed', 'analysis_failed'].includes(scan.state)
        ? empty(t('reportPending'))
        : null,
    );
  const stale = ['analyzing', 'analysis_failed', 'cancelling', 'cancelled'].includes(
    scan.state,
  );
  const coverage = h(
    'details',
    { open: !!limited, id: 'coverage' },
    h('summary', {}, t('coverage')),
    table(
      [t('tools'), t('state'), 'Parse', t('duration'), t('notes'), 'Evidence'],
      Object.values(scan.tools).map((tool) =>
        tr(
          [
            tool.tool_id,
            stateBadge(tool.state),
            tool.parse_status,
            duration(tool.duration_ms),
            h(
              'div',
              {},
              (toolRenderers[tool.tool_id] ?? defaultToolRenderer).summary(tool),
              ...tool.warnings.map((w) => h('p', {}, w)),
              errorBox(tool.error),
            ),
            tool.evidence.map((ev) => evidenceChip(ev.id, ctx)),
          ],
          `coverage-row-${tool.tool_id}`,
        ),
      ),
    ),

  );
  function findingSection(items, outside) {
    const key = outside ? 'other' : 'main';
    const page = Math.min(pages[key] ?? 0, Math.max(0, Math.ceil(items.length / 15) - 1));
    const ordered = [...items].sort((a, b) => {
      const rank = (x) =>
        severities.includes(x) ? severities.indexOf(x) : severities.length;
      return rank(a.severity) - rank(b.severity);
    });
    pages.expanded ??= {};
    const referenced = ctx.route.query.get('finding');
    const referenceIndex = ordered.findIndex((f) => f.id === referenced);
    const visiblePage = referenceIndex >= 0 ? Math.floor(referenceIndex / 15) : page;
    const rows = [];
    for (const f of ordered.slice(visiblePage * 15, visiblePage * 15 + 15)) {
      const expanded = pages.expanded[f.id] ?? referenced === f.id;
      const row = tr(
        [
          severity(f.severity),
          button(
            `F${String(ordered.findIndex((item) => item.id === f.id) + 1).padStart(2, '0')} · ${f.title}`,
            () => {
              pages.expanded[f.id] = !expanded;
              ctx.refreshView();
            },
            `finding-toggle-${f.id}`,
            {
              'aria-expanded': String(!!expanded),
              'aria-controls': `finding-detail-${f.id}`,
            },
          ),
          badgeAssessment(f.assessment),
          scope(f.scope),
          h(
            'span',
            {},
            ...f.evidence_ids.slice(0, 2).map((id) => evidenceChip(id, ctx)),
            f.evidence_ids.length > 2 ? `+${f.evidence_ids.length - 2}` : '',
          ),
        ],
        `finding-row-${f.id}`,
      );
      row.children[3].classList.add('finding-scope');
      rows.push(row);
      if (expanded)
        rows.push(
          h(
            'tr',
            {},
            h(
              'td',
              { colspan: 5 },
              h(
                'div',
                {
                  class: 'v-finding-detail',
                  id: `finding-detail-${f.id}`,
                  dataset: test(`finding-detail-${f.id}`),
                },
                scope(f.scope),
                ...['description', 'impact', 'recommendation'].map((key) =>
                  h(
                    'section',
                    {},
                    h('h3', {}, t(key)),
                    h('p', { class: 'prose' }, f[key]),
                  ),
                ),
                ...f.evidence_ids.map((id) => evidenceChip(id, ctx)),
                button(t('viewRaw'), () => ctx.evidenceRaw(f.evidence_ids[0])),
              ),
            ),
          ),
        );
    }
    const findings = table(
      [t('risk'), t('title'), t('assessment'), t('scope'), 'Evidence'],
      rows,
      t('findings'),
    );
    findings.querySelectorAll('th')[0].setAttribute('aria-sort', 'descending');
    findings.querySelectorAll('th')[3].classList.add('finding-scope');
    return h(
      'section',
      { dataset: outside ? test('other-path-section') : {} },
      h('h2', {}, t(outside ? 'otherPath' : 'findings'), ` (${items.length})`),
      outside ? banner(t('otherNote'), 'warn') : null,
      findings,
      items.length > 15
        ? pager(visiblePage, Math.ceil(items.length / 15), (p) => {
            pages[key] = p;
            ctx.refreshView();
          })
        : null,
    );
  }
  const main = report.findings.filter((f) => f.scope !== 'other_path');
  const other = report.findings.filter((f) => f.scope === 'other_path');
  const rank = (f) => severities.includes(f.severity) ? severities.indexOf(f.severity) : severities.length;
  const ordered = [...main].sort((a, b) => rank(a) - rank(b))
    .concat([...other].sort((a, b) => rank(a) - rank(b)));
  const citations = [...new Set(ordered.flatMap((f) => f.evidence_ids))];
  return h(
    'article', { class: 'v-report', dataset: test('report') },
    ...top,
    h('header', { class: 'v-report-cover', dataset: test('report-header') },
      h('p', { class: 'v-report-kicker' }, 'PENCHECKER / SECURITY ASSESSMENT'),
      h('h2', { dataset: test('report-document-title') }, t('reportDocumentTitle')),
      h('p', {}, stale ? `${t('stale')}: ` : '', t('reportEdition', { revision: envelope.revision })),
      kv([
        [t('reportReference'), scan.scan_id], [t('target'), scan.target.url],
        [t('reportAuthor'), `${envelope.provider_id} / ${envelope.model}`],
        [t('reportCreated'), timestamp(envelope.generated_at, ctx.store.get().prefs.tz)],
      ]),
    ),
    scan.state === 'analyzing' ? banner(t('retrying')) : null,
    stale ? banner(t('reportPreviousNote'), 'warn') : null,
    limited ? h('div', { dataset: test('report-limits-banner') },
      banner(`${t('partial')}. ${t('authNote')}`, 'warn')) : null,
    h('section', { class: 'v-report-executive' },
      heading(1, t('reportExecutive')),
      h('dl', { class: 'v-report-metrics' },
        h('div', {}, h('dt', {}, t('risk')), h('dd', { dataset: test('report-risk') }, severity(report.overall_risk))),
        h('div', {}, h('dt', {}, t('reportFindingCount')), h('dd', {}, String(report.findings.length))),
        h('div', {}, h('dt', {}, t('reportEvidenceCount')), h('dd', {}, String(allEvidence.size))),
      ),
      h('p', { class: 'prose' }, t('reportResultOverview', { tools: tools.length, findings: main.length, other: other.length })),
      report.overall_risk === 'unknown' ? h('p', {}, t('riskUnknown')) : null,
      h('h3', {}, t('reportAIAnalysis')),
      h('p', { class: 'meta' }, t('reportAISnapshotNote')),
      h('p', { class: 'prose v-report-analysis', dataset: test('report-summary') }, report.summary),
      h('small', {}, t('aiNote')),
    ),
    h('section', { dataset: test('report-scope') },
      heading(2, t('reportScope')),
      kv([[t('target'), scan.target.url], ['IP', scan.target.ip],
        [t('started'), timestamp(scan.created_at, ctx.store.get().prefs.tz)],
        [t('scanDuration'), collectionElapsed(scan)],
        ['Auth / security', `${scan.target.auth_mode} / ${scan.target.security_level}`]]),
      h('p', { class: 'prose' }, t('authNote')),
      h('ul', { class: 'v-report-methods' }, ...tools.map((tool) => h('li', {},
        h('strong', {}, `${tool.tool_id}: `), t(`reportMethod_${tool.tool_id}`)))),
    ),
    h('section', {}, heading(3, t('reportCollection')), coverage,
      h('div', { class: 'v-report-severity-counts' }, ...severities.map((v) =>
        h('span', {}, severity(v), ' ', String(report.findings.filter((f) => f.severity === v).length)))),
    ),
    h('section', {}, heading(4, t('reportDetailedFindings')),
      main.length ? findingSection(main, false) : empty(t('noFindings')),
      other.length ? findingSection(other, true) : null,
      h('p', { class: 'meta' }, t('observedNote')),
    ),
    h('section', { dataset: test('report-remediation') },
      heading(5, t('reportRemediation')), h('p', { class: 'prose' }, t('reportPriorityNote')),
      ordered.length ? h('ol', { class: 'v-report-remediation' }, ...ordered.map((f, i) =>
        h('li', {}, h('h3', {}, `F${String(i + 1).padStart(2, '0')} · `, f.title),
          severity(f.severity), ' ', scope(f.scope),
          h('p', { class: 'prose' }, f.recommendation || t('unknownField')))))
        : h('p', { class: 'prose' }, t('reportNoRemediation')),
    ),
    h('section', { dataset: test('report-observations') },
      heading(6, t('reportTechnical')), h('p', { class: 'prose' }, t('reportObservationNote')),
      ...tools.map((tool) => h('details', { class: 'v-report-technical' },
        h('summary', {}, `${tool.tool_id} · ${tool.observations.length} ${t('observations')}`),
        ...tool.observations.map((o) => h('article', { class: 'v-report-observation' },
          h('h3', {}, o.subject), scope(o.scope), h('span', { class: 'meta' }, ` ${o.kind}`),
          h('pre', { class: 'v-report-observation-value' }, JSON.stringify(o.value, null, 2)),
          ...o.evidence_ids.map((id) => evidenceChip(id, ctx)))),
        !tool.observations.length ? h('p', {}, t('reportNoObservations')) : null)),
    ),
    h('section', {}, heading(7, t('reportLimitations')),
      h('ul', { class: 'v-report-limitations' }, ...[...new Set([
        ...report.limitations, ...scan.warnings,
        ...tools.flatMap((tool) => tool.warnings.map((w) => `${tool.tool_id}: ${w}`)),
      ])].map((x) => h('li', {}, x))),
      h('p', { class: 'prose' }, t('reportReviewNote')),
    ),
    h('section', { dataset: test('report-evidence-appendix') },
      heading(8, t('reportAppendix')),
      citations.length ? citations.map((id, i) => {
        const e = allEvidence.get(id);
        return h('details', { class: 'v-report-evidence' },
          h('summary', {}, `E${String(i + 1).padStart(3, '0')} · ${id}`),
          e ? h('div', {}, h('p', {}, `${e.tool_id} / ${e.source} / ${e.locator}`),
            h('pre', { class: 'v-report-observation-value' }, e.excerpt), evidenceChip(id, ctx))
            : h('p', {}, t('reportEvidenceMissing')));
      }) : h('p', {}, t('reportNoCitations')),
    ),
    h('footer', { class: 'v-report-footer' }, t('reportFooter')),
  );
}

function badgeAssessment(value) {
  return h(
    'span',
    { class: 'c-badge' },
    ['observed', 'suspected'].includes(value) ? t(value) : value,
  );
}
