// Motion system. Views re-render on every poll, so entrance motion runs only on
// navigation, and continuous status motion is phase-locked to the document
// timeline: a re-created node continues the same pulse instead of restarting.
// Every effect checks reduced motion at call time and becomes a no-op.
const preference = matchMedia('(prefers-reduced-motion: reduce)');
const reduced = () => preference.matches;
const running = new Set();
const EASE_OUT = 'cubic-bezier(0.16, 1, 0.3, 1)';

preference.addEventListener('change', () => {
  if (!reduced()) return;
  for (const animation of running) animation.cancel();
  running.clear();
  // Cancel rather than finish: status pulses are infinite and cannot finish.
  for (const animation of document.getAnimations?.() ?? []) animation.cancel();
});

function track(animation) {
  running.add(animation);
  animation.finished.then(() => running.delete(animation), () => running.delete(animation));
  return animation;
}

// The caller enters a view only after navigation, never on a polling update.
export function enterView(root) {
  for (const animation of running) animation.cancel();
  running.clear();
  if (reduced()) return;
  track(root.animate([{ opacity: 0.4 }, { opacity: 1 }], { duration: 240, easing: EASE_OUT }));
  const items = [...root.children].filter((node) => node.getClientRects().length);
  items.slice(0, 10).forEach((node, index) => {
    track(node.animate(
      [{ opacity: 0, transform: 'translateY(10px)' }, { opacity: 1, transform: 'translateY(0)' }],
      { duration: 320, delay: index * 45, easing: EASE_OUT, fill: 'backwards' },
    ));
  });
  // Cards inside grids get a short secondary wave.
  root.querySelectorAll('[data-stagger]').forEach((grid) => {
    [...grid.children].slice(0, 24).forEach((node, index) => {
      track(node.animate(
        [{ opacity: 0, transform: 'translateY(8px) scale(0.985)' },
          { opacity: 1, transform: 'translateY(0) scale(1)' }],
        { duration: 300, delay: 120 + index * 30, easing: EASE_OUT, fill: 'backwards' },
      ));
    });
  });
}

// A short reveal for a region that appears inside an existing view (tab panels).
export function reveal(node) {
  if (reduced() || !node?.animate) return;
  track(node.animate(
    [{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 1, transform: 'translateY(0)' }],
    { duration: 240, easing: EASE_OUT },
  ));
}

const PRESSABLE = [
  'button:not(:disabled)',
  '.c-btn',
  '#rail > a',
  '.v-settings-toc a',
  '.c-choices .c-choice',
  '.c-tool-choice',
  '[data-testid="active-chip"]',
  'details > summary',
].join(',');

// Pointer ripple: positioned by WAAPI transforms, so no inline style is needed.
function ripple(event) {
  if (reduced() || event.button !== 0) return;
  const host = event.target.closest(PRESSABLE);
  if (!host || host.closest('.c-tool-choice input:disabled')) return;
  if (host.matches('.c-tool-choice, .c-choices .c-choice') && host.querySelector('input:disabled'))
    return;
  const rect = host.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  const size = Math.hypot(Math.max(x, rect.width - x), Math.max(y, rect.height - y)) / 8;
  const dot = document.createElement('span');
  dot.className = 'c-ripple';
  dot.setAttribute('aria-hidden', 'true');
  host.append(dot);
  const animation = dot.animate(
    [
      { transform: `translate(${x}px, ${y}px) scale(0)`, opacity: 1 },
      { transform: `translate(${x}px, ${y}px) scale(${size})`, opacity: 0 },
    ],
    { duration: 520, easing: 'cubic-bezier(0.2, 0.6, 0.3, 1)' },
  );
  animation.finished.then(() => dot.remove(), () => dot.remove());
}
document.addEventListener('pointerdown', ripple, { passive: true });

// Status pulses share one clock, so a node re-created by polling keeps its phase.
export function syncPulses(scope = document) {
  if (reduced()) return;
  for (const dot of scope.querySelectorAll('.c-live-dot')) {
    if (dot.getAnimations().length) continue;
    const animation = dot.animate(
      [
        { opacity: 1, boxShadow: '0 0 0 0 currentColor' },
        { opacity: 0.55, boxShadow: '0 0 0 5px transparent' },
        { opacity: 1, boxShadow: '0 0 0 0 transparent' },
      ],
      { duration: 1600, iterations: Infinity, easing: 'ease-out' },
    );
    animation.startTime = 0;
  }
}

// Tab indicator: remembers the last position per tab list and slides to the new one.
const indicatorPositions = new Map();
export function slideTabs(scope = document) {
  for (const list of scope.querySelectorAll('.c-tabs')) {
    const selected = list.querySelector('[aria-selected="true"]');
    let bar = list.querySelector(':scope > .c-tabs-indicator');
    if (!selected) {
      bar?.remove();
      continue;
    }
    if (!bar) {
      bar = document.createElement('span');
      bar.className = 'c-tabs-indicator';
      bar.setAttribute('aria-hidden', 'true');
      list.append(bar);
    }
    const left = selected.offsetLeft;
    const width = Math.max(1, selected.offsetWidth);
    const key = list.getAttribute('aria-label') ?? '';
    const previous = indicatorPositions.get(key);
    indicatorPositions.set(key, { left, width });
    const to = { transform: `translateX(${left}px) scaleX(${width})` };
    const from = previous
      ? { transform: `translateX(${previous.left}px) scaleX(${previous.width})` }
      : to;
    const moved = previous && (previous.left !== left || previous.width !== width);
    bar.getAnimations().forEach((animation) => animation.cancel());
    bar.animate([from, to], {
      duration: moved && !reduced() ? 300 : 0,
      easing: EASE_OUT,
      fill: 'forwards',
    });
  }
}

// <details>: animate only toggles the user caused, never re-rendered open state.
const userToggled = new WeakSet();
document.addEventListener('click', (event) => {
  const summary = event.target.closest('summary');
  if (summary?.parentElement?.tagName === 'DETAILS') userToggled.add(summary.parentElement);
}, true);
document.addEventListener('toggle', (event) => {
  const details = event.target;
  if (!(details instanceof HTMLDetailsElement) || !userToggled.has(details)) return;
  userToggled.delete(details);
  if (!details.open || reduced()) return;
  [...details.children]
    .filter((node) => node.tagName !== 'SUMMARY')
    .forEach((node, index) => track(node.animate(
      [{ opacity: 0, transform: 'translateY(-4px)' }, { opacity: 1, transform: 'translateY(0)' }],
      { duration: 220, delay: index * 25, easing: EASE_OUT, fill: 'backwards' },
    )));
}, true);

// Theme changes cross-fade through the View Transitions API when available.
export function transition(update) {
  if (reduced() || typeof document.startViewTransition !== 'function') {
    update();
    return;
  }
  document.startViewTransition(update);
}

export function dismiss(node, done = () => node.remove()) {
  if (reduced() || !node.isConnected) {
    done();
    return;
  }
  node.animate(
    [{ opacity: 1, transform: 'translateY(0)' }, { opacity: 0, transform: 'translateY(8px)' }],
    { duration: 180, easing: 'ease-in' },
  ).finished.then(done, done);
}

export const prefersReducedMotion = reduced;
