const preference = matchMedia('(prefers-reduced-motion: reduce)');
let entry = null;

preference.addEventListener('change', () => {
  if (preference.matches) entry?.cancel();
});

// The caller enters a view only after navigation, never on a polling update.
export function enterView(root) {
  entry?.cancel();
  if (preference.matches) return;
  entry = root.animate(
    [{ opacity: 0.35, transform: 'translateY(6px)' },
      { opacity: 1, transform: 'translateY(0)' }],
    { duration: 220, easing: 'cubic-bezier(0.2, 0.7, 0.2, 1)' },
  );
}
