export const shortcuts = [
  { keys: 'g d / g s / g c', label: 'shortcut.nav' },
  {
    keys: 'n',
    label: 'shortcut.new',
    run: (ctx) => document.querySelector('[data-testid="start-btn"]')?.focus(),
  },
  {
    keys: '/',
    label: 'shortcut.search',
    run: (ctx) =>
      document
        .querySelector('[data-testid="raw-search"], [data-testid="observations-search"]')
        ?.focus(),
  },
  { keys: '[ / ]', label: 'shortcut.tabs' },
  { keys: 'Escape', label: 'shortcut.close', run: (ctx) => ctx.closeDrawer() },
  { keys: '?', label: 'shortcuts', run: (ctx) => ctx.openShortcuts() },
  {
    keys: 't',
    label: 'shortcut.theme',
    run: (ctx) => {
      const themes = ['system', 'light', 'dark'];
      ctx.setPrefs({
        theme: themes[(themes.indexOf(ctx.store.get().prefs.theme) + 1) % 3],
      });
    },
  },
];
