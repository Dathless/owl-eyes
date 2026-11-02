(() => {
  let theme = 'system';
  try {
    const saved = JSON.parse(localStorage.getItem('kda.prefs'));
    if (['system', 'light', 'dark'].includes(saved?.theme)) theme = saved.theme;
  } catch {
    /* Preferences are optional. */
  }
  document.documentElement.dataset.pref = theme;
  document.documentElement.dataset.theme =
    theme === 'system'
      ? matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
      : theme;
})();
