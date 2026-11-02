export const routes = [
  { id: 'dashboard', pattern: /^\/$/, view: () => import('../views/dashboard.js') },
  {
    id: 'scan',
    pattern: /^\/scans\/([^/]+)(?:\/([^/]+))?\/?$/,
    keys: ['id', 'tab'],
    view: () => import('../views/scan.js'),
  },
  { id: 'scan', pattern: /^\/scan\/?$/, view: () => import('../views/scan.js') },
  {
    id: 'settings',
    pattern: /^\/settings(?:\/([^/]+))?\/?$/,
    keys: ['group'],
    view: () => import('../views/settings.js'),
  },
];
