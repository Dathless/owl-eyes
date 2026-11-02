export const settingsGroups = [
  { id: 'appearance', label: 'appearance', order: 10 },
  {
    id: 'target',
    label: 'target',
    order: 20,
    fromCaps: (c) =>
      Object.entries(c.target).map(([key, value]) => ({
        key,
        label: key,
        value,
        source: 'derived',
      })),
  },
  { id: 'providers', label: 'providers', order: 30, fromCaps: (c) => c.providers },
  { id: 'tools', label: 'tools', order: 40, fromCaps: (c) => c.tools },
  {
    id: 'limits',
    label: 'limits',
    order: 50,
    fromCaps: (c) =>
      Object.entries(c.limits ?? {}).map(([key, value]) => ({
        key,
        label: key,
        value,
        source: 'derived',
      })),
  },
  {
    id: 'server',
    label: 'server',
    order: 60,
    fromCaps: (c) =>
      ['app_version', 'schema_version', 'server_instance_id'].map((key) => ({
        key,
        label: key,
        value: c[key],
        source: 'derived',
      })),
  },
];
