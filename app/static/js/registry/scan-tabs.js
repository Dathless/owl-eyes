import { ReportTab } from '../components/report-tab.js';
import { ObservationsTab } from '../components/observations-tab.js';
import { AttemptsTab } from '../components/attempts-tab.js';
import { RawTab } from '../components/raw-tab.js';
export const scanTabs = [
  { id: 'report', label: 'report', order: 10, render: ReportTab },
  { id: 'observations', label: 'observations', order: 20, render: ObservationsTab },
  { id: 'raw', label: 'raw', order: 30, render: RawTab },
  { id: 'attempts', label: 'attempts', order: 40, render: AttemptsTab },
];
export const scanActions = [];
