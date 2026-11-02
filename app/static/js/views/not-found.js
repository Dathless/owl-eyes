import { h, replace } from '../core/dom.js';
import { t } from '../core/i18n.js';
import { link } from '../components/ui.js';
export function mount(root) {
  return {
    update() {
      replace(root, h('h1', {}, t('notFound')), link(t('home'), '/'));
    },
    destroy() {},
  };
}
