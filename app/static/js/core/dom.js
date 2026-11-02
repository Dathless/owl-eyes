export function h(tag, props = {}, ...children) {
  const svg = ['svg', 'use'].includes(tag);
  const node = svg
    ? document.createElementNS('http://www.w3.org/2000/svg', tag)
    : document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value == null || value === false) continue;
    if (key === 'class') node.setAttribute('class', value);
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key.startsWith('on') && typeof value === 'function')
      node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (
      ['value', 'checked', 'disabled', 'hidden', 'open', 'selected', 'tabIndex'].includes(
        key,
      )
    )
      node[key] = value;
    else if (
      [
        'id',
        'type',
        'name',
        'title',
        'role',
        'placeholder',
        'autocomplete',
        'min',
        'max',
        'step',
        'for',
        'href',
        'scope',
        'colspan',
        'viewBox',
      ].includes(key) ||
      key.startsWith('aria-')
    ) {
      if (
        key === 'href' &&
        !value.startsWith('#') &&
        !(tag === 'use' && value.startsWith('/static/icons.svg#'))
      )
        throw Error('Internal links only');
      node.setAttribute(key, String(value));
    } else throw Error(`Unsupported DOM property: ${key}`);
  }
  for (const child of children.flat(Infinity)) {
    if (child != null && child !== false)
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
export function replace(root, ...nodes) {
  const focused = root.contains(document.activeElement)
    ? document.activeElement.dataset.testid
    : null;
  root.replaceChildren(...nodes.flat().filter(Boolean));
  if (focused)
    root
      .querySelector(`[data-testid="${CSS.escape(focused)}"]`)
      ?.focus({ preventScroll: true });
}
export const test = (testid) => ({ testid });
