export const replaceSectionByID = (id, html) => {
  const current = document.getElementById(id);
  if (!current || typeof html !== 'string' || html.trim() === '') {
    return false;
  }
  if (current.outerHTML.trim() === html.trim()) {
    return false;
  }
  const wrapper = document.createElement('div');
  wrapper.innerHTML = html.trim();
  const next = wrapper.firstElementChild;
  if (!next) {
    return false;
  }
  current.replaceWith(next);
  return true;
};

export const parseFragmentRoot = (html) => {
  if (typeof html !== 'string' || html.trim() === '') {
    return null;
  }
  const wrapper = document.createElement('div');
  wrapper.innerHTML = html.trim();
  return wrapper.firstElementChild;
};

export const applySafeGroupOptionsHTML = (target, html) => {
  if (!(target instanceof Element) || typeof html !== 'string') {
    return false;
  }
  const parser = new DOMParser();
  const parsed = parser.parseFromString(`<select>${html}</select>`, 'text/html');
  const select = parsed.querySelector('select');
  if (!(select instanceof HTMLSelectElement)) {
    return false;
  }

  const fragment = document.createDocumentFragment();
  Array.from(select.children).forEach((node) => {
    if (node instanceof HTMLOptGroupElement) {
      const nextGroup = document.createElement('optgroup');
      nextGroup.label = node.label || '';
      if (node.disabled) {
        nextGroup.disabled = true;
      }
      Array.from(node.children).forEach((child) => {
        if (!(child instanceof HTMLOptionElement)) {
          return;
        }
        const option = document.createElement('option');
        option.value = child.value || '';
        option.textContent = child.textContent || '';
        option.disabled = child.disabled;
        option.selected = child.selected;
        nextGroup.appendChild(option);
      });
      fragment.appendChild(nextGroup);
      return;
    }

    if (node instanceof HTMLOptionElement) {
      const option = document.createElement('option');
      option.value = node.value || '';
      option.textContent = node.textContent || '';
      option.disabled = node.disabled;
      option.selected = node.selected;
      fragment.appendChild(option);
    }
  });

  target.replaceChildren(fragment);
  return true;
};

export const patchMonitorGrid = (currentGrid, nextGrid) => {
  if (!(currentGrid instanceof Element) || !(nextGrid instanceof Element)) {
    return false;
  }

  let changed = false;
  const currentCards = Array.from(currentGrid.querySelectorAll(':scope > .monitor-card'));
  const nextCards = Array.from(nextGrid.querySelectorAll(':scope > .monitor-card'));
  const currentByID = new Map(currentCards.map((card) => [card.dataset.monitorId || '', card]));
  const nextIDs = new Set(nextCards.map((card) => card.dataset.monitorId || ''));

  currentCards.forEach((card) => {
    const id = card.dataset.monitorId || '';
    if (!nextIDs.has(id)) {
      card.remove();
      changed = true;
    }
  });

  nextCards.forEach((nextCard, index) => {
    const id = nextCard.dataset.monitorId || '';
    if (!id) {
      return;
    }
    const current = currentByID.get(id);
    if (!current) {
      const currentOrdered = Array.from(currentGrid.querySelectorAll(':scope > .monitor-card'));
      const reference = currentOrdered[index] || null;
      currentGrid.insertBefore(nextCard.cloneNode(true), reference);
      changed = true;
      return;
    }

    if (current.outerHTML !== nextCard.outerHTML) {
      current.replaceWith(nextCard.cloneNode(true));
      changed = true;
    }

    const orderedAfter = Array.from(currentGrid.querySelectorAll(':scope > .monitor-card'));
    const currentNode = orderedAfter.find((node) => (node.dataset.monitorId || '') === id);
    if (!currentNode) {
      return;
    }
    if (orderedAfter[index] !== currentNode) {
      currentGrid.insertBefore(currentNode, orderedAfter[index] || null);
      changed = true;
    }
  });

  return changed;
};
