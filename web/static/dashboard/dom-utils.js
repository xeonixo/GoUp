import { tablePageSize } from './config.js';
import { tr } from './i18n.js';

export const bindOnce = (element, key, listener) => {
  if (!(element instanceof Element)) {
    return;
  }
  const attr = `bound${key}`;
  if (element.dataset[attr] === '1') {
    return;
  }
  element.dataset[attr] = '1';
  element.addEventListener('click', listener);
};

const clearChildren = (element) => {
  if (!(element instanceof Element)) {
    return;
  }
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
};

export const closeActionMenus = (except = null) => {
  document.querySelectorAll('.action-menu').forEach((menu) => {
    if (menu !== except) {
      menu.removeAttribute('open');
    }
  });
};

export const hasOpenDialog = () => Array.from(document.querySelectorAll('dialog')).some((dialogElement) => dialogElement.open);

export const bindDialogBackdropClose = (dialogElement) => {
  if (!(dialogElement instanceof HTMLDialogElement) || dialogElement.dataset.boundBackdropClose === '1') {
    return;
  }
  dialogElement.dataset.boundBackdropClose = '1';
  dialogElement.addEventListener('click', (event) => {
    if (event.target === dialogElement) {
      dialogElement.close();
    }
  });
};

export const renderTablePagination = (container, currentPage, pageCount, totalItems, onPageChange) => {
  if (!(container instanceof HTMLElement)) {
    return;
  }

  clearChildren(container);
  if (totalItems <= tablePageSize || pageCount <= 1) {
    container.hidden = true;
    return;
  }

  container.hidden = false;

  const summary = document.createElement('div');
  summary.className = 'table-pagination-summary';
  summary.textContent = tr('paginationSummary', 'Page {current} of {totalPages} · {totalItems} entries', {
    current: currentPage,
    totalPages: pageCount,
    totalItems
  });

  const actions = document.createElement('div');
  actions.className = 'table-pagination-actions';

  const prev = document.createElement('button');
  prev.className = 'button button-secondary button-small';
  prev.type = 'button';
  prev.textContent = tr('paginationPrev', '← Previous');
  prev.disabled = currentPage <= 1;
  prev.addEventListener('click', () => {
    if (currentPage > 1) {
      onPageChange(currentPage - 1);
    }
  });

  const next = document.createElement('button');
  next.className = 'button button-secondary button-small';
  next.type = 'button';
  next.textContent = tr('paginationNext', 'Next →');
  next.disabled = currentPage >= pageCount;
  next.addEventListener('click', () => {
    if (currentPage < pageCount) {
      onPageChange(currentPage + 1);
    }
  });

  actions.appendChild(prev);
  actions.appendChild(next);
  container.appendChild(summary);
  container.appendChild(actions);
};
