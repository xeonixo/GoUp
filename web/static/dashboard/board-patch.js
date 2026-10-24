import { parseFragmentRoot, patchMonitorGrid, replaceSectionByID } from './dom-patch.js';

const patchServiceCluster = (currentCluster, nextCluster) => {
  if (!(currentCluster instanceof Element) || !(nextCluster instanceof Element)) {
    return false;
  }

  const wasOpen = currentCluster.open;
  let changed = false;

  const currentSummary = currentCluster.querySelector(':scope > .service-cluster-header');
  const nextSummary = nextCluster.querySelector(':scope > .service-cluster-header');
  if (currentSummary && nextSummary) {
    const patchAttr = (currentElement, nextElement, attributeName) => {
      const currentValue = currentElement.getAttribute(attributeName) || '';
      const nextValue = nextElement.getAttribute(attributeName) || '';
      if (currentValue !== nextValue) {
        if (nextValue === '') {
          currentElement.removeAttribute(attributeName);
        } else {
          currentElement.setAttribute(attributeName, nextValue);
        }
        return true;
      }
      return false;
    };

    const currentCount = currentSummary.querySelector('.service-summary-right .service-count');
    const nextCount = nextSummary.querySelector('.service-summary-right .service-count');
    if (currentCount && nextCount) {
      if (currentCount.textContent !== nextCount.textContent) {
        currentCount.textContent = nextCount.textContent;
        changed = true;
      }
      if (patchAttr(currentCount, nextCount, 'aria-label')) {
        changed = true;
      }
    }

    const currentStatus = currentSummary.querySelector('.service-summary-right .status-pill');
    const nextStatus = nextSummary.querySelector('.service-summary-right .status-pill');
    if (currentStatus && nextStatus) {
      if (currentStatus.textContent !== nextStatus.textContent) {
        currentStatus.textContent = nextStatus.textContent;
        changed = true;
      }
      if (currentStatus.className !== nextStatus.className) {
        currentStatus.className = nextStatus.className;
        changed = true;
      }
    }

    const currentSettings = currentSummary.querySelector('.group-settings');
    const nextSettings = nextSummary.querySelector('.group-settings');
    if (currentSettings && nextSettings) {
      if (patchAttr(currentSettings, nextSettings, 'data-icon-slug')) {
        changed = true;
      }
    }

    const currentTitle = currentSummary.querySelector('.service-cluster-title h4');
    const nextTitle = nextSummary.querySelector('.service-cluster-title h4');
    if (currentTitle && nextTitle && currentTitle.textContent !== nextTitle.textContent) {
      currentTitle.textContent = nextTitle.textContent;
      changed = true;
    }

    const currentIcon = currentSummary.querySelector('.service-cluster-title .group-icon');
    const nextIcon = nextSummary.querySelector('.service-cluster-title .group-icon');
    const currentTitleWrapper = currentSummary.querySelector('.service-cluster-title');
    if (currentIcon && nextIcon) {
      if (currentIcon.getAttribute('src') !== nextIcon.getAttribute('src')) {
        currentIcon.setAttribute('src', nextIcon.getAttribute('src') || '');
        changed = true;
      }
      if (currentIcon.getAttribute('alt') !== nextIcon.getAttribute('alt')) {
        currentIcon.setAttribute('alt', nextIcon.getAttribute('alt') || '');
        changed = true;
      }
    } else if (!currentIcon && nextIcon && currentTitleWrapper) {
      currentTitleWrapper.insertBefore(nextIcon.cloneNode(true), currentTitleWrapper.firstChild || null);
      changed = true;
    } else if (currentIcon && !nextIcon) {
      currentIcon.remove();
      changed = true;
    }

    const currentTrendTrigger = currentSummary.querySelector('.service-summary-trend');
    const nextTrendTrigger = nextSummary.querySelector('.service-summary-trend');
    if (currentTrendTrigger && nextTrendTrigger) {
      ['data-monitor-name', 'data-monitor-kind', 'data-target', 'data-status', 'data-uptime', 'data-trend-label', 'data-last-check', 'data-last-message', 'data-executor', 'aria-label'].forEach((attributeName) => {
        if (patchAttr(currentTrendTrigger, nextTrendTrigger, attributeName)) {
          changed = true;
        }
      });

      const currentTrendBars = currentTrendTrigger.querySelector('.trend-bars');
      const nextTrendBars = nextTrendTrigger.querySelector('.trend-bars');
      if (currentTrendBars && nextTrendBars && currentTrendBars.innerHTML !== nextTrendBars.innerHTML) {
        currentTrendBars.innerHTML = nextTrendBars.innerHTML;
        changed = true;
      }
    } else if (!currentTrendTrigger && nextTrendTrigger) {
      const summaryBody = currentSummary.querySelector('.service-summary');
      if (summaryBody) {
        summaryBody.appendChild(nextTrendTrigger.cloneNode(true));
        changed = true;
      }
    } else if (currentTrendTrigger && !nextTrendTrigger) {
      currentTrendTrigger.remove();
      changed = true;
    }

    const currentMuted = currentSummary.querySelector('.service-summary > p.muted.compact');
    const nextMuted = nextSummary.querySelector('.service-summary > p.muted.compact');
    if (currentMuted && nextMuted) {
      if (currentMuted.textContent !== nextMuted.textContent) {
        currentMuted.textContent = nextMuted.textContent;
        changed = true;
      }
    } else if (!currentMuted && nextMuted) {
      const summaryBody = currentSummary.querySelector('.service-summary');
      if (summaryBody) {
        summaryBody.appendChild(nextMuted.cloneNode(true));
        changed = true;
      }
    } else if (currentMuted && !nextMuted) {
      currentMuted.remove();
      changed = true;
    }
  } else if (currentSummary?.innerHTML !== nextSummary?.innerHTML) {
    if (currentSummary && nextSummary) {
      currentSummary.innerHTML = nextSummary.innerHTML;
      changed = true;
    }
  }

  const currentGrid = currentCluster.querySelector(':scope > .monitor-grid');
  const nextGrid = nextCluster.querySelector(':scope > .monitor-grid');
  if (currentGrid && nextGrid) {
    if (patchMonitorGrid(currentGrid, nextGrid)) {
      changed = true;
    }
  } else if (currentCluster.outerHTML !== nextCluster.outerHTML) {
    currentCluster.replaceWith(nextCluster.cloneNode(true));
    return true;
  }

  currentCluster.open = wasOpen;
  return changed;
};

export const patchBoardSection = (html) => {
  const currentBoard = document.getElementById('dashboard-live-board');
  const nextBoard = parseFragmentRoot(html);
  if (!(currentBoard instanceof Element) || !(nextBoard instanceof Element)) {
    return false;
  }

  const currentList = currentBoard.querySelector('.service-group-list');
  const nextList = nextBoard.querySelector('.service-group-list');
  if (!(currentList instanceof Element) || !(nextList instanceof Element)) {
    return replaceSectionByID('dashboard-live-board', html);
  }

  let changed = false;
  const currentClusters = Array.from(currentList.querySelectorAll(':scope > .service-cluster'));
  const nextClusters = Array.from(nextList.querySelectorAll(':scope > .service-cluster'));
  const currentByGroup = new Map(currentClusters.map((cluster) => [cluster.dataset.group || '', cluster]));
  const nextGroups = new Set(nextClusters.map((cluster) => cluster.dataset.group || ''));

  currentClusters.forEach((cluster) => {
    const key = cluster.dataset.group || '';
    if (!nextGroups.has(key)) {
      cluster.remove();
      changed = true;
    }
  });

  nextClusters.forEach((nextCluster, index) => {
    const key = nextCluster.dataset.group || '';
    if (!key) {
      return;
    }
    const currentCluster = currentByGroup.get(key);
    if (!currentCluster) {
      const ordered = Array.from(currentList.querySelectorAll(':scope > .service-cluster'));
      const reference = ordered[index] || null;
      currentList.insertBefore(nextCluster.cloneNode(true), reference);
      changed = true;
      return;
    }

    if (patchServiceCluster(currentCluster, nextCluster)) {
      changed = true;
    }

    const orderedAfter = Array.from(currentList.querySelectorAll(':scope > .service-cluster'));
    const currentNode = orderedAfter.find((node) => (node.dataset.group || '') === key);
    if (!currentNode) {
      return;
    }
    if (orderedAfter[index] !== currentNode) {
      currentList.insertBefore(currentNode, orderedAfter[index] || null);
      changed = true;
    }
  });

  const currentBoardClasses = currentBoard.className || '';
  const nextBoardClasses = nextBoard.className || '';
  if (currentBoardClasses !== nextBoardClasses) {
    currentBoard.className = nextBoardClasses;
    changed = true;
  }

  return changed;
};

export const patchBoardGroups = (groupsHTML) => {
  if (!groupsHTML || typeof groupsHTML !== 'object' || Array.isArray(groupsHTML)) {
    return false;
  }

  const currentBoard = document.getElementById('dashboard-live-board');
  if (!(currentBoard instanceof Element)) {
    return false;
  }
  const currentList = currentBoard.querySelector('.service-group-list');
  if (!(currentList instanceof Element)) {
    return false;
  }

  let changed = false;
  Object.entries(groupsHTML).forEach(([groupName, html]) => {
    if (typeof groupName !== 'string' || groupName.trim() === '') {
      return;
    }
    const nextCluster = parseFragmentRoot(html);
    if (!(nextCluster instanceof Element)) {
      return;
    }

    const currentCluster = Array.from(currentList.querySelectorAll(':scope > .service-cluster'))
      .find((cluster) => (cluster.dataset.group || '') === groupName);

    if (!currentCluster) {
      currentList.appendChild(nextCluster.cloneNode(true));
      changed = true;
      return;
    }

    if (patchServiceCluster(currentCluster, nextCluster)) {
      changed = true;
    }
  });

  return changed;
};
