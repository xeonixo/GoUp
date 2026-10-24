import { appBase, dashboardStateOwner } from './config.js';

const dashboardStateScope = `${appBase || '/'}:${dashboardStateOwner}:${window.location.pathname}`;
const dashboardStateScrollKey = `goup.dashboard.scrollY:${dashboardStateScope}`;
const dashboardStateGroupsKey = `goup.dashboard.openGroups:${dashboardStateScope}`;

export const currentOpenGroups = () => Array.from(document.querySelectorAll('.service-cluster[open]'))
  .map((element) => element.dataset.group || '')
  .filter(Boolean);

export const restoreOpenGroups = (groups) => {
  if (!Array.isArray(groups) || groups.length === 0) {
    return;
  }
  document.querySelectorAll('.service-cluster').forEach((cluster) => {
    const group = cluster.dataset.group || '';
    if (groups.includes(group)) {
      cluster.open = true;
    }
  });
};

export const currentOpenActionMenus = () => {
  const keys = [];
  document.querySelectorAll('.action-menu[open]').forEach((menu) => {
    const monitorCard = menu.closest('.monitor-card');
    if (monitorCard instanceof HTMLElement) {
      const monitorID = (monitorCard.dataset.monitorId || '').trim();
      if (monitorID) {
        keys.push(`monitor:${monitorID}`);
        return;
      }
    }

    const serviceCluster = menu.closest('.service-cluster');
    if (serviceCluster instanceof HTMLElement) {
      const groupName = (serviceCluster.dataset.group || '').trim();
      if (groupName) {
        keys.push(`group:${groupName}`);
      }
    }
  });
  return keys;
};

export const restoreOpenActionMenus = (keys) => {
  if (!Array.isArray(keys) || keys.length === 0) {
    return;
  }

  keys.forEach((key) => {
    if (typeof key !== 'string' || key.trim() === '') {
      return;
    }

    if (key.startsWith('monitor:')) {
      const monitorID = key.slice('monitor:'.length);
      if (!monitorID) {
        return;
      }
      const monitorCard = Array.from(document.querySelectorAll('.monitor-card'))
        .find((node) => (node.dataset.monitorId || '') === monitorID);
      const menu = monitorCard ? monitorCard.querySelector('.action-menu') : null;
      if (menu instanceof HTMLDetailsElement) {
        menu.open = true;
      }
      return;
    }

    if (key.startsWith('group:')) {
      const groupName = key.slice('group:'.length);
      if (!groupName) {
        return;
      }
      const serviceCluster = Array.from(document.querySelectorAll('.service-cluster'))
        .find((node) => (node.dataset.group || '') === groupName);
      const menu = serviceCluster ? serviceCluster.querySelector('.service-summary-right .action-menu') : null;
      if (menu instanceof HTMLDetailsElement) {
        menu.open = true;
      }
    }
  });
};

export const saveDashboardState = () => {
  try {
    sessionStorage.setItem(dashboardStateScrollKey, String(window.scrollY || window.pageYOffset || 0));
    const openGroups = Array.from(document.querySelectorAll('.service-cluster[open]'))
      .map((element) => element.dataset.group || '')
      .filter(Boolean);
    localStorage.setItem(dashboardStateGroupsKey, JSON.stringify(openGroups));
  } catch (_) {
  }
};

export const restoreDashboardState = () => {
  try {
    const openGroupsRaw = localStorage.getItem(dashboardStateGroupsKey);
    if (openGroupsRaw) {
      const openGroups = JSON.parse(openGroupsRaw);
      if (Array.isArray(openGroups)) {
        document.querySelectorAll('.service-cluster').forEach((cluster) => {
          const group = cluster.dataset.group || '';
          cluster.open = openGroups.includes(group);
        });
      }
    }
    const scrollRaw = sessionStorage.getItem(dashboardStateScrollKey);
    if (scrollRaw) {
      const scrollY = Number(scrollRaw);
      if (Number.isFinite(scrollY) && scrollY >= 0) {
        requestAnimationFrame(() => requestAnimationFrame(() => window.scrollTo(0, scrollY)));
      }
      sessionStorage.removeItem(dashboardStateScrollKey);
    }
  } catch (_) {
  }
};
