import { appBase, currentTrend } from './config.js';
import { submitPost } from './requests.js';

let draggedMonitorPayload = null;

export function bindDragDrop() {
  document.querySelectorAll('.service-cluster').forEach((cluster) => {
    if (cluster.dataset.boundGroupDrag === '1') {
      return;
    }
    cluster.dataset.boundGroupDrag = '1';
    cluster.addEventListener('dragstart', (event) => {
      cluster.dataset.draggedGroup = cluster.dataset.group || '';
      cluster.classList.add('is-dragging');
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', cluster.dataset.draggedGroup || '');
    });
    cluster.addEventListener('dragend', () => {
      cluster.classList.remove('is-dragging');
      document.querySelectorAll('.service-cluster.drop-target').forEach((item) => item.classList.remove('drop-target'));
    });
    cluster.addEventListener('dragover', (event) => {
      const draggedGroup = event.dataTransfer.getData('text/plain') || '';
      const targetGroup = cluster.dataset.group || '';
      if (!draggedGroup || draggedGroup === targetGroup) {
        return;
      }
      event.preventDefault();
      cluster.classList.add('drop-target');
    });
    cluster.addEventListener('dragleave', () => {
      cluster.classList.remove('drop-target');
    });
    cluster.addEventListener('drop', (event) => {
      event.preventDefault();
      const draggedGroup = event.dataTransfer.getData('text/plain') || '';
      const targetGroup = cluster.dataset.group || '';
      cluster.classList.remove('drop-target');
      if (!draggedGroup || !targetGroup || draggedGroup === targetGroup) {
        return;
      }
      submitPost(appBase + 'groups/reorder', {
        dragged_group: draggedGroup,
        target_group: targetGroup,
        trend: currentTrend
      });
    });
  });

  document.querySelectorAll('.monitor-card').forEach((card) => {
    if (card.dataset.boundMonitorDrag === '1') {
      return;
    }
    card.dataset.boundMonitorDrag = '1';
    card.addEventListener('dragstart', (event) => {
      draggedMonitorPayload = {
        id: card.dataset.monitorId || '',
        group: card.dataset.group || ''
      };
      card.classList.add('is-dragging');
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', JSON.stringify(draggedMonitorPayload));
      event.stopPropagation();
    });
    card.addEventListener('dragend', () => {
      draggedMonitorPayload = null;
      card.classList.remove('is-dragging');
      document.querySelectorAll('.monitor-card.drop-target').forEach((item) => item.classList.remove('drop-target'));
    });
    card.addEventListener('dragover', (event) => {
      if (!draggedMonitorPayload) {
        return;
      }
      event.stopPropagation();
      const targetId = card.dataset.monitorId || '';
      const targetGroup = card.dataset.group || '';
      if (draggedMonitorPayload.id === targetId || draggedMonitorPayload.group !== targetGroup) {
        return;
      }
      event.preventDefault();
      card.classList.add('drop-target');
    });
    card.addEventListener('dragleave', () => {
      card.classList.remove('drop-target');
    });
    card.addEventListener('drop', (event) => {
      if (!draggedMonitorPayload) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      const targetId = card.dataset.monitorId || '';
      const targetGroup = card.dataset.group || '';
      card.classList.remove('drop-target');
      if (!targetId || draggedMonitorPayload.id === targetId || draggedMonitorPayload.group !== targetGroup) {
        return;
      }
      submitPost(appBase + 'monitors/reorder', {
        dragged_id: draggedMonitorPayload.id,
        target_id: targetId,
        group: targetGroup,
        trend: currentTrend
      });
    });
  });
}
