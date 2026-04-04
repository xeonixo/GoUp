(() => {
  window.addEventListener('DOMContentLoaded', () => {
    const matrixCard = document.getElementById('matrix-channel-card');
    const emptyState = document.getElementById('notifier-empty-state');
    const addButtons = Array.from(document.querySelectorAll('[data-add-notifier]'));

    if (!matrixCard && !emptyState && addButtons.length === 0) {
      return;
    }

    const syncNotifierState = () => {
      const hasMatrix = Boolean(matrixCard && !matrixCard.hidden);
      if (emptyState) {
        emptyState.hidden = hasMatrix;
      }
      addButtons.forEach((button) => {
        if (!(button instanceof HTMLButtonElement)) {
          return;
        }
        if (button.dataset.addNotifier === 'matrix') {
          button.disabled = hasMatrix;
        }
      });
    };

    addButtons.forEach((button) => {
      button.addEventListener('click', () => {
        if (button.dataset.addNotifier === 'matrix' && matrixCard) {
          matrixCard.hidden = false;
          const firstField = matrixCard.querySelector('input');
          if (firstField instanceof HTMLInputElement) {
            firstField.focus();
          }
          syncNotifierState();
        }
        const menu = button.closest('.action-menu');
        if (menu) {
          menu.removeAttribute('open');
        }
      });
    });

    syncNotifierState();
  });
})();
