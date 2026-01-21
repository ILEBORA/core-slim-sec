// events.js
document.addEventListener('click', e => {
    const btn = e.target.closest('[data-grid-action]');
    if (!btn) return;

    const action = btn.dataset.gridAction;
    window.Bora?.Grids?.actions?.[action]?.();
});
