(function (window, document) {

    document.addEventListener('DOMContentLoaded', () => {

        const btn = document.querySelector('[data-pwa-install]');
        if (!btn) return;

        window.addEventListener('pwa:ready', () => {
            btn.style.display = 'inline-block';
        });

        btn.addEventListener('click', () => {
            btn.disabled = true;

            window.PwaService.install();

            setTimeout(() => {
                btn.disabled = false;
            }, 1500);
        });

    });

})(window, document);