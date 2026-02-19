(function (window, document) {
    const INSTALLED_KEY = 'boracore_pwa_installed';
    let deferredPrompt = null;

    function isStandalone() {
        return window.matchMedia('(display-mode: standalone)').matches
            || window.navigator.standalone === true;
    }

    function isIOS() {
        return /iphone|ipad|ipod/i.test(window.navigator.userAgent);
    }

    function handlePageLoad() {
        if (isStandalone()) {
            localStorage.setItem(INSTALLED_KEY, '1');
            console.log('[Pwa] Running in standalone mode.');
        } else {
            if (localStorage.getItem(INSTALLED_KEY) === '1') {
                console.log('[Pwa] Installed before — attempting auto-launch...');
                setTimeout(() => {
                    if (!isStandalone()) {
                        window.location.href = window.location.origin + window.location.pathname + '?launch=pwa';
                    }
                }, 4200); //TODO:: increase timer
            } else {
                console.log('[Pwa] Not installed yet.');
            }
        }

        if (isIOS() && !isStandalone()) {
            document.querySelector('#ios-add-hint')?.classList.add('visible');
        }
    }

    function setupInstallPrompt() {
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            const btn = document.querySelector('[data-pwa-install]');
            if (btn) {
                btn.style.display = 'inline-block';
                btn.addEventListener('click', async () => {
                    btn.disabled = true;
                    const { outcome } = await deferredPrompt.prompt();
                    console.log('[Pwa] Install choice:', outcome);
                    if (outcome === 'accepted') {
                        localStorage.setItem(INSTALLED_KEY, '1');
                    }
                    deferredPrompt = null;
                    btn.disabled = false;
                });
            }
        });

        window.addEventListener('appinstalled', () => {
            console.log('[Pwa] App installed successfully.');
            localStorage.setItem(INSTALLED_KEY, '1');
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        handlePageLoad();
        setupInstallPrompt();
    });
})(window, document);