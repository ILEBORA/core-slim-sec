(function (window) {

    const INSTALLED_KEY = 'boracore_pwa_installed';

    const Service = {

        deferredPrompt: null,

        init() {
            this.bindInstallPrompt();
            this.handlePageLoad();
        },

        isStandalone() {
            return window.matchMedia('(display-mode: standalone)').matches
                || window.navigator.standalone === true;
        },

        isIOS() {
            return /iphone|ipad|ipod/i.test(navigator.userAgent);
        },

        markInstalled() {
            localStorage.setItem(INSTALLED_KEY, '1');
        },

        wasInstalled() {
            return localStorage.getItem(INSTALLED_KEY) === '1';
        },

        handlePageLoad() {
            if (this.isStandalone()) {
                this.markInstalled();
                return;
            }

            if (this.wasInstalled()) {
                setTimeout(() => {
                    if (!this.isStandalone()) {
                        window.location.href =
                            window.location.origin +
                            window.location.pathname +
                            '?launch=pwa';
                    }
                }, 4200);
            }
        },

        bindInstallPrompt() {
            window.addEventListener('beforeinstallprompt', (e) => {
                e.preventDefault();
                this.deferredPrompt = e;

                window.dispatchEvent(new CustomEvent('pwa:ready'));
            });

            window.addEventListener('appinstalled', () => {
                this.markInstalled();
                window.dispatchEvent(new CustomEvent('pwa:installed'));
            });
        },

        install() {
            if (!this.deferredPrompt) return;

            this.deferredPrompt.prompt();

            this.deferredPrompt.userChoice.then(({ outcome }) => {
                if (outcome === 'accepted') {
                    this.markInstalled();
                }
                this.deferredPrompt = null;
            });
        }
    };

    window.PwaService = Service;

})(window);