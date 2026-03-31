(function (window, document) {

    document.addEventListener('DOMContentLoaded', () => {
        window.PwaService.handlePageLoad();
        window.PwaService.bindInstallPrompt();
    });

})(window, document);