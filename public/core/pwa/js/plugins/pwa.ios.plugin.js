(function (window, document) {

    document.addEventListener('DOMContentLoaded', () => {

        if (
            window.PwaService.isIOS() &&
            !window.PwaService.isStandalone()
        ) {
            document
                .querySelector('#ios-add-hint')
                ?.classList.add('visible');
        }

    });

})(window, document);