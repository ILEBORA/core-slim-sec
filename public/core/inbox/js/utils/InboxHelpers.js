class InboxHelpers {

    debounce(fn, delay){

        let timer;

        return function(...args){

            clearTimeout(timer);

            timer = setTimeout(() => {
                fn.apply(this, args);
            }, delay);
        }
    }

    escape(text){

        const div = document.createElement('div');

        div.textContent = text ?? '';

        return div.innerHTML;
    }

}