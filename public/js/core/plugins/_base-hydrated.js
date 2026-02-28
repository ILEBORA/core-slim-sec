function createHydratedComponent(definition){

    return {
        mount(el, props){

            const instance = {
                el,
                props,
                state: {},
                ...definition
            };

            if(typeof instance.init === 'function'){
                instance.init();
            }

            return instance;
        }
    };
}