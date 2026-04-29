__BORA_REGISTER_PLUGIN__('store', async function(scope){

    const reactive = await scope.getPlugin('state.reactive');
    const { reactive: r } = reactive;

    const store = r({
        route: null,
        page: null,
        filter: '',
        pageNumber: 1,
        user: {},
        cart: {}
    });

    return store;
});