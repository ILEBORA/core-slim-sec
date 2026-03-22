__BORA_REGISTER_PLUGIN__('navigation.plugin', async function(scope){

    const navigation = await scope.getService('navigation');

    return {
        go: navigation.go,
        reload: navigation.reload,
        back: navigation.back
    };
});