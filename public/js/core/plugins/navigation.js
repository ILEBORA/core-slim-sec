__BORA_REGISTER_PLUGIN__('Navigation', function(scope){

    const navigation = scope.getService('navigation');

    return {
        go: navigation.go,
        reload: navigation.reload,
        back: navigation.back
    };
});