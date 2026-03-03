__BORA_REGISTER_SERVICE__('dashboards.editWidget', function(scope){

    const capability = scope.getService('capability');
    const popup      = scope.getService('popup');

    capability.when('dashboards.ready', function(dash){

        dash.bindClick('[data-edit-widget]', function(el){

            popup.open({
                mode: 'form',
                module: 'dashboards',
                group: 'dashpagewidgets',
                id: el.dataset.id,
                tab: 'add',
                size: 'lg',
                callback(type, data){
                    console.log('Callback Pipe::', type, data);
                }
            });

        });

        console.log('[Dashboards] edit capability attached');
    });

    return {};
});