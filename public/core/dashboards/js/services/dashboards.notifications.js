__BORA_REGISTER_SERVICE__(

'dashboards.notifications',

async function(scope){

    const alerts = await scope.getPlugin(
                        'alerts'
                    ); 

    function mount(){
        alert('here mount');
    }

    function unmount(){
        alert('here umount');
    }

    function notify(
        type,
        title,
        message,
        options = {}
    ){

        if(window.alertBora){
            alertBora.notifyRich({
                type: type,
                title: title,
                body: message,
                delay: 10,
                sound: true,
                onClick: () => {
                    this.navigation.go(``);
                }
            });

        }

    }

    return {
        mount,
        unmount,
        success(
            message,
            title = 'Billing'
        ){

            notify(
                'success',
                title,
                message
            );

        },

        error(
            message,
            title = 'Billing'
        ){

            notify(
                'error',
                title,
                message
            );

        },

        warning(
            message,
            title = 'Billing'
        ){

            notify(
                'warning',
                title,
                message
            );

        },

        info(
            message,
            title = 'Billing'
        ){

            notify(
                'info',
                title,
                message
            );

        },

    };

});