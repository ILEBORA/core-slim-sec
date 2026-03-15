__BORA_REGISTER_SERVICE__('activity.feed', function(scope){

    const http = scope.getService('http') || $;

    let since   = null;
    let loading = false;

    async function load({scopeName='home', limit=20, reset=false} = {}){

        if (loading) return [];
        loading = true;

        if(reset) since = null;

        try{

            const resp = await $.getJSON('api/modules/activity/feed', {
                scope: scopeName,
                since,
                limit
            });

            if(!resp.ok) return [];

            if(resp.data.length){
                since = resp.data[resp.data.length-1].created_at;
            }

            return resp.data;

        }finally{
            loading = false;
        }
    }

    return {
        load
    };

});