__BORA_REGISTER_PLUGIN__('activity.stories.state', async function(){

    const state = {
        groups:[],
        viewed:{}
    };

    function setGroups(groups){

        state.groups = groups;

    }

    function getGroups(){

        return state.groups;

    }

    return {
        setGroups,
        getGroups
    };

});