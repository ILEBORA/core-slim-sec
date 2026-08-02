__BORA_REGISTER_PLUGIN__(
'events.breadcrumbs',
async function(scope){

    const hooks = await scope.getService('hooks');

    const breadcrumbs = await scope
        .getService('breadcrumbs');

    function mount(){

        scope.on(
            'breadcrumbs:resolve',

            async ({ url, response }) => {

                /*
                |--------------------------------------------------------------------------
                | Events Index
                |--------------------------------------------------------------------------
                */

                if(
                    url === 'portal/events'
                ){

                    breadcrumbs.set([

                        {

                            label:'Events',

                            current:true
                        }
                    ]);

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Featured Events
                |--------------------------------------------------------------------------
                */

                if(
                    url?.startsWith(
                        'portal/events/featured'
                    )
                ){

                    breadcrumbs.set([

                        {

                            label:'Events',

                            href:'portal/events'
                        },

                        {

                            label:'Featured',

                            current:true
                        }
                    ]);

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Upcoming Events
                |--------------------------------------------------------------------------
                */

                if(
                    url?.startsWith(
                        'portal/events/upcoming'
                    )
                ){

                    breadcrumbs.set([

                        {

                            label:'Events',

                            href:'portal/events'
                        },

                        {

                            label:'Upcoming',

                            current:true
                        }
                    ]);

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Calendar
                |--------------------------------------------------------------------------
                */

                if(
                    url?.startsWith(
                        'portal/events/calendar'
                    )
                ){

                    breadcrumbs.set([

                        {

                            label:'Events',

                            href:'portal/events'
                        },

                        {

                            label:'Calendar',

                            current:true
                        }
                    ]);

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Search
                |--------------------------------------------------------------------------
                */

                if(
                    url?.startsWith(
                        'portal/events/search'
                    )
                ){

                    const query =
                        response?.data?.query
                        || '';

                    breadcrumbs.set([

                        {

                            label:'Events',

                            href:'portal/events'
                        },

                        {

                            label:'Search',

                            current:true
                        },

                        ...(query
                            ? [

                                {

                                    label:query,

                                    current:true
                                }

                            ]
                            : []
                        )
                    ]);

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Event View
                |--------------------------------------------------------------------------
                */

                if(
                    url?.startsWith(
                        'portal/events/event/view/'
                    )
                ){

                    const event =
                        response?.data?.event;

                    if(!event){

                        breadcrumbs.set([

                            {

                                label:'Events',

                                href:'portal/events'
                            },

                            {

                                label:'Event',

                                current:true
                            }
                        ]);

                        return;
                    }

                    breadcrumbs.set([

                        {

                            label:'Events',

                            href:'portal/events'
                        },

                        ...(event.event_type_name
                            ? [

                                {

                                    label:
                                        event
                                        .event_type_name,

                                    href:
                                        'portal/events/type/'
                                        + (
                                            event.event_type_slug
                                            || event.event_type_id
                                        )
                                }

                            ]
                            : []
                        ),

                        {

                            label:event.title,

                            current:true
                        }
                    ]);

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Attendees
                |--------------------------------------------------------------------------
                */

                if(
                    url?.startsWith(
                        'portal/events/event/attendees/'
                    )
                ){

                    const event =
                        response?.data?.event;

                    breadcrumbs.set([

                        {

                            label:'Events',

                            href:'portal/events'
                        },

                        ...(event
                            ? [

                                {

                                    label:event.title,

                                    href:
                                        'portal/events/event/view/'
                                        + (
                                            event.slug
                                            || event.id
                                        )
                                }

                            ]
                            : []
                        ),

                        {

                            label:'Attendees',

                            current:true
                        }
                    ]);

                    return;
                }

            }
        );
    }

    function unmount(){

        scope.off(
            'breadcrumbs:resolve'
        );
    }

    return {

        mount,

        unmount
    };

},
{
    activateOn: (route) => (

        route === 'portal/events'

        ||

        route.startsWith(
            'portal/events/'
        )
    )
},{
    //requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events')
});