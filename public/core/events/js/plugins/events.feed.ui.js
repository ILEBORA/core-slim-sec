__BORA_REGISTER_PLUGIN__(
'events.feed.ui',

async function(scope){

    const feed = await scope
        .getService('events.feed');

    const sse = await scope
        .getService('realtime.sse');

    let el;

    let scopeName = 'global';

    /*
    |--------------------------------------------------------------------------
    | Internal State
    |--------------------------------------------------------------------------
    */

    const state = {

        mounted:false
    };

    /*
    |--------------------------------------------------------------------------
    | Mount
    |--------------------------------------------------------------------------
    */

    function mount(){

        if(state.mounted) return;

        state.mounted = true;

        console.log(
            '[events.feed.ui] mounted'
        );

        waitForElement(

            '#eventsFeed',

            (node)=>{

                el = node;

                scopeName =
                    el.dataset.scope
                    || 'global';

                load();

                bindRealtime();
            }
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Wait For DOM
    |--------------------------------------------------------------------------
    */

    function waitForElement(
        selector,
        callback
    ){

        const found =
            document.querySelector(
                selector
            );

        if(found){

            return callback(found);
        }

        const observer =
            new MutationObserver(()=>{

                const found =
                    document.querySelector(
                        selector
                    );

                if(found){

                    observer.disconnect();

                    callback(found);
                }
            });

        observer.observe(

            document.body,

            {

                childList:true,

                subtree:true
            }
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Unmount
    |--------------------------------------------------------------------------
    */

    function unmount(){

        if(!state.mounted) return;

        state.mounted = false;

        sse?.off?.(
            'events.updated',
            handleUpdated
        );

        sse?.off?.(
            'events.deleted',
            handleDeleted
        );

        sse?.off?.(
            'events.created',
            handleCreated
        );

        sse?.off?.(
            'events.attendee.checked_in',
            handleCheckin
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Initial Load
    |--------------------------------------------------------------------------
    */

    async function load(reset=false){

        const data =
            await feed.load({

                scopeName,

                reset
            });

        if(!data?.length){

            $(el).html(`

                <div class="feed-empty">

                    No events found

                </div>

            `);

            return;
        }

        $(el).empty();

        data.forEach(item=>{

            /*
            |--------------------------------------------------------------------------
            | Timeline style DESC append
            |--------------------------------------------------------------------------
            */

            $(el).append(item.html);
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Insertions
    |--------------------------------------------------------------------------
    */

    function prepend(html){

        $(el).prepend(html);
    }

    function append(html){

        $(el).append(html);
    }

    /*
    |--------------------------------------------------------------------------
    | Realtime
    |--------------------------------------------------------------------------
    */

    function bindRealtime(){

        if(!sse) return;

        sse.on(
            'events.updated',
            handleUpdated
        );

        sse.on(
            'events.deleted',
            handleDeleted
        );

        sse.on(
            'events.created',
            handleCreated
        );

        sse.on(
            'events.attendee.checked_in',
            handleCheckin
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Updated
    |--------------------------------------------------------------------------
    */

    function handleUpdated(event){

        const batch =
            event.data.events || [];

        batch.forEach(ev=>{

            const payload =
                ev.payload;

            const id =
                payload.id;

            const $existing = $(

                `.event-item[data-id="${id}"]`
            );

            if($existing.length){

                $existing.replaceWith(
                    payload.html
                );

            }else{

                prepend(
                    payload.html
                );
            }
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Created
    |--------------------------------------------------------------------------
    */

    function handleCreated(event){

        const batch =
            event.data.events || [];

        batch.forEach(ev=>{

            const payload =
                ev.payload;

            const id =
                payload.id;

            const exists = $(

                `.event-item[data-id="${id}"]`
            ).length;

            if(exists) return;

            prepend(
                payload.html
            );
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Deleted
    |--------------------------------------------------------------------------
    */

    function handleDeleted(event){

        const id =
            event.data.id;

        $(

            `.event-item[data-id="${id}"]`

        )

        .fadeOut(

            200,

            function(){

                $(this).remove();
            }
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Checkins
    |--------------------------------------------------------------------------
    */

    function handleCheckin(event){

        const payload =
            event.data.payload || {};

        const eventId =
            payload.event_id;

        const count =
            payload.checked_in_count;

        const $counter = $(

            `.event-item[data-id="${eventId}"] .event-checkins-count`
        );

        if($counter.length){

            $counter.text(count);
        }
    }

    /*
    |--------------------------------------------------------------------------
    | Public API
    |--------------------------------------------------------------------------
    */

    return {

        mount,

        unmount,

        load,

        prepend,

        append
    };

},
{
    requires:[

        'events.feed',

        'realtime.sse'
    ],

    activateOn:(route)=>(

        route === 'portal/events'

        ||

        route.startsWith(
            'portal/events'
        )
    )
});