__BORA_REGISTER_PLUGIN__('events.actions', async function(scope){

    const callbora = await scope.getService('callbora');
    const uiActions = await scope.getService('ui.actions');
    const bNavigator = await scope.getService('navigator');
    const mNavigation = await scope.getService('navigation');

    const popup = await scope.getPlugin('popup');

    const uiStack = await __BORA_APP__.service('ui.stack');
    const lifecycle = await scope.getPlugin('entity.lifecycle');

    const dismissable = await __BORA_APP__
        .service('ui.dismissable');

    const state = {
        mounted:false,
        initialized:false
    };

    function mount(){
        // alert('event actions');
        if (state.mounted) return;
        state.mounted = true;
        
        init();
    }
    
    init();

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;
        state.initialized = false;
    }
    
    function init(){
        if(state.initialized) return;
        state.initialized = true;

        // alert('events.actions init');

        console.log('[events.actions] mounted');

        /*
        |--------------------------------------------------------------------------
        | Core actions
        |--------------------------------------------------------------------------
        */

        uiActions.register(
            'event.view',
            openEvent
        );

        uiActions.register(
            'event.add',
            popupComposer
        );

        uiActions.register(
            'event.edit',
            popupEdit
        );

        uiActions.register(
            'event.share',
            popupShare
        );

        uiActions.register(
            'event.calendar',
            addToCalendar
        );

        /*
        |--------------------------------------------------------------------------
        | Attendance
        |--------------------------------------------------------------------------
        */

        uiActions.register(
            'event.attend',
            handleAttend
        );

        uiActions.register(
            'event.interested',
            handleInterested
        );

        uiActions.register(
            'event.checkin',
            handleCheckin
        );

        uiActions.register(
            'event.remove-attendee',
            handleRemoveAttendee
        );

        /*
        |--------------------------------------------------------------------------
        | Lifecycle
        |--------------------------------------------------------------------------
        */

        uiActions.register(
            'event.publish',
            handlePublish
        );

        uiActions.register(
            'event.cancel',
            handleCancel
        );

        uiActions.register(
            'event.delete',
            handleDelete
        );

        uiActions.register(
            'event.restore',
            handleRestore
        );

        uiActions.register(
            'event.force-delete',
            handleForceDelete
        );
        // alert('actions');
        // Types
        // uiActions.register(
        //     'event-type.view',
        //     showTypeView
        // );

        // uiActions.register(
        //     'event-type.edit',
        //     popupEditType
        // );

        // uiActions.register(
        //     'event-type.analytics',
        //     showTypeAnalytics
        // );

        // uiActions.register(
        //     'event-type.delete',
        //     handleTypeDelete
        // );

        /*
        |--------------------------------------------------------------------------
        | Featured
        |--------------------------------------------------------------------------
        */

        // uiActions.register(
        //     'event.feature',
        //     handleFeature
        // );

        // uiActions.register(
        //     'event.unfeature',
        //     handleUnfeature
        // );

        /*
        |--------------------------------------------------------------------------
        | Favourite
        |--------------------------------------------------------------------------
        */

        uiActions.register(
            'event.toggle.favourite',
            handleFavourite
        );

        /*
        |--------------------------------------------------------------------------
        | Utility
        |--------------------------------------------------------------------------
        */

        // uiActions.register(
        //     'popup.close',
        //     ()=>{
        //         uiStack.closeTop();
        //     }
        // );

        // Listeners
        scope.on(
            'event.add',
            (data) => {
                console.log('data', data);
                prependEventCard(data);
            }
        );

        scope.on(
            'event.delete',
            (data) => {

                $(`.activity-item[data-id="${data.id}"]`)
                    .addClass('deleted');
            }
        );

        scope.on(
            'event.restore',
            (data) => {

                $(`.activity-item[data-id="${data.id}"]`)
                    .removeClass('deleted');
            }
        );

        scope.on(
            'event.force-delete',
            (data) => {

                $(`.activity-item[data-id="${data.id}"]`)
                    .remove();
            }
        );

    }

    

    /* =====================================================
     | Navigation
     |===================================================== */

    async function openEvent(el){

        const id = $(el)
            .data('event-id')
            || $(el).data('id');

        if(!id) return;

        mNavigation.go(`portal/events/event/view/${id}`)

        // bNavigator.go({

        //     route: 'events.view',

        //     params: { id }
        // });
    }

    async function popupComposer(el){

        bNavigator.go({

            route: 'event.composer',

            params: {  },

            surface:'popup'
        });
    }

    async function popupEdit(el){

        const id = $(el)
            .data('event-id')
            || $(el).data('id');

        if(!id) return;

        bNavigator.go({

            route: 'events.edit',

            params: { id },

            surface:'popup'
        });
    }

    async function popupShare(el){

        const id = $(el)
            .data('event-id');

        bNavigator.go({

            route: 'events.share',

            params:{ id },

            surface:'popup'
        });
    }

    /* =====================================================
     | Attendance
     |===================================================== */

    async function handleAttend(el){

        const eventId = $(el)
            .data('event-id');

        if(!eventId) return;

        const response = await callbora.post(

            `api/modules/events/event/${eventId}/attend`,

            {
                status:'going'
            }
        );

        if(response.success){

            alertBora.success(
                'Attendance confirmed'
            );

            $(el)
                .addClass('active')
                .text('Attending');

        } else {

            alertBora.error(
                response.message || 'Failed'
            );
        }
    }

    async function handleInterested(el){

        const eventId = $(el)
            .data('event-id');

        const response = await callbora.post(

            `api/modules/events/event/${eventId}/attend`,

            {
                status:'interested'
            }
        );

        if(response.success){

            alertBora.success(
                'Marked interested'
            );

        } else {

            alertBora.error(
                response.message || 'Failed'
            );
        }
    }

    async function handleCheckin(el){

        const eventId = $(el)
            .data('event-id');

        const userId = $(el)
            .data('user-id');

        const response = await callbora.post(

            `api/modules/events/event/${eventId}/checkin`,

            {
                user_id:userId
            }
        );

        if(response.success){

            alertBora.success(
                'Attendee checked in'
            );

        } else {

            alertBora.error(
                response.message || 'Failed'
            );
        }
    }

    async function handleRemoveAttendee(el){

        const eventId = $(el)
            .data('event-id');

        const userId = $(el)
            .data('user-id');

        const response = await callbora.post(

            `api/modules/events/event/${eventId}/unattend`,

            {
                user_id:userId
            }
        );

        if(response.success){

            alertBora.success(
                'Attendee checked in'
            );

        } else {

            alertBora.error(
                response.message || 'Failed'
            );
        }
    }

    /* =====================================================
     | Lifecycle
     |===================================================== */

    async function handlePublish(el){

        const id = $(el)
            .data('event-id');

        const response = await callbora.post(
            `api/modules/events/event/publish/${id}`
        );

        if(response.success){

            alertBora.success(
                'Event published'
            );

        } else {

            alertBora.error(
                response.message || 'Failed'
            );
        }
    }

    async function handleCancel(el){

        const id = $(el)
            .data('event-id');

        const response = await callbora.post(
            `api/modules/events/event/cancel/${id}`
        );

        if(response.success){

            alertBora.success(
                'Event cancelled'
            );

        } else {

            alertBora.error(
                response.message || 'Failed'
            );
        }
    }


    /* =====================================================
     | Favourite
     |===================================================== */

    async function handleFavourite(el){

        const eventId = $(el)
            .data('event-id');

        const response = await callbora.post(

            'api/modules/events/favourites/toggle',

            {
                entity_type:'event',
                entity_id:eventId
            }
        );

        if(response.success){

            $(el)
                .toggleClass('active');

        } else {

            alertBora.error(
                response.message || 'Failed'
            );
        }
    }

    /* =====================================================
     | Calendar
     |===================================================== */

    function addToCalendar(el){

        const title = $(el).data('title');
        const start = $(el).data('start');
        const end = $(el).data('end');

        console.log(
            'TODO:: Calendar export',
            title,
            start,
            end
        );
    }

    //
    async function handleDelete(el){
        return lifecycle.mutate({

            module: 'events',

            entity: 'event',

            id: $(el).data('id'),

            action: 'delete',

            source: el
        });

        // let activityId = $(el).data('id');

        // alertBora.prompt(
        //     '<h3>Confirm Action</h3>Enter your password to continue',
        //     {
        //         html: true,
        //         prompt: '<input type="password" name="password" placeholder="Password">'
        //     }
        // ).then(function(det){

        //     let password = btoa(det.password);

        //     callbora.post(`api/modules/events/event/${activityId}/delete`, {
        //         password: password
        //     }).then(function(response){
        //         if(response.success){
        //             alertBora.success('Activity soft deleted');

        //             //remove item
        //             // $('.activity-item[data-id"'+activityId+'"]').addClass('deleted');
        //             scope.emit(
        //                 'event.delete',
        //                 {
        //                     entity: 'event',
        //                     action: 'delete',

        //                     data: {
        //                         id: activityId
        //                     },

        //                     response,

        //                     source: el
        //                 }
        //             );
                    
        //             scope.emit('events.back');

        //         } else {
        //             alertBora.error(response.message || 'Failed');
        //         }

        //     });

        // }); 
    }

    async function handleRestore(el){
        return lifecycle.mutate({

            module: 'events',

            entity: 'event',

            id: $(el).data('id'),

            action: 'restore',

            source: el
        });
        // let activityId = $(el).data('id');

        // alertBora.prompt(
        //     '<h3>Confirm Action</h3>Enter your password to continue',
        //     {
        //         html: true,
        //         prompt: '<input type="password" name="password" placeholder="Password">'
        //     }
        // ).then(function(det){

        //     let password = btoa(det.password);

        //     callbora.post(`api/modules/events/event/${activityId}/restore`, {
        //         password: password
        //     }).then(function(response){

        //         if(response.success){
        //             alertBora.success('Event restore');

        //             //Restore item
        //             // $('.activity-item[data-id"'+activityId+'"]').removeClass('deleted');
        //             scope.emit(
        //                 'event.restore',
        //                 {
        //                     entity: 'event',
        //                     action: 'restore',

        //                     data: {
        //                         id: activityId
        //                     },

        //                     response,

        //                     source: el
        //                 }
        //             );

        //             if(response.redirect){
        //                 navigation.go(response.redirect);
        //             }
                    
        //         } else {
        //             alertBora.error(response.message || 'Failed');
        //         }

        //     });

        // }); 

    }

    async function handleForceDelete(el){
        return lifecycle.mutate({

            module: 'events',

            entity: 'event',

            id: $(el).data('id'),

            action: 'force-delete',

            source: el
        });
        // let activityId = $(el).data('id');

        // alertBora.prompt(
        //     '<h3>Confirm Action</h3>Enter your password to continue',
        //     {
        //         html: true,
        //         prompt: '<input type="password" name="password" placeholder="Password">'
        //     }
        // ).then(function(det){

        //     let password = btoa(det.password);

        //     callbora.post(`api/modules/events/event/${activityId}/forcedelete`, {
        //         password: password
        //     }).then(function(response){

        //         if(response.success){
        //             alertBora.success('event deleted');

        //             //remove item
        //             // $('.activity-item[data-id"'+activityId+'"]').remove();
        //             scope.emit(
        //                 'event.force-delete',
        //                 {
        //                     entity: 'event',
        //                     action: 'force-delete',

        //                     data: {
        //                         id: activityId
        //                     },

        //                     response,

        //                     source: el
        //                 }
        //             );

        //             scope.emit('events.back');
        //         } else {
        //             alertBora.error(response.message || 'Failed');
        //         }

        //     });

        // }); 

    }

    //
    /* ========================================
     * TAB CONTENT (HTML)
     * ====================================== */

    let tabCache  = new Map(); 
    // inflight requests
    let inflight = new Map();

    // TABS
    scope.on('events.tab.changed', async ({ tab, eventId }) => {

        const root = document.querySelector(
            `.event-view[data-event="${eventId}"]`
        );

        if (root) {
            root.querySelectorAll('.event-tabs button')
                .forEach(btn => {
                    btn.classList.toggle(
                        'active',
                        btn.dataset.tab === tab
                    );
                });

            root.querySelectorAll('.tab-panel')
                .forEach(panel => {
                    panel.classList.toggle(
                        'active',
                        panel.dataset.tab === tab
                    );
                });
        }

        await loadTab(eventId, tab);
    });

    // // $(document).on('click.events', '.event-tabs button', function () {
    // //     const tab = $(this).data('tab');

    // //     const root = $(this).closest('.event-view');
    // //     const eventId = root.data('event');

    // //     scope.emit('events.tab.changed', {
    // //         tab,
    // //         eventId,
    // //         root: root[0]
    // //     });
    // // });

    // function showTabLoading(tab) {
    //     const el = document.querySelector(
    //         `.tab-panel[data-tab="${tab}"]`
    //     );

    //     if (!el) return;

    //     el.innerHTML = `
    //         <div class="loading-state small">
    //             Loading...
    //         </div>
    //     `;
    // }

    // async function loadTab(eventId, tab) {

    //     if (tab === 'profile') return null;
        
    //     console.log('Tab changed to '+tab);

    //     showTabLoading(tab);

    //     const html = await getTabContent(eventId, tab);

    //     renderTabHTML(tab, html);

    //     return html;
    // }

    // async function getTabContent(eventId, tab) {

    //     const cacheKey = `${eventId}:${tab}`;

    //     if (tabCache.has(cacheKey)) {
    //         return tabCache.get(cacheKey);
    //     }

    //     const key = `tab:${cacheKey}`;

    //     if (inflight.has(key)) {
    //         return inflight.get(key);
    //     }

    //     const promise = callbora
    //         .get(`api/modules/events/event/${eventId}/tabs/${tab}`)
    //         .then(response => {

    //             let parsed = null;

    //             if (typeof response === 'object' && response !== null) {
    //                 parsed = response;
    //             } else if (typeof response === 'string') {
    //                 try {
    //                     parsed = JSON.parse(response);
    //                 } catch (e) {
    //                     parsed = null;
    //                 }
    //             }

    //             if (parsed && typeof parsed === 'object') {
    //                 // 🚨 JSON response → error case
    //                 if (parsed.success === false) {
    //                     const html = `
    //                         <div class="error unauthorized">
    //                             <strong>${parsed.message || 'Error'}</strong>
    //                         </div>
    //                     `;

    //                     // ✅ assume HTML
    //                     tabCache.set(cacheKey, html);
    //                     inflight.delete(key);

    //                     return html;
    //                 }
    //             }

    //             // ✅ assume HTML
    //             tabCache.set(cacheKey, response);
    //             inflight.delete(key);

    //             return response;
    //         })
    //         .catch(err => {
    //             inflight.delete(key);
    //             throw err;
    //         });

    //     inflight.set(key, promise);

    //     return promise;
    // }

    // function renderTabHTML(tab, html) {
    //     const el = document.querySelector(
    //         `.tab-panel[data-tab="${tab}"]`
    //     );

    //     if (!el) return;

    //     el.innerHTML = html;
    // }

    function prependEventCard(data){
        const eventsGrid = $('.events-grid');
        if(data.response.html){
            eventsGrid.append(data.response.html);
        }
    }

    function removeEventCard(id){
        const card = $(`.event-card[data-id="${id}"]`);
        if(card.length){
            
        }
    }


    return {
        mount,
        unmount
    };

},
{
    faces:['client']
});