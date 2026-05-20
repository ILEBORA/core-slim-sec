__BORA_REGISTER_PLUGIN__('renderers.calendar', async function(scope){

    const actions =
        await scope.getService(
            'grids.actions'
        );

    const transport =
        await scope.getService(
            'grids.transport'
        );

    const state =
        await scope.getService(
            'grids.state'
        );

    /* =====================================================
     | Config
     |===================================================== */

    const DEFAULTS = {

        view: 'month',

        selectable: true,

        navigable: true,

        editable: false
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function getCalendar(grid){

        return grid.element?.querySelector(
            '.grid-calendar'
        );
    }

    function getSlots(grid){

        return grid.element?.querySelectorAll(
            '.calendar-slot[data-date]'
        ) || [];
    }

    function getEvents(grid){

        return grid.element?.querySelectorAll(
            '.calendar-event[data-row-id]'
        ) || [];
    }

    /* =====================================================
     | View
     |===================================================== */

    async function setView(
        grid,
        view = 'month'
    ){

        grid.__calendarOptions.view =
            view;

        state.set(

            grid,

            {

                calendarView: view
            }
        );

        await transport.reload(grid);

        grid.emit(

            'calendar.view.changed',

            {

                view
            }
        );
    }

    /* =====================================================
     | Navigation
     |===================================================== */

    async function navigate(
        grid,
        direction = 'next'
    ){

        const current =
            grid.state.date
            || new Date();

        const next =
            new Date(current);

        const view =
            grid.__calendarOptions.view;

        /*
        |--------------------------------------------------------------------------
        | Month
        |--------------------------------------------------------------------------
        */

        if(view === 'month'){

            next.setMonth(

                next.getMonth()

                + (direction === 'next' ? 1 : -1)
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Week
        |--------------------------------------------------------------------------
        */

        if(view === 'week'){

            next.setDate(

                next.getDate()

                + (direction === 'next' ? 7 : -7)
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Day
        |--------------------------------------------------------------------------
        */

        if(view === 'day'){

            next.setDate(

                next.getDate()

                + (direction === 'next' ? 1 : -1)
            );
        }

        state.set(

            grid,

            {

                date:
                    next.toISOString()
            }
        );

        await transport.reload(grid);

        grid.emit(

            'calendar.navigated',

            {

                direction,

                date: next
            }
        );
    }

    /* =====================================================
     | Slots
     |===================================================== */

    function bindSlots(grid){

        if(
            !grid.__calendarOptions
                ?.selectable
        ){

            return;
        }

        getSlots(grid).forEach(slot => {

            slot.addEventListener(

                'click',

                async () => {

                    const payload = {

                        date:
                            slot.dataset.date,

                        time:
                            slot.dataset.time
                    };

                    grid.emit(

                        'calendar.slot.clicked',

                        payload
                    );

                    /*
                    |--------------------------------------------------------------------------
                    | Action
                    |--------------------------------------------------------------------------
                    */

                    await actions.execute(

                        grid,

                        'calendar.slot.select',

                        payload
                    );
                }
            );
        });
    }

    /* =====================================================
     | Events
     |===================================================== */

    function bindEvents(grid){

        getEvents(grid).forEach(eventEl => {

            eventEl.addEventListener(

                'click',

                () => {

                    grid.emit(

                        'calendar.event.clicked',

                        {

                            row:
                                eventEl.dataset.rowId,

                            element: eventEl
                        }
                    );
                }
            );
        });
    }

    /* =====================================================
     | Navigation Buttons
     |===================================================== */

    function bindNavigation(grid){

        if(
            !grid.__calendarOptions
                ?.navigable
        ){

            return;
        }

        grid.element?.addEventListener(

            'click',

            event => {

                /*
                |--------------------------------------------------------------------------
                | Prev
                |--------------------------------------------------------------------------
                */

                if(
                    event.target.closest(
                        '[data-calendar-prev]'
                    )
                ){

                    return navigate(
                        grid,
                        'prev'
                    );
                }

                /*
                |--------------------------------------------------------------------------
                | Next
                |--------------------------------------------------------------------------
                */

                if(
                    event.target.closest(
                        '[data-calendar-next]'
                    )
                ){

                    return navigate(
                        grid,
                        'next'
                    );
                }

                /*
                |--------------------------------------------------------------------------
                | Views
                |--------------------------------------------------------------------------
                */

                const view =
                    event.target.closest(
                        '[data-calendar-view]'
                    );

                if(view){

                    return setView(

                        grid,

                        view.dataset.calendarView
                    );
                }
            }
        );
    }

    /* =====================================================
     | Today Highlight
     |===================================================== */

    function highlightToday(grid){

        const today =
            new Date()
                .toISOString()
                .split('T')[0];

        getSlots(grid).forEach(slot => {

            slot.classList.toggle(

                'today',

                slot.dataset.date === today
            );
        });
    }

    /* =====================================================
     | Lifecycle
     |===================================================== */

    async function mount(
        grid,
        options = {}
    ){

        grid.__calendarOptions = {

            ...DEFAULTS,

            ...options
        };

        bindSlots(grid);

        bindEvents(grid);

        bindNavigation(grid);

        highlightToday(grid);

        /*
        |--------------------------------------------------------------------------
        | DOM replacement
        |--------------------------------------------------------------------------
        */

        grid.on(

            'dom.replaced',

            () => {

                bindSlots(grid);

                bindEvents(grid);

                bindNavigation(grid);

                highlightToday(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Mounted
        |--------------------------------------------------------------------------
        */

        grid.emit(
            'calendar.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'calendar.unmounted'
        );
    }

    return {

        compatible:[
            'calendar'
        ],

        mount,

        unmount,

        navigate,

        setView
    };

});