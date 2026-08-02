__BORA_REGISTER_PLUGIN__(
'events.calendar.ui',

async function(scope){

    const calendar =
        await scope.getService(
            'events.calendar'
        );

    let currentView = 'month';

    let currentDate = new Date();

    async function mount(){

        bindViewButtons();

        bindNavigation();

        console.log(
            '[events.calendar.ui] mounted'
        );
    }

    function bindViewButtons(){

        document.addEventListener(
            'click',
            async function(e){

                const btn =
                    e.target.closest(
                        '[data-view]'
                    );

                if(!btn) return;

                currentView =
                    btn.dataset.view;

                await render();
            }
        );
    }

    function bindNavigation(){

        document.addEventListener(
            'click',
            async function(e){

                if(
                    e.target.closest(
                        '[data-calendar-next]'
                    )
                ){

                    next();
                    await render();
                }

                if(
                    e.target.closest(
                        '[data-calendar-prev]'
                    )
                ){

                    prev();
                    await render();
                }
            }
        );
    }

    async function render(){

        const params =
            getRangeForView();

        const html =
            await calendar.load(
                currentView,
                params
            );

        const content =
            document.querySelector(
                '.calendar-content'
            );

        if(content){

            content.innerHTML = html;
        }
    }

    function getRangeForView(){

        const d = currentDate;

        switch(currentView){

            case 'day':

                return {
                    date: formatDate(d)
                };

            case 'week':

                return {
                    start: getWeekStart(d),
                    end: getWeekEnd(d)
                };

            case 'month':

                return {
                    start: getMonthStart(d),
                    end: getMonthEnd(d)
                };

            case 'year':

                return {
                    start: getYearStart(d),
                    end: getYearEnd(d)
                };
        }
    }

    function next(){

        switch(currentView){

            case 'day':
                currentDate.setDate(
                    currentDate.getDate() + 1
                );
                break;

            case 'week':
                currentDate.setDate(
                    currentDate.getDate() + 7
                );
                break;

            case 'month':
                currentDate.setMonth(
                    currentDate.getMonth() + 1
                );
                break;

            case 'year':
                currentDate.setFullYear(
                    currentDate.getFullYear() + 1
                );
                break;
        }
    }

    function prev(){

        switch(currentView){

            case 'day':
                currentDate.setDate(
                    currentDate.getDate() - 1
                );
                break;

            case 'week':
                currentDate.setDate(
                    currentDate.getDate() - 7
                );
                break;

            case 'month':
                currentDate.setMonth(
                    currentDate.getMonth() - 1
                );
                break;

            case 'year':
                currentDate.setFullYear(
                    currentDate.getFullYear() - 1
                );
                break;
        }
    }

    function formatDate(date){

        return date
            .toISOString()
            .split('T')[0];
    }

    //
    function formatDate(date){

    return date
        .toISOString()
        .split('T')[0];
}

/*
|--------------------------------------------------------------------------
| Day
|--------------------------------------------------------------------------
*/

function getDayStart(date){

    return formatDate(date);
}

function getDayEnd(date){

    return formatDate(date);
}

/*
|--------------------------------------------------------------------------
| Week
|--------------------------------------------------------------------------
*/

function getWeekStart(date){

    const d = new Date(date);

    const day =
        d.getDay();

    /*
    | Sunday = 0
    | Convert to Monday-based week
    */

    const diff =
        d.getDate() -
        day +
        (day === 0 ? -6 : 1);

    d.setDate(diff);

    return formatDate(d);
}

function getWeekEnd(date){

    const d =
        new Date(
            getWeekStart(date)
        );

    d.setDate(
        d.getDate() + 6
    );

    return formatDate(d);
}

/*
|--------------------------------------------------------------------------
| Month
|--------------------------------------------------------------------------
*/

function getMonthStart(date){

    const d = new Date(date);

    return formatDate(

        new Date(

            d.getFullYear(),

            d.getMonth(),

            1
        )
    );
}

function getMonthEnd(date){

    const d = new Date(date);

    return formatDate(

        new Date(

            d.getFullYear(),

            d.getMonth() + 1,

            0
        )
    );
}

/*
|--------------------------------------------------------------------------
| Year
|--------------------------------------------------------------------------
*/

function getYearStart(date){

    const d = new Date(date);

    return formatDate(

        new Date(

            d.getFullYear(),

            0,

            1
        )
    );
}

function getYearEnd(date){

    const d = new Date(date);

    return formatDate(

        new Date(

            d.getFullYear(),

            11,

            31
        )
    );
}

    return {
        mount
    };
},{
    //requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events/calendar')
});