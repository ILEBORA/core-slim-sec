__BORA_REGISTER_PLUGIN__(
'people.ui.interactions',

async function (scope) {

    const popup      = await scope.getPlugin('popup');
    const uiStack    = await scope.getService('ui.stack');
    const callbora   = await scope.getService('callbora');
    const navigation = await scope.getService('navigation');

    let initialized = false;
    let originalHTML = '';
    let currentIndex = -1;

    const ui = {

        grid() {
            return $('.people-grid');
        },
    
        search() {
            return $('[data-people-search]');
        },
    
        filters() {
            return $('.people-filters');
        }
    
    };

    function applyPeopleFilters() {

        const filter =
            $('.people-filters .active').data('type');
    
        $('.person-card').each(function () {
    
            const type = $(this).data('type');
            const fav  = $(this).data('favorite');
    
            const matchFilter =
                filter === 'all' ||
                (filter === 'members' && type === 'members') ||
                (filter === 'non-users' && type === 'non-users') ||
                (filter === 'favorites' && fav == 1);
    
            $(this).toggle(matchFilter);
    
        });
    
    }
    
    // function applyPeopleFiltersO() {

    //     const query  = $('[data-people-search]')
    //         .val()
    //         .toLowerCase();

    //     const filter =
    //         $('.people-filters .active')
    //             .data('type');

    //     $('.person-card').each(function () {

    //         const name =
    //             $(this)
    //                 .find('.name')
    //                 .text()
    //                 .toLowerCase();

    //         const type =
    //             $(this).attr('data-type');

    //         const fav =
    //             $(this).attr('data-favorite');

    //         if (!type && filter !== 'all') {
    //             $(this).show();
    //             return;
    //         }

    //         const matchSearch =
    //             name.includes(query);

    //         const matchFilter =
    //             filter === 'all' ||
    //             (filter === 'members' &&
    //                 type === 'members') ||
    //             (filter === 'non-users' &&
    //                 type === 'non-users') ||
    //             (filter === 'favorites' &&
    //                 fav == 1);

    //         $(this).toggle(
    //             matchSearch && matchFilter
    //         );

    //     });
    // }

    function debounce(fn, delay = 300) {

        let t;

        return function (...args) {

            clearTimeout(t);

            t = setTimeout(() => {
                fn.apply(this, args);
            }, delay);

        };
    }

    const debouncedSearch = debounce(
        async function () {

            const query = ($('[data-people-search]').val() || '').trim();

            const $container = $('.people-grid');

            if (!query.length) {

                if ($container.length && originalHTML) {
                    $container.html(originalHTML);
                }

                currentIndex = -1;

                return;
            }

            if (query.length < 2) {
                applyPeopleFilters();
                return;
            }

            const html = await callbora.get(
                `api/modules/people/search?q=${encodeURIComponent(query)}`
            );

            console.log('[HTML]',html);
            console.log(typeof html);

            // const container = $('#page_content').find('.people-grid');
            
            if ($container.length) {
                $container.html(html);
                console.log('[container]',$container);
                // applyPeopleFilters();

            }

        },
        300
    );

    function highlightItem(items) {

        items.removeClass('active');

        if (currentIndex >= 0) {

            const $item = items.eq(currentIndex);

            $item
                .addClass('active')
                .get(0)
                ?.scrollIntoView({
                    block: 'nearest'
                });

        }
    }

    return {

        async init() {

            if (initialized) {
                return;
            }

            // alert('People UI Intractions mounted');

            initialized = true;

            const $grid = $('.people-grid');

            if ($grid.length && !originalHTML) {
                originalHTML = $grid.html();
            }

            /* =====================================
             * DOM EVENTS ONLY
             * =================================== */

            // FOLLOW BUTTON
            $(document).on(
                'click.people',
                '.btn-follow',
                function (e) {

                    e.stopPropagation();

                    const personId =
                        $(this).data('person');

                    const isFollowing =
                        $(this)
                            .text()
                            .trim() === 'Following';

                    scope.emit(
                        'people.follow.toggle',
                        {
                            personId,
                            isFollowing
                        }
                    );

                }
            );

            // PERSON TABS
            $(document).on(
                'click.people',
                '.person-tabs button',
                function () {

                    const tab =
                        $(this).data('tab');

                    const root =
                        $(this)
                            .closest('.person-view');

                    const personId =
                        root.data('person');

                    scope.emit(
                        'people.tab.changed',
                        {
                            tab,
                            personId,
                            root: root[0]
                        }
                    );

                }
            );

            // BACK BUTTON
            $(document).on(
                'click.people',
                '.back-btn',
                function () {
                    
                    scope.emit('people.back');

                }
            );

            // SEARCH
            $(document).on(
                'input.people',
                '[data-people-search]',
                debouncedSearch
            );

            // FILTERS
            // $(document).on(
            //     'click.people',
            //     '.people-filters button',
            //     function () {

            //         $(this)
            //             .addClass('active')
            //             .siblings()
            //             .removeClass('active');

            //         const $container = $('.people-grid');

            //         if ($container.length && originalHTML) {
            //             $container.html(originalHTML);
            //         }

            //         applyPeopleFilters();

            //     }
            // );

            $(document).on(
                'click.people',
                '.people-filters button',
                function () {
            
                    $(this)
                        .addClass('active')
                        .siblings()
                        .removeClass('active');
            
                    applyPeopleFilters();
            
                }
            );

            // KEYBOARD NAVIGATION
            $(document).on(
                'keydown.people',
                '[data-people-search]',
                function (e) {

                    const items =
                        $('.person-card:visible');

                    if (!items.length) {
                        return;
                    }

                    // DOWN
                    if (e.key === 'ArrowDown') {

                        e.preventDefault();

                        currentIndex =
                            Math.min(
                                currentIndex + 1,
                                items.length - 1
                            );

                        highlightItem(items);

                    }

                    // UP
                    if (e.key === 'ArrowUp') {

                        e.preventDefault();

                        currentIndex =
                            Math.max(
                                currentIndex - 1,
                                0
                            );

                        highlightItem(items);

                    }

                    // ENTER
                    if (e.key === 'Enter') {

                        e.preventDefault();

                        const selected =
                            items.eq(currentIndex);

                        if (selected.length) {
                            selected.click();
                        }

                    }

                }
            );

            // TREE SELECT
            $(document).on(
                'change',
                '[data-tree-select]',
                function () {

                    const treeId =
                        $(this).val();

                    if (!treeId) {
                        return;
                    }

                    const root =
                        $(this)
                            .closest('.person-view');

                    const personId =
                        root.data('person');

                    scope.emit(
                        'people.tree.selected',
                        {
                            personId,
                            treeId: parseInt(
                                treeId,
                                10
                            )
                        }
                    );

                }
            );

            /* =====================================
             * PAGE VIEW EVENTS
             * =================================== */

            scope.on(
                'people.view.list',
                function () {

                    $('.thread_context_menu')
                        .hide();

                    $('.thread-info')
                        .addClass('is-hidden');

                }
            );

            scope.on(
                'people.view.thread',
                function () {

                    $('.thread_context_menu')
                        .show();

                    $('.thread-info')
                        .removeClass('is-hidden');

                }
            );

        }

    };

}
// ,{
//     //requires:['realtime'],
//     activateOn: (route) =>
//         route.startsWith('portal/people')
// }

);