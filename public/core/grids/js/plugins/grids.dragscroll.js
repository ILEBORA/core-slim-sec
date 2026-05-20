__BORA_REGISTER_PLUGIN__('grids.dragscroll', async function(scope){

    function bind(container){

        if(!container){

            return;
        }

        let active = false;

        let startX = 0;

        let scrollLeft = 0;

        container.addEventListener(

            'mousedown',

            event => {

                active = true;

                startX =
                    event.pageX
                    - container.offsetLeft;

                scrollLeft =
                    container.scrollLeft;

                container.classList.add(
                    'dragging'
                );
            }
        );

        window.addEventListener(

            'mouseup',

            () => {

                active = false;

                container.classList.remove(
                    'dragging'
                );
            }
        );

        window.addEventListener(

            'mousemove',

            event => {

                if(!active){

                    return;
                }

                event.preventDefault();

                const x =
                    event.pageX
                    - container.offsetLeft;

                const walk =
                    (x - startX) * 1.5;

                container.scrollLeft =
                    scrollLeft - walk;
            }
        );
    }

    async function mount(grid){

        const targets =
            grid.element?.querySelectorAll(

                '.grid-table-responsive, .grid-cards'
            ) || [];

        targets.forEach(bind);

        grid.on(

            'dom.replaced',

            () => {

                const next =
                    grid.element?.querySelectorAll(

                        '.grid-table-responsive, .grid-cards'
                    ) || [];

                next.forEach(bind);
            }
        );

        grid.emit(
            'dragscroll.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'dragscroll.unmounted'
        );
    }

    return {

        compatible:[
            'table',
            'cards',
            'timeline',
            'kanban'
        ],

        mount,

        unmount
    };

});