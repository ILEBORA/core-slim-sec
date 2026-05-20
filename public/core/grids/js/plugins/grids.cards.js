__BORA_REGISTER_PLUGIN__('grids.cards', async function(scope){

    const selection =
        await scope.getService(
            'grids.selection'
        );

    function bindCards(grid){

        grid.element?.addEventListener(

            'click',

            event => {

                const card =
                    event.target.closest(
                        '.grid-card'
                    );

                if(!card){

                    return;
                }

                grid.emit(

                    'card.clicked',

                    {

                        id:
                            card.dataset.rowId,

                        element: card
                    }
                );
            }
        );
    }

    function syncSelection(grid){

        grid.element
            ?.querySelectorAll(
                '.grid-card[data-row-id]'
            )
            .forEach(card => {

                card.classList.toggle(

                    'selected',

                    selection.isSelected(

                        grid,

                        card.dataset.rowId
                    )
                );
            });
    }

    async function mount(grid){

        bindCards(grid);

        syncSelection(grid);

        grid.on(

            'selection.changed',

            () => {

                syncSelection(grid);
            }
        );

        grid.on(

            'dom.replaced',

            () => {

                bindCards(grid);

                syncSelection(grid);
            }
        );

        grid.emit(
            'cards.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'cards.unmounted'
        );
    }

    return {

        compatible:[
            'cards',
            'feed',
            'mobile',
            'kanban'
        ],

        mount,

        unmount
    };

});