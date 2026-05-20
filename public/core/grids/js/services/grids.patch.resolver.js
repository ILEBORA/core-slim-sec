__BORA_REGISTER_SERVICE__(
    'grids.patch.resolver',

    async function(scope){

        function apply(
            patches = []
        ){

            patches.forEach(

                patch => {

                    const target =
                        document.querySelector(
                            patch.target
                        );

                    if(!target){
                        return;
                    }

                    switch(
                        patch.mode
                    ){

                        case 'append':

                            target.insertAdjacentHTML(
                                'beforeend',
                                patch.html
                            );

                            break;

                        case 'prepend':

                            target.insertAdjacentHTML(
                                'afterbegin',
                                patch.html
                            );

                            break;

                        case 'replace':

                        default:

                            target.innerHTML =
                                patch.html;
                    }
                }
            );
        }

        return {
            apply
        };
    }
);