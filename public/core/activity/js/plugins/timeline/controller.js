__BORA_REGISTER_PLUGIN__(

    'timeline.controller',
    
    async function(scope){
    
        let feed;
    
        const state = {
            mounted: false,
            initialized:false
        };

        async function init(){
            if (state.initialized) return;
            state.initialized = true;
            // const uiActions = await scope.getService('ui.actions');
            // const workspace = await scope.getPlugin('billing.workspace');
            // const notifications = await scope.getService('billing.notifications');
            // const resources = await scope.getService('resources');

            // ({
            //     feed,
                
            // } = await scope.importServices({
            //     feed: 'activity.feed',
               
            // }));

            // alert('timeline controller initialized');
        }

        
    
        async function mount(){
            if (state.mounted) return;
            state.mounted = true;
            // alert('timeline controller mounted');

            console.log('jQuery:', !!window.jQuery);
            console.log('Select2:', !!$.fn.select2);
            console.log($);
            console.log(jQuery);

            console.log($.fn.jquery);
            console.log($.fn.select2);

            console.log(window.$ === window.jQuery);

            await init();
            
            bind();
    
        }

        function unmount(){
            if (!state.mounted) return;
            state.mounted = false;
            state.initialized = false;
        }

        function bind(){
            scope.on(
                'people.tab.changed',
        
                async ({tab, personId, root})=>{
        
                        // optional immediate ui feedback
                        scope.emit(
                            'people.tab.ui',
                            {
                                tab,
                                personId,
                                root
                            }
                        );
        
                        await api.loadTab(
                            personId,
                            tab
                        );
        
                    }
                );
            // scope.on(
    
            //     'realtime:activity:timeline.updated',
    
            //     event=>{
    
            //         console.log('[PAYLOAD]',event);

            //         const post = event.payload.checkout;
            
            //         if(
            //             !checkout ||
            //             checkout.uid !== window.checkoutUid
            //         ){
            //             return;
            //         }

            //         // Status badge
            //         const badge = document.getElementById(
            //                         'checkout-status'
            //                     );

            //         badge.textContent = 'Paid';

            //         badge.classList.remove(
            //             'bg-secondary'
            //         );
                    
            //         badge.classList.add(
            //             'bg-success'
            //         );

            //         //Spinner:

            //         const spinner = document.getElementById(
            //                         'checkout-spinner'
            //                     );

            //         spinner.className = 'fas fa-check-circle fa-3x text-success';
                    
            //         // Title
            //         $('#checkout-title').text('Payment Successful');

            //         //Description
            //         $('#checkout-message').text(
            //             'Your payment has been confirmed.'
            //         );

            //         // Progress
            //         $('#checkout-progress').removeClass(
            //                         'progress-bar-striped progress-bar-animated'
            //                     );

                    
            //         alertBora.success(
            //             'Payment received.'
            //         );

            //         notifications.paymentSucceeded(
            //             event.payload.checkout
            //         );
    
            //     }
    
            // );

            // scope.on(

            //     'realtime:billing.payment.completed',
            
            //     async ({payload})=>{
            
            //         if(
            //             payload.checkout.uid !==
            //             window.checkoutUid
            //         ){
            //             return;
            //         }
            
            //         await resources.get(
            
            //             'checkout',
            
            //             payload.checkout.uid
            
            //         );
            
            //     }
            
            // );
    
            // scope.on(
    
            //     'realtime:billing.payment.completed',
    
            //     (event)=>{
            //         console.log('[PAYLOAD]',event);

            //         const checkout =
            //             event.payload.checkout;
            
            //         if(
            //             !checkout ||
            //             checkout.uid !== window.checkoutUid
            //         ){
            //             return;
            //         }

            //         // STatus badge
            //         const badge = document.getElementById(
            //                         'checkout-status'
            //                     );

            //         badge.textContent = 'Paid';

            //         badge.classList.remove(
            //             'bg-secondary'
            //         );
                    
            //         badge.classList.add(
            //             'bg-success'
            //         );

            //         //Spinner:

            //         const spinner = document.getElementById(
            //                         'checkout-spinner'
            //                     );

            //         spinner.className = 'fas fa-check-circle fa-3x text-success';
                    
            //         // Title
            //         $('#checkout-title').text('Payment Successful');

            //         //Description
            //         $('#checkout-message').text(
            //             'Your payment has been confirmed.'
            //         );

            //         // Progress
            //         $('#checkout-progress').removeClass(
            //                         'progress-bar-striped progress-bar-animated'
            //                     );

                    
            //         alertBora.success(
            //             'Payment received.'
            //         );

            //         notifications.paymentSucceeded(
            //             event.payload.checkout
            //         );
    
            //     }
    
            // );

            scope.on(
    
                'realtime:activity:timeline.created',
    
                (event)=>{
    
                    console.log('[PAYLOAD]',event);

                    const post =
                        event.payload.post;
    
                    alertBora.notify(
                        'Realtime post created.'
                    );
    
                }
    
            );
    
            scope.on(
    
                'realtime:activity:timeline.updated',
    
                (event)=>{
                    console.log('[PAYLOAD]',event);

                    const post =
                        event.payload.post;
    
                    alertBora.notify(
                        'Realtime post updated.'
                    );
    
                }
    
            );

            scope.on(
    
                'realtime:activity:timeline.deleted',
    
                (event)=>{
    
                    console.log('[PAYLOAD]',event);

                    const post =
                        event.payload.post;
    
                    alertBora.notify(
                        'Realtime post deleted.'
                    );
    
                }
    
            );
    
        }
    
        return{
    
            mount
    
        };
    
    });