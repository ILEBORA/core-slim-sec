__BORA_REGISTER_PLUGIN__('dashboards.dashboard', async function (scope) {

    const hooks   = await scope.getService('hooks');
    const billing = await scope.getService('billing');

    let revenueChart = null;
    let planChart    = null;
    let mounted      = false;

    let billingHandler = null;
    let changeHandler  = null;

    function mount() {
        if (mounted) return;
        mounted = true;

        // console.log('[BillingDashboard] mounted');

        bindUI();

        //Default charts
        // Revenue Trend Line
        new Chart(document.getElementById('revenueTrend'), {
            type: 'line',
            data: {
                labels: ['W1','W2','W3','W4'],
                datasets: [{
                    label: 'Revenue',
                    data: [0, 0, 0, 0],
                    borderColor: '#2563eb',
                    fill: false,
                    tension: 0.4
                }]
            },
            options: { responsive: true }
        });

        // // Plan Distribution Donut
        new Chart(document.getElementById('planDistribution'), {
            type: 'doughnut',
            data: {
                labels: ['Basic','Pro','Enterprise'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#93c5fd','#2563eb','#1e3a8a']
                }]
            },
            options: { responsive: true }
        });
        //End charts



        registerHooks();
        fetchData();
        
    }

    function unmount(){

        if(!mounted) return;
        mounted = false;

        if (billingHandler) {
            hooks.remove('billing:dashboard', billingHandler);
            billingHandler = null;
        }

        if (changeHandler) {
            document.removeEventListener('change', changeHandler);
            changeHandler = null;
        }

        destroyCharts();

        console.log('[BillingDashboard] unmounted');
    }

    function bindUI(){

        changeHandler = function(e){
            if (!e.target.matches('#billingrange')) return;

            changeRange(e.target.value);
        };

        document.addEventListener('change', changeHandler);
    }

    function changeRange(range){
        fetchData(range);
    }

    function registerHooks() {

        billingHandler = function(e) {

            if (!e || !e.type) return;

            switch (e.type) {
                case 'billing.payment_failed':
                    billing.incrementFailed();
                    break;
                case 'billing.subscription_cancelled':
                    billing.incrementCancelled();
                    break;
                case 'billing.subscription_upgraded':
                    billing.refreshPlanDistribution();
                    break;
                case 'billing.trial_converted':
                    billing.incrementRevenue(e.amount);
                    break;
            }
        };

        hooks.addHook('billing:dashboard', billingHandler);
    }

    function fetchData(range = 'this_month') {
        fetch(`api/modules/billing/api-dashboard?range=${range}`)
            .then(res => res.json())
            .then(async data => {
                const billing = await scope.getService('billing');
                billing.renderCharts(data);
                billing.updateDashboard(data);
            })
            .catch(err => {
                console.error("Billing dashboard failed:", err);
            });
    }

    // function fetchDataO() {
    //     fetch('api/modules/billing/api-dashboard')
    //         .then(res => res.json())
    //         .then(data => {

    //             const mrrEl = document.querySelector('[data-mrr]');
    //             if (mrrEl) {
    //                 mrrEl.dataset.target = data.revenue.mrr;
    //             }

    //             billing.renderCharts(data);
    //             billing.animateCounters();
    //         })
    //         .catch(err => {
    //             console.error("Billing dashboard failed:", err);
    //         });
    // }

    function destroyCharts(){
        revenueChart?.destroy?.();
        planChart?.destroy?.();
        revenueChart = null;
        planChart = null;
    }

    return { mount, unmount };

},
{
    requires:['hooks'],
    activateOn: route => route.startsWith('bo/billing')
});