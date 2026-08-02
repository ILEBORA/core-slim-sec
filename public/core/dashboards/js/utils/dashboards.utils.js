__BORA_REGISTER_SERVICE__('dashboards.utils', async function (scope) {

    let revenueChart = null;
    let planChart = null;

    const Chart = await scope.getService('chart.service');

    return {

        formatCurrency(value) {
            return window.BILLING_CURRENCY + Number(value).toLocaleString();
        },

        incrementFailed() {
            const el = document.querySelector('[data-failed]');
            if (!el) return;

            el.innerText = (parseInt(el.innerText || 0) + 1);
        },

        incrementCancelled() {
            const el = document.querySelector('[data-cancelled]');
            if (!el) return;

            el.innerText = (parseInt(el.innerText || 0) + 1);
        },

        incrementRevenue(amount) {
            const el = document.querySelector('[data-revenue]');
            if (!el) return;

            let current = parseFloat(el.dataset.target || 0);
            el.dataset.target = current + parseFloat(amount);

            this.animateCounters();
        },

        animateCounters() {
            document.querySelectorAll('.counter').forEach(counter => {

                let target = +counter.dataset.target || 0;
                let count = 0;
                let step = target / 60;

                function update() {
                    count += step;

                    if (count < target) {
                        counter.innerText = Math.floor(count).toLocaleString();
                        requestAnimationFrame(update);
                    } else {
                        counter.innerText = target.toLocaleString();
                    }
                }

                update();
            });
        },

        refreshPlanDistribution() {
            fetch('api/modules/billing/api/dashboard?range=this_month')
                .then(res => res.json())
                .then(data => {

                    const labels = data.growth.plan_distribution.map(p => p.name);
                    const totals = data.growth.plan_distribution.map(p => p.total);

                    if (planChart) planChart.destroy();

                    planChart = new Chart(
                        document.getElementById('planDistribution'),
                        {
                            type: 'doughnut',
                            data: {
                                labels,
                                datasets: [{ data: totals }]
                            }
                        }
                    );
                });
        },

        renderCharts(data) {

            if (document.getElementById('revenueTrend') && data.revenue.revenue_trend) {

                const labels = data.revenue.revenue_trend.map(r => r.date);
                const totals = data.revenue.revenue_trend.map(r => r.total);

                if (revenueChart) revenueChart.destroy();

                revenueChart = new Chart(
                    document.getElementById('revenueTrend'),
                    {
                        type: 'line',
                        data: {
                            labels,
                            datasets: [{ label: 'Revenue', data: totals }]
                        }
                    }
                );
            }
        },

        updateDashboard(data){

            if(!data) return;

            this.updateRevenue(data.revenue);
            this.updateSubscriptions(data.subscriptions);
            this.updateGrowth(data.growth);
            this.updateAlerts(data.alerts);

            this.renderRevenueTrend(data.revenue?.revenue_trend);
            this.renderPlanDistribution(data.growth?.plan_distribution);

            // defer animation
            requestAnimationFrame(() => {
                this.animateCounters();
            });
        },

        setText(selector, value){
            const el = document.querySelector(selector);
            if(el) el.innerText = value ?? 0;
        },

        setTarget(selector, value){
            const el = document.querySelector(selector);
            if(el) el.dataset.target = value ?? 0;
        },

        updateRevenue(r){
            if(!r) return;

            this.setTarget('[data-mrr]', r.mrr);
            this.setTarget('[data-revenue]', r.revenue_period);
            this.setTarget('[data-outstanding]', r.outstanding);
            this.setText('[data-failed]', r.failed_payments);
        },

        updateSubscriptions(s){
            if(!s) return;

            this.setText('[data-active]', s.active);
            this.setText('[data-trial]', s.trialing);
            this.setText('[data-cancelled]', s.cancelled_30);
            this.setText('[data-upgrades]', s.upgrades ?? 0);
        },

        updateGrowth(g){
            if(!g) return;

            this.setText('[data-conversion]', (g.trial_conversion ?? 0) + "%");
            this.setText('[data-ltv]', this.formatCurrency(g.ltv));
            this.setText('[data-top-plan]', g.top_plan);
        },

        updateAlerts(a){
            if(!a) return;

            this.setText('[data-overdue]', `${a.overdue_14 ?? 0} invoices overdue >14 days`);
            this.setText('[data-expiring]', `${a.expiring_7 ?? 0} subscriptions expiring in 7 days`);
            this.setText('[data-retries]', `${a.payment_retries ?? 0} payment retries scheduled today`);
        },

        /* ==================================================
        CHARTS
        ================================================== */

        renderRevenueTrend(trend){

            const el = document.getElementById('revenueTrend');
            if(!el || !trend || typeof Chart === 'undefined') return;

            const labels = trend.map(r => r.date);
            const totals = trend.map(r => r.total);

            if(revenueChart) revenueChart.destroy();

            revenueChart = new Chart(el, {
                type:'line',
                data:{
                    labels,
                    datasets:[{
                        label:'Revenue',
                        data:totals,
                        borderColor:'#2563eb',
                        fill:false,
                        tension:0.4
                    }]
                },
                options:{
                    responsive:true,
                    maintainAspectRatio:false
                }
            });
            
        },

        renderPlanDistribution(dist){

            const el = document.getElementById('planDistribution');
            if(!el || !dist || typeof Chart === 'undefined') return;

            const labels = dist.map(p => p.name);
            const totals = dist.map(p => p.total);

            if(planChart) planChart.destroy();

            planChart = new Chart(el, {
                type:'doughnut',
                data:{
                    labels,
                    datasets:[{
                        data:totals,
                        backgroundColor:['#93c5fd','#2563eb','#1e3a8a']
                    }]
                },
                options:{
                    responsive:true,
                    maintainAspectRatio:false
                }
            });
        },

        //End
    };
});