__BORA_REGISTER_PLUGIN__(
    {
        name: 'dashboards.workspace',
        contract: 'workspace'
    },
    async function(scope){

        const resources =
            await scope.getService(
                'resources'
            );

        const appState =
            await scope.getService(
                'state'
            );

        const local = {

            mounted:false,

            dashboardUid:null,

            ui:null,

            state:null,

            realtime:null,

            api:null

        };

        function ensureServices(){

            if(
                local.ui
            ){
                return;
            }

            local.ui =
                new DashboardsUI(
                    scope
                );

            local.state =
                new DashboardsState(
                    local.ui
                );

            local.realtime =
                new DashboardsRealtime({

                    scope,

                    state:local.state,

                    ui:local.ui

                });

            local.api =
                new DashboardsAPI(
                    resources
                );

        }

        async function ensureController(){

            return await scope.getPlugin(
                'dashboards.controller'
            );

        }

        async function mount(){

            console.log(
                '[DASHBOARDS] mount'
            );

            const ctx =
                window.__DASBOARDS_CONTEXT__
                || {};

            if(
                !ctx.dashboardUid
            ){
                return;
            }

            if(
                local.mounted
            ){
                return;
            }

            ensureServices();

            await ensureController();

            local.dashboardUid =
                ctx.dashboardUid;

            appState
                .scope('dashboards')
                .set(
                    'dashboard',
                    ctx.dashboardUid
                );

            local.ui.init();

            await local.api.dashboard(
                ctx.dashboardUid
            );

            local.realtime.subscribeDashboard(
                ctx.dashboardUid
            );

            scope.on(
                'dashboards.checkout.rendered',
                async ({ plugin, data }) => {

                    const gateway =
                        await scope.getPlugin(
                            plugin
                        );

                    await gateway.init(
                        data
                    );

                }
            );

            local.mounted = true;

        }

        function unmount(){

            if(
                !local.mounted
            ){
                return;
            }

            local.realtime.destroy();

            local.ui.destroy();

            appState
                .scope('dashboards')
                .set(
                    'dashboard',
                    null
                );

            local.dashboardUid =
                null;

            local.mounted =
                false;

        }

        return {

            mount,

            unmount,

            get ui(){

                return local.ui;

            },

            get state(){

                return local.state;

            },

            get api(){

                return local.api;

            },

            get realtime(){

                return local.realtime;

            },

            get dashboardUid(){

                return local.dashboardUid;

            }

        };

    }
);