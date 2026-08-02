class DashboardsRealtime
{

    constructor({
        scope,
        ui,
        state
    }){

        this.scope = scope;
        this.ui = ui;
        this.state = state;

        this.handlers = [];

    }

    subscribeDashboard(uid){
        scope.on(
            'realtime:dashboard.updated',

            event=>{
                this.state.patch(
                    event.dashboard
                );
            }
        );

    }

    destroy(){

        

    }

}