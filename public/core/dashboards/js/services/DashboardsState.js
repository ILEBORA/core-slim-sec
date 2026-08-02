class DashboardsState
{
    constructor(ui){
        this.ui = ui;
    }

    patch(dashboard){
        this.dashboard =
        dashboard;

        this.ui.render(
            dashboard
        );
    }

}