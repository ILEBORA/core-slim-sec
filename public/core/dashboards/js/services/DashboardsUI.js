class DashboardsUI
{

    init(){

        this.root =
            $('[data-dashboard]');

    }

    render(dashboard){

        bindings.patch(

            this.root,

            dashboard

        );

    }

    destroy(){

        this.root=null;

    }

}