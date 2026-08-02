class DashboardsAPI
{

    constructor(
        resources
    ){

        this.resources = resources;

    }

    async dashboard(
        uid
    ){

        return await this.resources.load(
            'dashboard',
            uid
        );

    }

    // async invoice(
    //     uid
    // ){

    //     return await this.resources.load(
    //         'invoice',
    //         uid
    //     );

    // }

    // async subscription(
    //     uid
    // ){

    //     return await this.resources.load(
    //         'subscription',
    //         uid
    //     );

    // }

    // async payment(
    //     uid
    // ){

    //     return await this.resources.load(
    //         'payment',
    //         uid
    //     );

    // }

}