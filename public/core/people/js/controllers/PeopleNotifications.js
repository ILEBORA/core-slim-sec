class PeopleNotifications {

    constructor(ui, navigation) {
        this.ui         = ui;
        this.navigation = navigation;
    }

    notifyFollow(person) {
        alertBora.notifyRich({
            title: 'New Follow',
            body: `${person.name} followed you`,
            onClick: () => {
                this.navigation.go(`portal/people/${person.id}`);
            }
        });
    }
}