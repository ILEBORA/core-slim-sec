class InboxNotifications {

    constructor(ui, navigation){

        this.ui = ui;
        this.navigation = navigation;
    }

    bumpThread(data){

        const {thread_id, preview, time} = data;

        let item = this.ui.getThreadItem(thread_id);

        if(!item){

            this.ui.createThreadItem({
                thread_id,
                preview,
                time
            });

            return;

        }

        this.ui.updateThreadPreview(item, preview);
        this.ui.updateThreadTime(item, time);

        ui.bumpThread(thread_id);
        //

        if(this.ui.getActiveThread() !== thread_id){
            // Notify
            this.ui.incrementThreadBadge(thread_id);
            
            this.notifyThread(thread_id, preview);
        }

    }
    notifyThread(threadId, preview){

        if(document.hidden && "Notification" in window){

            new Notification("New message", {
                body: preview
            });

        } else {
            alertBora.notify(
                'New message',
                preview || 'You received a message',
                4,
                () => {
                    this.navigation.go(`portal/inbox/show/${threadId}`);
                    setTimeout(()=>{
                        ui.scrollBottom();
                    },300);
                }
            );
        }

    }
}