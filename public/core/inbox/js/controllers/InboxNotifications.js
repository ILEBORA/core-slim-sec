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

        // this.bumpThread(thread_id);
        //

        if(this.ui.getActiveThread() !== thread_id){
            // Notify
            this.ui.incrementThreadBadge(thread_id);
            
            //TODO:: notify
            // this.notifyThread(thread_id, preview);
        }

    }
    notifyThread(data){

        const preview = this.formatPreview(data);

        const isActiveThread =
            this.ui.getActiveThread() === data.thread_id;

        // 🔕 Don't notify if already in thread
        if (isActiveThread) return;

        // =========================
        // 🔔 Browser Notification
        // =========================
        if(document.hidden && "Notification" in window){

            if (Notification.permission === 'granted') {

                const n = new Notification(preview.title, {
                    body: preview.body,
                    icon: '/assets/img/avatar-default.png', // optional
                    tag: `thread-${data.thread_id}`, // 👈 prevents spam stacking
                    data: {
                        thread_id: data.thread_id
                    }
                });

                n.onclick = () => {
                    window.focus();
                    this.navigation.go(`portal/inbox/show/${data.thread_id}`);
                    setTimeout(()=>this.ui.scrollBottom(),300);
                    n.close();
                };

            } else if (Notification.permission !== 'denied') {

                Notification.requestPermission();

            }

            return;
        }

        // =========================
        // 🔔 In-app Toast
        // =========================

        alertBora.notifyRich({
            title: preview.title,
            body: preview.body,
            delay: 4,
            sound: true,
            onClick: () => {
                this.navigation.go(`portal/inbox/show/${data.thread_id}`);
                setTimeout(()=>this.ui.scrollBottom(),300);
            }
        });
    }

    // notifyThreadO(data){
    //     const preview = formatPreview(data);

    //     if(document.hidden && "Notification" in window){

    //         new Notification("New message", {
    //             body: preview
    //         });

    //     } else {

    //         const isActiveThread =
    //             this.ui.getActiveThread() === data.thread_id;
                    
    //         alertBora.notifyRich({
    //             title: preview.title,
    //             body: preview.body,
    //             delay: 4,
    //             sound: !isActiveThread, // 👈 key logic
    //             onClick: () => {
    //                 this.navigation.go(`portal/inbox/show/${data.thread_id}`);
    //                 setTimeout(()=>this.ui.scrollBottom(),300);
    //             }
    //         });
    //         // alertBora.notify(
    //         //     'New message',
    //         //     preview || 'You received a message',
    //         //     4,
    //         //     () => {
    //         //         this.navigation.go(`portal/inbox/show/${data.thread_id}`);
    //         //         setTimeout(()=>{
    //         //             ui.scrollBottom();
    //         //         },300);
    //         //     }
    //         // );
    //     }

    // }

    formatPreview(data){

        let body = '';

        switch(data.type_hint){

            case 'image':
                body = '📷 Photo';
            break;

            case 'video':
                body = '🎥 Video';
            break;

            case 'file':
                body = '📎 Attachment';
            break;

            case 'system':
                body = this.truncate(data.body || 'System update', 60);
            break;

            default:
                body = this.truncate(data.body || '', 60);
        }

        return {
            title: data.sender_name || 'New message',
            body: body,
            raw: data // 👈 useful for future reuse
        };
    }

    truncate(text, max = 60){
        if(!text) return '';
        return text.length > max
            ? text.slice(0, max) + '…'
            : text;
    }
}