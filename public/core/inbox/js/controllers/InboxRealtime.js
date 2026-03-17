class InboxRealtime{

    constructor(scope, ui, typing, presence, notifications){

        this.scope  = scope;
        this.ui     = ui;
        this.typing = typing;
        this.presence = presence;
        this.notifications = notifications;

        this.threadHook = null;
        
        this.userId = rd('uID') ?? window.MAIN_USER_ID ?? null;
    }

    initUserChannel(){

        if(!this.userId) return;

        this.scope.on(
            `realtime:inbox:user:${this.userId}`,
            this.handleUserEvent.bind(this)
        );
    }

    subscribeThread(threadId){
        console.log('subscribeThread:: ',threadId);
        if(this.threadHook){
            this.scope.off(this.threadHook, this.handleThreadEvent);
        }

        this.threadHook = `realtime:inbox:thread:${threadId}`;

        this.scope.on(this.threadHook, this.handleThreadEvent.bind(this));
    }

    handleUserEvent(e){

        const data = e?.payload;
        if(!data) return;

        if(data.type === 'thread.bumped'){
            // this.ui.updateThreadPreview(data);
            this.notifications.bumpThread(data);
        }

        if(data.type === 'inbox.toast'){
            // Nothing like data.message
            this.notifications.notifyThread(data);
            // alertBora.notify(`Inbox Message from ${data.sender_id} with id ${data.message_id} for thread ${data.thread_id}`);
        }
    }

    handleThreadEvent(e){
        console.log('HANDLE THREAD EVENT:: ', e);
        const data = e?.payload;
        if(!data) return;

        console.log(
            "message from",
            data.sender_id,
            "current user",
            window.MAIN_USER_ID
        );

        switch(data.type){

            case 'message.sent':
                this.ui.appendMessage(data);
            break;

            case 'typing.start':
            case 'typing.stop':
                this.typing.handleRealtime(data);
            break;

            case 'presence.update':
                this.presence.update(data);
            break;

            case 'thread.bumped':
                this.notifications.bumpThread(data);
            break;
        }
    }

    destroy(){
        if(this.threadHook){
            this.scope.off(this.threadHook, this.handleThreadEvent);
        }
    }
}