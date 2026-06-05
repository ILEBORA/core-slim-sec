class InboxRealtime{

    constructor(scope, ui, typing, presence, notifications){

        this.scope  = scope;
        this.ui     = ui;
        this.typing = typing;
        this.presence = presence;
        this.notifications = notifications;

        this.threadHook = null;
        
        this.userId = rd('uID') ?? window.MAIN_USER_ID ?? null;
        this.lastSound = 0;
    }

    initUserChannel(){
        if(!this.userId) return;
        // alert('initUserChannel: ' + this.userId);
        this.scope.off(`realtime:inbox:user:${this.userId}`);
        this.scope.on(
            `realtime:inbox:user:${this.userId}`,
            this.handleUserEvent.bind(this)
        );
    }

    async subscribeThread(threadId){
        
        console.log('subscribeThread:: ',threadId);
        
        if(this.threadHook){
            this.scope.off(this.threadHook, this.handleThreadEvent);
        }

        this.threadHook = `realtime:inbox:thread:${threadId}`;

        this.scope.on(this.threadHook, this.handleThreadEvent.bind(this));

        this.scope.on('realtime:inbox.message.received', (msg) => {

            const isActive = msg.thread_id === this.ui.getActiveThread();
            const isMine   = msg.sender_id === currentUserId;

            if(!isMine && !isActive){
                this.sound?.play('message');   // 🔔 play sound
                this.ui.incrementThreadBadge(msg.thread_id);
                this.ui.bumpThread(msg.thread_id);
                return;
            }

            this.ui.appendMessage(msg);
        });

        this.scope.on('realtime:inbox.message.delivered', (data) => {
            this.ui.updateMessageStatus(data.message_id, 'delivered');
        });

        this.scope.on('realtime:inbox.message.read', (data) => {
            this.ui.updateMessageStatus(data.message_id, 'read');
        });

    }

    handleUserEvent(e){
        const data = e?.payload;
        if(!data) return;

        switch(data.type){

            case 'thread.bumped':
                this.notifications.bumpThread(data);
            break;

            case 'inbox.toast':
                this.notifications.notifyThread(data);
            break;

            // NEW: unread count update
            case 'inbox.unread.updated':
                this.ui.updateUnreadBadge(data.count);
            break;

            // NEW: thread read
            case 'thread.read':
                this.ui.clearThreadBadge(data.thread_id);
            break;
        }
    }

    handleThreadEvent(e){
        // console.log('HANDLE THREAD EVENT:: ', e);
        const data = e?.payload;
        if(!data) return;

        // console.log(
        //     "message from",
        //     data.sender_id,
        //     "current user",
        //     window.MAIN_USER_ID
        // );

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