class InboxAPI{

    constructor(controllers){

        this.loader   = controllers.loader;
        this.ui       = controllers.ui;
        this.realtime = controllers.realtime;
    }

    loadThread(id){
        this.loader.load(id);
    }

    openThread(id){
        this.ui.setActiveThread(id);
        this.ui.setView('thread');
        this.realtime.subscribeThread(id);
        this.loader.load(id);
    }

    appendMessage(msg){
        this.ui.appendMessage(msg);
    }

}


$(function(){
    // alert('Inbox here');
    alertBora.notifyRich({
        title: 'Test',
        body: 'Test message',
        delay: 40,
        sound: true,
        onClick: () => {
            let url = `portal/inbox/show/6`;
            const nav = window.__BORA_APP__?.service('navigation');
            if(nav){
                nav.go(url);
            }else{
                window.location.href = url;
            }
            setTimeout(()=>this.ui.scrollBottom(),300);
        }
    });
});

   