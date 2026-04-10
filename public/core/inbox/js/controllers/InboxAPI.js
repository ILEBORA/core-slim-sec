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

        this.ui.setActiveThread(id);
    }

    appendMessage(msg){
        this.ui.appendMessage(msg);
    }

}
   