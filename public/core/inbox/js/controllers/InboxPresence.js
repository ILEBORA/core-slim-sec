class InboxPresence {

    constructor(ui){

        this.ui = ui;
    }

    update(data){
        
        const el = document.querySelector(
            `.thread-item[data-thread="${data.thread_id}"] .status-dot`
        );

        if(!el) return;

        el.classList.toggle('online', data.online);
    }
}