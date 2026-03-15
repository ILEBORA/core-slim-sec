class InboxTyping {

    constructor(scope, callbora, ui){

        this.scope = scope;
        this.callbora = callbora;
        this.ui = ui;

        this.threadId = null;
        this.timer = null;
        this.input = null;

        this.boundHandler = this.handleInput.bind(this);
    }

    bind(threadId){

        this.threadId = threadId;

        const form = document.querySelector('.composer');
        if(!form) return;

        this.input = form.querySelector('input[name="body"]');
        if(!this.input) return;

        this.input.addEventListener('input', this.boundHandler);
    }

    unbind(){

        if(!this.input) return;

        this.input.removeEventListener('input', this.boundHandler);

        this.input = null;
        this.threadId = null;
    }

    handleInput(){

        if(!this.threadId) return;

        // typing start
        this.callbora.post(
            `api/modules/inbox/typing-start/${this.threadId}`
        );

        clearTimeout(this.timer);

        this.timer = setTimeout(()=>{

            this.callbora.post(
                `api/modules/inbox/typing-stop/${this.threadId}`
            );

        },1200);
    }

    handleRealtime(data){

        switch(data.type){

            case 'typing.start':
                this.ui.showTyping();
            break;

            case 'typing.stop':
                this.ui.hideTyping();
            break;

        }

    }
}