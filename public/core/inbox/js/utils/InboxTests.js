window.inboxTest = {

    message(thread=1){

        const scope = window.__BORA_APP__;

        scope.emit(
            `realtime:inbox:thread:${thread}`,
            {
                payload:{
                    type:"message.sent",
                    id: Date.now(),
                    thread_id: thread,
                    html:"<div class='message'>Test message</div>"
                }
            }
        );

    },

    typing(thread=1){

        const scope = window.__BORA_APP__;

        scope.emit(
            `realtime:inbox:thread:${thread}`,
            {
                payload:{
                    type:"typing.start"
                }
            }
        );

    }

};