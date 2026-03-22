__BORA_REGISTER_SERVICE__('jobQueue', async function(scope){

    const call = await scope.getService('callbora');

    const KEY = '__bora_jobs__';

    let queue = JSON.parse(localStorage.getItem(KEY) || '[]');

    function persist(){
        localStorage.setItem(KEY, JSON.stringify(queue));
    }

    async function process(){

        if(!navigator.onLine) return;

        for(const job of [...queue]){

            try{
                await call.request(job);
                queue = queue.filter(j=> j.id !== job.id);
                persist();
            }
            catch(e){
                console.warn('Job failed, retry later');
                break;
            }
        }
    }

    function add(job){
        job.id = Date.now() + '_' + Math.random();
        queue.push(job);
        persist();
        process();
    }

    window.addEventListener('online', process);

    return { add, process };
});