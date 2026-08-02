__BORA_REGISTER_PLUGIN__('activity.composer', async function(scope){

    const uid = await scope.getService('uid');

    let attachments = [];
    let bound = false;

    function bindUI(){
        if(bound) return;
        // alert('bind');
        $(document).on('click','.attach-photo', openFileDialog);
        $(document).on('change','#composerUpload', uploadFiles);
        $(document).on('click','.remove-media', handleRemoveMedia);

        bound = true;

    }

    function handleRemoveMedia(){
        const parent = $(this).closest('.composer-media');
        const id = parent.data('id');

        attachments = attachments.filter(m => m.id !== id);

        parent.remove();

        updateHiddenField();
    }

    function openFileDialog(){
        $('#composerUpload').click();
    }

    function uploadFiles(e){
        const files = e.target.files;

        for(let file of files){

            const fd = new FormData();
            fd.append('file', file);

            $.ajax({
                url:'api/modules/activity/upload',
                method:'POST',
                data:fd,
                processData:false,
                contentType:false,

                success(resp){
                    // alert('respp');
                    if(!resp.success) return;
                    // alert('respp2');
                    const media = {
                        file: resp.data.file,
                        preview: resp.data.preview,
                        type: resp.data.type
                    };
                    console.log('MEDIA::', media);
                    attachments.push(media);

                    renderPreview(media);

                    updateHiddenField();
                }
            });
        }
    }

    function renderPreview(media){

        let html = '';

        if(media.type === 'image'){

            html = `
            <div class="composer-media">
                <img src="${media.preview}">
                <span class="remove-media">✕</span>
            </div>
            `;

        }

        if(media.type === 'video'){

            html = `
            <div class="composer-media">
                <video src="${media.preview}" controls></video>
                <span class="remove-media">✕</span>
            </div>
            `;
        }

        $('#composerPreview').append(html);
    }

    function updateHiddenField(){
        $('input.post-attachments')
            .val(JSON.stringify(attachments));
    }

    async function open(){
        showActivityComposer();
        // const popup = await scope.getPlugin('popup');

        // popup.open({
        //     mode:'form',
        //     module:'activity',
        //     group:'timeline',
        //     view:'add',
        //     size:'md'
        // });

        bindUI();
    }

    async function showActivityComposer(){

        const navigator = await scope.getService('navigator');

        navigator.go({
            route: 'activity.composer',
            params: { tab: 'post' },
            surface: 'popup'
        });
    }


    //
    async function runPipeline(file){

        let current = file;

        const processors = await scope.getPluginsByPrefix('image.processor').catch(() => []);

        for (let processor of processors){
            if(!processor.process) continue;

            current = await processor.process(current);

            if(!current) return null; // cancelled
        }

        return current;
    }

    async function uploadFiles(e){

        const files = Array.from(e.target.files);

        for (let file of files){

            let processed = await runPipeline(file);
            if(!processed) continue;

            await uploadProcessedFile(processed);
        }

        // reset input so same file can be reselected
        e.target.value = '';
    }

    function uploadProcessedFile(file){

        return new Promise((resolve) => {

            const fd = new FormData();
            fd.append('file', file);

            $.ajax({
                url:'api/modules/activity/upload',
                method:'POST',
                data:fd,
                processData:false,
                contentType:false,

                success(resp){
                    if(!resp.success) return resolve(null);

                    const media = normalizeMedia(resp.data);

                    attachments.push(media);
                    renderPreview(media);
                    updateHiddenField();

                    resolve(media);
                },

                error(){
                    resolve(null);
                }
            });

        });
    }

    function normalizeMedia(data){
        return {
            id: uid.generate('media'),
            file: data.file,
            preview: data.preview,
            type: data.type,
            meta: {},
            transforms: null
        };
    }

    function renderPreview(media){

        const el = $(`
            <div class="composer-media" data-id="${media.id}">
                ${renderMediaContent(media)}
                <span class="remove-media">✕</span>
            </div>
        `);

        $('#composerPreview').append(el);
    }

    function renderMediaContent(media){
        if(media.type === 'image'){
            return `<img src="${media.preview}">`;
        }

        if(media.type === 'video'){
            return `<video src="${media.preview}" controls></video>`;
        }

        return '';
    }

    return { open };

},{
    //requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/activity')
});