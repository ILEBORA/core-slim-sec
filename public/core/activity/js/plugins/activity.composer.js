__BORA_REGISTER_PLUGIN__('activity.composer', async function(scope){

    const callbora = await scope.getService('callbora');

    let attachments = [];
    let bound = false;

    function bindUI(){

        /*
        | Remove previous namespace
        */

        $(document).off('.activity-composer');

        /*
        | Upload
        */

        $(document).on(
            'click.activity-composer',
            '.attach-photo',
            openFileDialog
        );

        $(document).on(
            'change.activity-composer',
            '#composerUpload',
            uploadFiles
        );

    }

    // function bindUIO(){
    //     // if(bound) return;
    //     // alert('bind');
    //     $(document).on('click','.attach-photo', openFileDialog);
    //     $(document).on('change','#composerUpload', uploadFiles);

    //     bound = true;

    // }

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
                    if(!resp.success){
                        alertBora.notify(
                            resp.message || 'Action failed',
                            'error',
                            5
                        );
                        return;
                    }
                    // alert('respp2');
                    const media = {
                        id:resp.data.id,
                        file: resp.data.file,
                        preview: resp.data.preview,
                        type: resp.data.type
                    };
                    console.log('MEDIA::', media);
                    attachments.push(media);

                    renderPreview(media);

                    updateHiddenField();  

                    alertBora.notify(
                            resp.message || 'Successful',
                            'success',
                            5
                        );
                }
            });
        }
    }

    function renderPreview(media){

        let html = '';

        /*
        | IMAGE
        */

        if(isImage(media.type)){

            html = `
            <div class="composer-media">

                <span
                    class="remove-media"
                    data-action="act-remove-media"
                    data-id="${media.id}"
                >
                    ✕
                </span>

                <img
                    class="added-media${media.id}"
                    src="${media.preview}"
                    data-id="${media.id}"
                >

                <div class="media-actions bottom">

                    <button
                        class="rotate-media"
                        data-action="act-rotate-media"
                        data-angle="-90"
                        data-id="${media.id}"
                    >
                        ⟲
                    </button>

                    <button
                        class="rotate-media"
                        data-action="act-rotate-media"
                        data-angle="90"
                        data-id="${media.id}"
                    >
                        ⟳
                    </button>

                </div>

            </div>
            `;

        }

        /*
        | VIDEO
        */

        if(isVideo(media.type)){

            html = `
            <div class="composer-media">

                <video
                    src="${media.preview}"
                    controls
                    preload="metadata"
                ></video>

                <span
                    class="remove-media"
                    data-action="act-remove-media"
                    data-id="${media.id}"
                >
                    ✕
                </span>

            </div>
            `;

        }

        $('#composerPreview').append(html);

    }

    function renderPreviewO(media){

        let html = '';

        if(media.type === 'image'){

            html = `
            <div class="composer-media">
                <span class="remove-media" data-action="act-remove-media" data-id="${media.id}">✕</span>
                <img class="added-media${media.id}" src="${media.preview}" data-id="${media.id}">
                <div class="media-actions bottom">
                    <button class="rotate-media" data-action="act-rotate-media" data-angle="-90" data-id="${media.id}">⟲</button>
                    <button class="rotate-media" data-action="act-rotate-media" data-angle="90" data-id="${media.id}">⟳</button>
                </div>
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

    function isImage(type=''){

        type = type.toLowerCase();

        return [
            'jpg',
            'jpeg',
            'png',
            'gif',
            'webp',
            'bmp',
            'svg'
        ].includes(type);

    }

    function isVideo(type=''){

        type = type.toLowerCase();

        return [
            'mp4',
            'webm',
            'mov',
            'avi',
            'mkv'
        ].includes(type);

    }

    function updateHiddenField(){

        $('input.post-attachments')
            .val(JSON.stringify(attachments));
    }

    async function open(){

        // const popup = await scope.getPlugin('popup');

        // popup.open({
        //     mode:'form',
        //     module:'activity',
        //     group:'timeline',
        //     view:'add',
        //     size:'md'
        // });

        const bNavigator = await scope.getService('navigator');

        // console.log('bNavigator',bNavigator);

        bNavigator.go({

            route: 'activity.composer',

            params:{},

            surface:'popup',

            onLoaded: ()=>{
                // alert('bind');
                bindUI();
            }
        });

        // bindUI();
    }

    //Options
    async function handleRemoveMedia(el){
        let id = $(el).data('id');

        if(!id) return;

        callbora.post(`api/modules/app/agent/remove/${id}`, {
            id: id
        }).then(function(response){
            if(response.success){
                alertBora.success('Media removed.');
            } else {
                alertBora.error(response.message || 'Failed');
            }

        });

    }

    async function handleRotateMedia(el){
        let id = $(el).data('id');
        let angle = $(el).data('angle');
        const container = $(el).closest('.composer-media');

        if(!id || !angle) return;

        callbora.post(`api/modules/app/agent/rotate`, {
            id: id,
            angle: angle
        }).then(function(response){
            if(response.success){
                alertBora.success(`Rotated ${angle}.`);

                // bust cache to force reload
                const img = container.find(`img.added-media${id}`);

                const newSrc = img.attr('src') + '?v=' + Date.now();
                img.attr('src', newSrc);
            } else {
                alertBora.error(response.message || 'Failed');
            }

        });

    }

    function reset(){
        attachments = [];
    }

    return { open, handleRemoveMedia, handleRotateMedia, reset };

},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/activity')
});