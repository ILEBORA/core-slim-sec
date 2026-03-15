__BORA_REGISTER_PLUGIN__('ActivityComposer', function(scope){

    let attachments = [];
    let bound = false;

    function bindUI(){
        if(bound) return;
        alert('bind');
        $(document).on('click','.attach-photo', openFileDialog);
        $(document).on('change','#composerUpload', uploadFiles);

        bound = true;

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

                    if(!resp.success) return;

                    const media = {
                        file: resp.data.file,
                        preview: resp.data.preview,
                        type: resp.data.type
                    };

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

    function open(){

        const popup = scope.getService('popup');

        popup.open({
            mode:'form',
            module:'activity',
            group:'timeline',
            view:'add',
            size:'md'
        });

        bindUI();
    }

    return { open };

});