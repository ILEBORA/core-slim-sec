__BORA_REGISTER_PLUGIN__('activity.story.composer', async function(scope){

    let file = null;
    let bound = false;

    function bindUI(){
        if(bound) return;

        $(document).on('click', '#storyPreview', openFileDialog);
        $(document).on('change', '#storyUpload', handleFile);

        bound = true;
    }

    function openFileDialog(){
        $('#storyUpload').click();
    }

    function handleFile(e){
        const f = e.target.files[0];
        if(!f) return;

        file = f;

        renderPreview(f);
    }

    function renderPreview(file){

        const url = URL.createObjectURL(file);
        let html = '';

        if(file.type.startsWith('image')){
            html = `<img src="${url}" class="story-preview-media">`;
        }

        if(file.type.startsWith('video')){
            html = `<video src="${url}" class="story-preview-media" autoplay muted loop></video>`;
        }

        $('#storyPreview').html(html);
    }

    async function open(){

        const popup = await scope.getPlugin('popup');

        popup.open({
            mode:'form',
            module:'activity',
            group:'story',
            view:'add',
            size:'lg'
        });

        bindUI();
    }

    return { open };

},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/activity/stories')
});