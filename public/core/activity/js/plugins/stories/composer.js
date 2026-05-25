__BORA_REGISTER_PLUGIN__('activity.stories.composer', async function(scope){

    let bound = false;

    function mount(){

        if(bound) return;

        bind();

        bound = true;
    }

    function bind(){

        $(document).on(
            'click',
            '#storyPreview',
            openFileDialog
        );

        $(document).on(
            'change',
            '#storyUpload',
            handleFile
        );

    }

    function openFileDialog(){

        $('#storyUpload').click();

    }

    function handleFile(e){

        const file = e.target.files[0];

        if(!file) return;

        renderPreview(file);

    }

    function renderPreview(file){

        const url = URL.createObjectURL(file);

        let html = '';

        if(file.type.startsWith('image')){

            html = `
                <img
                    src="${url}"
                    class="story-preview-media"
                >
            `;

        }

        if(file.type.startsWith('video')){

            html = `
                <video
                    src="${url}"
                    class="story-preview-media"
                    autoplay
                    muted
                    loop
                ></video>
            `;

        }

        $('#storyPreview').html(html);

    }

    return {
        mount
    };

});