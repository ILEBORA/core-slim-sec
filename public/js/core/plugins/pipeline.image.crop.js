__BORA_REGISTER_PLUGIN__('pipeline.image.crop', function(scope){

    function loadScript(src){
        return new Promise((resolve, reject) => {

            // prevent duplicate loads
            if(document.querySelector(`script[src="${src}"]`)){
                return resolve();
            }

            const script = document.createElement('script');
            script.src = src;
            script.async = true;

            script.onload = resolve;
            script.onerror = reject;

            document.head.appendChild(script);
        });
    }

    return {
        priority: 50,

        async process(ctx){

            if(!ctx.file.type.startsWith('image/')) return ctx;

            if(!window.Cropper){
                await global.__BORA_LOADER__.ensure('lib.cropper');
            }

            return new Promise((resolve) => {

                const reader = new FileReader();

                reader.onload = function(e){

                    const img = document.createElement('img');
                    img.src = e.target.result;

                    $('#composerEditor').html(img);

                    const cropper = new Cropper(img, {
                        viewMode: 1,
                        autoCropArea: 1
                    });

                    $('#applyEdit').off().on('click', function(){
                        cropper.getCroppedCanvas().toBlob((blob)=>{
                            ctx.file = blob;
                            resolve(ctx);
                        }, 'image/jpeg', 0.9);
                    });

                    $('#skipEdit').off().on('click', () => resolve(ctx));
                    $('#cancelEdit').off().on('click', () => resolve(null));
                };

                reader.readAsDataURL(ctx.file);
            });
        }
    };
});