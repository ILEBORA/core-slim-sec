__BORA_REGISTER_PLUGIN__('pipeline.image.compress', function(){

    return {
        priority: 70,

        async process(ctx){

            if(!ctx.file.type.startsWith('image/')) return ctx;

            const canvas = document.createElement('canvas');
            const img = new Image();

            return new Promise((resolve) => {

                img.onload = function(){

                    canvas.width = img.width;
                    canvas.height = img.height;

                    const c = canvas.getContext('2d');
                    c.drawImage(img, 0, 0);

                    canvas.toBlob((blob)=>{
                        ctx.file = blob;
                        resolve(ctx);
                    }, 'image/jpeg', 0.8);
                };

                img.src = URL.createObjectURL(ctx.file);
            });
        }
    };
});