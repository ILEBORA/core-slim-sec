__BORA_REGISTER_PLUGIN__('pipeline.image.validate', function(){

    return {
        priority: 10,

        async process(ctx){

            if(!ctx.file.type.startsWith('image/')){
                return ctx; // skip non-images
            }

            if(ctx.file.size > 5 * 1024 * 1024){
                alert('Image too large');
                return null;
            }

            return ctx;
        }
    };
});