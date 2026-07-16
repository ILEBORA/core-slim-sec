__BORA_REGISTER_PLUGIN__(
    'ui.bindings',
    
    async function(scope){
    
        const $ =
            await scope.getService(
                'jquery'
            );
    
        const state =
            await scope.getService(
                'state'
            );

        const dom =
            await scope.getService(
                'ui.dom'
            );
    
        const renderers = new Map();
    
        const directives = new Map();
    
        const mounted = new WeakMap();

        const DEBUG = true;
        // alert(DEBUG);
    
        function renderer(
            name,
            fn
        ){
            renderers.set(
                name,
                fn
            );
        }
    
        function directive(
            name,
            fn
        ){
            directives.set(
                name,
                fn
            );
        }

        const binders = [];

        const registries = {

            scalar: [],
        
            object: [],
        
            list: []
        
        };

        function register(def){

            registries[
                def.type
            ].push({
        
                priority: 0,
        
                ...def
        
            });
        
            registries[
                def.type
            ].sort(
                (a,b)=>
                    b.priority-a.priority
            );
        
        }

        function mount(root = document){

            initialize();
        
            // const targets = [
        
            //     {
            //         selector: '[data-bind]',
            //         type: 'scalar'
            //     },
        
            //     {
            //         selector: '[data-bind-object]',
            //         type: 'object'
            //     },
        
            //     {
            //         selector: '[data-bind-list]',
            //         type: 'list'
            //     }
        
            // ];
        
            // targets.forEach(target => {
        
            //     root
            //         .querySelectorAll(target.selector)
            //         .forEach(el => {
        
            //             compile(
            //                 el,
            //                 target.type
            //             );
        
            //         });
        
            // });

            dom.register({

                name:'bindings',
            
                priority:100,
            
                selector:
                    '[data-bind],[data-bind-object],[data-bind-list]',
            
                mount(el){
            
                    bind();
            
                },
            
                destroy(el){
            
                    unmount(el);
            
                }
            
            });
        
        }

        function bind(root = document){
            // alert('bind called');
            initialize();

            const targets = [
        
                {
                    selector: '[data-bind]',
                    type: 'scalar'
                },
        
                {
                    selector: '[data-bind-object]',
                    type: 'object'
                },
        
                {
                    selector: '[data-bind-list]',
                    type: 'list'
                }
        
            ];
        
            targets.forEach(target => {
        
                root
                    .querySelectorAll(target.selector)
                    .forEach(el => {
                        if(DEBUG){
                            el.classList.add('ui-bound');
                        }
                        compile(
                            el,
                            target.type
                        );
        
                    });
        
            });
        }


        function destroy(root = document){

            root
                .querySelectorAll(
                    '[data-bind],[data-bind-object],[data-bind-list]'
                )
                .forEach(el => {
        
                    const bindings =
                        mounted.get(el);
        
                    if(!bindings){
                        return;
                    }
        
                    bindings.forEach(binding => {
        
                        binding.destroy();
        
                    });
        
                    mounted.delete(el);
        
                });
        
        }
        
        let initialized=false;

        function initialize(){

            if(initialized){
                return;
            }

            initialized=true;

            registerDefaults();

        }

        function registerDefaults(){

            /*
            |--------------------------------------------------------------------------
            | Object
            |--------------------------------------------------------------------------
            */
        
            register({
        
                type: 'object',
        
                name: 'default',
        
                priority: 1,
        
                test(){
        
                    return true;
        
                },
        
                create(ctx){
                    // console.log('[DEF]', ctx);
                    return new ObjectBinding(
                        ctx
                    );
        
                }
        
            });
        
            /*
            |--------------------------------------------------------------------------
            | List
            |--------------------------------------------------------------------------
            */
        
            register({
        
                type: 'list',
        
                name: 'default',
        
                priority: 1,
        
                test(){
        
                    return true;
        
                },
        
                create(ctx){
        
                    return new ListBinding(
                        ctx
                    );
        
                }
        
            });
        
            /*
            |--------------------------------------------------------------------------
            | Scalar Bindings
            |--------------------------------------------------------------------------
            */
        
            register({
        
                type: 'scalar',
        
                name: 'html',
        
                priority: 100,
        
                test(ctx){
        
                    return ctx.element.hasAttribute(
                        'data-bind-html'
                    );
        
                },
        
                create(ctx){
        
                    return new HtmlBinding(
                        ctx
                    );
        
                }
        
            });
        
            register({
        
                type: 'scalar',
        
                name: 'attribute',
        
                priority: 90,
        
                test(ctx){
        
                    return ctx.element.hasAttribute(
                        'data-bind-attr'
                    );
        
                },
        
                create(ctx){
        
                    return new AttrBinding(
                        ctx
                    );
        
                }
        
            });
        
            register({
        
                type: 'scalar',
        
                name: 'class',
        
                priority: 80,
        
                test(ctx){
        
                    return ctx.element.hasAttribute(
                        'data-bind-class'
                    );
        
                },
        
                create(ctx){
        
                    return new ClassBinding(
                        ctx
                    );
        
                }
        
            });
        
            register({
        
                type: 'scalar',
        
                name: 'show',
        
                priority: 70,
        
                test(ctx){
        
                    return ctx.element.hasAttribute(
                        'data-bind-show'
                    );
        
                },
        
                create(ctx){
        
                    return new ShowBinding(
                        ctx
                    );
        
                }
        
            });
        
            register({
        
                type: 'scalar',
        
                name: 'hide',
        
                priority: 60,
        
                test(ctx){
        
                    return ctx.element.hasAttribute(
                        'data-bind-hide'
                    );
        
                },
        
                create(ctx){
        
                    return new HideBinding(
                        ctx
                    );
        
                }
        
            });
        
            register({
        
                type: 'scalar',
        
                name: 'disabled',
        
                priority: 50,
        
                test(ctx){
        
                    return ctx.element.hasAttribute(
                        'data-bind-disabled'
                    );
        
                },
        
                create(ctx){
        
                    return new DisabledBinding(
                        ctx
                    );
        
                }
        
            });
        
            register({
        
                type: 'scalar',
        
                name: 'style',
        
                priority: 40,
        
                test(ctx){
        
                    return ctx.element.hasAttribute(
                        'data-bind-style'
                    );
        
                },
        
                create(ctx){
        
                    return new StyleBinding(
                        ctx
                    );
        
                }
        
            });
        
            /*
            |--------------------------------------------------------------------------
            | Default Text Binding
            |--------------------------------------------------------------------------
            */
        
            register({
        
                type: 'scalar',
        
                name: 'text',
        
                priority: 1,
        
                test(){
        
                    return true;
        
                },
        
                create(ctx){
        
                    return new TextBinding(
                        ctx
                    );
        
                }
        
            });
        
        }

        function compile(
            element,
            type
        ){
        
            const key =
        
                type === 'scalar'
                    ? element.dataset.bind
                    : type === 'object'
                        ? element.dataset.bindObject
                        : element.dataset.bindList;
        
            if(!key){
                return;
            }
        
            const ctx = {
        
                scope,
        
                state,
        
                key,
        
                element,
        
                renderers,
        
                directives
        
            };
        
            const binder =
        
                registries[type]
                    .find(
                        b => b.test(ctx)
                    );
        
            if(!binder){
                return;
            }
        
            const instance =
                binder.create(ctx);
        
            instance.mount();
        
            mounted.set(
                element,
                [instance]
            );
        
        }

        function destroyElement(element){

            const bindings =
                mounted.get(element);
        
            if(!bindings){
                return;
            }
        
            bindings.forEach(binding => {
        
                binding.destroy();
        
            });
        
            mounted.delete(element);
        
        }

        function unmount(root = document){

            root
                .querySelectorAll(
                    '[data-bind],[data-bind-object],[data-bind-list]'
                )
                .forEach(
                    destroyElement
                );
        
        }

        return {
            mount, 
            unmount,
            renderer,
            directive,

            register,

            bind
        }

        // End plugin
});

    

class Binding{

    constructor(ctx){

        Object.assign(this, ctx);

        this.el = ctx.element;

        this.unsub = null;

    }

    watch(callback){

        if(this.unsub){
            this.unsub();
        }
    
        this.unsub =
            this.state.subscribe(
                this.key,
                callback,
                true
            );
    
        return this.unsub;
    
    }

    mount(){}

    destroy(){

        this.unsub?.();

        this.unsub = null;

    }

}

class TextBinding
extends Binding{

    mount(){
        this.watch(value => {

            if(
                this.el.textContent
                !=
                (
                    value ??
                    ''
                )
            ){

                this.el.textContent =
                    value ?? '';

            }

        });
        

    }

}

class HtmlBinding
extends Binding{

    mount(){
        this.watch(value => {

            const html =
                value ?? '';

            if(
                this.el.innerHTML
                != html
            ){

                this.el.innerHTML =
                    html;

            }

        });

    

    }

}

class AttrBinding extends Binding{

    constructor(ctx){

        super(ctx);

        this.attr =
            this.el.dataset.bindAttr;

    }

    mount(){

        this.watch(value => {

            this.el.setAttribute(
                this.attr,
                value ?? ''
            );

        });

    }

}

class StyleBinding extends Binding{

    constructor(ctx){

        super(ctx);

        this.style =
            this.el.dataset.bindStyle;

    }

    mount(){
        this.watch(value => {

            this.el.style[
                this.style
            ] = value ?? '';

        });
       

    }

}


class ClassBinding extends Binding{

    constructor(ctx){

        super(ctx);

        this.className =
            this.el.dataset.bindClass;

    }

    mount(){
        this.watch(value => {

            this.el.classList.toggle(
                this.className,
                !!value
            );

        });

    }

}

class ObjectBinding extends Binding{

    mount(){

        const fields =
            this.el.querySelectorAll(
                '[data-field]'
            );

        this.unsub =
            this.state.subscribe(

                this.key,

                object => {

                    fields.forEach(field => {

                        const name =
                            field.dataset.field;

                        const value =
                            object?.[name];

                        const rendererName =
                            field.dataset.renderer;

                        if(rendererName){

                            const renderer =
                                this.renderers.get(
                                    rendererName
                                );

                            if(renderer){

                                renderer(
                                    field,
                                    value,
                                    object
                                );

                                return;
                            }

                        }

                        if(
                            !object ||
                            !Object.prototype.hasOwnProperty.call(object, name)
                        ){
                            return;
                        }

                        field.textContent = value ?? '';

                    });

                },

                true

            );

    }

}

class ObjectBindingO 
extends Binding{

    mount(){


        // console.log(
        //     'SUBSCRIBED TO',
        //     this.key
        // );

        const fields =
            this.el.querySelectorAll(
                '[data-field]'
            );
        
        
        this.unsub =
            this.state.subscribe(

                this.key,

                object => {

                    fields.forEach(field => {

                        const name =
                            field.dataset.field;

                        if(
                            !object ||
                            !Object.prototype.hasOwnProperty.call(object, name)
                        ){
                            return;
                        }
                        field.textContent =
                            object?.[name] ?? '';

                    });

                },

                true

            );

    }

}

class ShowBinding
extends Binding{

    mount(){
        this.watch(value => {

            this.el.hidden =
                        !value;

        });
        // this.unsub =
        //     this.state.subscribe(

        //         this.key,

        //         value => {

        //             this.el.hidden =
        //                 !value;

        //         },

        //         true
        //     );

    }

}

class HideBinding
extends Binding{

    mount(){
        this.watch(value => {

            this.el.hidden =
                        !!value;

        });
        // this.unsub =
        //     this.state.subscribe(

        //         this.key,

        //         value => {

        //             this.el.hidden =
        //                 !!value;

        //         },

        //         true
        //     );

    }

}

class DisabledBinding
extends Binding{

    mount(){
        this.watch(value => {
            this.el.disabled =
                        !!value;
        });
        // this.unsub =
        //     this.state.subscribe(

        //         this.key,

        //         value => {

        //             this.el.disabled =
        //                 !!value;

        //         },

        //         true
        //     );

    }

}