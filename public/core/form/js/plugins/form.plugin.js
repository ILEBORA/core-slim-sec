__BORA_REGISTER_PLUGIN__('form.plugin', async function(scope){

    class FormDraftManager {

        constructor(form, options = {}) {

            this.form = $(form);

            this.key =
                options.key ||
                'form_draft';

            this.exclude = options.exclude || [
                'password',
                'file'
            ];
        }

        init() {

            this.restore();

            this.bind();
        }

        bind() {

            const self = this;

            this.form.on(
                'input change',
                'input, textarea, select',
                function () {

                    self.save();
                }
            );
        }

        save() {

            let data = {};

            this.form.find(
                'input, textarea, select'
            ).each(function () {

                const el = $(this);

                const type = (
                    el.attr('type') || ''
                ).toLowerCase();

                const name = el.attr('name');

                if(!name) return;

                if(type === 'file') return;

                if(
                    type === 'checkbox'
                ){
                    data[name] =
                        el.is(':checked');

                    return;
                }

                if(
                    type === 'radio'
                ){

                    if(el.is(':checked')){

                        data[name] =
                            el.val();
                    }

                    return;
                }

                data[name] = el.val();
            });

            localStorage.setItem(
                this.key,
                JSON.stringify(data)
            );
        }

        restore() {

            const raw =
                localStorage.getItem(
                    this.key
                );

            if(!raw) return;

            let data = {};

            try {

                data = JSON.parse(raw);

            } catch(e){

                return;
            }

            Object.entries(data).forEach(
                ([name, value]) => {

                    const el =
                        this.form.find(
                            `[name="${name}"]`
                        );

                    if(!el.length) return;

                    const type =
                        (
                            el.attr('type') || ''
                        ).toLowerCase();

                    if(type === 'checkbox'){

                        el.prop(
                            'checked',
                            !!value
                        );

                        return;
                    }

                    if(type === 'radio'){

                        this.form.find(
                            `[name="${name}"][value="${value}"]`
                        ).prop(
                            'checked',
                            true
                        );

                        return;
                    }

                    el.val(value);

                    /*
                    | Trigger editor updates
                    */

                    el.trigger('change');
                }
            );
        }

        clear() {

            localStorage.removeItem(
                this.key
            );
        }
    }

    class BoraForm {

        constructor(form)
        {
            this.form = $(form);

            this.isDirtyFlag = false;

            this.hasSubmittedSuccessfully = false;

            this.init();

            
            
        }

        static boot(form)
        {
            const $form = $(form);

            if(
                $form.data('bora-form')
            ){
                return;
            }

            const instance =
                new BoraForm(form);

            $form.data(
                'bora-form',
                instance
            );
        }

        getName()
        {
            return (
                this.form.data('form-name')
                || 'unknown'
            );
        }

        init()
        {
            this.initDrafts();
            this.bindDirtyTracking();
            this.bindPopupCloseProtection();
        }

        initDrafts()
        {
            const key =
                this.form.data('draft-key');

            console.log(
                'Draft key:',
                key
            );

            if(!key){
                return;
            }

            this.draft =
                new FormDraftManager(
                    this.form,
                    { key }
                );

            this.draft.init();

            this.resetDirty();
        }

        bindPopupCloseProtection()
        {
            if(!this.draft){
                return;
            }

            scope.on(
                'popup:beforeClose',
                async (popup, force = false) => {
                    
                    /*
                    | Only forms inside popup
                    */

                    if(
                        !popup.$popup
                        .find(this.form)
                        .length
                    ){
                        return;
                    }

                    //
                    if(
                        this.hasSubmittedSuccessfully
                    ){
                        return;
                    }

                    /*
                    | Empty forms don't matter
                    */

                    if(!this.isDirty()){
                        return;
                    }

                    const keep =
                        alertBora.confirm(
                            'Keep your draft?'
                        );

                    if(keep){

                        this.draft.save();

                    } else {

                        this.draft.clear();
                    }
                }
            );
            
        }

        markSubmitted(response = null)
        {
            this.hasSubmittedSuccessfully = true;

            this.resetDirty();

            this.clearDraft();

            this.form.trigger(
                'bora.form.submitted',
                {
                    form: this,
                    response,
                    name: this.getName(),
                    draftKey: this.draft?.key
                }
            );
        }

        clearDraft()
        {
            if(this.draft){

                this.draft.clear();
            }
        }

        markDirty()
        {
            this.isDirtyFlag = true;
        }

        resetDirty()
        {
            this.isDirtyFlag = false;
        }

        isDirty()
        {
            return this.isDirtyFlag;
        }

        bindDirtyTracking()
        {
            this.form.on(
                'input change',
                'input, textarea, select',
                () => {

                    this.markDirty();
                }
            );
        }
    }

    class BoraFormObserver {

        constructor()
        {
            this.initExisting();

            this.observe();
        }

        initExisting()
        {
            $('form[data-bora-form]')
            .each((_, form) => {

                this.initForm(form);
            });
        }

        observe()
        {
            const observer =
                new MutationObserver(
                    (mutations) => {

                    mutations.forEach(
                        (mutation) => {

                        mutation.addedNodes.forEach(
                            (node) => {

                            if(
                                node.nodeType !== 1
                            ){
                                return;
                            }

                            if(
                                $(node).is(
                                    'form[data-bora-form]'
                                )
                            ){
                                this.initForm(node);
                            }

                            $(node)
                            .find(
                                'form[data-bora-form]'
                            )
                            .each((_, form) => {

                                this.initForm(form);
                            });
                        });
                    });
                });

            observer.observe(
                document.body,
                {
                    childList: true,
                    subtree: true
                }
            );
        }

        initForm(form)
        {
            BoraForm.boot(form);
        }
    }

    new BoraFormObserver();

    $(document).on(
        'bora.form.submitted',
        'form',
        function(e, detail){

            console.log('e', e);
            console.log('detail',detail);

            if(!detail?.name){
                return;
            }

            const [entity, action] =
                detail.name.split('.');

            scope.emit(
                detail.name,
                {
                    entity,
                    action,
                    data:
                        detail.response?.[
                            entity
                        ] || null,

                    response:
                        detail.response,

                    source:
                        detail.form
                }
            );
        }
    );

    $(document).on(
        'input',
        '[bora-transform]',
        function(){

            const type =
                this.getAttribute(
                    'bora-transform'
                );

            switch(type){

                case 'lowercase':

                    this.value =
                        this.value.toLowerCase();

                break;

                case 'uppercase':

                    this.value =
                        this.value.toUpperCase();

                break;

                case 'capitalize':

                    this.value =
                        this.value.replace(
                            /\b\w/g,
                            c => c.toUpperCase()
                        );

                break;

                case 'slug':

                    this.value =
                        this.value
                            .toLowerCase()
                            .replace(/\s+/g, '-')
                            .replace(/[^\w\-]+/g, '');

                break;

            }

        }
    );

    $(document).on(
        'click',
        '[data-action="form.clear"]',
        function(){

            const $form =
                $(this).closest('form');

            $form[0].reset();

            /*
            |-----------------------------------
            | Clear draft storage
            |-----------------------------------
            */

            const draftKey =
                $form.data('draft-key');

            if(draftKey){

                localStorage.removeItem(
                    'bora_form_' + draftKey
                );

            }

            /*
            |-----------------------------------
            | Trigger refresh hooks
            |-----------------------------------
            */

            $form.trigger('form:cleared');

        }
    );

    $.fn.dictionarySelect =
    async function(
        resource,
        options = {}
    ){

        const placeholder =
            options.placeholder
            ?? `Select ${resource}...`;

        const resources =
            await scope.getService(
                'resources'
            );

        const data =
            await resources.get(
                resource
            );

        return this.each(
            function(){

                $(this)
                    .append(
                        new Option(
                            '',
                            '',
                            false,
                            false
                        )
                    )
                    .select2({
                        width:
                            '100%',
                        placeholder,
                        allowClear:
                            true,
                        data
                    });
            }
        );
    };

    $.fn.peopleSelect = async function(options = {}) {

        const resources =
            await scope.getService(
                'resources'
            );

        const people =
            await resources.get(
                'people'
            );

        const placeholder =
            options.placeholder
                ?? 'Select person...';

        const entity =
            options.entity ?? 'person';

        return this.each(function () {

            const data = [
                {
                    id: '',
                    text: `Select ${entity}...`
                },
                ...people
            ];

            $(this).select2({
                width: '100%',
                placeholder: `Select ${entity}...`,
                allowClear: true,
                data
            });
        });
    };
    $.fn.peopleSelectO = async function(){

        const resources =
            await scope.getService(
                'resources'
            );

        const people =
            await resources.get(
                'people'
            );

        return this.select2({
            width: '100%',
            placeholder:
                'Search person...',
            data: people
        });
    };

    
    /*
    |--------------------------------------------------------------------------
    | Taxonomy Fields
    |--------------------------------------------------------------------------
    */

    function initTaxonomies(context = document)
    {
        $(context)
        .find('.bora-taxonomy')
        .each(function(){

            const $el = $(this);

            /*
            |--------------------------------------------------------------------------
            | Prevent Double Init
            |--------------------------------------------------------------------------
            */

            if(
                $el.data('taxonomy-init')
            ){
                return;
            }

            $el.data(
                'taxonomy-init',
                true
            );

            console.log(
                'Initializing taxonomy:',
                $el.attr('name')
            );

            const allowCreate =
                Number(
                    $el.data(
                        'taxonomy-create'
                    )
                ) === 1;

            /*
            |--------------------------------------------------------------------------
            | Ensure Select2 Exists
            |--------------------------------------------------------------------------
            */

            if(
                typeof $.fn.select2 !== 'function'
            ){

                console.error(
                    'Select2 is not loaded'
                );

                return;
            }

            $el.select2({

                width: '100%',

                tags: allowCreate,

                ajax: {

                    url:
                        'api/modules/form/taxonomy/search',

                    dataType: 'json',

                    delay: 250,

                    cache: true,

                    data(params){

                        return {

                            q:
                                params.term || '',

                            source:
                                $el.data(
                                    'taxonomy-source'
                                )
                        };
                    },

                    processResults(data){

                        return {

                            results:
                                data.results || []
                        };
                    }
                },

                /*
                |--------------------------------------------------------------------------
                | Allow Custom Creation
                |--------------------------------------------------------------------------
                */

                createTag(params){

                    const term =
                        $.trim(
                            params.term
                        );

                    if(term === ''){

                        return null;
                    }

                    return {

                        // id:
                        //     '__new__:' + term,
                        id:
                            '__taxonomy__|'
                            + $el.data('taxonomy-source')
                            + '|'
                            + term,

                        text:
                            term,

                        newTag:
                            true
                    };
                }
            });
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Initialize Existing
    |--------------------------------------------------------------------------
    */

    initTaxonomies();

    /*
    |--------------------------------------------------------------------------
    | Observe Dynamic DOM Changes
    |--------------------------------------------------------------------------
    */

    const taxonomyObserver =
        new MutationObserver(
            (mutations) => {

            mutations.forEach(
                (mutation) => {

                mutation.addedNodes.forEach(
                    (node) => {

                    if(
                        node.nodeType !== 1
                    ){
                        return;
                    }

                    initTaxonomies(node);
                });
            });
        });

    taxonomyObserver.observe(
        document.body,
        {
            childList: true,
            subtree: true
        }
    );

});