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

    class BoraTaxonomySelect {

        constructor(element) {
    
            this.el = $(element);
    
            this.input =
                this.el.find('.bora-taxonomy-input');

            this.originalPlaceholder =
                this.input.attr('placeholder')
                || 'Select option';
    
            this.value =
                this.el.find('.bora-taxonomy-value');
    
            this.dropdown =
                this.el.find('.bora-taxonomy-dropdown');
    
            this.source =
                this.el.data('taxonomy-source');
    
            this.allowCreate =
                Number(
                    this.el.data('taxonomy-create')
                ) === 1;
    
            this.timer = null;

            this.lastSelectedText = '';

            this.initializing = true;

            this.excludeParameter = this.el.data('taxonomy-exclude-parameter') || null;

            const excludeField = this.el.data('taxonomy-exclude');

            if (excludeField) {

                const excludeValue =
                    $(`[name="${excludeField}"]`).val();

                if (excludeValue) {
                    params.exclude_id = excludeValue;
                }
            }

            /*
            |--------------------------------------------------------------------------
            | Dependency
            |--------------------------------------------------------------------------
            */

            this.dependsOn =
                this.el.data('taxonomy-depends-on')
                || null;

            this.dependsParameter =
                this.el.data('taxonomy-depends-parameter')
                || 'parent_id';
    
            this.bind();

            this.bindDependency();

            this.initializeDependency();

            // prepopulate
            this.initializeValue();
        }

        

        async initializeValue() {

            const value = $.trim(
                this.value.val()
            );

            if (!value) {
                this.initializing = false;
                return;
            }
        
            /*
             * Nothing to hydrate.
             */
            if (!value) {
                return;
            }
        
            /*
             * New taxonomy values don't need
             * resolving through the database.
             */
            if (
                String(value).startsWith('__taxonomy__|')
            ) {
                return;
            }
        
            if (!this.source) {
                return;
            }
        
            try {
        
                const params = {
                    source: this.source,
                    id: value
                };
        
                /*
                 * Include dependency if applicable.
                 */
                const dependencyValue =
                    this.getDependencyValue();
        
                if (
                    this.dependsOn &&
                    dependencyValue
                ) {
                    params[this.dependsParameter] =
                        dependencyValue;
                }
        
                const response =
                    await fetch(
                        'api/modules/form/taxonomy/value?' +
                        new URLSearchParams(params)
                    );
        
                const data =
                    await response.json();
        
                if (
                    data.success &&
                    data.result
                ) {
        
                    this.input.val(
                        data.result.text
                    );

                    /*
                    * Tell dependent taxonomies that
                    * this field has been initialized.
                    */
                    this.el.trigger(
                        'taxonomy:initialized',
                        [data.result]
                    );
        
                }
        
            } catch (error) {
        
                console.error(
                    'Taxonomy value hydration failed',
                    error
                );
            } finally {

                this.initializing = false;
            }
        }

        
    
        initializeDependency() {

            this.updateState();
        
            /*
             * If this is a dependent field and
             * the parent already has a value, leave
             * it enabled.
             */
        
            if (
                this.dependsOn &&
                this.getDependencyValue()
            ) {
                return;
            }
        
            if (this.dependsOn) {
        
                this.input.prop(
                    'disabled',
                    true
                );
            }
        }
    
        bind() {
    
            this.input.on(
                'input',
                () => this.search()
            );
    
            // this.input.on(
            //     'focus',
            //     () => this.search()
            // );
            this.input.on(
                'focus.boraTaxonomy',
                () => this.search()
            );
            
            this.input.on(
                'click.boraTaxonomy',
                () => {
                    if (!this.input.val().trim()) {
                        this.search();
                    }
                }
            );

            // this.input.on(
            //     'input.boraTaxonomy',
            //     () => {
            //         this.search();
            
            //         // If this taxonomy is a parent,
            //         // notify dependent taxonomies.
            //         this.value.trigger('change');
            //     }
            // );

            this.input.on(
                'input.boraTaxonomy',
                () => {
            
                    const text =
                        $.trim(this.input.val());
            
                    /*
                     * If the user edits/removes the selected
                     * text, invalidate the selected value.
                     */
                    if (
                        !text ||
                        text !== this.lastSelectedText
                    ) {
            
                        this.value.val('');
            
                        this.value.trigger('change');
            
                        this.updateState();
                    }
            
                    this.search();
                }
            );
    
            $(document).on(
                'click.boraTaxonomy',
                (e) => {
    
                    if(
                        !this.el.is(e.target) &&
                        this.el.has(e.target).length === 0
                    ) {
                        this.close();
                    }
    
                }
            );
        }

        setValue(value, text = '') {

            const oldValue =
                this.value.val();

            const newValue =
                value == null
                    ? ''
                    : String(value);

            const changed =
                String(oldValue) !== newValue;

            this.input.val(text);

            this.value.val(newValue);

            this.lastSelectedText = text;

            if (changed) {
                this.value.trigger('change');
            }

            return changed;
        }

        bindDependency() {

            if (!this.dependsOn) {
                return;
            }
        
            const parent =
                $(`[name="${this.dependsOn}"]`);
        
            if (!parent.length) {
        
                console.warn(
                    'Taxonomy dependency not found:',
                    this.dependsOn
                );
        
                return;
            }
        
            parent.on(
                'change.boraTaxonomyDependency',
                () => {
        
                    this.reset();
        
                }
            );
        }

        getDependencyValue() {

            if (!this.dependsOn) {
                return null;
            }
        
            const parent =
                $(`[name="${this.dependsOn}"]`);
        
            if (!parent.length) {
                return null;
            }
        
            /*
             * Taxonomy fields store their actual
             * value in .bora-taxonomy-value.
             */
        
            const taxonomyValue =
                parent
                    .closest('.bora-taxonomy')
                    .find('.bora-taxonomy-value');
        
            if (taxonomyValue.length) {
                return taxonomyValue.val() || null;
            }
        
            return parent.val() || null;
        }

        reset() {
            const hadValue = !!this.value.val();

            this.input.val('');
        
            this.value.val('');
        
            this.dropdown.empty();
        
            this.close();
        
            this.updateState();
        
            if (hadValue) {
                this.value.trigger('change');
            }

            this.el.trigger(
                'taxonomy:reset',
                [null]
            );
        }

        updateState() {

            if (!this.dependsOn) {
        
                this.input.prop(
                    'disabled',
                    false
                );
        
                return;
            }
        
            const parentValue =
                this.getDependencyValue();
        
            const disabled =
                !parentValue;
        
            this.input.prop(
                'disabled',
                disabled
            );
        
            if (disabled) {
        
                this.input.attr(
                    'placeholder',
                    'Select parent first'
                );
        
            } else {
        
                this.input.attr(
                    'placeholder',
                    this.originalPlaceholder
                        || 'Select option'
                );
            }
        }
    
        search() {

            if (this.dependsOn) {
        
                const parentValue =
                    this.getDependencyValue();
        
                if (!parentValue) {
        
                    this.reset();
        
                    return;
                }
            }
        
            const q =
                $.trim(this.input.val());
        
            clearTimeout(this.timer);
        
            this.timer = setTimeout(
                () => this.fetch(q),
                q ? 250 : 0
            );
        }

        searchO() {

            if (this.dependsOn) {
        
                const parentValue =
                    this.getDependencyValue();
        
                if (!parentValue) {
        
                    this.reset();
        
                    return;
                }
            }
        
            const q =
                $.trim(this.input.val());
        
            clearTimeout(this.timer);
        
            this.timer = setTimeout(
                () => this.fetch(q),
                250
            );
        }
    
    
        async fetch(q) {
    
            if(!this.source){
                return;
            }

            const params = {
                q,
                source: this.source
            };

            const dependencyValue = this.getDependencyValue();

            if (this.dependsOn && dependencyValue) {

                params[this.dependsParameter] = dependencyValue;
            }
    
            try {
    
                this.loading();
    
                const response =
                    await fetch(
                        'api/modules/form/taxonomy/search?' +
                        new URLSearchParams(params)
                    );
    
                const data =
                    await response.json();
    
                this.render(
                    data.results || [],
                    q
                );
    
            } catch(error) {
    
                console.error(
                    'Taxonomy search failed',
                    error
                );
    
                this.dropdown.empty();
    
            }
    
        }
    
    
        loading() {
    
            this.dropdown
                .html(
                    '<div class="bora-taxonomy-loading">' +
                        'Searching...' +
                    '</div>'
                )
                .show();
        }
    
    
        render(results, query) {
    
            this.dropdown.empty();
    
            results.forEach(item => {
    
                // const option =
                //     $('<div>')
                //         .addClass(
                //             'bora-taxonomy-option'
                //         )
                //         .text(item.text)
                //         .attr(
                //             'data-value',
                //             item.id
                //         );

                const option =
                    $('<div>')
                        .addClass('bora-taxonomy-option')
                        .attr('data-value', item.id);

                if (item.html) {

                    option.html(item.html);

                } else {

                    option.text(item.text);
                }
    
                option.on(
                    'click',
                    () => this.select(item)
                );
    
                this.dropdown.append(option);
            });
    
    
            if(
                this.allowCreate &&
                query &&
                !results.some(
                    item =>
                        String(item.text).toLowerCase() ===
                        query.toLowerCase()
                )
            ) {
    
                const create =
                    $('<div>')
                        .addClass(
                            'bora-taxonomy-create'
                        )
                        .text(
                            `Create "${query}"`
                        );
    
                create.on(
                    'click',
                    () => this.create(query)
                );
    
                this.dropdown.append(create);
            }
    
    
            this.dropdown.show();
        }
    
    
        select(item) {
            // const oldValue = this.value.val();

            // const newValue = String(item.id);

            // const changed = String(oldValue) !== newValue;
            // this.input.val(
            //     item.text
            // );
    
            // this.value.val(
            //     item.id
            // );

            this.setValue(
                item.id,
                item.text
            );

            this.lastSelectedText = item.text;
    
            this.close();
    
            /*
            * Only notify dependents when the
            * actual selected value changed.
            */
            // if (changed) {

            //     this.value.trigger('change');

            // }
    
            this.el.trigger(
                'taxonomy:selected',
                [item]
            );
        }
    
    
        create(text) {
    
            const item = {
    
                id:
                    '__taxonomy__|' +
                    this.source +
                    '|' +
                    text,
    
                text: text,
    
                newTag: true
    
            };
    
            this.select(item);
        }
    
    
        close() {
    
            this.dropdown.hide();
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

                if(
                    $el.data('taxonomy-init')
                ){
                    return;
                }

                $el.data(
                    'taxonomy-init',
                    true
                );

                new BoraTaxonomySelect(this);
            });
    }

    // function initTaxonomies(context = document)
    // {
    //     $(context)
    //     .find('.bora-taxonomy')
    //     .each(function(){

    //         const $el = $(this);

    //         /*
    //         |--------------------------------------------------------------------------
    //         | Prevent Double Init
    //         |--------------------------------------------------------------------------
    //         */

    //         if(
    //             $el.data('taxonomy-init')
    //         ){
    //             return;
    //         }

    //         $el.data(
    //             'taxonomy-init',
    //             true
    //         );

    //         console.log(
    //             'Initializing taxonomy:',
    //             $el.attr('name')
    //         );

    //         const allowCreate =
    //             Number(
    //                 $el.data(
    //                     'taxonomy-create'
    //                 )
    //             ) === 1;

    //         /*
    //         |--------------------------------------------------------------------------
    //         | Ensure Select2 Exists
    //         |--------------------------------------------------------------------------
    //         */
 
    //         if(
    //             typeof $.fn.select2 !== 'function'
    //         ){

    //             console.error(
    //                 'Select2 is not loaded'
    //             );

    //             return;
    //         }

    //         $el.select2({

    //             width: '100%',

    //             tags: allowCreate,

    //             ajax: {

    //                 url:
    //                     'api/modules/form/taxonomy/search',

    //                 dataType: 'json',

    //                 delay: 250,

    //                 cache: true,

    //                 data(params){

    //                     return {

    //                         q:
    //                             params.term || '',

    //                         source:
    //                             $el.data(
    //                                 'taxonomy-source'
    //                             )
    //                     };
    //                 },

    //                 processResults(data){

    //                     return {

    //                         results:
    //                             data.results || []
    //                     };
    //                 }
    //             },

    //             /*
    //             |--------------------------------------------------------------------------
    //             | Allow Custom Creation
    //             |--------------------------------------------------------------------------
    //             */

    //             createTag(params){

    //                 const term =
    //                     $.trim(
    //                         params.term
    //                     );

    //                 if(term === ''){

    //                     return null;
    //                 }

    //                 return {

    //                     // id:
    //                     //     '__new__:' + term,
    //                     id:
    //                         '__taxonomy__|'
    //                         + $el.data('taxonomy-source')
    //                         + '|'
    //                         + term,

    //                     text:
    //                         term,

    //                     newTag:
    //                         true
    //                 };
    //             }
    //         });
    //     });
    // }

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