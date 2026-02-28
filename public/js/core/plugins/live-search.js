__BORA_REGISTER_PLUGIN__('LiveSearch', function(scope){

    const $ = scope.getService('jquery');

    function mount(el, props){

        const $el = $(el);
        const $input = $el.find('.search-input');
        const $results = $el.find('.results');

        let timeout = null;

        function search(query){

            $.getJSON(props.endpoint, { q: query }, function(data){
                renderResults(data);
            });
        }

        function renderResults(data){

            $results.empty();

            data.forEach(item=>{
                $results.append(
                    `<div class="result-item">${item.name}</div>`
                );
            });
        }

        $input.on('input', function(){

            const value = this.value;

            if(value.length < (props.minChars || 2)) return;

            clearTimeout(timeout);

            timeout = setTimeout(()=>{
                search(value);
            }, 250);
        });

        return {
            destroy(){
                $input.off('input');
            }
        };
    }

    return { mount };
});