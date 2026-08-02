__BORA_REGISTER_PLUGIN__(
'system.roleperm.plugin',
async function(scope){
    // const callbora = await scope.getService('callbora');
    // const navigation = await scope.getService('navigation');
    // const uiActions = await scope.getService('ui.actions');
    // // const s2 = await scope.getService('select2');

    let callbora, navigation, uiActions;

    const state = {
        mounted: false
    };

    async function init(){

        // callbora   = await scope.getService('callbora');
        // navigation = await scope.getService('navigation');
        // uiActions  = await scope.getService('ui.actions');
        // const select2    = await scope.getService('select2');

        ({
            callbora,
            navigation,
            uiActions
        } = await scope.importServices({
            callbora: 'callbora',
            navigation: 'navigation',
            uiActions: 'ui.actions'
        }));
    

        console.log('Consts loaded...');
    }

    async function mount(){
        if (state.mounted) return;
        state.mounted = true;

        await init();
        // alert('System mounted');

        console.log('[System] system.roleperm.plugin mounted');

        $(function(){
            uiBind();
        });
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;  

        console.log('[System] system.roleperm.plugin unmounted');
    }
    //
    
    function uiBind(){

        uiActions.register('system.perm.toggle', (el)=>{
            // console.log("checked:", el.checked);
            var stt = ($(el).prop('checked')) ? 1 : 0;
            var role = $(el).attr('data-role');
            var perm = $(el).attr('data-perm');
            var pLi = $('#perm-'+role+'-'+perm);
        
            callbora.post(`api/modules/system/permissions/update`, {
                stt:stt,
                role:role,
                perm:perm
            }).then(function(res){
                if(res.success){
                    if(res.stt==1){
                        pLi.addClass('active');
                    }else{
                        pLi.removeClass('active');
                    }
                    alertBora.notify(res.message, 'success', 40);
                    
                }else{
                    alertBora.notify(res.message, 'error', 40);
                }
            })
            .catch(err => {
                console.error(err);
            })
            .finally(() => {
                console.log("Request finished");
            });
            
        });

        uiActions.register('system.perm.access.toggle', (el)=>{
            var stt = ($(el).prop('checked')) ? 1 : 0;
            var id = $(el).attr('data-id');

            new CallBora("api/modules/system/permissions/permAccess")
                    .setMethod("POST")
                    .setParams({stt:stt,id:id})
                    .setCallback((res) => {
                        //appHooks.call('after.logout');
                        //redirectTo('', true);
                        if(res.success){
                            alertBora.notify(res.message, 'success', 40);
                        }else{
                            alertBora.notify(res.message, 'error', 40);
                        }
                    })
                    .setDone(() => {
                        console.log("Request finished");
                        // alert(rd('uID'));
                        //if(typeof authChannel !== 'undefined'){
                        //    authChannel.postMessage({cmd:'logout',usr:rd('bID')});
                        //}
                    })
                    .setError((xhr) => console.error("Error:", xhr))
                    .build();
        });
   
            var resID = $('#permission_block');
            resID.html('');
            // alert('here');
            if(typeof select2 !== 'undefined'){
                // $('#roletype').select2();
                // $('#roleperm').select2();
            }
            $('#roletype').change(function(){
                // alert('Perms');
                var rid = $(this).val();
                // var rnm = $(this).text();
                if(rid != 0){
                    var myData ={id:rid};
                    
                    resID.html('<div align="center"><img src="assets/images/icons/ajax.gif"/></div>');
        
                    callbora.post(`api/modules/system/permissions`, {
                        id:rid
                    }).then(function(res){
                        // if(res.success){
                            resID.html('');
                            $('#roleperm').html(res.data);
                        // } else {
                        //     alertBora.error(res.message || 'Failed');
                        // }
        
                    });

                    // new CallBora("api/modules/system/permissions")
                    //     .setMethod("POST")
                    //     .setParams({id:rid})
                    //     .setCallback((res) => {
                    //         //appHooks.call('after.logout');
                    //         //redirectTo('', true);
                    //         resID.html('');
                    //         $('#roleperm').html(res.data);
                    //     })
                    //     .setDone(() => {
                    //         console.log("Request finished");
                    //         // alert(rd('uID'));
                    //         //if(typeof authChannel !== 'undefined'){
                    //         //    authChannel.postMessage({cmd:'logout',usr:rd('bID')});
                    //         //}
                    //     })
                    //     .setError((xhr) => console.error("Error:", xhr))
                    //     .build();
                }
            });
        
            $('#roleperm').change(function(){
                var rid = $('#roletype').val();
                var pid = $(this).val();
                // var rnm = $(this).text();
                if(rid != 0){
                    var myData ={id:rid,pid:pid};
                    
                    resID.html('<div align="center"><img src="assets/images/icons/ajax.gif"/></div>');
        
                    callbora.post(`api/modules/system/permissions/list`, {
                        id:rid,
                        pid:pid
                    }).then(function(res){
                        // if(res.success){
                            resID.html(res.data);
                        // } else {
                        //     alertBora.error(res.message || 'Failed');
                        // }
        
                    });

                    // new CallBora("api/modules/system/permissions/list")
                    //     .setMethod("POST")
                    //     .setParams({id:rid,pid:pid})
                    //     .setCallback((res) => {
                    //         //appHooks.call('after.logout');
                    //         //redirectTo('', true);
                    //         resID.html(res.data);
                    //     })
                    //     .setDone(() => {
                    //         console.log("Request finished");
                    //         // alert(rd('uID'));
                    //         //if(typeof authChannel !== 'undefined'){
                    //         //    authChannel.postMessage({cmd:'logout',usr:rd('bID')});
                    //         //}
                    //     })
                    //     .setError((xhr) => console.error("Error:", xhr))
                    //     .build();
        
                   
                }
            });
        
        
            $('#newrl').on('click', function() {
                var ths = $(this);
                $.alertable.prompt('<h2>Alert:</h2>You need <i>elevated<i> permssion:', {
                    html: true,
                    prompt:
                    '<input type="password" class="alertable-input" name="pss" placeholder="Password">' +
                    '<h2>New Role Details</h2>' +
                    '<input type="text" class="alertable-input" name="rolename" placeholder="Page Name">'
                    
                }).then(function(det) {
                    det['pss'] = md5(det['pss'].trim());
                    $.ajax({
                        type: "POST", 
                        url: rd('prjFolder')+'/admn/role/add',
                        data:Object.assign({},det),
                        dataType: 'json',
                        success: function(data){			
                            if(data.response == "perm"){
                                alertBora.alert('Wrong password!');
                                alertBora.notify("Error: Wrong Password!", 'error');
                            }else if(data.response == "success"){
                                alertBora.alert('Success: Role Added!');
                                alertBora.notify("Success: Role Added!", 'success');
                                $('#roletype').append(data.data);
                            }else if(data.response == 'exists'){
                                alertBora.alert('Error: Role already exists!');
                                alertBora.notify("Error: Role already exists!", 'error');
                            }else if(data.response == 'notset'){
                                alertBora.alert('Error: Rolename not set!');
                                alertBora.notify("Error: Rolename not set!", 'error');
                            }else{
                                alertBora.alert('Oops! Something went wrong!');
                                alertBora.notify("Error: Something went wrong!", 'error');
                                
                            }
                        }
                    });
                }, function() {
                    // logTest('Role Add canceled');
                });
            });
        
        
        
        
        

        $('#search').on('keyup', function(){
            const term = $(this).val().toLowerCase();

            $('#translationsTable tr').each(function(){
                const key = $(this).find('td:first').text().toLowerCase();
                $(this).toggle(key.includes(term));
            });
        });

        //
        $('#loadModule').on('click', function(){
            const module = $('#moduleSelect').val();
            window.location.href = `bo/system/langmanager/missing/${module}`;
        });

        $('#addAllMissing').on('click', function(e){
            e.preventDefault();

            const data = $('#missingForm').serialize();
            const module = $('#moduleSelect').val();

            $.post(`api/modules/system/langmanager/save/${module}/en`, data, function(res){
                if(res.success){
                    alertBora.notify('Added to EN', 'success');
                    location.reload();
                } else {
                    alertBora.notify(res.message ?? 'Error', 'error');
                }
            });
        });

    }


    return { mount, unmount };

},
{

    requires:[],//['realtime'],//,'hooks','events'],
    activateOn:(route)=> route.startsWith('bo/system/rolepermission')
    //TODO:: runtime face mount
    // faces: ['client', 'admin']
}
);