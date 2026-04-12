// (function( mPGs, $, undefined ) {
    function cAccessPermission(obj,e){
        var stt = ($(obj).prop('checked')) ? 1 : 0;
        var id = $(obj).attr('data-id');

        new CallBora("api/modules/system/permissions/permaccess")
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

    };
// }( window.mPGs = window.mPGs || {}, jQuery ));


alert('Here system...');