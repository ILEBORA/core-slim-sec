(function( mPGs, $, undefined ) {
    mPGs.resetPss = function(obj){
        Debug.log("Reset Password!");
            alertBora.prompt('<h2><img src="assets/images/icons/login.png" /> Password Reset</h2>', {
                html: true,
                prompt:'' +
                'Previous: <input type="password" autocomplete="off" accept="image/jpeg" style="width:100%;" required class="alertable-input custom-input" id="prevpss" name="prevpss" >' +
                'New: <input type="password" class="alertable-input custom-input" style="width:100%;" required placeholder="new..." id="newpss" name="newpss"/>' +
                'Confirm: <input type="password" class="alertable-input custom-input" style="width:100%;" required placeholder="confirm" id="confpss" name="confpss"/>'
            }).then(function(det) {
                EInit.ajx('/settings/profile/pss/change',Object.assign({},det),function(data){
                    $('#prevpss,#newpss,confpss').val('');
                    //Update options
                    if(data.response == 'updated'){
                        $.alertable.alert('Updated!');
                        if($('#pssChange').length >0){
                            $('#pssChange').fadeOut('slow');
                        }
                    }else if(data.response == 'perm'){
                        $.alertable.alert('You entered a wrong password!');
                    }else{
                        $.alertable.alert('Opps! Something went wrong!');
                    }
                });
                
            }, function() {
                $('#prevpss,#newpss,confpss').val('');
                logTest('Pss Changecanceled');
            });
    };
}( window.mPGs = window.mPGs || {}, jQuery ));