
(function( mPGs, $, undefined ) {
    mPGs.deleteDashPageWidgets = function(sid,callback){
        $.alertable.prompt('<h2>Caution:</h2>You need <i>elevated<i> permssion to Delete item (Cannot be undone).', {
            html: true,
            prompt:
            '<input type="password" class="alertable-input" name="pss" placeholder="Password">'
        }).then(function(det) {
            // det += mfd;
            det['pss'] = md5(det['pss'].trim());
            det['id'] = sid;
            // logTest(Object.assign({},det));
            EInit.ajx('/auth/dashpagewidgets/del',Object.assign({},det),function(data){
                EInit.response(data,{
                    success:function(){
                        callback(data);
                        // EInit.getAlert('alertable',data);
                        // $.alertable.alert(data.message);
                        var typ = (typeof data.response !== 'undefined') ? data.response : 'success';
                         alertifyShow(typ, data.message, 2000);
                         
                    },
                    error : function(){
                        // $.alertable.alert(data.message);
                        alertifyShow('error', data.message, 2000);
                    }
                });

            });

        }, function() {
            logTest('Item Delete canceled');
        });
    };
}( window.mPGs = window.mPGs || {}, jQuery ));

appWidgets.addMethods({
    delWidget(obj){
        alert('Del Page widget');
        //Get id
        var id = $(obj).data('id');
        
        if(id){
            mPGs.deleteDashPageWidgets(id,function(data){
                EInit.response(data,{
                    success:function(){
                        //remove element
                        var widget = $('.dwidget'+id);
                        if(data.flushed == 1){
                            widget.fadeOut('slow');
                        }else{
                            widget.removeClass('maintenance').addClass('todelete animated shake');
                            // widget.fadeOut('slow');
                        }
                    },
                    error : function(){
                        $.alertable.alert(data.message);
                        // alertifyShow('error', data.message, 2000);
                    }
                });
            });
        }
    }
});

console.log('TODO::Fix del Widges here');
alert('Delete Dash Page Widgets');