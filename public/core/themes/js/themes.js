/*Themes Plugin*/
(function( mPGs, $, undefined ) {
    mPGs.editThemeItem = function(obj){
        var btn = $(obj);
        var btntext_prev = btn.find('.btn_text').html();
        var btnloading = btn.find('.btn_loading');
        var id = btn.data('id');
        var itm = btn.closest('tr').find('input.itemvalue').val();

        if(id && itm){
            btn.prop( "disabled", true);
            btnloading.html('<img class="jx_status" src="assets/images/icons/ajax.gif"/>');
            new CallBora("api/modules/themes/edititem")
            .setMethod("POST")
            .setParams({id:id,itm:itm})
            .setCallback((res) => {
                btnloading.html('<img class="jx_status" src="assets/images/icons/success.png"/>');
                btn.find(".jx_status").delay(5000).fadeOut(800);  
                if(res.response=="success"){
                    alertBora.notify(res.message, 'success', 2);
                    $("body").get(0).style.setProperty(res.data.item, res.data.value);
                }else{
                    alertBora.notify(res.message, 'error', 20);
                }
                
                btnloading.delay(3000).queue(function(next) {
                    $(this).html('');
                    
                    next();
                });

                
            })
            .setDone(() => {
                console.log("Request finished");
                btn.prop( "disabled", false);                
            })
            .setError((xhr) => console.error("Error:", xhr))
            .build();
    
        }
    };

    mPGs.themeItemChange = function(e){
        e.preventDefault();
        // $(this).parent().find('.color').css("background-color", $(this).colorpicker('getValue', '#ffffff') );
    
        // var id = $(this).parent().find('input.itemvalue').attr('data-id');
        // var itm = $(this).parent().find('input.itemvalue').val();
        // logTest(id);
        // $('#item-'+id+'_img').html('<button id="btn_'+id+'" class="btn small  btn-success" data-id="'+id+'" data-itm="'+itm+'" onclick="event.preventDefault();mPGs.editThemeItem(this)"><span class="btn_text">Save</span><span class="btn_loading"></span></button>');
    };
    mPGs.themeTest = function(){
        logTest('mPGs.themeTest Loaded!');
    };

}( window.mPGs = window.mPGs || {}, jQuery ));


function exportTheme(obj){
    var id = $(obj).data('id')??1;
    alertBora.notify("Exporting theme...", 'success');

    let win = window.open(
        `api/modules/themes/exporttheme?id=${id}`,
        "themeDownload",
        "width=10,height=10,left=10000,top=10000"
    );

    if (!win) {
        alertBora.notify("Popup blocked. Please allow popups.", "error");
        return;
    }

    if (win) {
        win.addEventListener("beforeunload", () => {
            setTimeout(() => {
                if (!win.closed) win.close();
            }, 50);
        });
    }

    // Close after safe delay
    setTimeout(() => {
        if (win && !win.closed) win.close();
    }, 3000);

    //Call API
    // new CallBora(`api/modules/themes/exporttheme`)
    //         .setMethod("POST")
    //         .setParams({id:id})
    //         // NEW: enable file download!
    //         .setDownload("theme.json")
    //         .setResponseType("blob")
    //         .setCallback((res) => {
    //             alertBora.notify("Exported", 'success');
    //         })
    //         .setDone(() => {
    //             console.log("Request finished");
    //         })
    //         .setError((xhr) => {
    //             alertBora.notify("Error exporting theme", "error");
    //             console.error(xhr);
    //         })
    //         .build();
}

// alert('Here Themes...');