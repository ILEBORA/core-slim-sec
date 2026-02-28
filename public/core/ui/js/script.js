appUI.dropDown = addPlugin(
    BoraPlugin,
    {
        pluginName: 'dropDown',
        debug: false,
        activeItemClass: 'menu-target-active', // custom highlight class

        init: function() {
            BoraPlugin.init.call(this);
            const self = this;
            if (self.debug) console.log('Dropdown plugin initialized.');

            $(function() {
                // --- Toggle dropdown
                $(document).off('click.appDropdown')
                    .on('click.appDropdown', '.dropdown .dropdown-toggle', function(e) {
                        e.preventDefault();
                        e.stopPropagation();

                        const $dropdown = $(this).closest('.dropdown');
                        const $menu = $dropdown.find('.dropdown-menu');

                        // Close others first
                        self.closeAll();

                        // Toggle current one
                        $menu.toggleClass('show');

                        // Highlight related item
                        if ($menu.hasClass('show')) {
                            self.highlightItem($dropdown);
                        } else {
                            self.unhighlightAll();
                        }

                        if (self.debug) console.log('Dropdown toggled:', $dropdown[0]);
                    });

                // --- Close on outside click
                $(document).off('click.closeDropdown')
                    .on('click.closeDropdown', function(e) {
                        if ($(e.target).closest('.dropdown').length === 0) {
                            self.closeAll();
                            self.unhighlightAll();
                            if (self.debug) console.log('Closed all dropdowns (outside click)');
                        }
                    });

                // --- Close when clicking a dropdown item
                $(document).off('click.dropdownItem')
                    .on('click.dropdownItem', '.dropdown .dropdown-item', function(e) {
                        const $menu = $(this).closest('.dropdown-menu');
                        $menu.removeClass('show');
                        self.unhighlightAll();
                        if (self.debug) console.log('Dropdown item clicked, menu closed.');
                    });
            });
        },

        closeAll() {
            $('.dropdown .dropdown-menu.show').removeClass('show');
        },

        highlightItem($dropdown) {
            // Find the parent element to highlight
            const $target = $dropdown.closest('[data-menu-id], .grid-item, .table-row, .card, .list-item');
            if ($target.length) {
                this.unhighlightAll(); // remove previous highlights
                $target.addClass(this.activeItemClass);
                if (this.debug) console.log('Highlighting item:', $target[0]);
            }
        },

        unhighlightAll() {
            $('.' + this.activeItemClass).removeClass(this.activeItemClass);
        }
    }
);

// Optional CSS highlight class
$('<style>')
    .prop('type', 'text/css')
    .html(`
        .menu-target-active {
            background-color: rgba(0, 123, 255, 0.08);
            transition: background-color 0.3s;
        }
    `)
    .appendTo('head');

// Init + Debug
appUI.dropDown.setDebug(true);
appUI.dropDown.init();


(function( mPGs, $, undefined ) {
        mPGs.hideOptionsMenu = function() {
            // remove td active
            $(".table-opt").removeClass('active');
            
            var menu = $(".optionsMenu");
                menu.css("display", "none").removeClass('active');
            var optionsBtn = $('.optionsButton');
                optionsBtn.removeClass('active');
            // if(menu.css("display") != "none") {
                
                
                
            // }
            $('table tr').css('border','none');
            // $('table.pledges tr').animate({
            //     borderWidth: "0"
            //  }, 2000);
            mPGs.menuActive = false;
        };

        mPGs.menuActive = false;
        
        mPGs.showOptionsMenu = function (button) {
            mPGs.hideOptionsMenu();
            // var menu = $(".optionsMenu");
            //     menu.css("display", "none")
            //     .removeClass('active');
            // logTest('this one');
            // logTest(mPGs.menuActive);
            var btn = $(button);
                btn.addClass('active');
                // btn.addClass('activer');
            // var songId = $(button).prevAll(".songId").val();
            var menu = btn.next("nav.optionsMenu");
                menu.addClass('active');
                // menu.show();
                // menu.html('test');
    
            var tr  = btn.closest('tr');
                tr.css('border','#333 2px solid');
            var menuWidth = menu.width;
            // menu.find(".songId").val(songId);
        
            var scrollTop = $(window).scrollTop(); //Distance from top of the window to top of the document
            var elementOffset = $(button).offset().top; //Distance from top of the document
            var top = elementOffset - scrollTop; //Calculation new position of the options menu
        
            var right = '60px';
        
            menu.css({"right": "60px", "display": "block" });

            mPGs.menuActive = true;

            // add active/
            var tdButtonCont = $(button).closest("td.table-opt");
                tdButtonCont.addClass('active');

            if(!mPGs.isInView($(button).closest("td").get(0))){
                // logTest('needs fixing');//TODO:: fix optionsmenu
                $('.optionsMenu').css({top: "-150px"});
            }else{
                // logTest('probably okay');
                $('.optionsMenu').css({top: "-50px"});
            }

            //TODO:: scrollable long list
        };

        mPGs.isInView = function(el) {
            var rect = el.getBoundingClientRect();
            var elBottom = rect.bottom+$(el).height()+100;
            
            var visible = (elBottom <= window.innerHeight);
            
            return visible;
        };
        
        mPGs.openTab = function(pop,tab){
            var pop = eval(pop);
            pop.findTab(tab)
        };
    
        mPGs.hideOptionsMenu = function() {
            var menu = $(".optionsMenu");
                menu.css("display", "none").removeClass('active');
            var optionsBtn = $('.optionsButton');
                optionsBtn.removeClass('active');
            // if(menu.css("display") != "none") {
                
                
                
            // }
            $('table tr').css('border','none');
            // $('table.pledges tr').animate({
            //     borderWidth: "0"
            //  }, 2000);
            mPGs.menuActive = false;
        };

        mPGs.menuActive = false;

        mPGs.changeAvatar = function(obj){
            Debug.log("Add item pop!");
            const container = $(obj).closest('.bora-prompt');
            var prev = $(obj).attr('data-prev');
            var typ = $(obj).attr('data-id');
            var itm = $(obj).attr('data-itm');
            if(prev){
                alertBora.prompt('<h2>Change Picture</h2>', {
                    html: true,
                    prompt:'' +
                    'Profile pic: <input type="file" data-itm="'+itm+'" data-id="'+typ+'" accept="image/jpeg" class="alertable-input" id="newimage" name="newimage" onchange="mPGs.uploadAvatar(this)">' +
                    '<div align="center"><span id="artUpload" class="badge" style="font-size:small;"></span><img id="artHolder" src="'+prev+'" onerror="this.onerror=null;this.src=\'assets/images/icons/placeholder.png\';" width="250" class="frame" />' +
                    '<input type="hidden" class="alertable-input hide" placeholder="path" id="artworkPath" name="artworkPath"/>' +
                    '<input type="hidden" class="alertable-input hide" placeholder="file" id="artworkFile" name="artworkFile"/>'
                }).then(function(det) {
                    det['typ'] = typ;
                    det['itm'] = itm;
                    if($('#artworkFile').val()!=''){
                        new CallBora("api/modules/ui/userprofile/avatar/change")
                            .setMethod("POST")
                            .setParams(Object.assign({},det))
                            .setCallback((data) => {
                                // appHooks.call('user.logout');
                                 mPGs.uploaded = "";
                                //Update options
                                if(data.success){
                                    $('.'+typ+'Avatar'+itm).attr('src',data.data.path);
                                    $('#avtrBox').attr('data-prev',data.data.path);
                                    alertBora.notify('Updated!', 'success');
                                    if($('#avtrChange'+itm).length >0){
                                        $('#avtrChange'+itm).fadeOut('slow');
                                    }
                                }else if(data.response == 'exists'){
                                    alertBora.notify('The '+typ+' Already Exists!', 'error');
                                }else{
                                    alertBora.notify('Opps! Something went wrong!', 'error');
                                }
                            })
                            .setDone(() => {
                                console.log("Request finished");
                            })
                            .setError((xhr) => console.error("Error:", xhr))
                            .build();
                    }
                }, function() {
                    logTest('Avatar Add canceled');
                    if($('#artworkFile').val()!=''){
                        mPGs.purgeArt(typ);
                    }
                });
        }else{
            alertBora.notify('Please try again!');
        }
    };


    mPGs.purgeArt = function(typ){
        if(mPGs.uploaded){
            new CallBora("api/modules/ui/userprofile/avatar/purge")
                .setMethod("POST")
                .setParams({fl:mPGs.uploaded,typ:typ})
                .setCallback((data) => {
                    // appHooks.call('user.logout');
                    mPGs.uploaded = "";
                    console.log('purged...');
                })
                .setDone(() => {
                    console.log("Request finished");
                })
                .setError((xhr) => console.error("Error:", xhr))
                .build();
        }
    };

    mPGs.uploadAvatar = function(obj){
        const container = $(obj).closest('.bora-prompt');
        var file = $(obj)[0].files[0];
        var typ = $(obj).attr('data-id');
        var itm = $(obj).attr('data-itm');
        var xhr = new XMLHttpRequest();
        (xhr.upload || xhr).addEventListener('progress',function(e){
            var done = e.position || e.loaded;
            var total = e.totalSize || e.total;
            var prog = Math.round(done/total*100);
            console.log('xhr progress:' + prog + '%');
            container.find('#artUpload').html(prog+'%');
        });

        xhr.addEventListener('load', function(e){
            console.log('xhr upload complete 5', e, this.responseText);
            var resp = $.parseJSON(this.responseText);
            console.log("Preview:: ",resp.data.preview);
            container.find('#artworkPath').val(resp.data.preview);
            container.find('#artworkFile').val(resp.data.file);
            container.find('#artHolder').attr('src',resp.data.preview);
            mPGs.uploaded = resp.data.file;
            container.find('#artUpload').html('');
        });

        xhr.open('post','api/modules/ui/userprofile/avatar/upload',true);
        var fd = new FormData();
        fd.append('typ',typ);
        fd.append('itm',itm);
        fd.append('newimage',file);

        xhr.send(fd);
    };
        
    mPGs.klassPopupO = function (klass, group, itm = null, tab = 'add', openCall = null, closeCall = null, callbackPipe = null) {
        // Store callback pipe if provided
        if (callbackPipe) {
            mPGs.callbackPipe = callbackPipe;
        }

        // Build URL for form route
        // Example: api/modules/dashboards/pagewidgets/form/add
        // or:     api/modules/dashboards/pagewidgets/form/edit/3
        let urlParts = ['api/modules', klass];

        if (group) urlParts.push('form',group);
        if (tab) urlParts.push(tab);
        if (itm) urlParts.push(itm); // optional id

        var popUrl = urlParts.join('/');

        // alert(popUrl);

        // Call the popup loader
        return mPGs.klassDiag('diagPop', klass, group, itm, tab, popUrl, openCall, closeCall);
    };

    mPGs.buildFormUrl = function (klass, group, tab = 'add', itm = null, meta = null) {
        let url = '';
        const parts = ['api/modules', klass, 'form', group, tab];
        if (itm) parts.push(itm);
        
        url = parts.join('/');

        if (meta && typeof meta === 'object') {
            const params = new URLSearchParams(meta).toString();
            url += `?${params}`;
        }
        
        return url;
    };

    mPGs.buildViewUrl = function (klass, view, tab = 'view', itm = null) {
        const parts = ['api/modules', klass, 'view', view, tab];
        if (itm) parts.push(itm);
        return parts.join('/');
    };

    mPGs.klassPopup = function (
                        klass, 
                        group, 
                        itm = null, 
                        tab = 'add', 
                        openCall = null, 
                        closeCall = null, 
                        meta = null,
                        options = {}
                    ) {
        const popUrl = mPGs.buildFormUrl(klass, group, tab, itm, meta);

        return mPGs.klassDiag(
            'diagPop',
            klass,
            group,
            itm,
            tab,
            popUrl,
            openCall,
            closeCall,
            { mode: 'form', meta },
            options
        );
    };

    mPGs.klassView = function (klass, view, itm = null, options = {}) {
        const {
            tab = 'view',
            size = 'lg',
            openCall = null,
            closeCall = null,
            state = null
        } = options;

        const popUrl = mPGs.buildViewUrl(klass, view, tab, itm);

        return mPGs.klassDiag(
            'diagPop',
            klass,
            view,
            itm,
            tab,
            popUrl,
            openCall,
            closeCall,
            {
                mode: 'view',
                size,
                state
            }
        );
    };

    mPGs.klassDiag = function (
        diagType,
        klass,
        group,
        itm,
        tab,
        popUrl,
        openCall,
        closeCall,
        meta,
        options = {}
    ) {
        const {
            size = 'md',
            mode = 'form',
            state = null
        } = options;

        // Store state globally for popup context if needed
        if (state) {
            mPGs.popupState = state;
        }

        const diag = mPGs.klassDiagO(
            diagType,   // container id
            klass,
            group,
            itm,
            tab,
            popUrl,
            openCall,
            closeCall,
            options
        );

        // annotate popup instance
        diag.__klass = klass;
        diag.__mode  = mode;
        diag.__group = group;
        diag.__item  = itm;
        diag.__size  = size;
        diag.__meta = options.meta || null;

        // apply size class (non-invasive)
        $('#' + (diagType || 'diagPop'))
            .removeClass('diag-sm diag-md diag-lg diag-full')
            .addClass('diag-' + size);

        return diag;
    };

    mPGs.klassDiagO = function (
                        pop, 
                        klass, 
                        group, 
                        itm, 
                        tab, 
                        popUrl, 
                        openCall, 
                        closeCall, 
                        options = {}
                    ) {
        if (mPGs.activePopup) {
            console.log('OPRIONS',options);
            if (options.force) {
                console.log('Forcing popup replacement');
                // mPGs.activePopup.close();
                // mPGs.activePopup = null;
            } 
            else if (options.reuse) {
                console.log('Reusing active popup');
                return mPGs.activePopup;
            } 
            else {
                console.warn('Popup already active, ignoring new request');
                return mPGs.activePopup;
            }
        }

        // Create a new popup instance
        const diagPop = new BoraPopup({
            containerId: pop || 'diagPop',
            onOpen: () => {
                if (typeof openCall === 'function') openCall();
            },
            onLoaded: (url) => {
                console.log('Popup content loaded from:', url);
                // If callbackPipe exists, inject it into the popup DOM
                if (mPGs.callbackPipe) {
                    alert('Context');
                    // const params = new URLSearchParams(mPGs.callbackPipe).toString();
                    // popUrl += "?" + params;
                    // alert('Here'+popUrl);
                    // TODO:: explore popup context
                    // const container = document.querySelector(`#${pop || 'diagPop'} .bora-form`);
                    // if (container) { //alert('Context found');
                    //     const input = document.createElement("input");
                    //     input.type = "text";
                    //     input.name = "_context";
                    //     input.value = JSON.stringify(mPGs.callbackPipe);
                    //     container.appendChild(input);
                    // }
                }
            },
            onClose: () => {
                if (typeof closeCall === 'function') closeCall();
            }
        });

        // mPGs.activePopup = diagPop;

        // Debug (optional)
        if (mPGs.callbackPipe) {
            // alert('Add Context');
            const params = new URLSearchParams(mPGs.callbackPipe).toString();
            popUrl += "?" + params;
            // alert('Here'+popUrl);
        }
        console.log('Opening popup from:', popUrl);
        // alert('there'+popUrl);
        // Open the popup (loads HTML content from backend)
        diagPop.open(popUrl);

        mPGs.activePopup = diagPop;

        return diagPop;
    };


        mPGs.callbackPipe = null;

        mPGs.mainCallBack  = function(data){
            if(mPGs.callbackPipe){
                mPGs.callbackPipe($data);
            }
        };

    
    
    }( window.mPGs = window.mPGs || {}, jQuery ));
    
    $(document).mouseup(function() {
        mouseDown = false;
    });
    
    function childOf(/*child node*/c, /*parent node*/p){ //returns boolean
        while((c=c.parentNode)&&c!==p); 
        return !!c; 
      }

    $(document).click(function(click) {
        // click.preventDefault(); //Messes with Alertable
        var target = $(click.target);
        var targetParent = (click.target.parentNodet);
        // logTest(targetParent);
        
        //TODO:: dont close menu on popup interaction
        if(!target.hasClass("item") && !target.hasClass("optionsButton active")) {
            //Only outside Popups
            if (target.parents('div.myTabs').length == 0 && mPGs.menuActive){
                logTest('inside');
                mPGs.hideOptionsMenu();
            }else{
                logTest('Outside')
            }
        }
        
    });
    
    $(window).scroll(function() {
        // mPGs.hideOptionsMenu();
    });
    
    function demoFromHTML() {
        var pdf = new jsPDF('p', 'pt', 'a4');
        // source can be HTML-formatted string, or a reference
        // to an actual DOM element from which the text will be scraped.
        source = $('#dashboard-counts')[0];
    
        // we support special element handlers. Register them with jQuery-style 
        // ID selector for either ID or node name. ("#iAmID", "div", "span" etc.)
        // There is no support for any other type of selectors 
        // (class, of compound) at this time.
        specialElementHandlers = {
            // element with id of "bypass" - jQuery style selector
            '#bypassme': function (element, renderer) {
                // true = "handled elsewhere, bypass text extraction"
                return true
            }
        };
        margins = {
            top: 80,
            bottom: 60,
            left: 40,
            width: 522
        };
        // all coords and widths are in jsPDF instance's declared units
        // 'inches' in this case
        pdf.fromHTML(
        source, // HTML string or DOM elem ref.
        margins.left, // x coord
        margins.top, { // y coord
            'width': margins.width, // max width of content on PDF
            'elementHandlers': specialElementHandlers
        },
    
        function (dispose) {
            // dispose: object with X, Y of the last line add to the PDF 
            //          this allow the insertion of new lines after html
            pdf.save('Test.pdf');
        }, margins);
    }

class KlassPopup {
    constructor() {
        this.klass = null;
        this.group = null;
        this.item = null;
        this.tab = null;
        this.openCall = null;
        this.closeCall = null;
        this.callbackPipe = null;
    }

    setClass(klass) {
        this.klass = klass;
        return this;
    }

    setGroup(group) {
        this.group = group;
        return this;
    }

    setItem(item) {
        this.item = item;
        return this;
    }

    setTab(tab) {
        this.tab = tab;
        return this;
    }

    setOpenCall(openCall) {
        this.openCall = openCall;
        return this;
    }

    setCloseCall(closeCall) {
        this.closeCall = closeCall;
        return this;
    }

    setCallbackPipe(callbackPipe) {
        this.callbackPipe = callbackPipe;
        return this;
    }

    build() {
        console.count('LEGACY POPUP constructed');
        forceNs("EPop", () => {
            if (typeof diagPop === 'undefined') {
                console.log('diagPop not defined!');
                diagPop = new EPop.Class('diagPop');
                diagPop.clickAway(false);
                diagPop.init();
            } else {
                console.log('diagPop is defined!');
                diagPop = new EPop.Class('diagPop');
                diagPop.clickAway(false);
                diagPop.init();
            }

            if (this.callbackPipe) {
                mPGs.callbackPipe = this.callbackPipe;
            }

            return mPGs.klassDiag('diagPop', this.klass, this.group, this.item, this.tab, this.openCall, this.closeCall);
        });
    }

    static show({ klass, group, item, tab, openCall, closeCall, callbackPipe }) {
        return new KlassPopup()
            .setClass(klass)
            .setGroup(group)
            .setItem(item)
            .setTab(tab)
            .setOpenCall(openCall)
            .setCloseCall(closeCall)
            .setCallbackPipe(callbackPipe)
            .build();
    }
};
    
window.KlassPopup = KlassPopup;
// alert('here');
//Loader
// document.addEventListener('DOMContentLoaded', function () {
//     var avatars = document.querySelectorAll('img.lazy[data-src]');
//     avatars.forEach(function (el) {
//         alert('load');
//         var real = el.dataset.src;
//         if (!real) return;

//         var pre = new Image();
//         pre.onload = function () { el.src = real; };
//         pre.onerror = function () { /* keep placeholder */ };
//         pre.src = real;
//     });
// });


//Notifications:
appUI.notify = addPlugin(
    BoraPlugin, 
    {
        pluginName: 'app_notify',
        init : function(){
            BoraPlugin.init.call(this); // Call the base init method
            console.log('App Notify  initialization.');
            
            
        },

        updateStt : function(obj){
            var stt = ($(obj).prop('checked')) ? 1 : 0;
            var itm = $(obj).attr('data-role');
            var pid = $(obj).attr('data-id');
            new CallBora("api/modules/notifications/update")
                .setMethod("POST")
                .setParams({stt:stt,itm:itm,pid:pid})
                .setCallback((res) => {
                    if(res.success){
                        alertBora.notify(res.message, res.type??'success', res.duration??10);
                    }else{
                        alertBora.notify(res.message, 'error', res.duration??10);
                    }
                })
                .setDone(() => {
                    //TODO:: update Ui
                })
                .setError((xhr) => console.error("Error:", xhr))
                .build();
        },
        
    }
);

//debug
appUI.notify.setDebug(true);
 
appUI.notify.init();

// On load
$(function() {
    
});


//GRIDS
$.fn.attachDragger = (function(){
    var attachment = false, lastPosition, position, difference;
    $( $(this).selector ).on("mousedown mouseup mousemove",function(e){
        if( e.type == "mousedown" ) attachment = true, lastPosition = [e.clientX, e.clientY];
        if( e.type == "mouseup" ) attachment = false;
        if( e.type == "mousemove" && attachment == true ){
            position = [e.clientX, e.clientY];
            difference = [ (position[0]-lastPosition[0]), (position[1]-lastPosition[1]) ];
            $(this).scrollLeft( $(this).scrollLeft() - difference[0] );
            $(this).scrollTop( $(this).scrollTop() - difference[1] );
            lastPosition = [e.clientX, e.clientY];
        }
    });
    $(window).on("mouseup", function(){
        attachment = false;
    });
});

$(function(){
    //Tabke Overflow
    var els = document.getElementsByClassName('table-opt-margin');
    var cont = document.getElementsByClassName('grid-wrapper');
    for (var i = 0; i < els.length; i++) {
        var el = els[i];
        // el.style.borderColor = (isOverflown(el) ? 'red' : 'green');
        var elOverflown = isOverflown(el);
        

        var parentWithClass = el.closest('.grid-wrapper');
            parentWithClass.style.borderColor = (elOverflown ? '#db652e' : 'white');

        // var overflown = document.getElementsByClassName('.overflown');
        //     overflown.style.display = "block"

        if(elOverflown){
            $(".grid-wrapper").attachDragger();
        }
        //TODO::add oveflow scrollable
        // console.log("Element #" + i + " is " + (isOverflown(el) ? '' : 'not ') + "overflown.");
        // console.log(parentWithClass);
    }
});

function evaluateDependencies($form, debug = false) {

    $form.find('[data-depends-on]').each(function () {

        const $el  = $(this);
        const rule = ($el.data('depends-on') || '').toString().trim();

        if (!rule) return;

        // OR conditions
        const orGroups = rule.split('|');
        let isVisible = false;
            
        for (let g = 0; g < orGroups.length; g++) {
            
            const andRules = orGroups[g].split('&');
            let andMatch = true;

            for (let r = 0; r < andRules.length; r++) {

                const expr = andRules[r].trim();

                // Parse operator
                let operator = '=';
                if (expr.includes('!=')) operator = '!=';
                else if (expr.includes('=')) operator = '=';

                const parts = expr.split(operator);
                const field = parts[0]?.trim();
                const expectedRaw = parts[1]?.trim();

                if (!field || expectedRaw === undefined) {
                    andMatch = false;
                    break;
                }

                const $input = $form.find(`[name="${field}"]`);

                if (!$input.length) {
                    if (debug) console.warn('Dependency field not found:', field);
                    andMatch = false;
                    break;
                }

                let actual;

                // Handle input types
                if ($input.is(':checkbox')) {
                    actual = $input.is(':checked') ? '1' : '0';
                }
                else if ($input.is(':radio')) {
                    actual = $form.find(`[name="${field}"]:checked`).val();
                }
                else {
                    actual = $input.val();
                }

                const expectedValues = expectedRaw.split(',').map(v => v.trim());

                const match =
                    operator === '='
                        ? expectedValues.includes(actual)
                        : !expectedValues.includes(actual);

                if (debug) {
                    console.log('DEPENDS:', {
                        field,
                        actual,
                        operator,
                        expectedValues,
                        match
                    });
                }

                if (!match) {
                    andMatch = false;
                    break;
                }
            }

            if (andMatch) {
                isVisible = true;
                break;
            }
        }

        // Apply visibility
        if (isVisible) {
            $el.show();
        } else {
            $el.hide();

            // Clear only user-editable inputs
            $el.find('input:not([type=hidden]), select, textarea')
               .not(':checkbox, :radio')
               .val('');

            $el.find(':checkbox, :radio').prop('checked', false);
        }
    });
}

alert('Here UI...');