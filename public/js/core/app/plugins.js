//JQUERY Plugins
$.fn.center = function() {
    this.css({
        'position': 'fixed',
        'left': '50%',
        'top': '50%'
    });
    this.css({
        'margin-left': -this.outerWidth() / 2 + 'px',
        'margin-top': -this.outerHeight() / 2 + 'px'
    });

    return this;
};

$.fn.centerIn = function(obj) {
    if(obj){
        paro = $(obj);
    }else{
        paro = this.parent();
    // Debug.log('Parent id:' + paro.attr('id'));
    };

    var l = paro.width()/2 - this.width()/2;
    var t = paro.height()/2 - this.height()/2;
    // Debug.log('left:'+l+' top:'+t);
    this.css({top: t , left: l });
    return this;
};

$.fn.positionOn = function(element, align) {
    return this.each(function() {
        var target   = $(this);
        var position = element.position();

        var x      = position.left; 
        var y      = position.top;

        // Debug.log('Conmtent pos y:'+y);

        if(align == 'right') {
            x -= (target.outerWidth() - element.outerWidth());
        } else if(align == 'center') {
            x -= target.outerWidth() / 2 - element.outerWidth() / 2;
        };

        target.css({
            position: 'absolute',
            zIndex:   5000,
            top:      y, 
            left:     x
        });
    });
};

$.fn.addEffect = function(fx) {
    this.addClass("animated").removeClass(fx).addClass(fx);
    return this;
};

$.fn.notify = function(){
    var fx = 'backgroundAnimated';
    var obj = this;
    this.removeClass(fx).addClass(fx).removeNotifyEffect(fx);
};

$.fn.removeNotifyEffect = function(fx) {
    var obj = this;
    this.on('webkitAnimationEnd oanimationend msAnimationEnd animationend',
        function(e){
        obj.removeClass('backgroundAnimated');
    });
    return this;
};

$.fn.removeEffect = function(fx) {
    var obj = this;
    this.one('webkitAnimationEnd oanimationend msAnimationEnd animationend',
    function(e){
    obj.removeClass('animated').removeClass(fx);
    });
    return this;
};

$.fn.addFX = function(fx) {
    if(this.hasClass("animated")) this.removeClass("animated");
    if(this.hasClass(fx)) this.removeClass(fx);   
    this.addClass("animated").animate();
    this.addClass(fx).removeEffect(fx);
    return this;
};

$.fn.onlyAlphabets = (function (){
    $(this).on('keypress', function (e) {
        // logTest('works' + e.keyCode);
        try {
            var charCode = e.keyCode;
            if ((charCode > 64 && charCode < 91) || (charCode > 96 && charCode < 123) || charCode == 8 || charCode == 32)
                return true;
            else
                return false;
        }
        catch (err) {
            alert(err.Description);
        }
    });
});

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

function alertifyReset(params) {
    // $("#toggleCSS").attr("href", "../themes/alertify.default.css");
    var params = {
        labels : {
            ok     : "OK",
            cancel : "Cancel"
        },
        delay : 5000,
        buttonReverse : false,
        buttonFocus   : "ok"
    };


    alertify.set(params);
}

function alertifyShow(type, message, duration){
    var duration = (typeof duration === 'undefined') ? 3000 : duration;
    if (typeof duration !== "number") throw new Error("duration must be a number");
    // if(message == "") return;
    message = _defaults(message,"Info...");

    alertifyReset();
    alert_type = alertify.log;
    switch(type){
        case "info":
            alert_type = alertify.log;
            break;
        case "success":
            alert_type = alertify.success;
            break;
        case "error":
            alert_type = alertify.error;
            break;
        default:
            alert_type = alertify.log;
            break;
    }

    alert_type(message,duration);
}

function _defaults( arg , def ){
    return (typeof arg == 'undefined' ? def : arg );
}

function getFormData($form){
    var unindexed_array = $form.serializeArray();
    var indexed_array = {};

    $.map(unindexed_array, function(n, i){
        indexed_array[n['name']] = n['value'];
    });

    return indexed_array;
}
function hideSelected(value) {
    if (value && !value.selected) {
      return $('<span>' + value.text + '</span>');
    }
}

$.fn.isOnScreen = function(partial){

    //let's be sure we're checking only one element (in case function is called on set)
    var t = $(this).first();
    
    //we're using getBoundingClientRect to get position of element relative to viewport
    //so we dont need to care about scroll position
    var box = t[0].getBoundingClientRect();
    
    //let's save window size
    var win = {
        h : $(window).height(),
        w : $(window).width()
    };
    
    //now we check against edges of element
    
    //firstly we check one axis
    //for example we check if left edge of element is between left and right edge of scree (still might be above/below)
    var topEdgeInRange = box.top >= 0 && box.top <= win.h;
    var bottomEdgeInRange = box.bottom >= 0 && box.bottom <= win.h;
    
    var leftEdgeInRange = box.left >= 0 && box.left <= win.w;
    var rightEdgeInRange = box.right >= 0 && box.right <= win.w;
    
    
    //here we check if element is bigger then window and 'covers' the screen in given axis
    var coverScreenHorizontally = box.left <= 0 && box.right >= win.w;
    var coverScreenVertically = box.top <= 0 && box.bottom >= win.h;
    
    //now we check 2nd axis
    var topEdgeInScreen = topEdgeInRange && ( leftEdgeInRange || rightEdgeInRange || coverScreenHorizontally );
    var bottomEdgeInScreen = bottomEdgeInRange && ( leftEdgeInRange || rightEdgeInRange || coverScreenHorizontally );
    
    var leftEdgeInScreen = leftEdgeInRange && ( topEdgeInRange || bottomEdgeInRange || coverScreenVertically );
    var rightEdgeInScreen = rightEdgeInRange && ( topEdgeInRange || bottomEdgeInRange || coverScreenVertically );
    
    //now knowing presence of each edge on screen, we check if element is partially or entirely present on screen
    var isPartiallyOnScreen = topEdgeInScreen || bottomEdgeInScreen || leftEdgeInScreen || rightEdgeInScreen;
    var isEntirelyOnScreen = topEdgeInScreen && bottomEdgeInScreen && leftEdgeInScreen && rightEdgeInScreen;
    
    return partial ? isPartiallyOnScreen : isEntirelyOnScreen;
    
};
    
$.expr.filters.onscreen = function(elem) {
    return $(elem).isOnScreen(true);
};
    
$.expr.filters.entireonscreen = function(elem) {
    return $(elem).isOnScreen(true);
};
function adjustFooter(){
    var sh = 0;
    $('section').each(function(){
        sh += $(this).height();
    });
    if($('header').length != 0){
        var hd = $('header').height();
    }else{
        var hd = $('nav').height();
    }

    if($('footer').length == 0){
        return;
    }

    var docH = $(document).height();
    var ftrH = $('footer').height();
    var siteH = sh + hd + ftrH;
    var ovflH = docH - siteH; 
    if(docH > siteH){
        $('footer').height(ovflH-50);
    }
    // console.log('document: '+docH);
    // console.log('site: '+siteH);
    // console.log('header: '+hd);
    // console.log('sections: '+sh);
    // console.log('footer: '+ftrH);
    // console.log('overflow: '+ovflH);
}

function isDefined(obj){
    if(typeof obj != 'undefined'){
        return true;
    }
    if(typeof _log != 'undefined'){
        Logger.info(obj+" is not isDefined");   
    }
    return false;
}