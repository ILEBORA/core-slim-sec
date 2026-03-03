
var appWidgets = addPlugin('appWidgets', {
    pluginName: 'appWidgets',
    b: 0,
    saving: false,
    init() {

    }
});

// settings.registerElement();
// settings.initElements();
appWidgets.addMethods({
    
});


(function() {
    // appWidgets.registerFunc('manageWidgets',function(){
    //     console.log('Register manageWidgets');
		// Toggle dash controls when container is clicked
        $(document).on('click', '.dash-controls-toggle', function() {
            $(this).toggleClass('opened');
            var cont = $(this).parent('.dash-controls-container');
                cont.toggleClass('expanded');
                cont.find('.dash-controls').toggleClass('expanded');
                // Adjust container height based on content visibility
                
                cont.find('.dash-controls-toggle i').toggleClass('fa-cogs fa-times');
        });
        
        // Show tools on hover
        $(document).on('mouseenter', '.widget_container', function() {
            // When mouse enters the container
            $(this).find('.widget_tools').show();
        });
    
        $(document).on('mouseleave', '.widget_container', function() {
            // When mouse leaves the container
            $(this).find('.widget_tools').hide();
        });
    // });

    // this.manageWidgets = function(obj){
    //     alert('manageWidgets widget');
    // };

    

}).apply(appWidgets);

console.log('TODO::Fix Manage Widgets here');

$(function(){
    // $(".dashboard-counts .row").sortable({
    //     // axis: "y", // Allow sorting only vertically
    //     containment: "parent", // Constrain sorting within the parent element
    //     cursor: "move", // Change cursor to indicate draggable
    //     tolerance: "pointer", // Make the mouse pointer sensitive to the draggable item
    // }).disableSelection(); // Prevent text selection while dragging
    ILEBORA.use('assets/js/draggable', function() {
        if(typeof draggable !== 'undefined'){
            if(typeof draggable !== 'undefined'){
                $('.widget_container').draggable({
                    handle: '.handle', 
                    revert: true,
                    placeholder: true,
                    // connectToSortable: ".dashboard-counts .row",
                    // helper: "clone", // Create a clone of the dragged item
                    // revert: "invalid" ,
                    // droptarget: '.drop',
                    // drop: function(evt, droptarget) {
                    //     $(this).appendTo(droptarget).draggable('destroy');
                    // }
                });
            }
        }

        $(".parent").droppable({
            accept: '.drop',
            drop: function(event, ui) {
            $(this).append($(ui.draggable));
            }
        });
    });
});

// alert('dashboard');