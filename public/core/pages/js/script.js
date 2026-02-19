mPGs.openPageEditor = function(id) {
    // return mPGs.klassPopup('pages', 'manage', id, 'edit');
    return mPGs.klassPopup('pages', 'manage', id, 'edit', null, null, null);
};

mPGs.openMotherPageSettings = function (id, tab = 'settings') {
    return mPGs.klassPopup('pages', 'manage', id, 'settings', null, null, null);
};


mPGs.openSubpageModal = function(id){
    return mPGs.klassPopup('pages', 'manage', id, 'subpage', null, null, null);
};

mPGs.openArrangeUI = function(id){
    return mPGs.klassPopup('pages', 'manage', null, 'arrange', null, null, null);
};

mPGs.togglePageStatus = function(id){
    return mPGs.klassPopup('pages', 'manage', id, 'toggle', null, null, null);
};


mPGs.confirmDelete = function(id){
    alertBora.confirm('Are you <em>really</em> sure?', {
            html: true
    }).autoCancel(20)
    .then(function() {
        // TODO:: soft delete
    }, function() {
        logTest('Confirmation canceled');
    });
};


$(function(){
    alertBora.set('notifierPosition', 'bottom-left').set('notifierDelay', 4);
    alertBora.notify('Pages Module active!', 'success', 5);
});

