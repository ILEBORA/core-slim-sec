mPGs.openPageEditor = function(id) {
    // return mPGs.klassPopup('pages', 'manage', id, 'edit');
    // return mPGs.klassPopup('pages', 'manage', id, 'edit', null, null, null);
    const popup = window.__BORA_APP__?.service?.('popup');
    if (!popup) return;

    popup.open({
        mode:   'form',
        module: 'pages',
        group:  'manage',
        view:   'edit',
        id:     id,
        tab:    'edit',
        size:   'md',
        meta:   null
    });
};

mPGs.openMotherPageSettings = function (id, tab = 'settings') {
    // return mPGs.klassPopup('pages', 'manage', id, 'settings', null, null, null);
    const popup = window.__BORA_APP__?.service?.('popup');
    if (!popup) return;

    popup.open({
        mode:   'form',
        module: 'pages',
        group:  'manage',
        view:   'settings',
        id:     id,
        tab:    'settings',
        size:   'md',
        meta:   null
    });
};


mPGs.openSubpageModal = function(id){
    // return mPGs.klassPopup('pages', 'manage', id, 'subpage', null, null, null);
    const popup = window.__BORA_APP__?.service?.('popup');
    if (!popup) return;

    popup.open({
        mode:   'form',
        module: 'pages',
        group:  'manage',
        view:   'subpage',
        id:     id,
        tab:    'subpage',
        size:   'md',
        meta:   null
    });
};

mPGs.openArrangeUI = function(id){
    // return mPGs.klassPopup('pages', 'manage', null, 'arrange', null, null, null);
    const popup = window.__BORA_APP__?.service?.('popup');
    if (!popup) return;

    popup.open({
        mode:   'form',
        module: 'pages',
        group:  'manage',
        view:   'arrange',
        id:     id,
        tab:    'arrange',
        size:   'md',
        meta:   null
    });
};

mPGs.togglePageStatus = function(id){
    // return mPGs.klassPopup('pages', 'manage', id, 'toggle', null, null, null);
    const popup = window.__BORA_APP__?.service?.('popup');
    if (!popup) return;

    popup.open({
        mode:   'form',
        module: 'pages',
        group:  'manage',
        view:   'toggle',
        id:     id,
        tab:    'toggle',
        size:   'md',
        meta:   null
    });
};


mPGs.confirmDelete = function(id){
    alertBora.confirm('Are you <em>really</em> sure?', {
            html: true
    }).autoCancel(20)
    .then(function() {
        // TODO:: soft delete
        alert('Delete not activated.');
    }, function() {
        logTest('Confirmation canceled');
    });
};


$(function(){
    alertBora.set('notifierPosition', 'bottom-left').set('notifierDelay', 4);
    alertBora.notify('Pages Module active!', 'success', 5);
});

