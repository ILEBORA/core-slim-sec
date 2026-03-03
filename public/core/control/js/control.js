var modControl = addPlugin('modControl', {
    pluginName: 'modControl',
    init() {

    },
    toggleModule(btn) {
        const moduleId = btn.dataset.moduleId;
        const action = btn.dataset.action;

        //Bora.formPopup('modules/control/forms/module/toggle', {
        //    module_id: moduleId,
        //    action: action
        //});

        
        mPGs.klassPopup('control', 'module', moduleId, 'edit', null, null, { action:action, module_id: moduleId });
    }
});

// alert('Control...');